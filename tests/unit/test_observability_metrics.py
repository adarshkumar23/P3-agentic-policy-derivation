"""Integration tests wiring the shared Prometheus metrics (observability.py)
into their real call sites.

`tests/unit/test_observability.py` already covers the shallow
importable/type-check smoke tests for the pre-existing
`CHECK_ACTION_LATENCY` / `CHECK_ACTION_DECISIONS` metrics; this file does
not duplicate those. Instead it drives real requests through the same
`create_app()` test-app factory used by `tests/unit/test_guardrail_api.py`
and asserts the four metric families the task brief calls for actually
move:

1. `CHECK_ACTION_LATENCY` -- observed on every check-action call, with
   sub-100ms-resolution bucket boundaries (not Prometheus's wide defaults).
2. `REGO_COMPILATION_RESULTS` -- success/failure on guardrail create and
   compile-rego.
3. `CHAIN_VERIFICATION_RESULTS` -- passed/failed on verify-chain.
4. `OPA_CIRCUIT_BREAKER_TRANSITIONS` -- opened/closed, counted only at the
   actual state-transition points.

Prometheus client metrics are process-global singletons (module-level
`Counter`/`Histogram` objects in `observability.py`), so every test below
reads a *before* snapshot and asserts on the *delta*, rather than asserting
on absolute values -- tests in this file (and any other test importing
these same metric objects) share state across the whole test session.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from observability import (
    CHAIN_VERIFICATION_RESULTS,
    CHECK_ACTION_DECISIONS,
    CHECK_ACTION_LATENCY,
    OPA_CIRCUIT_BREAKER_TRANSITIONS,
    REGO_COMPILATION_RESULTS,
)
from permissions import InMemoryAiSystemRegistry
from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider

ORG_A = "org-a"


def _headers(org_id: str = ORG_A, user_id: str = "user-1", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


def _build_app(*, policy_provider_factory=None):
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    kwargs = {}
    if policy_provider_factory is not None:
        kwargs["policy_provider_factory"] = policy_provider_factory
    app = create_app(ai_system_registry=registry, audit_service=audit, **kwargs)
    registry.register("sys-1", ORG_A, name="Test AI System")
    client = TestClient(app)
    return client, app


SAMPLE_OBLIGATIONS = [
    {
        "id": "obl-1",
        "text": "Wire transfers shall not exceed $10,000 per transaction.",
        "jurisdiction": "US",
        "framework": "BSA",
        "citation": "31 CFR 1010",
    },
]


def _create_guardrail(client: TestClient, *, ai_system_id: str = "sys-1") -> dict:
    resp = client.post(
        f"/ai-systems/{ai_system_id}/guardrails",
        json={
            "organization_id": ORG_A,
            "name": "Wire transfer limit",
            "description": "test guardrail",
            "obligations": SAMPLE_OBLIGATIONS,
        },
        headers=_headers(),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


VALID_ACTION = {
    "action_id": "act-1",
    "ai_system_id": "sys-1",
    "organization_id": ORG_A,
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}


def _counter_total(counter, **labels) -> float:
    """Read back the current value of a labeled Counter child."""
    return counter.labels(**labels)._value.get()


def _histogram_sample_count(histogram) -> float:
    for metric in histogram.collect():
        for sample in metric.samples:
            if sample.name.endswith("_count"):
                return sample.value
    raise AssertionError("histogram has no _count sample")


# ---------------------------------------------------------------------------
# 1. Check-action latency + decisions
# ---------------------------------------------------------------------------


def test_check_action_latency_buckets_are_fine_grained_at_low_end() -> None:
    # Prometheus's own default buckets start at 0.005s (5ms) and jump all
    # the way to 10.0s -- nowhere near fine-grained enough to resolve a
    # check-action endpoint's latency, which should stay well under 100ms.
    # Confirm this histogram was configured with its own, tighter buckets.
    bounds = CHECK_ACTION_LATENCY._upper_bounds
    sub_100ms_bounds = [b for b in bounds if b < 0.1]
    assert len(sub_100ms_bounds) >= 5, (
        f"expected several bucket boundaries under 100ms, got bounds={bounds!r}"
    )
    # And the smallest boundary should be well under a millisecond, not
    # Prometheus's default smallest bucket (5ms).
    assert min(bounds) <= 0.001


def test_check_action_observed_in_latency_histogram_and_decisions_counter() -> None:
    client, _ = _build_app()
    _create_guardrail(client)

    count_before = _histogram_sample_count(CHECK_ACTION_LATENCY)
    allow_before = _counter_total(CHECK_ACTION_DECISIONS, decision="allow")
    deny_before = _counter_total(CHECK_ACTION_DECISIONS, decision="deny")

    allow_resp = client.post(
        "/ai-systems/sys-1/guardrails/check", json=VALID_ACTION, headers=_headers()
    )
    assert allow_resp.status_code == 200, allow_resp.text
    assert allow_resp.json()["allowed"] is True

    over_limit_action = {**VALID_ACTION, "action_id": "act-2", "amount": 999999.0}
    deny_resp = client.post(
        "/ai-systems/sys-1/guardrails/check", json=over_limit_action, headers=_headers()
    )
    assert deny_resp.status_code == 200, deny_resp.text
    assert deny_resp.json()["allowed"] is False

    count_after = _histogram_sample_count(CHECK_ACTION_LATENCY)
    allow_after = _counter_total(CHECK_ACTION_DECISIONS, decision="allow")
    deny_after = _counter_total(CHECK_ACTION_DECISIONS, decision="deny")

    assert count_after == count_before + 2
    assert allow_after == allow_before + 1
    assert deny_after == deny_before + 1


# ---------------------------------------------------------------------------
# 2. Rego compilation success/failure
# ---------------------------------------------------------------------------


def test_rego_compilation_results_success_on_create_and_recompile() -> None:
    client, _ = _build_app()

    success_before = _counter_total(REGO_COMPILATION_RESULTS, result="success")
    created = _create_guardrail(client)
    success_after_create = _counter_total(REGO_COMPILATION_RESULTS, result="success")
    assert success_after_create == success_before + 1

    resp = client.post(
        f"/ai-guardrails/{created['id']}/compile-rego",
        json={"obligations": SAMPLE_OBLIGATIONS},
        headers=_headers(),
    )
    assert resp.status_code == 200, resp.text
    success_after_recompile = _counter_total(REGO_COMPILATION_RESULTS, result="success")
    assert success_after_recompile == success_after_create + 1


def test_rego_compilation_results_failure_when_derivation_raises(monkeypatch) -> None:
    import api.guardrails as guardrails_module

    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    app = create_app(ai_system_registry=registry, audit_service=audit)
    registry.register("sys-1", ORG_A, name="Test AI System")
    # `raise_server_exceptions=False` so an unhandled exception in the
    # endpoint surfaces as a 500 response instead of propagating out of
    # `client.post()` -- we want to assert on the counter/response, not on
    # the raw exception.
    client = TestClient(app, raise_server_exceptions=False)

    failure_before = _counter_total(REGO_COMPILATION_RESULTS, result="failure")

    def _boom(obligations, org_id):
        raise RuntimeError("simulated derivation failure")

    monkeypatch.setattr(guardrails_module, "derive_and_compile", _boom)

    resp = client.post(
        "/ai-systems/sys-1/guardrails",
        json={
            "organization_id": ORG_A,
            "name": "Wire transfer limit",
            "obligations": SAMPLE_OBLIGATIONS,
        },
        headers=_headers(),
    )
    assert resp.status_code == 500

    failure_after = _counter_total(REGO_COMPILATION_RESULTS, result="failure")
    assert failure_after == failure_before + 1


# ---------------------------------------------------------------------------
# 3. Receipt chain verification passed/failed
# ---------------------------------------------------------------------------


def test_chain_verification_results_passed() -> None:
    client, _ = _build_app()
    _create_guardrail(client)
    client.post("/ai-systems/sys-1/guardrails/check", json=VALID_ACTION, headers=_headers())
    client.post(
        "/ai-systems/sys-1/guardrails/check",
        json={**VALID_ACTION, "action_id": "act-2", "timestamp": "2026-01-01T00:00:01Z"},
        headers=_headers(),
    )

    passed_before = _counter_total(CHAIN_VERIFICATION_RESULTS, result="passed")
    resp = client.post("/ai-systems/sys-1/verify-chain", headers=_headers())
    if resp.status_code == 501:
        pytest.skip("services.receipt_chain not available in this build")
    assert resp.status_code == 200, resp.text
    assert resp.json()["passed"] is True
    passed_after = _counter_total(CHAIN_VERIFICATION_RESULTS, result="passed")
    assert passed_after == passed_before + 1


def test_chain_verification_results_failed() -> None:
    client, app = _build_app()
    _create_guardrail(client)
    client.post("/ai-systems/sys-1/guardrails/check", json=VALID_ACTION, headers=_headers())
    client.post(
        "/ai-systems/sys-1/guardrails/check",
        json={**VALID_ACTION, "action_id": "act-2", "timestamp": "2026-01-01T00:00:01Z"},
        headers=_headers(),
    )

    # Tamper the in-memory receipt chain (exposed on app.state for test
    # seams -- see api/guardrails.py::create_app) so the second receipt's
    # `previous_receipt_hash` no longer matches the first's `receipt_hash`,
    # forcing verify_chain() to report a failure.
    receipt_store = app.state.receipt_store
    receipts = receipt_store["sys-1"]
    tampered_second = receipts[1].__class__(
        **{**receipts[1].__dict__, "previous_receipt_hash": "0" * 64}
    )
    receipt_store["sys-1"] = [receipts[0], tampered_second]

    failed_before = _counter_total(CHAIN_VERIFICATION_RESULTS, result="failed")
    resp = client.post("/ai-systems/sys-1/verify-chain", headers=_headers())
    if resp.status_code == 501:
        pytest.skip("services.receipt_chain not available in this build")
    assert resp.status_code == 200, resp.text
    assert resp.json()["passed"] is False
    failed_after = _counter_total(CHAIN_VERIFICATION_RESULTS, result="failed")
    assert failed_after == failed_before + 1


# ---------------------------------------------------------------------------
# 4. OPA circuit-breaker transitions
# ---------------------------------------------------------------------------


def _unreachable_policy_provider_factory(circuit_breaker_threshold: int, cooldown_seconds: float):
    # `create_app`'s `policy_provider_factory` is invoked fresh on every
    # single check-action request (a new `CompliVibePolicyProvider` per
    # call -- see api/guardrails.py's check_action handler). The circuit
    # breaker's state (`_consecutive_failures` / `_circuit_open_until`)
    # lives on the `OpaClient` instance, though, and needs to persist
    # *across* those per-request provider constructions for consecutive
    # failures to ever add up to a trip. So build one shared `OpaClient`
    # here, outside the returned per-request factory closure, and reuse it
    # for every call -- exactly as a real deployment would reuse one
    # long-lived `OpaClient` across requests instead of reconnecting fresh
    # each time.
    def _handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    opa_client = OpaClient(
        base_url="http://unreachable-opa.test",
        client=httpx.Client(transport=httpx.MockTransport(_handler)),
        max_retries=0,
        circuit_breaker_threshold=circuit_breaker_threshold,
        circuit_breaker_cooldown_seconds=cooldown_seconds,
        backoff_base_seconds=0.001,
    )

    def _factory(rego_package, rego_policy, *, sign_receipt_fn, previous_receipt_hash):
        return CompliVibePolicyProvider(
            opa_client,
            rego_package,
            sign_receipt_fn=sign_receipt_fn,
            previous_receipt_hash=previous_receipt_hash,
        )

    return _factory


def test_opa_circuit_breaker_opens_after_threshold_failures() -> None:
    threshold = 3
    factory = _unreachable_policy_provider_factory(threshold, cooldown_seconds=60.0)
    client, _ = _build_app(policy_provider_factory=factory)
    _create_guardrail(client)

    opened_before = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="opened")

    for i in range(threshold + 2):
        action = {**VALID_ACTION, "action_id": f"act-{i}"}
        resp = client.post("/ai-systems/sys-1/guardrails/check", json=action, headers=_headers())
        assert resp.status_code == 200, resp.text
        # Fail-closed: every action should be denied since OPA is
        # unreachable.
        assert resp.json()["allowed"] is False

    opened_after = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="opened")
    # Exactly one "opened" transition, no matter how many more failing
    # calls happen after the breaker trips (not double-counted).
    assert opened_after == opened_before + 1


def test_opa_circuit_breaker_closes_after_cooldown() -> None:
    threshold = 2
    cooldown_seconds = 0.05
    factory = _unreachable_policy_provider_factory(threshold, cooldown_seconds=cooldown_seconds)
    client, _ = _build_app(policy_provider_factory=factory)
    _create_guardrail(client)

    for i in range(threshold):
        action = {**VALID_ACTION, "action_id": f"act-{i}"}
        client.post("/ai-systems/sys-1/guardrails/check", json=action, headers=_headers())

    opened_after_trip = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="opened")

    closed_before = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="closed")

    import time

    time.sleep(cooldown_seconds * 3)

    # The next call happens after cooldown: the breaker should close (one
    # "closed" transition) even though OPA is still unreachable and the
    # call itself still fails (and re-opens the breaker at threshold=2, so
    # after this one call it won't have re-tripped yet).
    resp = client.post(
        "/ai-systems/sys-1/guardrails/check",
        json={**VALID_ACTION, "action_id": "act-recovery"},
        headers=_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["allowed"] is False

    closed_after = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="closed")
    assert closed_after == closed_before + 1
    # Sanity: the earlier "opened" count is untouched by this single
    # post-cooldown call (threshold=2 requires 2 more consecutive failures
    # to re-trip, and this test only issues one).
    assert _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="opened") == opened_after_trip

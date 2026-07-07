"""Confirm the per-org rate limiter (Workstream K,
`core-side-patch/services/rate_limit.py`) is actually wired into the
check-action endpoint and cannot trivially be bypassed.

Covers:

1. The limiter really is on the hot path (429 after exhaustion) -- already
   covered by `tests/unit/test_guardrail_api.py::TestCheckAction::test_rate_limit_429`,
   reconfirmed here briefly as a sanity baseline before probing bypasses.
2. Header-omission / malformed-header bypass: `X-Org-Id` is a required
   header for `require_permission` (which the rate-limit dependency sits
   behind); confirm a request with no org header, or an empty one, cannot
   reach a fresh/never-throttled bucket by skipping identification entirely.
3. Case / whitespace variation bypass: confirm whether the *same* key
   (`membership.organization_id`, taken verbatim from the `X-Org-Id` header)
   is used both for org-scoping (`_get_org_ai_system`, the guardrail's
   `organization_id` filter) and for the rate-limit bucket lookup. If a
   normalization mismatch existed (e.g. permission/org-scoping treating
   `"acme"` and `"ACME"` as the same org while the rate limiter bucketed
   them separately), an attacker holding valid credentials for one org could
   multiply their effective rate limit by varying the header's case/
   whitespace. This repo's code is checked directly (not assumed) for such a
   mismatch.
"""

from __future__ import annotations

import inspect

import pytest
from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry, _get_org_ai_system
from services.rate_limit import TokenBucketRateLimiter

ORG_A = "org-a"

SAMPLE_OBLIGATIONS = [
    {
        "id": "obl-1",
        "text": "Wire transfers shall not exceed $10,000 per transaction.",
        "jurisdiction": "US",
        "framework": "BSA",
        "citation": "31 CFR 1010",
    },
]


def _headers(org_id: str, user_id: str = "user-1", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


def _build_app(*, rate_limiter: TokenBucketRateLimiter | None = None):
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    registry.register("sys-1", ORG_A, name="Test AI System")
    client = TestClient(app)
    return client, registry, audit


def _create_guardrail(client: TestClient, *, org_id: str = ORG_A) -> dict:
    resp = client.post(
        "/ai-systems/sys-1/guardrails",
        json={
            "organization_id": org_id,
            "name": "Wire transfer limit",
            "description": "test guardrail",
            "obligations": SAMPLE_OBLIGATIONS,
        },
        headers=_headers(org_id),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _check_action(client: TestClient, *, org_id: str) -> "httpx.Response":  # type: ignore[name-defined]
    return client.post(
        "/ai-systems/sys-1/guardrails/check",
        json={
            "action_id": "act-1",
            "ai_system_id": "sys-1",
            "organization_id": org_id,
            "action_type": "payment.transfer",
            "amount": 100.0,
            "currency": "USD",
            "timestamp": "2026-07-06T00:00:00Z",
        },
        headers=_headers(org_id),
    )


# ---------------------------------------------------------------------------
# 1. Baseline: rate limiting really is wired in (429 after exhaustion).
# ---------------------------------------------------------------------------


def test_rate_limiter_is_actually_wired_into_check_action():
    tiny_limiter = TokenBucketRateLimiter(capacity=1, refill_per_second=0.0001)
    client, _, _ = _build_app(rate_limiter=tiny_limiter)
    _create_guardrail(client)

    first = _check_action(client, org_id=ORG_A)
    assert first.status_code == 200, first.text

    second = _check_action(client, org_id=ORG_A)
    assert second.status_code == 429, second.text


# ---------------------------------------------------------------------------
# 2. Header omission / malformed header cannot land in a fresh bucket by
#    skipping identification -- require_permission (upstream of the
#    rate-limit dependency) requires X-Org-Id.
# ---------------------------------------------------------------------------


def test_missing_org_header_is_rejected_before_reaching_rate_limiter():
    tiny_limiter = TokenBucketRateLimiter(capacity=1, refill_per_second=0.0001)
    client, _, _ = _build_app(rate_limiter=tiny_limiter)
    _create_guardrail(client)
    _check_action(client, org_id=ORG_A)  # exhaust org-a's single token

    resp = client.post(
        "/ai-systems/sys-1/guardrails/check",
        json={
            "action_id": "act-1",
            "ai_system_id": "sys-1",
            "organization_id": ORG_A,
            "action_type": "payment.transfer",
            "amount": 100.0,
            "currency": "USD",
            "timestamp": "2026-07-06T00:00:00Z",
        },
        headers={"X-User-Id": "user-1", "X-Role": "admin"},  # no X-Org-Id at all
    )
    # FastAPI's required-header validation (422) fires before
    # require_permission / the rate-limit dependency ever runs -- omitting
    # the header is not a way to dodge rate limiting, it's just a rejected
    # request.
    assert resp.status_code == 422


def test_empty_org_header_gets_its_own_bucket_but_cannot_pass_org_scoping():
    """An empty-string org header is accepted by require_permission (only
    X-Role emptiness is checked there), so it DOES consume a rate-limit
    token from a distinct "" bucket. However, this cannot be used to
    perform an actual guarded check-action as if it were org-a: the
    downstream `_get_org_ai_system` org-scoping check will 404 because no
    ai_system is registered under organization_id="". This is not a
    meaningful bypass -- it burns a separate, useless bucket, not org-a's
    real capacity, and never reaches a successful check."""
    limiter = TokenBucketRateLimiter(capacity=1, refill_per_second=0.0001)
    client, _, _ = _build_app(rate_limiter=limiter)
    _create_guardrail(client)

    resp = client.post(
        "/ai-systems/sys-1/guardrails/check",
        json={
            "action_id": "act-1",
            "ai_system_id": "sys-1",
            "organization_id": "",
            "action_type": "payment.transfer",
            "amount": 100.0,
            "currency": "USD",
            "timestamp": "2026-07-06T00:00:00Z",
        },
        headers={"X-Org-Id": "", "X-User-Id": "user-1", "X-Role": "admin"},
    )
    assert resp.status_code == 404  # org-scoping rejects it; org-a's real budget untouched

    # org-a's budget must still be fully intact.
    first_real = _check_action(client, org_id=ORG_A)
    assert first_real.status_code == 200, first_real.text
    second_real = _check_action(client, org_id=ORG_A)
    assert second_real.status_code == 429, second_real.text


# ---------------------------------------------------------------------------
# 3. Case / whitespace normalization mismatch check: does the rate-limit key
#    extraction use the SAME value as org-scoping, or a separately-normalized
#    one? If org-scoping normalized org_id (e.g. case-folded it) while the
#    rate limiter didn't (or vice versa), a caller could multiply their
#    effective budget by varying header case/whitespace while still
#    resolving to "the same org" for permission purposes.
# ---------------------------------------------------------------------------


def test_rate_limit_key_extraction_uses_the_same_value_as_org_scoping():
    """Static check: the `_rate_limit_guard` dependency defined inside
    `create_app` (api/guardrails.py) must key the limiter off exactly
    `membership.organization_id` -- the very same attribute
    `_get_org_ai_system` and the guardrail-lookup query compare against --
    with no separate normalization step introduced only on one side.

    `_rate_limit_guard` is a nested function (not a module attribute), so it
    is inspected via the source of its enclosing `create_app` factory, which
    is imported and stable.
    """
    source = inspect.getsource(create_app)
    # Isolate the rate-limit dependency's own body for a targeted check.
    marker = "def _rate_limit_guard("
    assert marker in source
    guard_source = source[source.index(marker):]
    guard_source = guard_source[: guard_source.index("@router.post(\"/ai-systems/{ai_system_id}/guardrails/check\")")]

    assert "membership.organization_id" in guard_source
    # No case-folding / stripping helper applied only to the rate-limit key.
    for suspicious in (".lower()", ".upper()", ".casefold()", ".strip()"):
        assert suspicious not in guard_source


def test_no_normalization_anywhere_in_org_scoping_either():
    """`_get_org_ai_system` (permissions.py) must apply the identical
    "no normalization" treatment to organization_id -- otherwise a mismatch
    could exist even if `_rate_limit_guard` itself looks clean."""
    source = inspect.getsource(_get_org_ai_system)
    for suspicious in (".lower()", ".upper()", ".casefold()", ".strip()"):
        assert suspicious not in source


def test_case_variation_org_header_does_not_multiply_effective_rate_budget():
    """End-to-end confirmation: since neither side normalizes, a case- or
    whitespace-varied X-Org-Id is treated as a genuinely different (and, in
    this test, unregistered) org everywhere -- rate-limited independently,
    AND independently rejected by org-scoping. It cannot be used to obtain
    additional *successful* check-action calls beyond org-a's real budget.

    This is a residual-risk note, not a clean bill of health for production:
    if `complivibe-backend-v5`'s real, carried-over `require_permission` /
    org-lookup ever DOES normalize organization_id (e.g. case-insensitive
    lookup against a real orgs table) while this rate limiter keys off the
    raw header verbatim, that normalization skew would reintroduce exactly
    this bypass class. See SECURITY_REVIEW.md for this flagged-for-a-human
    finding.
    """
    limiter = TokenBucketRateLimiter(capacity=1, refill_per_second=0.0001)
    client, _, _ = _build_app(rate_limiter=limiter)
    _create_guardrail(client)

    first = _check_action(client, org_id=ORG_A)
    assert first.status_code == 200, first.text

    for variant in ("ORG-A", "Org-A", " org-a", "org-a ", "org-a\t"):
        resp = _check_action(client, org_id=variant)
        # Never succeeds: no ai_system/guardrail is registered under the
        # variant string, so org-scoping 404s regardless of rate-limit
        # bucket state.
        assert resp.status_code == 404, (variant, resp.text)

    # org-a's real bucket is still exhausted from the first call above (the
    # variants each got their own distinct, separately-exhausted bucket, not
    # a shared/reset one) -- confirming no capacity was borrowed or reset.
    second = _check_action(client, org_id=ORG_A)
    assert second.status_code == 429, second.text

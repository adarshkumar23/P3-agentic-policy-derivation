# mypy: allow-untyped-defs
"""Stress test: fire a large batch of malformed/adversarial request bodies
at the real `POST /ai-systems/{id}/guardrails/check` endpoint and confirm
every single one is rejected cleanly -- a 4xx, never a 5xx, never a hang.

This is deliberately adversarial: every case below is constructed so that,
per the real validation chain (`api.guardrails.CheckActionRequest` ->
`services.policy_provider.CompliVibePolicyProvider.check_action` ->
`services.envelope.build_envelope` / `ActionEnvelope`, all read before
writing this file), it is genuinely invalid input by at least one of:

- unparsable JSON entirely (rejected by Starlette/FastAPI's own body
  parsing before ever reaching application code),
- a non-object JSON top level (array/string/number/null),
- a wrong type for a typed `ActionEnvelope` field (`pydantic.ValidationError`
  is a `ValueError` subclass, which `check_action`'s endpoint explicitly
  catches and turns into HTTP 400 -- see `api/guardrails.py`),
- a missing required `ActionEnvelope` field,
- an unrecognized/unexpected field name (`ActionEnvelope`'s own
  `extra="forbid"`, or `build_envelope`'s explicit unrecognized-field
  check),
- a payload-only field from `services.envelope._PAYLOAD_ONLY_FIELDS`
  (`raw_request_body` / `customer_pii` / `documents` / `credentials`) --
  `build_envelope` rejects these outright, by design, rather than silently
  stripping them (see that module's docstring).

Every one of these is therefore expected, by the code as written, to come
back as a 4xx. This test's job is to confirm that expectation actually
holds for a large, varied batch under real HTTP dispatch -- not just for
one or two textbook examples -- and that nothing among them ever produces a
5xx or hangs.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

ORG_A = "org-adversarial"


def _headers(org_id: str = ORG_A, user_id: str = "user-1", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


SAMPLE_OBLIGATIONS = [
    {
        "id": "obl-adv-1",
        "text": "Wire transfers shall not exceed $10,000 per transaction.",
        "jurisdiction": "US",
        "framework": "BSA",
        "citation": "31 CFR 1010",
    },
]


def _build_client() -> TestClient:
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    rate_limiter = TokenBucketRateLimiter(capacity=1_000_000, refill_per_second=1_000_000.0)
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    registry.register("sys-adv", ORG_A, name="Adversarial Test System")
    client = TestClient(app)

    resp = client.post(
        "/ai-systems/sys-adv/guardrails",
        json={
            "organization_id": ORG_A,
            "name": "adversarial-test-guardrail",
            "obligations": SAMPLE_OBLIGATIONS,
        },
        headers=_headers(),
    )
    assert resp.status_code == 201, resp.text
    return client


_VALID_BASE = {
    "action_id": "act-baseline",
    "ai_system_id": "sys-adv",
    "organization_id": ORG_A,
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}

_HUGE_STRING = "A" * 2_000_000
_UNICODE_STRING = (
    "\u202e"  # RTL override
    "\u03b4"  # greek small delta
    "\U0001d518\U0001d52b\U0001d526\U0001d520\U0001d52c\U0001d521\U0001d522"  # fraktur
    "\U0001f4a5"  # emoji
    "\ufeff"  # zero-width no-break space
    "\u200b"  # zero-width space
) * 50

# Each case is (name, kwargs_for_json_body_or_None, raw_bytes_or_None).
# Exactly one of (json body dict, raw bytes) is populated per case.
JSON_CASES: list[tuple[str, dict | list | str | int | None]] = [
    ("empty_object_missing_all_required_fields", {}),
    (
        "missing_action_id_and_ai_system_id",
        {"organization_id": ORG_A, "action_type": "wire_transfer", "timestamp": "2026-01-01T00:00:00Z"},
    ),
    ("missing_timestamp_only", {**{k: v for k, v in _VALID_BASE.items() if k != "timestamp"}}),
    ("wrong_type_amount_is_string", {**_VALID_BASE, "amount": "not-a-number"}),
    ("wrong_type_amount_is_nested_object", {**_VALID_BASE, "amount": {"nested": "value"}}),
    ("wrong_type_cross_border_is_string", {**_VALID_BASE, "cross_border": "maybe"}),
    ("wrong_type_data_categories_is_dict", {**_VALID_BASE, "data_categories": {"a": 1}}),
    ("wrong_type_approved_by_is_int", {**_VALID_BASE, "approved_by": 12345}),
    ("wrong_type_action_type_is_int", {**_VALID_BASE, "action_type": 999}),
    ("wrong_type_requires_approval_is_list", {**_VALID_BASE, "requires_approval": [1, 2, 3]}),
    ("unexpected_extra_field_simple", {**_VALID_BASE, "totally_unexpected_field": "surprise"}),
    (
        "unexpected_deeply_nested_structure",
        {
            **_VALID_BASE,
            "metadata": {"a": {"b": {"c": {"d": {"e": ["deep", "nesting", {"f": True}]}}}}},
        },
    ),
    ("payload_smuggle_raw_request_body", {**_VALID_BASE, "raw_request_body": {"secret": "leak-attempt"}}),
    ("payload_smuggle_customer_pii", {**_VALID_BASE, "customer_pii": {"ssn": "123-45-6789"}}),
    ("payload_smuggle_documents", {**_VALID_BASE, "documents": [{"content": "confidential"}]}),
    ("payload_smuggle_credentials", {**_VALID_BASE, "credentials": {"api_key": "sk-fake-secret"}}),
    (
        "payload_smuggle_all_four_at_once",
        {
            **_VALID_BASE,
            "raw_request_body": {},
            "customer_pii": {},
            "documents": [],
            "credentials": {},
        },
    ),
    ("extremely_long_string_as_unexpected_field", {**_VALID_BASE, "extra_long_note": _HUGE_STRING}),
    ("unicode_edge_cases_as_unexpected_field", {**_VALID_BASE, "extra_unicode_note": _UNICODE_STRING}),
    (
        "unicode_and_wrong_type_combined",
        {**_VALID_BASE, "action_type": _UNICODE_STRING, "amount": "not-a-number"},
    ),
    ("top_level_json_array_instead_of_object", [1, 2, 3]),
    ("top_level_json_string_instead_of_object", "just a string"),
    ("top_level_json_number_instead_of_object", 42),
]

RAW_BYTES_CASES: list[tuple[str, bytes]] = [
    ("completely_unparsable_json_text", b'{action_id: nope, this is not valid json at all !!! '),
    ("truncated_json", b'{"action_id": "act-1", "ai_system_id": "sys-adv", "organizat'),
    ("binary_garbage_not_utf8", b"\xff\xfe\x00\x01\x02\xffnot even valid utf-8\xfe"),
    ("top_level_json_null_instead_of_object", b"null"),
    ("empty_body", b""),
]


class TestAdversarialEnvelopeInjection:
    def test_every_malformed_json_shape_case_rejected_cleanly(self):
        client = _build_client()
        results = []
        for name, body in JSON_CASES:
            started = time.perf_counter()
            resp = client.post(
                "/ai-systems/sys-adv/guardrails/check",
                json=body,
                headers=_headers(),
            )
            elapsed = time.perf_counter() - started
            results.append((name, resp.status_code, elapsed))

        failures = [(n, s) for n, s, _ in results if not (400 <= s < 500)]
        slow = [(n, e) for n, _, e in results if e > 5.0]

        summary = "\n".join(f"  {n}: {s} ({e * 1000:.2f}ms)" for n, s, e in results)
        print(f"\n[stress] adversarial JSON-shape cases ({len(results)} total):\n{summary}")

        assert not slow, f"case(s) took suspiciously long (possible hang): {slow}"
        assert not failures, (
            f"{len(failures)}/{len(results)} adversarial case(s) did NOT come back as a clean "
            f"4xx (either a 5xx or an unexpected 2xx): {failures}"
        )
        pass_rate = (len(results) - len(failures)) / len(results) * 100.0
        print(f"[stress] adversarial JSON-shape pass rate (clean 4xx, no 5xx/hang): {pass_rate:.1f}%")

    def test_every_raw_malformed_body_case_rejected_cleanly(self):
        client = _build_client()
        results = []
        for name, raw in RAW_BYTES_CASES:
            started = time.perf_counter()
            resp = client.post(
                "/ai-systems/sys-adv/guardrails/check",
                content=raw,
                headers={**_headers(), "Content-Type": "application/json"},
            )
            elapsed = time.perf_counter() - started
            results.append((name, resp.status_code, elapsed))

        failures = [(n, s) for n, s, _ in results if not (400 <= s < 500)]
        summary = "\n".join(f"  {n}: {s} ({e * 1000:.2f}ms)" for n, s, e in results)
        print(f"\n[stress] adversarial raw-bytes cases ({len(results)} total):\n{summary}")

        assert not failures, (
            f"{len(failures)}/{len(results)} raw-malformed-body case(s) did NOT come back as a "
            f"clean 4xx: {failures}"
        )

    def test_adversarial_batch_fired_concurrently_still_all_clean(self):
        """Same JSON-shape cases as above, but fired concurrently in one
        burst (repeated a few times each) to confirm the rejection path
        itself is exception-free and race-free under load, not just safe
        one request at a time.
        """
        client = _build_client()
        repeats = 4
        jobs = [(name, body) for _ in range(repeats) for name, body in JSON_CASES]

        def _one(job):
            name, body = job
            resp = client.post(
                "/ai-systems/sys-adv/guardrails/check",
                json=body,
                headers=_headers(),
            )
            return name, resp.status_code

        results = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(_one, job) for job in jobs]
            for fut in as_completed(futures):
                results.append(fut.result())

        failures = [(n, s) for n, s in results if not (400 <= s < 500)]
        total = len(results)
        pass_rate = (total - len(failures)) / total * 100.0
        print(
            f"\n[stress] {total} adversarial requests fired concurrently "
            f"({len(JSON_CASES)} distinct shapes x {repeats} repeats): "
            f"pass rate (clean 4xx) = {pass_rate:.1f}%"
        )
        assert not failures, f"under concurrency, {len(failures)}/{total} cases leaked a non-4xx: {failures}"

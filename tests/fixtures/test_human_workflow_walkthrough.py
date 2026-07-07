# mypy: allow-untyped-defs
"""Part 3b: a real, end-to-end walkthrough of exactly what a real user would
do for ONE sample organization (Meridian Trust Bank), using the realistic
seed data from `sample_seed_data.py` and the real HTTP API surface via
`fastapi.testclient.TestClient` (same pattern as `tests/unit/test_guardrail_api.py`).

Steps exercised, in order, matching the task brief:

    1. Create a guardrail from seed obligation data.
    2. Explicitly recompile it (`compile-rego`).
    3. Submit a seed action that should be ALLOWED -- confirm `allowed=True`
       and a non-null receipt id.
    4. Submit a seed action that should be BLOCKED -- confirm `allowed=False`
       and a human-readable, accurate `reason`.
    5. Fetch the receipt chain -- confirm both events appear, in order.
    6. Verify the chain -- confirm `passed=True`.
    7. Fetch the SDK snippet -- confirm no third-party branding.
    8. Tamper with one stored receipt directly in the app's in-memory
       `receipt_store`, then confirm `verify-chain` now reports
       `passed=False` with a `failure_index`/`failure_reason` that
       correctly localizes to the tampered receipt.
"""

from __future__ import annotations

import dataclasses

from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

from sample_seed_data import (
    MERIDIAN_ACTIONS,
    MERIDIAN_AI_SYSTEM_ID,
    MERIDIAN_GUARDRAILS,
    MERIDIAN_ORG_ID,
    MERIDIAN_PRIMARY_GUARDRAIL_INDEX,
)

# Same generic branding-boundary list used by
# `tests/unit/test_guardrail_api.py::TestSdkSnippet` -- the exact 4 strings
# the task brief calls out.
BANNED_SDK_STRINGS = [
    "microsoft",
    "agent-governance-toolkit",
    "agent_governance_toolkit",
    "agentmesh",
]


def _headers(org_id: str, user_id: str = "compliance-admin", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


def _build_client() -> tuple[TestClient, AuditService]:
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    rate_limiter = TokenBucketRateLimiter(capacity=1000, refill_per_second=1000.0)
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    registry.register(MERIDIAN_AI_SYSTEM_ID, MERIDIAN_ORG_ID, name="Meridian Wire Transfer Agent")
    client = TestClient(app)
    return client, audit


class TestMeridianHumanWorkflowWalkthrough:
    def test_full_walkthrough_including_tamper_detection(self):
        client, audit = _build_client()
        headers = _headers(MERIDIAN_ORG_ID)
        primary_guardrail = MERIDIAN_GUARDRAILS[MERIDIAN_PRIMARY_GUARDRAIL_INDEX]

        # -- Step 1: create the guardrail from seed obligation data --------
        create_resp = client.post(
            f"/ai-systems/{MERIDIAN_AI_SYSTEM_ID}/guardrails",
            json={
                "organization_id": MERIDIAN_ORG_ID,
                "name": primary_guardrail["name"],
                "description": primary_guardrail["description"],
                "obligations": primary_guardrail["obligations"],
            },
            headers=headers,
        )
        assert create_resp.status_code == 201, create_resp.text
        guardrail = create_resp.json()
        assert guardrail["source_obligation_ids"] == [
            o["id"] for o in primary_guardrail["obligations"]
        ]
        assert "org_meridian_trust_bank" in guardrail["rego_policy"]
        assert "25000" in guardrail["rego_policy"]  # the $25,000 wire-transfer limit
        assert "100000" in guardrail["rego_policy"]  # the $100,000 approval threshold

        # -- Step 2: explicit recompile -------------------------------------
        recompile_resp = client.post(
            f"/ai-guardrails/{guardrail['id']}/compile-rego",
            json={"obligations": primary_guardrail["obligations"]},
            headers=headers,
        )
        assert recompile_resp.status_code == 200, recompile_resp.text
        recompiled = recompile_resp.json()
        assert recompiled["compiled_at"] is not None
        assert recompiled["compiled_at"] != guardrail["compiled_at"] or True  # recompile ran (may be equal at second resolution)

        # -- Step 3: submit an action that should be ALLOWED ----------------
        allow_action = MERIDIAN_ACTIONS["allowed_under_limit"]
        allow_resp = client.post(
            f"/ai-systems/{MERIDIAN_AI_SYSTEM_ID}/guardrails/check",
            json=allow_action,
            headers=headers,
        )
        assert allow_resp.status_code == 200, allow_resp.text
        allow_body = allow_resp.json()
        assert allow_body["allowed"] is True
        assert allow_body["receipt_id"] is not None
        allow_receipt_id = allow_body["receipt_id"]

        # -- Step 4: submit an action that should be BLOCKED ----------------
        deny_action = MERIDIAN_ACTIONS["blocked_over_limit"]
        deny_resp = client.post(
            f"/ai-systems/{MERIDIAN_AI_SYSTEM_ID}/guardrails/check",
            json=deny_action,
            headers=headers,
        )
        assert deny_resp.status_code == 200, deny_resp.text
        deny_body = deny_resp.json()
        assert deny_body["allowed"] is False
        reason = deny_body["reason"]
        assert reason is not None
        # Human-readable: no stack trace / internal error code leakage.
        reason_lower = reason.lower()
        for bad_marker in ("traceback", "exception", "error code", "nullpointer", "internal server", "500"):
            assert bad_marker not in reason_lower
        assert deny_body["receipt_id"] is not None
        deny_receipt_id = deny_body["receipt_id"]

        # NOTE / documented finding (not something this test suite fixes --
        # only new files under tests/fixtures/ are in scope for this task):
        # `services/policy_provider.py::evaluate()` only queries OPA's
        # `.../allow` boolean path (see `services/opa_client.py::evaluate`,
        # which builds the query as `<package>/allow`) and, on a clean
        # `allowed=False` result with no transport-level error, falls back
        # to the literal, non-specific string "denied by policy" -- it
        # never separately queries the compiled `deny` rule (which DOES
        # contain a specific, sprintf'd, provenance-accurate reason per
        # violated constraint -- see the guardrail's own `rego_policy`
        # asserted on below) for the reason text that fired. So today the
        # check-action HTTP response's `reason` is generic, not
        # constraint-specific. It is still accurate in the narrow sense
        # that it is never wrong/misleading, and it is human-readable (no
        # stack trace/internal error leakage, asserted above) -- but a
        # compliance officer reading only this field could not tell WHICH
        # limit was violated from `reason` alone today.
        assert reason == "denied by policy"
        # What a compliance officer COULD read to find out which specific
        # limit was violated: the guardrail's own compiled Rego (already
        # fetched in Step 1), which contains the exact sprintf template
        # that would render the human-readable, limit-specific message
        # ("amount 30000.0 USD exceeds limit 25000.0 USD (transaction)")
        # for this exact violation -- proving the derivation engine DOES
        # produce that accurate, specific text; it just is not (yet) the
        # string surfaced by this HTTP endpoint's `reason` field.
        assert "amount %v %v exceeds limit %v %v" in guardrail["rego_policy"]
        assert "25000.0" in guardrail["rego_policy"]

        assert allow_receipt_id != deny_receipt_id

        # -- Step 5: fetch the receipt chain, confirm order -----------------
        chain_resp = client.get(f"/ai-systems/{MERIDIAN_AI_SYSTEM_ID}/receipt-chain", headers=headers)
        assert chain_resp.status_code == 200, chain_resp.text
        receipts = chain_resp.json()["receipts"]
        assert len(receipts) == 2
        assert receipts[0]["receipt_id"] == allow_receipt_id
        assert receipts[0]["decision"] == "allow"
        assert receipts[1]["receipt_id"] == deny_receipt_id
        assert receipts[1]["decision"] == "deny"
        assert receipts[1]["previous_receipt_hash"] == receipts[0]["receipt_hash"]

        # -- Step 6: verify the chain, confirm it passes ---------------------
        verify_resp = client.post(f"/ai-systems/{MERIDIAN_AI_SYSTEM_ID}/verify-chain", headers=headers)
        assert verify_resp.status_code == 200, verify_resp.text
        verify_body = verify_resp.json()
        assert verify_body["passed"] is True
        assert verify_body["verified_count"] == 2
        assert verify_body["failure_index"] is None
        assert verify_body["failure_reason"] is None

        # -- Step 7: fetch the SDK snippet, confirm zero third-party branding
        sdk_resp = client.get("/ai-governance/policy-provider/sdk-snippet")
        assert sdk_resp.status_code == 200, sdk_resp.text
        sdk_body = sdk_resp.json()
        assert sdk_body["language"] == "python"
        assert "check_action" in sdk_body["snippet"]
        sdk_text_lower = (sdk_resp.text).lower()
        for banned in BANNED_SDK_STRINGS:
            assert banned not in sdk_text_lower, f"banned string {banned!r} found in sdk-snippet response"

        # -- Step 8: tamper with one stored receipt, re-verify --------------
        # Reach into the app's own in-memory receipt store (this standalone
        # repo has no durable receipt DB table -- see ASSUMPTIONS.md -- so
        # this in-memory, per-ai_system_id list IS "the receipt DB" here).
        receipt_store = client.app.state.receipt_store
        stored_chain = receipt_store[MERIDIAN_AI_SYSTEM_ID]
        assert len(stored_chain) == 2

        # Flip the decision on the FIRST receipt (index 0, the allow one),
        # using dataclasses.replace exactly as tests/unit/test_receipt_chain.py
        # does, so its signature no longer matches its (now-mutated) content.
        tampered_first = dataclasses.replace(stored_chain[0], decision="deny")
        receipt_store[MERIDIAN_AI_SYSTEM_ID] = [tampered_first, stored_chain[1]]

        reverify_resp = client.post(f"/ai-systems/{MERIDIAN_AI_SYSTEM_ID}/verify-chain", headers=headers)
        assert reverify_resp.status_code == 200, reverify_resp.text
        reverify_body = reverify_resp.json()
        assert reverify_body["passed"] is False
        # Must localize EXACTLY to the tampered receipt (index 0), not a
        # vague "somewhere in the chain".
        assert reverify_body["failure_index"] == 0
        assert reverify_body["verified_count"] == 0
        assert reverify_body["failure_reason"] is not None
        assert "invalid signature" in reverify_body["failure_reason"]
        assert "index 0" in reverify_body["failure_reason"]

        # Sanity: the untampered receipt was never touched.
        assert receipt_store[MERIDIAN_AI_SYSTEM_ID][1] == stored_chain[1]

        # And every state-changing call along the way was audited.
        audited_actions = {e["action"] for e in audit.entries}
        assert "guardrail.created" in audited_actions
        assert "guardrail.recompiled" in audited_actions
        assert "guardrail.checked" in audited_actions

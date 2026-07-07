# mypy: allow-untyped-defs
"""Part 3c: multi-tenant sanity check with realistic seed data.

`tests/security/test_concurrent_cross_org_isolation.py` already proves
concurrent-load cross-org isolation with minimal synthetic data (three orgs,
bare financial limits, no realistic obligation text). This module does NOT
duplicate that -- it is not about concurrency. Instead it proves DATA-LEVEL
isolation: all 3 realistic sample orgs from `sample_seed_data.py` (each with
its own realistic obligation text, guardrail, and action envelopes) coexist
simultaneously in ONE running app instance, with their guardrail creation,
compilation, and check-action calls sequentially INTERLEAVED (create A, then
B, then C; check A, then B, then C; etc.) rather than done one org fully at a
time. Confirms:

- Org A's receipt chain never contains org B's or org C's events.
- Org A's action checks are evaluated against ONLY org A's compiled Rego
  limits (never a different org's limit "bleeding" in), even with all three
  orgs' real data loaded at once.
- Cross-org 404s still hold with all this realistic data loaded
  simultaneously.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

from sample_seed_data import SAMPLE_ORGS


def _headers(org_id: str, user_id: str = "compliance-admin", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


def _build_client() -> TestClient:
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    rate_limiter = TokenBucketRateLimiter(capacity=10_000, refill_per_second=10_000.0)
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    for org in SAMPLE_ORGS:
        registry.register(org["ai_system_id"], org["org_id"], name=org["ai_system_name"])
    return TestClient(app)


class TestMultiTenantSeedDataSanity:
    def test_all_sample_orgs_coexist_without_cross_contamination(self):
        client = _build_client()

        # ---- Interleaved guardrail creation: A, then B, then C -----------
        guardrail_ids: dict[str, str] = {}
        for org in SAMPLE_ORGS:
            primary = org["guardrails"][org["primary_guardrail_index"]]
            resp = client.post(
                f"/ai-systems/{org['ai_system_id']}/guardrails",
                json={
                    "organization_id": org["org_id"],
                    "name": primary["name"],
                    "description": primary["description"],
                    "obligations": primary["obligations"],
                },
                headers=_headers(org["org_id"]),
            )
            assert resp.status_code == 201, resp.text
            guardrail_ids[org["org_id"]] = resp.json()["id"]

        # ---- Interleaved recompile: A, then B, then C ---------------------
        for org in SAMPLE_ORGS:
            primary = org["guardrails"][org["primary_guardrail_index"]]
            resp = client.post(
                f"/ai-guardrails/{guardrail_ids[org['org_id']]}/compile-rego",
                json={"obligations": primary["obligations"]},
                headers=_headers(org["org_id"]),
            )
            assert resp.status_code == 200, resp.text

        # ---- Interleaved check-action: allow for A, allow for B, allow for
        #      C, then deny for A, deny for B, deny for C -------------------
        allow_results: dict[str, dict] = {}
        for org in SAMPLE_ORGS:
            action = org["actions"]["allowed_under_limit"]
            resp = client.post(
                f"/ai-systems/{org['ai_system_id']}/guardrails/check",
                json=action,
                headers=_headers(org["org_id"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["allowed"] is True, (
                f"org {org['org_id']}'s own within-limit action was unexpectedly "
                f"blocked while other orgs' data coexists: {body}"
            )
            allow_results[org["org_id"]] = body

        deny_results: dict[str, dict] = {}
        for org in SAMPLE_ORGS:
            action = org["actions"]["blocked_over_limit"]
            resp = client.post(
                f"/ai-systems/{org['ai_system_id']}/guardrails/check",
                json=action,
                headers=_headers(org["org_id"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["allowed"] is False, (
                f"org {org['org_id']}'s own over-limit action was unexpectedly "
                f"allowed while other orgs' (more permissive) data coexists: {body}"
            )
            deny_results[org["org_id"]] = body

        # ---- Each org's receipt chain contains EXACTLY its own 2 events,
        #      never another org's, and in the right (allow-then-deny) order.
        for org in SAMPLE_ORGS:
            chain_resp = client.get(f"/ai-systems/{org['ai_system_id']}/receipt-chain", headers=_headers(org["org_id"]))
            assert chain_resp.status_code == 200, chain_resp.text
            receipts = chain_resp.json()["receipts"]
            assert len(receipts) == 2, (
                f"org {org['org_id']}'s receipt chain should contain exactly its "
                f"own 2 events (1 allow + 1 deny), got {len(receipts)}"
            )
            assert receipts[0]["receipt_id"] == allow_results[org["org_id"]]["receipt_id"]
            assert receipts[0]["decision"] == "allow"
            assert receipts[1]["receipt_id"] == deny_results[org["org_id"]]["receipt_id"]
            assert receipts[1]["decision"] == "deny"

            # None of this org's receipt ids match any OTHER org's receipt
            # ids -- direct proof of no cross-org receipt bleed.
            this_org_receipt_ids = {r["receipt_id"] for r in receipts}
            for other_org in SAMPLE_ORGS:
                if other_org["org_id"] == org["org_id"]:
                    continue
                other_ids = {
                    allow_results[other_org["org_id"]]["receipt_id"],
                    deny_results[other_org["org_id"]]["receipt_id"],
                }
                assert not (this_org_receipt_ids & other_ids), (
                    f"org {org['org_id']}'s receipt chain unexpectedly contains a "
                    f"receipt id belonging to org {other_org['org_id']}"
                )

        # ---- Each org's own chain still independently verifies (each org's
        #      chain was built purely from its own two events, interleaved
        #      creation/checks notwithstanding).
        for org in SAMPLE_ORGS:
            verify_resp = client.post(f"/ai-systems/{org['ai_system_id']}/verify-chain", headers=_headers(org["org_id"]))
            assert verify_resp.status_code == 200, verify_resp.text
            result = verify_resp.json()
            assert result["passed"] is True, f"org {org['org_id']}'s own chain failed to verify: {result}"
            assert result["verified_count"] == 2

        # ---- Cross-org 404s still hold with all this realistic data loaded
        #      simultaneously: every ordered pair of distinct orgs attempting
        #      to reach another org's ai_system_id must 404, for every kind
        #      of ai_system-scoped endpoint.
        for org in SAMPLE_ORGS:
            for other_org in SAMPLE_ORGS:
                if other_org["org_id"] == org["org_id"]:
                    continue

                cross_check_resp = client.post(
                    f"/ai-systems/{other_org['ai_system_id']}/guardrails/check",
                    json=org["actions"]["allowed_under_limit"],
                    headers=_headers(org["org_id"]),
                )
                assert cross_check_resp.status_code == 404, (
                    f"org {org['org_id']} unexpectedly did NOT get 404 checking "
                    f"an action against org {other_org['org_id']}'s ai_system"
                )

                cross_chain_resp = client.get(
                    f"/ai-systems/{other_org['ai_system_id']}/receipt-chain",
                    headers=_headers(org["org_id"]),
                )
                assert cross_chain_resp.status_code == 404, (
                    f"org {org['org_id']} unexpectedly did NOT get 404 reading "
                    f"org {other_org['org_id']}'s receipt chain"
                )

                cross_verify_resp = client.post(
                    f"/ai-systems/{other_org['ai_system_id']}/verify-chain",
                    headers=_headers(org["org_id"]),
                )
                assert cross_verify_resp.status_code == 404, (
                    f"org {org['org_id']} unexpectedly did NOT get 404 verifying "
                    f"org {other_org['org_id']}'s receipt chain"
                )

                cross_create_resp = client.post(
                    f"/ai-systems/{other_org['ai_system_id']}/guardrails",
                    json={
                        "organization_id": org["org_id"],
                        "name": "cross-org attempt",
                        "obligations": org["guardrails"][org["primary_guardrail_index"]]["obligations"],
                    },
                    headers=_headers(org["org_id"]),
                )
                assert cross_create_resp.status_code == 404, (
                    f"org {org['org_id']} unexpectedly did NOT get 404 creating a "
                    f"guardrail against org {other_org['org_id']}'s ai_system"
                )

                cross_compile_resp = client.post(
                    f"/ai-guardrails/{guardrail_ids[other_org['org_id']]}/compile-rego",
                    json={"obligations": other_org["guardrails"][other_org["primary_guardrail_index"]]["obligations"]},
                    headers=_headers(org["org_id"]),
                )
                assert cross_compile_resp.status_code == 404, (
                    f"org {org['org_id']} unexpectedly did NOT get 404 recompiling "
                    f"org {other_org['org_id']}'s guardrail"
                )

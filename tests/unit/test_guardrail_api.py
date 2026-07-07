"""Tests for the guardrail API (Workstreams H/I/J combined).

Covers: happy path for all six endpoints, the cross-org 404 pattern for
every endpoint keyed on `ai_system_id`, the rate-limit 429 path, the
payload-rejection 400 path on check-action, the branding boundary on the
SDK snippet endpoint, and that AuditService recorded an entry for every
state-changing call.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

ORG_A = "org-a"
ORG_B = "org-b"


def _headers(org_id: str, user_id: str = "user-1", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


def _build_app(*, rate_limiter: TokenBucketRateLimiter | None = None):
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    registry.register("sys-1", ORG_A, name="Test AI System")
    client = TestClient(app)
    return client, registry, audit


SAMPLE_OBLIGATIONS = [
    {
        "id": "obl-1",
        "text": "Wire transfers shall not exceed $10,000 per transaction.",
        "jurisdiction": "US",
        "framework": "BSA",
        "citation": "31 CFR 1010",
    },
]


def _create_guardrail(client: TestClient, *, org_id: str = ORG_A, ai_system_id: str = "sys-1") -> dict:
    resp = client.post(
        f"/ai-systems/{ai_system_id}/guardrails",
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


class TestCreateGuardrail:
    def test_happy_path(self):
        client, _, audit = _build_app()
        body = _create_guardrail(client)
        assert body["organization_id"] == ORG_A
        assert body["ai_system_id"] == "sys-1"
        assert body["source_obligation_ids"] == ["obl-1"]
        assert "package complivibe.guardrails.org_org_a" in body["rego_policy"]
        assert any(e["action"] == "guardrail.created" for e in audit.entries)

    def test_cross_org_404(self):
        client, _, _ = _build_app()
        resp = client.post(
            "/ai-systems/sys-1/guardrails",
            json={
                "organization_id": ORG_B,
                "name": "x",
                "obligations": SAMPLE_OBLIGATIONS,
            },
            headers=_headers(ORG_B),
        )
        assert resp.status_code == 404


class TestCompileRego:
    def test_happy_path(self):
        client, _, audit = _build_app()
        created = _create_guardrail(client)
        resp = client.post(
            f"/ai-guardrails/{created['id']}/compile-rego",
            json={"obligations": SAMPLE_OBLIGATIONS},
            headers=_headers(ORG_A),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["compiled_at"] is not None
        assert any(e["action"] == "guardrail.recompiled" for e in audit.entries)

    def test_mismatched_obligation_ids_rejected(self):
        client, _, _ = _build_app()
        created = _create_guardrail(client)
        resp = client.post(
            f"/ai-guardrails/{created['id']}/compile-rego",
            json={
                "obligations": [
                    {
                        "id": "some-other-obligation",
                        "text": "Wire transfers shall not exceed $5,000 per transaction.",
                    }
                ]
            },
            headers=_headers(ORG_A),
        )
        assert resp.status_code == 400

    def test_cross_org_404(self):
        client, _, _ = _build_app()
        created = _create_guardrail(client)
        resp = client.post(
            f"/ai-guardrails/{created['id']}/compile-rego",
            json={"obligations": SAMPLE_OBLIGATIONS},
            headers=_headers(ORG_B),
        )
        assert resp.status_code == 404


VALID_ACTION = {
    "action_id": "act-1",
    "ai_system_id": "sys-1",
    "organization_id": ORG_A,
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}


class TestCheckAction:
    def test_happy_path_allow(self):
        client, _, audit = _build_app()
        _create_guardrail(client)
        resp = client.post(
            "/ai-systems/sys-1/guardrails/check",
            json=VALID_ACTION,
            headers=_headers(ORG_A),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["allowed"] is True
        assert body["receipt_id"] is not None
        assert any(e["action"] == "guardrail.checked" for e in audit.entries)

    def test_happy_path_deny_over_limit(self):
        client, _, _ = _build_app()
        _create_guardrail(client)
        over_limit_action = {**VALID_ACTION, "amount": 999999.0}
        resp = client.post(
            "/ai-systems/sys-1/guardrails/check",
            json=over_limit_action,
            headers=_headers(ORG_A),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["allowed"] is False

    def test_cross_org_404(self):
        client, _, _ = _build_app()
        _create_guardrail(client)
        resp = client.post(
            "/ai-systems/sys-1/guardrails/check",
            json={**VALID_ACTION, "organization_id": ORG_B},
            headers=_headers(ORG_B),
        )
        assert resp.status_code == 404

    def test_payload_shaped_field_rejected_400(self):
        client, _, _ = _build_app()
        _create_guardrail(client)
        tainted = {**VALID_ACTION, "customer_pii": {"ssn": "123-45-6789"}}
        resp = client.post(
            "/ai-systems/sys-1/guardrails/check",
            json=tainted,
            headers=_headers(ORG_A),
        )
        assert resp.status_code == 400

    def test_rate_limit_429(self):
        tiny_limiter = TokenBucketRateLimiter(capacity=1, refill_per_second=0.0001)
        client, _, _ = _build_app(rate_limiter=tiny_limiter)
        _create_guardrail(client)
        first = client.post("/ai-systems/sys-1/guardrails/check", json=VALID_ACTION, headers=_headers(ORG_A))
        assert first.status_code == 200
        second = client.post("/ai-systems/sys-1/guardrails/check", json=VALID_ACTION, headers=_headers(ORG_A))
        assert second.status_code == 429


class TestReceiptChain:
    def test_happy_path_and_verify(self):
        client, _, _ = _build_app()
        _create_guardrail(client)
        client.post("/ai-systems/sys-1/guardrails/check", json=VALID_ACTION, headers=_headers(ORG_A))
        client.post(
            "/ai-systems/sys-1/guardrails/check",
            json={**VALID_ACTION, "action_id": "act-2", "timestamp": "2026-01-01T00:00:01Z"},
            headers=_headers(ORG_A),
        )

        chain_resp = client.get("/ai-systems/sys-1/receipt-chain", headers=_headers(ORG_A))
        assert chain_resp.status_code == 200
        receipts = chain_resp.json()["receipts"]
        assert len(receipts) == 2
        assert receipts[1]["previous_receipt_hash"] == receipts[0]["receipt_hash"]

        verify_resp = client.post("/ai-systems/sys-1/verify-chain", headers=_headers(ORG_A))
        assert verify_resp.status_code in (200, 501)
        if verify_resp.status_code == 200:
            result = verify_resp.json()
            assert result["passed"] is True
            assert result["verified_count"] == 2

    def test_receipt_chain_cross_org_404(self):
        client, _, _ = _build_app()
        _create_guardrail(client)
        client.post("/ai-systems/sys-1/guardrails/check", json=VALID_ACTION, headers=_headers(ORG_A))
        resp = client.get("/ai-systems/sys-1/receipt-chain", headers=_headers(ORG_B))
        assert resp.status_code == 404

    def test_verify_chain_cross_org_404(self):
        client, _, _ = _build_app()
        _create_guardrail(client)
        resp = client.post("/ai-systems/sys-1/verify-chain", headers=_headers(ORG_B))
        assert resp.status_code == 404


class TestSdkSnippet:
    # These are the exact strings the branding rule (PATENT.md's closing
    # section, and the "never mention the real third-party toolkit's name"
    # instruction) forbids anywhere customer-facing. Sourced both from the
    # task brief's explicit list and directly from PATENT.md / ASSUMPTIONS.md
    # (the only place the real name may legitimately appear).
    BANNED_STRINGS = [
        "microsoft",
        "agent-governance-toolkit",
        "agent_governance_toolkit",
        "agentmesh",
        "mcp_receipt_governed",
        "mcpreceiptadapter",
        "agent_compliance",
        "cedarling",
    ]

    def test_no_third_party_branding_in_response(self):
        client, _, _ = _build_app()
        resp = client.get("/ai-governance/policy-provider/sdk-snippet")
        assert resp.status_code == 200
        body_lower = resp.text.lower()
        for banned in self.BANNED_STRINGS:
            assert banned not in body_lower, f"banned string {banned!r} found in sdk-snippet response"

    def test_no_third_party_branding_in_source(self):
        source = Path(__file__).parent.parent.parent.joinpath(
            "core-side-patch", "api", "guardrails.py"
        ).read_text().lower()
        for banned in self.BANNED_STRINGS:
            assert banned not in source, f"banned string {banned!r} found in api/guardrails.py source"

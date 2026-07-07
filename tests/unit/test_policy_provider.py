"""Tests for CompliVibePolicyProvider (Workstream D)."""

from __future__ import annotations

import httpx
import pytest

from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider
from services.receipts import ReceiptSigner, verify_receipt


def _make_opa_client(handler) -> OpaClient:
    transport = httpx.MockTransport(handler)
    return OpaClient(base_url="http://opa.test", client=httpx.Client(transport=transport))


def _allow_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"result": True})


def _deny_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"result": False})


VALID_ACTION = {
    "action_id": "act-1",
    "ai_system_id": "sys-1",
    "organization_id": "org-1",
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}


class TestPolicyProviderProtocolShape:
    def test_has_name_property(self):
        provider = CompliVibePolicyProvider(_make_opa_client(_allow_handler), "complivibe.guardrails.org_acme")
        assert isinstance(provider.name, str) and provider.name

    def test_evaluate_matches_backend_shape(self):
        provider = CompliVibePolicyProvider(_make_opa_client(_allow_handler), "complivibe.guardrails.org_acme")
        result = provider.evaluate("wire_transfer", {"action": {}})
        assert result.allowed is True
        assert result.backend == provider.name
        assert result.latency_ms >= 0

    def test_evaluate_deny_carries_reason(self):
        provider = CompliVibePolicyProvider(_make_opa_client(_deny_handler), "complivibe.guardrails.org_acme")
        result = provider.evaluate("wire_transfer", {"action": {}})
        assert result.allowed is False
        assert result.reason

    def test_healthy_true_when_opa_reachable(self):
        provider = CompliVibePolicyProvider(_make_opa_client(_allow_handler), "complivibe.guardrails.org_acme")
        assert provider.healthy() is True

    def test_healthy_false_when_opa_unreachable(self):
        def _boom(request):
            raise httpx.ConnectError("no route", request=request)

        provider = CompliVibePolicyProvider(_make_opa_client(_boom), "complivibe.guardrails.org_acme")
        assert provider.healthy() is False


class TestCheckAction:
    def test_check_action_rejects_payload_shaped_input(self):
        provider = CompliVibePolicyProvider(_make_opa_client(_allow_handler), "complivibe.guardrails.org_acme")
        tainted = {**VALID_ACTION, "customer_pii": {"ssn": "123-45-6789"}}
        with pytest.raises(ValueError):
            provider.check_action(tainted, timestamp="2026-01-01T00:00:00Z")

    def test_check_action_without_signer_has_no_receipt(self):
        provider = CompliVibePolicyProvider(_make_opa_client(_allow_handler), "complivibe.guardrails.org_acme")
        result = provider.check_action(VALID_ACTION, timestamp="2026-01-01T00:00:00Z")
        assert result.decision.allowed is True
        assert result.receipt is None

    def test_check_action_with_signer_produces_verifiable_chained_receipt(self):
        signer = ReceiptSigner(signing_key_hex="ab" * 32)
        provider = CompliVibePolicyProvider(
            _make_opa_client(_allow_handler),
            "complivibe.guardrails.org_acme",
            sign_receipt_fn=signer.sign_receipt,
        )
        first = provider.check_action(VALID_ACTION, timestamp="2026-01-01T00:00:00Z")
        assert first.receipt is not None
        assert first.receipt.previous_receipt_hash is None
        assert verify_receipt(first.receipt) is True

        second = provider.check_action(VALID_ACTION, timestamp="2026-01-01T00:00:01Z")
        assert second.receipt is not None
        assert second.receipt.previous_receipt_hash == first.receipt.receipt_hash
        assert verify_receipt(second.receipt) is True

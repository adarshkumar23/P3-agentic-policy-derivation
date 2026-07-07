"""Confirm the Ed25519 signing key never leaks: not in HTTP response bodies,
not in exception messages, not in any captured log output.

Per `core-side-patch/services/receipts.py`'s key-custody boundary (see
PATENT.md Claim 4 and ASSUMPTIONS.md): `ReceiptSigner` is the only thing that
ever touches a *private* key; a `Receipt` only ever carries the *public* key
(`public_key_hex`). This file drives a real signing key hex string as a
sentinel through `ReceiptSigner` directly and through the full
`/ai-systems/{id}/guardrails/check` HTTP endpoint, and asserts the private
sentinel never appears anywhere observable -- while confirming, as a positive
control, that the corresponding *public* key legitimately does appear where
expected (so a trivially-broken/no-op assertion isn't masquerading as a
passing test).
"""

from __future__ import annotations

import io
import logging

import pytest
import structlog
from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.receipts import Receipt, ReceiptSigner, verify_receipt

# A real, valid 32-byte hex seed used as the "signing key" sentinel. Since a
# private Ed25519 seed and a signature/public key are all fixed-length hex,
# we use a value that is trivially greppable.
PRIVATE_KEY_HEX_SENTINEL = "ab" * 32
ORG_A = "org-sentinel"

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


def _build_app_with_sentinel_key():
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    app = create_app(
        ai_system_registry=registry,
        audit_service=audit,
        signing_key_hex=PRIVATE_KEY_HEX_SENTINEL,
    )
    registry.register("sys-1", ORG_A, name="Test AI System")
    client = TestClient(app)
    return client, registry, audit


def _create_guardrail(client: TestClient) -> dict:
    resp = client.post(
        "/ai-systems/sys-1/guardrails",
        json={
            "organization_id": ORG_A,
            "name": "Wire transfer limit",
            "description": "test guardrail",
            "obligations": SAMPLE_OBLIGATIONS,
        },
        headers=_headers(ORG_A),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# 1. ReceiptSigner in isolation: private key never appears on the Receipt,
#    never in exception messages for malformed input.
# ---------------------------------------------------------------------------


def test_receipt_never_carries_the_private_key_hex():
    signer = ReceiptSigner(signing_key_hex=PRIVATE_KEY_HEX_SENTINEL)
    receipt = signer.sign_receipt(
        decision="allow",
        reasons=["ok"],
        envelope_hash="hash-1",
        previous_receipt_hash=None,
        timestamp="2026-07-06T00:00:00Z",
    )

    # Positive control: the *public* key legitimately appears.
    assert receipt.public_key_hex == signer.public_key_hex
    assert receipt.public_key_hex != PRIVATE_KEY_HEX_SENTINEL

    receipt_repr = repr(receipt)
    receipt_str = str(receipt)
    receipt_fields = vars(receipt)

    assert PRIVATE_KEY_HEX_SENTINEL not in receipt_repr
    assert PRIVATE_KEY_HEX_SENTINEL not in receipt_str
    assert PRIVATE_KEY_HEX_SENTINEL not in str(receipt_fields)
    for value in receipt_fields.values():
        assert value != PRIVATE_KEY_HEX_SENTINEL


def test_receipt_signer_repr_does_not_expose_private_key():
    signer = ReceiptSigner(signing_key_hex=PRIVATE_KEY_HEX_SENTINEL)
    assert PRIVATE_KEY_HEX_SENTINEL not in repr(signer)
    assert PRIVATE_KEY_HEX_SENTINEL not in str(signer)
    # public_key_hex is the only public attribute exposing key material.
    assert signer.public_key_hex != PRIVATE_KEY_HEX_SENTINEL


def test_malformed_signing_key_hex_error_does_not_echo_the_value():
    """Even when construction fails, the offending value (which might BE
    the real signing key, mistyped) must not ride along in the exception
    message."""
    bad_key = PRIVATE_KEY_HEX_SENTINEL[:-2]  # wrong length (31 bytes)
    with pytest.raises(ValueError) as exc_info:
        ReceiptSigner(signing_key_hex=bad_key)
    # The error is allowed to report the *length*, just never the *value*.
    assert bad_key not in str(exc_info.value)
    assert PRIVATE_KEY_HEX_SENTINEL not in str(exc_info.value)


def test_non_hex_signing_key_error_does_not_echo_the_value():
    bad_key = "not-valid-hex-" + PRIVATE_KEY_HEX_SENTINEL
    with pytest.raises(ValueError) as exc_info:
        ReceiptSigner(signing_key_hex=bad_key)
    assert bad_key not in str(exc_info.value)
    assert PRIVATE_KEY_HEX_SENTINEL not in str(exc_info.value)


def test_verify_receipt_cannot_be_handed_a_private_key_at_all():
    """Structural guarantee: verify_receipt's only parameter is a Receipt,
    which has no private-key-shaped field. Passing a raw private key hex
    string is a TypeError, not a code path that could accidentally verify
    against or log a private key."""
    with pytest.raises((TypeError, AttributeError)):
        verify_receipt(PRIVATE_KEY_HEX_SENTINEL)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. Full HTTP check-action endpoint: private key never in the response body.
# ---------------------------------------------------------------------------


def test_check_action_response_never_contains_the_private_key():
    client, _, _ = _build_app_with_sentinel_key()
    _create_guardrail(client)

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
        headers=_headers(ORG_A),
    )
    assert resp.status_code == 200, resp.text
    assert PRIVATE_KEY_HEX_SENTINEL not in resp.text
    assert "receipt_id" in resp.json()


def test_receipt_chain_endpoint_carries_public_key_but_never_private_key():
    client, _, _ = _build_app_with_sentinel_key()
    _create_guardrail(client)
    check_resp = client.post(
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
        headers=_headers(ORG_A),
    )
    assert check_resp.status_code == 200, check_resp.text

    chain_resp = client.get("/ai-systems/sys-1/receipt-chain", headers=_headers(ORG_A))
    assert chain_resp.status_code == 200, chain_resp.text
    body = chain_resp.json()

    assert PRIVATE_KEY_HEX_SENTINEL not in chain_resp.text
    # Positive control: the public key IS legitimately present on receipts.
    receipts = body["receipts"]
    assert len(receipts) >= 1
    assert all("public_key_hex" in r and r["public_key_hex"] for r in receipts)
    assert all(r["public_key_hex"] != PRIVATE_KEY_HEX_SENTINEL for r in receipts)


def test_check_action_400_error_body_does_not_contain_private_key():
    """Trigger the payload-rejection 400 path (services/envelope.py's
    build_envelope raising ValueError) and confirm the error response body
    -- which does echo back field *names* by design -- never contains the
    private signing key."""
    client, _, _ = _build_app_with_sentinel_key()
    _create_guardrail(client)

    resp = client.post(
        "/ai-systems/sys-1/guardrails/check",
        json={
            "action_id": "act-1",
            "ai_system_id": "sys-1",
            "organization_id": ORG_A,
            "action_type": "payment.transfer",
            "timestamp": "2026-07-06T00:00:00Z",
            "customer_pii": {"ssn": "123-45-6789"},
        },
        headers=_headers(ORG_A),
    )
    assert resp.status_code == 400, resp.text
    assert PRIVATE_KEY_HEX_SENTINEL not in resp.text


# ---------------------------------------------------------------------------
# 3. Log output: private key never appears in any log line during a full
#    check-action call, captured via both stdlib logging (caplog) and a
#    StringIO-backed handler wired the way test_envelope_separation.py does,
#    plus structlog's own configured pipeline.
# ---------------------------------------------------------------------------


def test_full_check_action_call_never_logs_the_private_key(caplog):
    log_stream = io.StringIO()
    stream_handler = logging.StreamHandler(log_stream)
    root_logger = logging.getLogger()
    root_logger.addHandler(stream_handler)
    previous_level = root_logger.level
    root_logger.setLevel(logging.DEBUG)

    # Route structlog through stdlib logging so anything logged via
    # structlog during this call is also captured by the handlers above.
    structlog.configure(
        processors=[structlog.stdlib.render_to_log_kwargs],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    caplog.set_level(logging.DEBUG)

    try:
        client, _, _ = _build_app_with_sentinel_key()
        _create_guardrail(client)
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
            headers=_headers(ORG_A),
        )
        assert resp.status_code == 200, resp.text

        # Also exercise a failure path in the same captured window, since
        # that's often where secrets accidentally get logged.
        try:
            ReceiptSigner(signing_key_hex=PRIVATE_KEY_HEX_SENTINEL[:-2])
        except ValueError as exc:
            logging.getLogger("test").error("signer construction failed: %s", exc)
    finally:
        root_logger.removeHandler(stream_handler)
        root_logger.setLevel(previous_level)
        stream_handler.close()
        structlog.reset_defaults()

    captured_stream = log_stream.getvalue()
    captured_caplog = caplog.text

    assert PRIVATE_KEY_HEX_SENTINEL not in captured_stream
    assert PRIVATE_KEY_HEX_SENTINEL not in captured_caplog

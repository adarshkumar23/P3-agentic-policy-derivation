"""Failure-mode tests for receipt signing (Workstream F/D hardening).

`core-side-patch/services/receipts.py` wraps the real, installed
`mcp_receipt_governed` package (see that module's docstring and
ASSUMPTIONS.md's "Newly verified" section for the migration history away
from a hand-rolled Ed25519 stand-in). This file tests two distinct failure
modes:

1. A signing key becoming unavailable/rotated *mid-chain* -- constructing a
   second `ReceiptSigner` with an invalid `signing_key_hex` partway through
   producing a chain must raise a clear, catchable exception, and must not
   corrupt or invalidate any receipt already produced by the first signer.

2. `CompliVibePolicyProvider.check_action()`'s behavior when a *configured*
   `sign_receipt_fn` raises, as opposed to no signer being configured at
   all. These are two very different situations -- "no receipt needed" vs.
   "a receipt was supposed to be produced but signing failed" -- and
   conflating them (e.g. by catching the signer's exception and returning
   `receipt=None` as if no signer were configured) would be misleading: a
   caller checking `result.receipt is None` would have no way to tell
   "this org doesn't use receipts" from "a receipt was silently lost."
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx
import pytest

from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider
from services.receipts import ReceiptSigner, verify_receipt


def _hex_seed() -> str:
    return os.urandom(32).hex()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _allow_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"result": True})


def _make_opa_client() -> OpaClient:
    return OpaClient(base_url="http://opa.test", client=httpx.Client(transport=httpx.MockTransport(_allow_handler)))


VALID_ACTION = {
    "action_id": "act-1",
    "ai_system_id": "sys-1",
    "organization_id": "org-1",
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# 1. Signing key becoming unavailable mid-chain.
# ---------------------------------------------------------------------------


class TestSignerBecomingUnavailableMidChain:
    def test_second_signer_with_invalid_key_raises_clearly(self):
        first_signer = ReceiptSigner(_hex_seed())
        first = first_signer.sign_receipt(
            decision="allow",
            reasons=["first in chain"],
            envelope_hash="envelope-1",
            previous_receipt_hash=None,
            timestamp=_now(),
        )
        second = first_signer.sign_receipt(
            decision="allow",
            reasons=["second in chain"],
            envelope_hash="envelope-2",
            previous_receipt_hash=first.receipt_hash,
            timestamp=_now(),
        )

        # Simulate a key becoming unavailable/rotated mid-sequence: the next
        # link in the chain would need a new ReceiptSigner, but the
        # available key material is invalid (e.g. truncated, corrupted,
        # wrong length after a botched rotation).
        with pytest.raises(ValueError):
            ReceiptSigner("dead" * 4)  # 8 bytes, not the required 32

        # Already-produced receipts must remain wholly unaffected: valid,
        # verifiable, and still correctly chained to each other.
        assert verify_receipt(first) is True
        assert verify_receipt(second) is True
        assert second.previous_receipt_hash == first.receipt_hash

    def test_second_signer_with_malformed_hex_raises_clearly(self):
        first_signer = ReceiptSigner(_hex_seed())
        first = first_signer.sign_receipt(
            decision="allow",
            reasons=["only link"],
            envelope_hash="envelope-1",
            previous_receipt_hash=None,
            timestamp=_now(),
        )

        with pytest.raises(ValueError):
            ReceiptSigner("not-valid-hex-at-all")

        assert verify_receipt(first) is True

    def test_failed_second_signer_construction_does_not_leave_a_usable_half_state(self):
        """A `ReceiptSigner` that fails to construct must not exist as a
        usable, partially-initialized object -- the constructor should have
        raised before any attribute (e.g. `public_key_hex`) was set on an
        object a caller could accidentally hang onto."""
        try:
            bad = ReceiptSigner("00")
            pytest.fail("expected ValueError, got a constructed ReceiptSigner instead")
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# 2. CompliVibePolicyProvider.check_action() when a configured signer fails.
# ---------------------------------------------------------------------------


class TestCheckActionSignerFailureSurfacesClearly:
    def test_no_signer_configured_returns_receipt_none_without_error(self):
        """Baseline: with no signer at all, check_action succeeds and
        simply has no receipt -- this is the "not configured" case that
        must be distinguishable from "configured but failed" below."""
        provider = CompliVibePolicyProvider(_make_opa_client(), "complivibe.guardrails.org_acme")
        result = provider.check_action(dict(VALID_ACTION), timestamp="2026-01-01T00:00:00Z")
        assert result.decision.allowed is True
        assert result.receipt is None

    def test_configured_but_failing_signer_raises_rather_than_returning_none(self):
        """The core assertion: a signer that IS configured but throws must
        surface that failure to the caller (so the caller knows a receipt
        was NOT produced when one was expected), not be silently swallowed
        into a `receipt=None` result indistinguishable from "no signer
        configured".
        """

        def _failing_signer(**kwargs):
            raise RuntimeError("customer-side signer unavailable (simulated)")

        provider = CompliVibePolicyProvider(
            _make_opa_client(),
            "complivibe.guardrails.org_acme",
            sign_receipt_fn=_failing_signer,
        )

        with pytest.raises(RuntimeError, match="customer-side signer unavailable"):
            provider.check_action(dict(VALID_ACTION), timestamp="2026-01-01T00:00:00Z")

    def test_configured_but_failing_signer_does_not_advance_the_chain_state(self):
        """If signing fails, `_previous_receipt_hash` must not be advanced
        (there is no new receipt_hash to advance it to) -- a subsequent
        successful call must still chain off the last *real* receipt, not
        off some placeholder from the failed attempt."""
        signer = ReceiptSigner(_hex_seed())
        calls = {"n": 0}

        def _flaky_signer(**kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("simulated transient signer failure")
            return signer.sign_receipt(**kwargs)

        provider = CompliVibePolicyProvider(
            _make_opa_client(),
            "complivibe.guardrails.org_acme",
            sign_receipt_fn=_flaky_signer,
        )

        first = provider.check_action(dict(VALID_ACTION), timestamp="2026-01-01T00:00:00Z")
        assert first.receipt is not None

        with pytest.raises(RuntimeError):
            provider.check_action(dict(VALID_ACTION), timestamp="2026-01-01T00:00:01Z")

        third = provider.check_action(dict(VALID_ACTION), timestamp="2026-01-01T00:00:02Z")
        assert third.receipt is not None
        # Must chain to the last successfully-produced receipt, not to
        # anything from the failed second attempt.
        assert third.receipt.previous_receipt_hash == first.receipt.receipt_hash

"""Tests for the receipt-signing stand-in (Workstream F).

See `core-side-patch/services/receipts.py`'s module docstring and
PATENT.md §1.1(4)/Claim 4 for the key-custody boundary this workstream
exists to enforce: `ReceiptSigner` is the only thing that ever touches a
private key; `verify_receipt` is a module-level, key-free function that can
only ever be handed a public key (carried on the `Receipt` itself).
"""

from __future__ import annotations

import inspect
import os
from datetime import datetime, timezone

import pytest

from services.receipts import Receipt, ReceiptSigner, verify_receipt


def _hex_seed() -> str:
    return os.urandom(32).hex()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_sign_and_verify_roundtrip() -> None:
    signer = ReceiptSigner(_hex_seed())
    receipt = signer.sign_receipt(
        decision="allow",
        reasons=["within spend limit"],
        envelope_hash="abc123",
        previous_receipt_hash=None,
        timestamp=_now(),
    )

    assert isinstance(receipt, Receipt)
    assert receipt.previous_receipt_hash is None
    assert receipt.public_key_hex == signer.public_key_hex
    assert verify_receipt(receipt) is True


def test_tampered_receipt_fails_verification() -> None:
    signer = ReceiptSigner(_hex_seed())
    receipt = signer.sign_receipt(
        decision="allow",
        reasons=["within spend limit"],
        envelope_hash="abc123",
        previous_receipt_hash=None,
        timestamp=_now(),
    )

    tampered = Receipt(
        receipt_id=receipt.receipt_id,
        timestamp=receipt.timestamp,
        envelope_hash=receipt.envelope_hash,
        decision="deny",  # flipped after signing
        reasons=receipt.reasons,
        previous_receipt_hash=receipt.previous_receipt_hash,
        signature=receipt.signature,
        receipt_hash=receipt.receipt_hash,
        public_key_hex=receipt.public_key_hex,
    )

    assert verify_receipt(receipt) is True  # sanity: original still verifies
    assert verify_receipt(tampered) is False


def test_receipt_chain_links_correctly() -> None:
    signer = ReceiptSigner(_hex_seed())

    first = signer.sign_receipt(
        decision="allow",
        reasons=["first in chain"],
        envelope_hash="envelope-1",
        previous_receipt_hash=None,
        timestamp=_now(),
    )
    second = signer.sign_receipt(
        decision="allow",
        reasons=["second in chain"],
        envelope_hash="envelope-2",
        previous_receipt_hash=first.receipt_hash,
        timestamp=_now(),
    )

    assert first.previous_receipt_hash is None
    assert second.previous_receipt_hash == first.receipt_hash
    assert verify_receipt(first) is True
    assert verify_receipt(second) is True


def test_verify_receipt_signature_cannot_hold_a_private_key() -> None:
    """The core security assertion for this workstream: `verify_receipt`'s
    signature must be physically incapable of accepting a private signing
    key, by construction -- not merely by convention.
    """
    sig = str(inspect.signature(verify_receipt)).lower()
    assert "private" not in sig
    assert "signing_key" not in sig


def test_invalid_signing_key_hex_length_rejected() -> None:
    with pytest.raises(ValueError):
        ReceiptSigner("00" * 16)  # 16 bytes, not 32

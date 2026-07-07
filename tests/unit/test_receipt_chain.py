"""Tests for full-chain receipt verification (Workstream G).

See `core-side-patch/services/receipt_chain.py`'s module docstring and
PATENT.md §1.1(4)/Claim 4 for background: `verify_chain` walks a whole list
of receipts and confirms both (a) each receipt's own signature (reusing
`verify_receipt` from `services.receipts`, never reimplemented here) and
(b) the hash-chain link between consecutive receipts.
"""

from __future__ import annotations

import dataclasses
import os
from datetime import datetime, timezone

from services.receipt_chain import ChainVerificationResult, verify_chain
from services.receipts import ReceiptSigner, verify_receipt


def _hex_seed() -> str:
    return os.urandom(32).hex()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_chain(signer: ReceiptSigner, length: int) -> list:
    """Build a real, validly-signed chain of `length` receipts using
    `ReceiptSigner`, chaining each one to the previous exactly as
    `test_receipts.py::test_receipt_chain_links_correctly` does.
    """
    receipts = []
    previous_hash = None
    for i in range(length):
        receipt = signer.sign_receipt(
            decision="allow",
            reasons=[f"reason {i}"],
            envelope_hash=f"envelope-{i}",
            previous_receipt_hash=previous_hash,
            timestamp=_now(),
        )
        receipts.append(receipt)
        previous_hash = receipt.receipt_hash
    return receipts


def test_full_untampered_chain_passes() -> None:
    signer = ReceiptSigner(_hex_seed())
    receipts = _build_chain(signer, 5)

    result = verify_chain(receipts)

    assert isinstance(result, ChainVerificationResult)
    assert result.passed is True
    assert result.verified_count == len(receipts) == 5
    assert result.failure_index is None
    assert result.failure_reason is None


def test_empty_chain_passes_trivially() -> None:
    result = verify_chain([])

    assert result.passed is True
    assert result.verified_count == 0
    assert result.failure_index is None
    assert result.failure_reason is None


def test_single_receipt_chain_passes() -> None:
    signer = ReceiptSigner(_hex_seed())
    receipts = _build_chain(signer, 1)

    result = verify_chain(receipts)

    assert result.passed is True
    assert result.verified_count == 1
    assert result.failure_index is None
    assert result.failure_reason is None


def test_single_receipt_chain_fails_if_not_a_root() -> None:
    """A length-1 'chain' whose sole receipt does not have
    previous_receipt_hash=None is not a valid root and must fail."""
    signer = ReceiptSigner(_hex_seed())
    first, second = _build_chain(signer, 2)

    result = verify_chain([second])  # second has a non-None previous_receipt_hash

    assert result.passed is False
    assert result.verified_count == 0
    assert result.failure_index == 0
    assert result.failure_reason is not None
    assert "previous_receipt_hash is None" in result.failure_reason


def test_tampered_field_on_middle_receipt_fails_signature_check() -> None:
    """Scenario (a): mutate a signed field (decision) on the middle receipt
    directly, keeping its receipt_hash/signature as they were. This must be
    caught as an invalid-signature failure at exactly that index, and
    everything at or after that index must be treated as unverified.
    """
    signer = ReceiptSigner(_hex_seed())
    receipts = _build_chain(signer, 5)

    tampered_middle = dataclasses.replace(receipts[2], decision="deny")
    tampered_chain = receipts[:2] + [tampered_middle] + receipts[3:]

    # Sanity: the tampering actually breaks that receipt's own verification,
    # and the untouched receipts still verify individually.
    assert verify_receipt(tampered_middle) is False
    assert verify_receipt(receipts[1]) is True
    assert verify_receipt(receipts[3]) is True

    result = verify_chain(tampered_chain)

    assert result.passed is False
    assert result.failure_index == 2
    # verification stopped at the tampered receipt: only receipts 0 and 1
    # (strictly before it) were confirmed good -- receipts 3 and 4 were never
    # reached, regardless of their own individual validity.
    assert result.verified_count == 2
    assert result.failure_reason is not None
    assert "invalid signature" in result.failure_reason
    assert "index 2" in result.failure_reason


def test_middle_receipt_replaced_with_unrelated_receipt_fails_hash_link_check() -> None:
    """Scenario (b): the middle receipt is replaced by a different,
    independently and validly-signed receipt (own signature checks out
    fine) whose previous_receipt_hash does not point at the actual receipt
    before it in this chain. This must be reported as a broken hash link,
    NOT as a signature failure -- distinguishing the two failure modes.
    """
    signer = ReceiptSigner(_hex_seed())
    receipts = _build_chain(signer, 5)

    # An unrelated, standalone, validly-signed receipt that has nothing to
    # do with this chain (wrong previous_receipt_hash for slot 2).
    unrelated = signer.sign_receipt(
        decision="allow",
        reasons=["unrelated receipt from a different chain"],
        envelope_hash="envelope-unrelated",
        previous_receipt_hash="not-the-real-previous-hash",
        timestamp=_now(),
    )
    tampered_chain = receipts[:2] + [unrelated] + receipts[3:]

    # Sanity: the substituted receipt is validly signed on its own.
    assert verify_receipt(unrelated) is True
    assert unrelated.previous_receipt_hash != receipts[1].receipt_hash

    result = verify_chain(tampered_chain)

    assert result.passed is False
    assert result.failure_index == 2
    assert result.verified_count == 2
    assert result.failure_reason is not None
    assert "previous_receipt_hash does not match" in result.failure_reason
    assert "invalid signature" not in result.failure_reason
    assert "index 2" in result.failure_reason
    assert "index 1" in result.failure_reason

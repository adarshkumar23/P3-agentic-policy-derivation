# mypy: allow-untyped-defs
"""Stress test: `services.receipt_chain.verify_chain()` over long chains
(500 / 1000 / 2000+ receipts), confirming real wall-clock scaling stays
roughly linear (not quadratic or worse) as the chain grows.

Builds chains directly via `services.receipts.ReceiptSigner`, chaining each
receipt to the previous one's `receipt_hash` -- the same pattern used in
`tests/stress/test_receipt_chain_concurrency.py`, just sequential and much
longer (that file's chains top out at 30-40 receipts to isolate a
concurrency race; this one is about verification cost at scale, not
concurrency).
"""

from __future__ import annotations

import time

from services.receipt_chain import verify_chain
from services.receipts import Receipt, ReceiptSigner

SIGNING_KEY_HEX = "cd" * 32


def _build_chain(signer: ReceiptSigner, n: int) -> list[Receipt]:
    receipts: list[Receipt] = []
    previous_hash: str | None = None
    for i in range(n):
        receipt = signer.sign_receipt(
            decision="allow" if i % 3 != 0 else "deny",
            reasons=[] if i % 3 != 0 else ["over configured limit"],
            envelope_hash=f"envelope-hash-{i}",
            previous_receipt_hash=previous_hash,
            timestamp=f"2026-01-01T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z",
        )
        receipts.append(receipt)
        previous_hash = receipt.receipt_hash
    return receipts


class TestChainVerificationAtScale:
    def test_verify_chain_of_2000_receipts_and_scaling_is_roughly_linear(self):
        signer = ReceiptSigner(signing_key_hex=SIGNING_KEY_HEX)

        sizes = [500, 1000, 2000]
        timings: dict[int, float] = {}
        per_receipt_us: dict[int, float] = {}

        for n in sizes:
            chain = _build_chain(signer, n)
            assert len(chain) == n

            started = time.perf_counter()
            result = verify_chain(chain)
            elapsed = time.perf_counter() - started

            assert result.passed, f"verify_chain failed at n={n}: {result.failure_reason} @ {result.failure_index}"
            assert result.verified_count == n

            timings[n] = elapsed
            per_receipt_us[n] = (elapsed / n) * 1_000_000.0

        table_lines = "\n".join(
            f"    n={n:>5}  total={timings[n] * 1000:>8.3f}ms  per_receipt={per_receipt_us[n]:>7.3f}us"
            for n in sizes
        )
        print(f"\n[stress] verify_chain timing at scale:\n{table_lines}")

        # Linearity check: per-receipt cost at the largest size should not
        # have blown up relative to the smallest size. A quadratic (or
        # worse) algorithm would show per-receipt cost growing with n; a
        # linear one keeps it roughly flat modulo noise. Allow up to 2x
        # slowdown (task brief's own stated tolerance) before treating it as
        # a real superlinearity finding rather than measurement noise.
        smallest, largest = sizes[0], sizes[-1]
        slowdown_factor = per_receipt_us[largest] / per_receipt_us[smallest] if per_receipt_us[smallest] > 0 else 1.0
        print(
            f"[stress] per-receipt slowdown from n={smallest} to n={largest}: "
            f"{slowdown_factor:.2f}x"
        )
        assert slowdown_factor < 2.0, (
            f"verify_chain's per-receipt cost grew {slowdown_factor:.2f}x from n={smallest} to "
            f"n={largest} -- this looks like worse-than-linear scaling, not measurement noise"
        )

    def test_verify_chain_detects_failure_early_without_scanning_whole_chain(self):
        """A tampered receipt near the *start* of a long chain should fail
        fast (verify_chain stops at first failure, per its own docstring),
        not take proportionally as long as a full successful scan of the
        same length. This is a cheap, real confirmation that the
        stop-at-first-failure behavior documented in receipt_chain.py
        actually holds at this scale, not just for tiny lists.
        """
        signer = ReceiptSigner(signing_key_hex=SIGNING_KEY_HEX)
        n = 2000
        chain = _build_chain(signer, n)

        # Tamper with the signature of the 10th receipt so verification
        # fails there instead of running to completion.
        tampered = list(chain)
        bad = tampered[10]
        tampered[10] = Receipt(
            receipt_id=bad.receipt_id,
            timestamp=bad.timestamp,
            envelope_hash=bad.envelope_hash,
            decision=bad.decision,
            reasons=bad.reasons,
            previous_receipt_hash=bad.previous_receipt_hash,
            signature="00" * 64,  # corrupt signature
            receipt_hash=bad.receipt_hash,
            public_key_hex=bad.public_key_hex,
        )

        started = time.perf_counter()
        result = verify_chain(tampered)
        elapsed = time.perf_counter() - started

        assert not result.passed
        assert result.failure_index == 10
        assert result.verified_count == 10
        print(
            f"\n[stress] tampered-at-index-10 verify_chain over n={n} receipts "
            f"returned in {elapsed * 1000:.3f}ms (stopped early, did not scan remaining "
            f"{n - 10} receipts)"
        )

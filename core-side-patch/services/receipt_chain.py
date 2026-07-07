# mypy: allow-untyped-defs
"""Full hash-chain verification for signed decision receipts (Workstream G).

See `services/receipts.py`'s module docstring and PATENT.md §1.1(4)/Claim 4
for the key-custody boundary this workstream builds on top of: this module
never touches a private key, and never reimplements signature verification.
It reuses `verify_receipt` (a module-level, key-free function) from
`services.receipts` for each individual receipt's own signature check, and
adds the piece `verify_receipt` deliberately does *not* do on its own: making
sure a whole *list* of receipts forms one unbroken, correctly-ordered chain
(each receipt's `previous_receipt_hash` pointing at the true
`receipt_hash` of the receipt immediately before it in the list).

Design notes / explicitly-decided behavior
-------------------------------------------
- An empty list is treated as trivially passing: `passed=True`,
  `verified_count=0`, `failure_index=None`, `failure_reason=None`. There is
  nothing to fail; vacuously, every (zero) receipt in it is verified.
- Verification is strictly sequential and stops at the first failure. This
  is deliberate: once a receipt at index `i` fails (bad signature) or its
  link to index `i - 1` is broken, every receipt after it in the list is of
  unknown provenance -- it may not even belong to this chain. We do not
  "skip past" a bad receipt and keep verifying the tail in isolation, since
  that would misreport a broken chain as "mostly fine". `verified_count`
  therefore always equals the number of receipts confirmed good *before*
  hitting the failure (i.e. `failure_index` when there is a failure, or
  `len(receipts)` when there isn't).
- The two distinct failure modes are reported with distinct, specific
  messages so a caller (or a human reading a report) can tell at a glance
  whether the problem is a tampered/forged receipt (signature invalid) or a
  chain-assembly problem (hash link broken / wrong root), rather than one
  generic "verification failed".
"""

from __future__ import annotations

from dataclasses import dataclass

from services.receipts import Receipt, verify_receipt

__all__ = ["ChainVerificationResult", "verify_chain"]


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of walking a full chain of receipts.

    `verified_count` is the number of receipts, starting from index 0, that
    were confirmed to have both a valid signature and a correct
    `previous_receipt_hash` link. When `passed` is True this equals the
    length of the input list. When `passed` is False this equals
    `failure_index` -- i.e. every receipt strictly before the failing one
    was independently confirmed good, and nothing at or after the failing
    index was verified (its trustworthiness is unknown, not "assumed fine").
    """

    passed: bool
    verified_count: int
    failure_index: int | None
    failure_reason: str | None


def verify_chain(receipts: list[Receipt]) -> ChainVerificationResult:
    """Walk `receipts` in order, verifying each receipt's own signature
    (via `verify_receipt`) and its hash-chain link to the receipt before it.

    Stops at the first failure. See module docstring for the full rationale
    behind the empty-list and stop-at-first-failure decisions.
    """
    if not receipts:
        return ChainVerificationResult(
            passed=True,
            verified_count=0,
            failure_index=None,
            failure_reason=None,
        )

    for i, receipt in enumerate(receipts):
        if i == 0:
            if receipt.previous_receipt_hash is not None:
                return ChainVerificationResult(
                    passed=False,
                    verified_count=0,
                    failure_index=0,
                    failure_reason=(
                        "chain does not start with a receipt whose "
                        "previous_receipt_hash is None (receipt at index 0 "
                        f"has previous_receipt_hash={receipt.previous_receipt_hash!r})"
                    ),
                )
        else:
            previous = receipts[i - 1]
            if receipt.previous_receipt_hash != previous.receipt_hash:
                return ChainVerificationResult(
                    passed=False,
                    verified_count=i,
                    failure_index=i,
                    failure_reason=(
                        f"receipt at index {i}'s previous_receipt_hash does not "
                        f"match receipt at index {i - 1}'s receipt_hash"
                    ),
                )

        if not verify_receipt(receipt):
            return ChainVerificationResult(
                passed=False,
                verified_count=i,
                failure_index=i,
                failure_reason=f"receipt at index {i} has an invalid signature",
            )

    return ChainVerificationResult(
        passed=True,
        verified_count=len(receipts),
        failure_index=None,
        failure_reason=None,
    )

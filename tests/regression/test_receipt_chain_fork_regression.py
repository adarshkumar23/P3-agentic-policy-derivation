# mypy: allow-untyped-defs
"""Focused regression test for finding #1 in ASSUMPTIONS.md's "Concurrency
findings from Workstream N (stress testing) and follow-up fixes" section.

What regressed before: `CompliVibePolicyProvider.check_action()`
(`core-side-patch/services/policy_provider.py`) used to read
`self._previous_receipt_hash`, sign a receipt against that value, and write
the new hash back, with no lock around the sequence. Two concurrent
`check_action()` calls on the same provider instance could both read the
same parent hash before either wrote its update, producing two receipts
that both claim the same `previous_receipt_hash` -- a fork in the chain
instead of a single line. This was found and fixed with `self._chain_lock`
(a `threading.Lock` wrapped around the whole read-sign-write sequence).

This test is intentionally narrow -- it is not the full stress battery
(`tests/stress/test_receipt_chain_concurrency.py` already covers that in
depth, including a from-scratch and a chained-onto-history scenario). Its
only job is to be a small, unmistakably-named tripwire: if the lock is ever
removed or narrowed (e.g. only locking the write instead of the whole
read-sign-write), this test should fail immediately and by name, pointing
straight back at this exact bug.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider
from services.receipts import ReceiptSigner

SIGNING_KEY_HEX = "cd" * 32


def _always_allow_transport() -> httpx.MockTransport:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": True})

    return httpx.MockTransport(_handler)


def _make_provider() -> CompliVibePolicyProvider:
    opa_client = OpaClient(
        base_url="http://local-opa.test",
        client=httpx.Client(transport=_always_allow_transport()),
    )
    signer = ReceiptSigner(signing_key_hex=SIGNING_KEY_HEX)
    return CompliVibePolicyProvider(
        opa_client,
        rego_package="complivibe.guardrails.regression_test",
        sign_receipt_fn=signer.sign_receipt,
    )


def _raw_action(i: int) -> dict:
    return {
        "action_id": f"regression-act-{i}",
        "ai_system_id": "sys-1",
        "organization_id": "org-a",
        "action_type": "wire_transfer",
        "amount": 100.0,
        "currency": "USD",
        "timestamp": f"2026-01-01T00:00:{i % 60:02d}Z",
    }


def test_previous_receipt_hash_race_does_not_fork_chain():
    """Regression test for the `_previous_receipt_hash` read-modify-write
    race (ASSUMPTIONS.md, "Concurrency findings ..." -> finding #1).

    Fires N concurrent `check_action()` calls on one shared
    `CompliVibePolicyProvider` instance. The specific signature of "a fork
    occurred" is: two or more receipts sharing the same
    `previous_receipt_hash` value. Assert this never happens -- the
    resulting receipts must form exactly one linear chain.
    """
    provider = _make_provider()
    n = 40

    def _one(i: int):
        return provider.check_action(_raw_action(i), timestamp=f"2026-01-01T00:00:{i % 60:02d}Z").receipt

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_one, i) for i in range(n)]
        receipts = [fut.result() for fut in as_completed(futures)]

    assert len(receipts) == n
    assert all(r is not None for r in receipts)

    # The fork signature: any previous_receipt_hash value claimed by more
    # than one receipt.
    parent_counts: dict[str | None, int] = {}
    for r in receipts:
        parent_counts[r.previous_receipt_hash] = parent_counts.get(r.previous_receipt_hash, 0) + 1

    forked_parents = {parent: count for parent, count in parent_counts.items() if count > 1}
    assert not forked_parents, (
        "chain fork detected: the following previous_receipt_hash value(s) "
        f"were each claimed by more than one receipt: {forked_parents}. This is "
        "exactly the race documented in ASSUMPTIONS.md's 'Concurrency "
        "findings from Workstream N (stress testing) and follow-up fixes' "
        "section (finding #1): an unlocked read-modify-write of "
        "CompliVibePolicyProvider._previous_receipt_hash in "
        "core-side-patch/services/policy_provider.py. If this test fails, "
        "the self._chain_lock fix has been removed, narrowed, or otherwise "
        "broken."
    )

    # Exactly one root (no parent) -- a single unbroken line has exactly one
    # starting point.
    roots = [r for r in receipts if r.previous_receipt_hash is None]
    assert len(roots) == 1, f"expected exactly one root receipt, found {len(roots)}"

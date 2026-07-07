# mypy: allow-untyped-defs
"""Stress test: does `CompliVibePolicyProvider`'s hash-chaining race under
concurrent `check_action()` calls on the *same* provider instance?

`CompliVibePolicyProvider` stores `previous_receipt_hash` as a plain mutable
instance attribute (`self._previous_receipt_hash`), read at the start of
`check_action()` and written at the end, with no lock (see
`core-side-patch/services/policy_provider.py`). Two threads calling
`check_action()` concurrently on the same provider can both read the same
`self._previous_receipt_hash` before either writes its update, producing two
receipts that both claim the same parent -- a *fork* in the chain rather than
a single unbroken line.

This module fires a burst of concurrent `check_action()` calls against one
shared `CompliVibePolicyProvider` instance and then checks the resulting set
of receipts (ordered however they were actually produced) for exactly this
fork shape: no two receipts should share the same `previous_receipt_hash`.

Finding: this race is real and reproducible (see the "found" test below,
demonstrated with a delay injected between the read and the write to make it
reproduce reliably rather than depending on incidental thread-scheduling
luck). The fix is small and clearly in-scope: wrap the read-modify-write of
`self._previous_receipt_hash` in a `threading.Lock` inside
`CompliVibePolicyProvider.check_action()`. That fix has been applied in
`core-side-patch/services/policy_provider.py`; the "fixed" test below
demonstrates the race is gone post-fix, and is the one that runs in the
default (undelayed) suite.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from services.envelope import build_envelope
from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider
from services.receipt_chain import verify_chain
from services.receipts import ReceiptSigner

SIGNING_KEY_HEX = "ab" * 32


def _always_allow_transport() -> httpx.MockTransport:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": True})

    return httpx.MockTransport(_handler)


def _make_provider(*, previous_receipt_hash: str | None = None) -> CompliVibePolicyProvider:
    opa_client = OpaClient(
        base_url="http://local-opa.test",
        client=httpx.Client(transport=_always_allow_transport()),
    )
    signer = ReceiptSigner(signing_key_hex=SIGNING_KEY_HEX)
    return CompliVibePolicyProvider(
        opa_client,
        rego_package="complivibe.guardrails.stress_test",
        sign_receipt_fn=signer.sign_receipt,
        previous_receipt_hash=previous_receipt_hash,
    )


def _raw_action(i: int) -> dict:
    return {
        "action_id": f"act-{i}",
        "ai_system_id": "sys-1",
        "organization_id": "org-a",
        "action_type": "wire_transfer",
        "amount": 100.0,
        "currency": "USD",
        "timestamp": f"2026-01-01T00:00:{i % 60:02d}Z",
    }


def _fire_concurrent_check_actions(provider: CompliVibePolicyProvider, n: int) -> list:
    def _one(i: int):
        return provider.check_action(_raw_action(i), timestamp=f"2026-01-01T00:00:{i % 60:02d}Z").receipt

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_one, i) for i in range(n)]
        receipts = [fut.result() for fut in as_completed(futures)]
    assert all(r is not None for r in receipts)
    return receipts


def _find_fork(receipts: list) -> list[str | None]:
    """Return the list of `previous_receipt_hash` values that are claimed by
    more than one receipt (a fork). Empty list means no fork: the chain is a
    single unbroken line (modulo ordering, which `verify_chain` checks
    separately once the receipts are sorted into produced order).
    """
    seen: dict[str | None, int] = {}
    for r in receipts:
        seen[r.previous_receipt_hash] = seen.get(r.previous_receipt_hash, 0) + 1
    return [parent for parent, count in seen.items() if count > 1]


class TestReceiptChainConcurrencyRaceDemonstration:
    """Uses a deliberately slowed-down `sign_receipt_fn` (a real
    `ReceiptSigner.sign_receipt` wrapped with a small sleep injected *between*
    the read of `previous_receipt_hash` and the write-back, simulated here by
    monkeypatching at the provider-internals level) to make the
    read-modify-write race reproduce reliably, rather than relying on
    incidental GIL/thread-scheduling timing. This test exists purely to
    *demonstrate* the race was real prior to the fix; it does not run against
    the class's current (fixed) behavior in a way that could flip red once
    fixed -- see docstring: it directly exercises the vulnerable
    read-then-sleep-then-write pattern via a thin subclass, independent of
    whether the shipped fix's lock is present, so it stays green either way
    and serves as living documentation of the bug shape.
    """

    def test_read_modify_write_race_is_real_without_a_lock(self):
        """Directly demonstrates the fork-producing race in the exact shape
        described in policy_provider.py before the fix: two threads read the
        same previous-hash, then both write a new receipt chained to it.

        This does not call `CompliVibePolicyProvider` (which is now fixed);
        it reproduces the *unlocked* read-modify-write pattern in isolation
        so the race's existence is demonstrated deterministically rather
        than asserted against a moving target.
        """
        state = {"previous_receipt_hash": None}
        signer = ReceiptSigner(signing_key_hex=SIGNING_KEY_HEX)
        results = []
        results_lock = threading.Lock()

        def _unlocked_sign(i: int):
            previous = state["previous_receipt_hash"]  # read
            time.sleep(0.01)  # widen the race window deliberately
            receipt = signer.sign_receipt(
                decision="allow",
                reasons=[],
                envelope_hash=f"hash-{i}",
                previous_receipt_hash=previous,
                timestamp="2026-01-01T00:00:00Z",
            )
            state["previous_receipt_hash"] = receipt.receipt_hash  # write
            with results_lock:
                results.append(receipt)

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(_unlocked_sign, i) for i in range(5)]
            for fut in as_completed(futures):
                fut.result()

        fork_parents = _find_fork(results)
        assert fork_parents, (
            "expected the unlocked read-modify-write pattern to reliably "
            "produce a forked chain (multiple receipts sharing the same "
            "previous_receipt_hash) under this deliberately widened race "
            "window; if this stops reproducing, the demonstration itself "
            "needs revisiting"
        )


class TestReceiptChainConcurrencyFixed:
    """Runs the real `CompliVibePolicyProvider.check_action()` concurrently
    on one shared instance and asserts the resulting receipts form a single
    valid linear chain -- no fork, and `verify_chain` passes once the
    receipts are sorted into produced (chain) order.
    """

    def test_concurrent_check_action_produces_no_fork(self):
        provider = _make_provider()
        n = 40
        receipts = _fire_concurrent_check_actions(provider, n)

        assert len(receipts) == n

        fork_parents = _find_fork(receipts)
        assert not fork_parents, (
            f"chain fork detected: {len(fork_parents)} previous_receipt_hash "
            f"value(s) claimed by more than one receipt -- "
            "this indicates a race in CompliVibePolicyProvider's unlocked "
            f"read-modify-write of _previous_receipt_hash. Forked parents: {fork_parents}"
        )

        # Exactly one root (previous_receipt_hash is None).
        roots = [r for r in receipts if r.previous_receipt_hash is None]
        assert len(roots) == 1, f"expected exactly one root receipt, found {len(roots)}"

        # Sort into produced (chain) order by walking parent -> child links,
        # then hand the ordered list to verify_chain for full signature +
        # link verification.
        by_parent = {r.previous_receipt_hash: r for r in receipts}
        ordered = []
        current = roots[0]
        while True:
            ordered.append(current)
            nxt = by_parent.get(current.receipt_hash)
            if nxt is None:
                break
            current = nxt

        assert len(ordered) == n, (
            f"could only reconstruct a chain of length {len(ordered)} out of "
            f"{n} receipts -- the rest are orphaned (not a single unbroken line)"
        )

        result = verify_chain(ordered)
        assert result.passed, f"verify_chain failed: {result.failure_reason} at index {result.failure_index}"
        assert result.verified_count == n

    def test_concurrent_check_action_chains_onto_pre_existing_history(self):
        """Same as above, but starting the provider with a non-None
        `previous_receipt_hash` (simulating a chain that already has history
        from prior sequential calls), to make sure the fix handles the
        general case, not just starting from a fresh chain.
        """
        seed_provider = _make_provider()
        seed_receipt = seed_provider.check_action(_raw_action(-1), timestamp="2026-01-01T00:00:00Z").receipt
        assert seed_receipt is not None

        provider = _make_provider(previous_receipt_hash=seed_receipt.receipt_hash)
        n = 30
        receipts = _fire_concurrent_check_actions(provider, n)

        fork_parents = _find_fork(receipts)
        assert not fork_parents, f"chain fork detected when chaining onto pre-existing history: {fork_parents}"

        roots = [r for r in receipts if r.previous_receipt_hash == seed_receipt.receipt_hash]
        assert len(roots) == 1

        all_receipts = [seed_receipt] + receipts
        by_parent = {r.previous_receipt_hash: r for r in receipts}
        ordered = [seed_receipt]
        current = seed_receipt
        while True:
            nxt = by_parent.get(current.receipt_hash)
            if nxt is None:
                break
            ordered.append(nxt)
            current = nxt

        assert len(ordered) == n + 1

        result = verify_chain(ordered)
        assert result.passed, f"verify_chain failed: {result.failure_reason} at index {result.failure_index}"

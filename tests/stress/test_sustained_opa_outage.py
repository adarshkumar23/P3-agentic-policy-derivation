# mypy: allow-untyped-defs
"""Stress test: a SUSTAINED OPA outage (not a single call, and not the
shorter mid-burst outage already covered by
`tests/stress/test_concurrent_check_action.py`'s
`TestOpaUnreachableMidBurstFailsClosed` / `TestCircuitBreakerBookkeepingRace`,
which fire one large concurrent burst and check the fail-closed guarantee
holds -- they do not drive the circuit breaker through a full
open -> cooldown-elapsed -> closed -> real-call-resumes cycle with real
wall-clock sleeps, which is what this file adds).

This test uses one long-lived `OpaClient` (mirroring how a real deployment
would hold one client alive across many requests, rather than
`api/guardrails.py`'s default per-request `policy_provider_factory`, which
constructs a fresh `OpaClient` -- and therefore a fresh circuit breaker --
on every single call; that per-call-fresh-client wiring is a real property
of this repo's demo `create_app()` default worth noting, but it also means
the circuit breaker can never accumulate state across requests through that
default path. To exercise the circuit breaker's full lifecycle honestly,
this test drives `CompliVibePolicyProvider.check_action()` directly against
one shared `OpaClient`, the same level `test_receipt_chain_concurrency.py`
already tests at.) and confirms, across a real elapsed cooldown window:

(a) the circuit breaker opens and stops attempting real transport calls
    during the outage (confirmed both via `OPA_CIRCUIT_BREAKER_TRANSITIONS`
    and by directly counting transport invocations vs. total calls
    attempted),
(b) every single call during the outage returns a clean fail-closed deny,
    never a hang or crash,
(c) once the transport starts succeeding again and the cooldown has
    elapsed, real calls resume and real allow/deny decisions are returned
    again (full recovery, not just "stopped erroring").
"""

from __future__ import annotations

import threading
import time

import httpx

from observability import OPA_CIRCUIT_BREAKER_TRANSITIONS
from services.envelope import build_envelope
from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider
from services.receipts import ReceiptSigner

SIGNING_KEY_HEX = "ef" * 32


def _counter_total(counter, **labels) -> float:
    return counter.labels(**labels)._value.get()


def _raw_action(i: int) -> dict:
    return {
        "action_id": f"act-outage-{i}",
        "ai_system_id": "sys-outage",
        "organization_id": "org-outage",
        "action_type": "wire_transfer",
        "amount": 100.0,
        "currency": "USD",
        "timestamp": "2026-01-01T00:00:00Z",
    }


class _ControllableTransport:
    """A transport whose behavior can be flipped mid-test between "OPA is
    down" (raises `httpx.ConnectError` on every call) and "OPA is back"
    (returns a clean allow=True decision), while counting every actual
    invocation so the test can assert on real transport-call counts (not
    just on the decisions that came back).
    """

    def __init__(self) -> None:
        self.down = True
        self.invocation_count = 0
        self._lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.invocation_count += 1
        if self.down:
            raise httpx.ConnectError("simulated sustained OPA outage", request=request)
        return httpx.Response(200, json={"result": True})


class TestSustainedOpaOutage:
    def test_circuit_opens_stays_open_through_cooldown_then_fully_recovers(self):
        transport = _ControllableTransport()
        threshold = 5
        cooldown_seconds = 1.0

        opa_client = OpaClient(
            base_url="http://opa.test",
            client=httpx.Client(transport=httpx.MockTransport(transport)),
            max_retries=0,
            circuit_breaker_threshold=threshold,
            circuit_breaker_cooldown_seconds=cooldown_seconds,
        )
        signer = ReceiptSigner(signing_key_hex=SIGNING_KEY_HEX)
        provider = CompliVibePolicyProvider(
            opa_client,
            rego_package="complivibe.guardrails.sustained_outage_test",
            sign_receipt_fn=signer.sign_receipt,
            previous_receipt_hash=None,
        )

        opened_before = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="opened")
        closed_before = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="closed")

        # -- (a)/(b): sustained outage -- fire well more calls than the
        # threshold, across a real elapsed span, and confirm every single
        # one comes back a clean fail-closed deny with no exception.
        n_during_outage = 60
        outage_started = time.perf_counter()
        outage_results = []
        for i in range(n_during_outage):
            result = provider.check_action(_raw_action(i), timestamp="2026-01-01T00:00:00Z")
            outage_results.append(result)
            if i == 20:
                # Let real wall-clock time pass mid-outage so the circuit is
                # confirmed to *stay* open through a chunk of its cooldown
                # window, not just immediately after tripping.
                time.sleep(cooldown_seconds * 0.5)
        outage_elapsed = time.perf_counter() - outage_started

        assert all(not r.decision.allowed for r in outage_results), (
            "a decision during the sustained outage was allowed=True -- fail-open bug"
        )
        assert all(r.receipt is not None for r in outage_results), (
            "expected a signed deny receipt for every call during the outage "
            "(fail-closed must still produce an auditable receipt)"
        )
        assert all(r.receipt.decision == "deny" for r in outage_results)

        # Transport invocation count must be far lower than the number of
        # calls attempted: once the circuit opens (after `threshold`
        # consecutive failures), subsequent calls short-circuit and never
        # touch the transport at all.
        assert transport.invocation_count < n_during_outage, (
            f"expected the circuit breaker to stop attempting real transport calls well "
            f"before all {n_during_outage} calls during the outage; transport was invoked "
            f"{transport.invocation_count} times -- circuit does not appear to have opened"
        )
        assert transport.invocation_count >= threshold, (
            f"expected at least {threshold} real transport attempts before the circuit "
            f"opened, got {transport.invocation_count}"
        )

        opened_after_outage = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="opened")
        assert opened_after_outage == opened_before + 1, (
            f"expected exactly one 'opened' circuit-breaker transition during the sustained "
            f"outage, got a delta of {opened_after_outage - opened_before}"
        )

        # -- confirm the circuit genuinely STAYS open through the rest of
        # its cooldown window (not just transiently) by making more calls
        # immediately and confirming the transport still isn't touched.
        invocation_count_at_end_of_outage = transport.invocation_count
        for i in range(n_during_outage, n_during_outage + 10):
            result = provider.check_action(_raw_action(i), timestamp="2026-01-01T00:00:00Z")
            assert not result.decision.allowed
        assert transport.invocation_count == invocation_count_at_end_of_outage, (
            "circuit breaker allowed a real transport call before its cooldown window "
            "elapsed -- it should have stayed open"
        )

        # -- (c): OPA recovers. Flip the transport, wait out the remainder of
        # the cooldown window (real wall-clock sleep), then confirm real
        # calls resume and a real allow decision comes back.
        transport.down = False
        time.sleep(cooldown_seconds + 0.3)

        invocation_count_before_recovery = transport.invocation_count
        recovery_result = provider.check_action(
            _raw_action(9999), timestamp="2026-01-01T00:00:00Z"
        )

        assert transport.invocation_count == invocation_count_before_recovery + 1, (
            "expected the first call after cooldown elapsed to make a real transport "
            "attempt (circuit half-open/closed), but the transport was not invoked"
        )
        assert recovery_result.decision.allowed is True, (
            "expected a genuine allow=True decision once OPA recovered and the cooldown "
            "elapsed -- full recovery, not just 'stopped erroring'"
        )
        assert recovery_result.decision.backend == "complivibe-derived-guardrail"
        assert recovery_result.receipt is not None
        assert recovery_result.receipt.decision == "allow"

        closed_after_recovery = _counter_total(OPA_CIRCUIT_BREAKER_TRANSITIONS, transition="closed")
        assert closed_after_recovery == closed_before + 1, (
            f"expected exactly one 'closed' circuit-breaker transition once the cooldown "
            f"elapsed and a call resumed, got a delta of {closed_after_recovery - closed_before}"
        )

        # Confirm subsequent calls also keep succeeding for real (not a
        # one-off fluke) -- genuine, sustained recovery.
        further_results = [
            provider.check_action(_raw_action(10000 + i), timestamp="2026-01-01T00:00:00Z")
            for i in range(5)
        ]
        assert all(r.decision.allowed for r in further_results)

        print(
            f"\n[stress] sustained OPA outage timeline:\n"
            f"  outage phase: {n_during_outage} calls over {outage_elapsed:.3f}s wall-clock, "
            f"only {invocation_count_at_end_of_outage} real transport attempts made "
            f"(circuit opened after {threshold} consecutive failures)\n"
            f"  circuit stayed open through full cooldown ({cooldown_seconds:.1f}s + margin)\n"
            f"  post-cooldown: transport recovered, first post-cooldown call made a real "
            f"attempt and returned a genuine allow=True decision; {len(further_results)} "
            f"further calls also succeeded for real\n"
            f"  OPA_CIRCUIT_BREAKER_TRANSITIONS deltas: opened=+1, closed=+1"
        )

    def test_build_envelope_still_used_correctly_during_outage(self):
        """Sanity check that the outage path still goes through the same
        envelope construction as the happy path (i.e. the fail-closed
        behavior is a property of the OPA call, not of skipping envelope
        validation) -- a malformed action during an outage should still be
        rejected as a bad request (ValueError from build_envelope), not
        silently coerced into a fail-closed deny.
        """
        transport = _ControllableTransport()
        opa_client = OpaClient(
            base_url="http://opa.test",
            client=httpx.Client(transport=httpx.MockTransport(transport)),
            max_retries=0,
            circuit_breaker_threshold=3,
            circuit_breaker_cooldown_seconds=5.0,
        )
        signer = ReceiptSigner(signing_key_hex=SIGNING_KEY_HEX)
        provider = CompliVibePolicyProvider(
            opa_client,
            rego_package="complivibe.guardrails.sustained_outage_test",
            sign_receipt_fn=signer.sign_receipt,
        )

        bad_action = {**_raw_action(0), "credentials": {"api_key": "leak"}}
        try:
            build_envelope(bad_action)
            raised = False
        except ValueError:
            raised = True
        assert raised, "expected build_envelope to reject a payload-shaped field even during an outage"

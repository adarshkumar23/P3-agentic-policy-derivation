# mypy: allow-untyped-defs
"""Regression / safety-proof test for finding #3 in ASSUMPTIONS.md's
"Concurrency findings from Workstream N (stress testing) and follow-up
fixes" section -- the one deliberately left UNFIXED.

What was found: `OpaClient`'s circuit-breaker bookkeeping
(`self._consecutive_failures`, `self._circuit_open_until` in
`core-side-patch/services/opa_client.py`) is an unlocked read-modify-write.
Concurrent failures can lose counter updates and shift exactly when the
circuit opens/closes relative to a single-threaded run. This was judged
low-severity and non-exploitable and deliberately left unfixed (only the
small, clearly-scoped `previous_receipt_hash` lock was authorized), on the
following safety argument:

    An `OpaDecision` with `allowed=True` is only ever constructed on the
    branch of `OpaClient.evaluate()` where *that specific call's own* HTTP
    round trip returned a clean 2xx response with a well-formed
    `{"result": ...}` body (see `_record_success()` / the final `return
    OpaDecision(allowed=bool(result), ..., source="opa", ...)` branch).
    The racy shared counters (`_consecutive_failures`,
    `_circuit_open_until`) are consulted *only* by `_circuit_is_open()`,
    which gates whether an HTTP attempt is made at all -- it decides
    "skip and fail-closed immediately" vs. "actually call out to OPA". A
    race in that bookkeeping can therefore only affect *whether an HTTP
    call happens*, never *what `allowed` value is derived once one does*.
    There is no code path where `allowed=True` is synthesized from shared
    state instead of from the current call's own genuine OPA response.

This test does not re-fix or re-litigate the counter race itself (that is
already demonstrated in
`tests/stress/test_concurrent_check_action.py::TestCircuitBreakerBookkeepingRace`).
Instead, it adversarially maximizes contention on those exact counters
(many threads, a real mix of successes and failures, zero artificial
delays that would reduce contention) while maintaining an independent
ground-truth record of what each call's transport response *actually was*,
and proves the safety property directly: every `OpaDecision` with
`allowed=True` corresponds -- by that call's own index -- to a transport
response that was itself a genuine, successful 200 `{"result": true}`.
No matter what the race does to the internal counters, it never manages to
produce an accidental allow.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from services.opa_client import OpaClient


def _make_ground_truth_transport(ground_truth: dict[int, str], lock: threading.Lock) -> httpx.MockTransport:
    """Build a mock transport whose per-call behavior is fully determined by
    a `call_index` embedded in the request body by the test, so the test can
    later cross-check exactly which calls the transport genuinely answered
    with success vs. failure -- independent of (and unaffected by) any race
    in OpaClient's own shared circuit-breaker bookkeeping.

    Roughly two-thirds of calls "succeed" (200, `{"result": true}`) and
    one-third "fail" (a connect error), deterministic per `call_index` so
    the ground-truth record is reproducible, but still a genuine mix so the
    circuit breaker actually opens and closes multiple times during the
    test -- maximizing contention on `_consecutive_failures` /
    `_circuit_open_until` rather than avoiding it.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        call_index = body["input"]["call_index"]
        # Deterministic per-index mix: fails on every 3rd call, so failures
        # and successes are interleaved in a fixed but non-trivial pattern.
        will_succeed = call_index % 3 != 0
        with lock:
            ground_truth[call_index] = "success" if will_succeed else "failure"
        if will_succeed:
            return httpx.Response(200, json={"result": True})
        raise httpx.ConnectError("simulated OPA failure", request=request)

    return httpx.MockTransport(_handler)


def test_allowed_true_never_appears_without_a_genuine_successful_response():
    """Adversarial concurrent-failure test proving the circuit-breaker race
    documented in ASSUMPTIONS.md (finding #3) is non-exploitable: no matter
    what it does to `_consecutive_failures` / `_circuit_open_until`,
    `allowed=True` is never returned except for a call whose own transport
    response was a genuine, successful 200 `{"result": true}`.

    Structure: a mock transport records, per call, whether it *genuinely*
    succeeded or failed (the ground truth), keyed by a `call_index` the
    test embeds in each request so it can be recovered later regardless of
    how threads interleave. A low circuit-breaker threshold and a real mix
    of failures (every 3rd call) are used deliberately, so the circuit
    breaker actually flips open and closed repeatedly during the burst --
    maximizing contention on the unlocked counters rather than sidestepping
    it. `max_retries=0` keeps each `evaluate()` call mapped to at most one
    transport invocation (or zero, if the circuit breaker's skip-path is
    taken), so the ground-truth record unambiguously corresponds to each
    call's real outcome.

    The assertion: for every returned `OpaDecision` with `allowed=True`,
    cross-check against the ground-truth record that this call's transport
    really did return a successful response. This is the literal safety
    property that makes the race "non-exploitable" rather than merely
    "hasn't broken yet" -- see the module docstring for why it holds
    structurally.
    """
    ground_truth: dict[int, str] = {}
    ground_truth_lock = threading.Lock()
    transport = _make_ground_truth_transport(ground_truth, ground_truth_lock)

    client = OpaClient(
        base_url="http://opa.test",
        client=httpx.Client(transport=transport),
        max_retries=0,  # one evaluate() call -> at most one transport invocation
        circuit_breaker_threshold=5,
        circuit_breaker_cooldown_seconds=0.0,  # cooldown expires ~immediately: circuit reopens for more contention
    )

    n_calls = 400

    def _one(i: int):
        decision = client.evaluate(
            package="complivibe.guardrails.circuit_breaker_regression",
            input_data={"call_index": i},
        )
        return i, decision

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = [pool.submit(_one, i) for i in range(n_calls)]
        results = [fut.result() for fut in as_completed(futures)]

    assert len(results) == n_calls

    allowed_true_results = [(i, d) for i, d in results if d.allowed is True]

    # Sanity: the mix actually produced some genuine allows and the circuit
    # breaker actually had material to work with (both successes and
    # failures occurred), otherwise this test would be vacuously passing.
    assert allowed_true_results, "expected at least some genuine allow=True decisions in this mix"
    assert any(v == "failure" for v in ground_truth.values()), (
        "expected the transport to have recorded genuine failures too -- "
        "otherwise the circuit breaker never had contention to race on"
    )

    # The actual safety property: every allowed=True decision must trace
    # back, via its call index, to a transport response that was itself a
    # genuine success. If the unlocked _consecutive_failures /
    # _circuit_open_until race could ever fabricate an allow, this is where
    # it would show up.
    violations = []
    for i, decision in allowed_true_results:
        if decision.source != "opa":
            violations.append((i, decision.source, decision.error, "allowed=True but source != 'opa'"))
            continue
        truth = ground_truth.get(i)
        if truth != "success":
            violations.append(
                (i, decision.source, truth, "allowed=True but ground truth for this call was not a success")
            )

    assert not violations, (
        "found OpaDecision(allowed=True) not backed by a genuine successful "
        "transport response for that same call -- this would mean the "
        "circuit-breaker bookkeeping race (ASSUMPTIONS.md finding #3) is "
        f"exploitable after all, contrary to the documented safety argument: {violations}"
    )

    # Converse sanity check: every ground-truth failure must never have
    # produced allowed=True for that index (redundant with the above, but
    # stated the other way round for clarity as executable documentation).
    for i, decision in results:
        if ground_truth.get(i) == "failure":
            assert decision.allowed is False, (
                f"call {i} had a genuine transport failure but OpaClient returned allowed=True"
            )

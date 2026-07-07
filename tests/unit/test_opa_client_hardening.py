"""Hardening test: OPA slow-but-not-erroring must fail closed, not silently
allow.

`OpaClient` is documented as fail-closed for unreachable/erroring OPA calls
(see `services/opa_client.py`'s module docstring), but a genuinely *slow*
OPA that eventually returns a normal 200 `{"result": true}` is a different
failure mode: nothing raises, nothing looks malformed -- the response just
arrives late. If `timeout_seconds` isn't actually enforced against that
case, the client would treat "OPA took 10x longer than its configured
timeout, but still said allow" as a normal allow, silently defeating the
whole point of having a configurable timeout on the hot check-action path.

`httpx.Client(timeout=...)` only bounds real socket I/O -- it does not (and
cannot) interrupt an `httpx.MockTransport` handler that is simply running
slow synchronous Python code (e.g. `time.sleep(...)`), since no actual
socket read/connect/write ever happens for a mock transport. This test
proves the client enforces its configured timeout regardless of what the
underlying transport is doing.
"""

from __future__ import annotations

import time

import httpx

from services.opa_client import OpaClient


def test_slow_but_successful_response_past_timeout_fails_closed_not_open():
    """A handler that sleeps past `timeout_seconds` before returning a clean
    200 `{"result": true}` must be treated as a timeout -> fail-closed, not
    as a slow-but-successful allow.
    """
    timeout_seconds = 0.2

    def handler(request: httpx.Request) -> httpx.Response:
        time.sleep(timeout_seconds + 0.5)
        return httpx.Response(200, json={"result": True})

    transport = httpx.MockTransport(handler)
    client = OpaClient(
        base_url="http://opa.internal:8181",
        timeout_seconds=timeout_seconds,
        max_retries=0,
        client=httpx.Client(transport=transport),
    )

    started = time.monotonic()
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {"amount": 5})
    elapsed = time.monotonic() - started

    assert decision.allowed is False, "a slow-but-200 response must never be treated as an allow"
    assert decision.source == "fail_closed"
    assert decision.error is not None
    # Must actually return around the configured timeout, not wait for the
    # full slow handler to complete (that would defeat the point of having
    # a timeout at all on the hot check-action path).
    assert elapsed < timeout_seconds + 0.4, (
        f"evaluate() took {elapsed:.2f}s, expected it to give up near "
        f"timeout_seconds={timeout_seconds}s rather than waiting for the "
        "slow handler to finish"
    )


def test_response_that_arrives_within_timeout_is_still_a_normal_allow():
    """Sanity check: the timeout enforcement added above must not make fast,
    well-within-budget responses spuriously fail closed."""
    timeout_seconds = 1.0

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": True})

    transport = httpx.MockTransport(handler)
    client = OpaClient(
        base_url="http://opa.internal:8181",
        timeout_seconds=timeout_seconds,
        max_retries=0,
        client=httpx.Client(transport=transport),
    )

    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {"amount": 5})
    assert decision.allowed is True
    assert decision.source == "opa"


def test_slow_deny_response_past_timeout_is_still_fail_closed_deny():
    """A slow response that would have been a deny anyway must still surface
    as fail_closed (source), not as a same-looking-but-differently-sourced
    "opa" deny -- the caller needs to be able to tell these two situations
    apart (e.g. for alerting on a degraded OPA vs. a routine policy deny)."""
    timeout_seconds = 0.15

    def handler(request: httpx.Request) -> httpx.Response:
        time.sleep(timeout_seconds + 0.3)
        return httpx.Response(200, json={"result": False})

    transport = httpx.MockTransport(handler)
    client = OpaClient(
        base_url="http://opa.internal:8181",
        timeout_seconds=timeout_seconds,
        max_retries=0,
        client=httpx.Client(transport=transport),
    )

    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {"amount": 5})
    assert decision.allowed is False
    assert decision.source == "fail_closed"

"""Unit tests for `services.opa_client.OpaClient`.

All HTTP is mocked via `httpx.MockTransport` (built into httpx) -- no real
network calls are made and no OPA instance needs to be running.
"""

from __future__ import annotations

import json

import httpx
import pytest

from services.opa_client import OpaClient, OpaDecision


def _client_with_handler(handler, **kwargs) -> OpaClient:
    transport = httpx.MockTransport(handler)
    httpx_client = httpx.Client(transport=transport)
    return OpaClient(
        base_url="http://opa.internal:8181",
        client=httpx_client,
        backoff_base_seconds=0.001,
        **kwargs,
    )


def test_allow_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/data/compli_vibe/guardrails/spend_limit/allow"
        body = json.loads(request.content)
        assert body == {"input": {"amount": 5}}
        return httpx.Response(200, json={"result": True})

    client = _client_with_handler(handler)
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {"amount": 5})

    assert decision.allowed is True
    assert decision.source == "opa"
    assert decision.raw_result is True
    assert decision.error is None
    assert decision.evaluation_ms >= 0


def test_deny_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": False})

    client = _client_with_handler(handler)
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {"amount": 999})

    assert decision.allowed is False
    assert decision.source == "opa"
    assert decision.raw_result is False
    assert decision.error is None


def test_explicit_query_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/data/some/custom/decision"
        return httpx.Response(200, json={"result": True})

    client = _client_with_handler(handler)
    decision = client.evaluate(query_path="some/custom/decision", input_data={"x": 1})
    assert decision.allowed is True


def test_missing_package_and_query_path_raises():
    client = _client_with_handler(lambda request: httpx.Response(200, json={"result": True}))
    with pytest.raises(ValueError):
        client.evaluate(input_data={"x": 1})


def test_connection_error_retries_then_fails_closed():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ConnectError("connection refused", request=request)

    client = _client_with_handler(handler, max_retries=2)
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})

    assert decision.allowed is False
    assert decision.source == "fail_closed"
    assert "ConnectError" in decision.error
    # max_retries=2 -> 3 total attempts
    assert calls["count"] == 3


def test_timeout_retries_then_fails_closed():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ReadTimeout("timed out", request=request)

    client = _client_with_handler(handler, max_retries=1)
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})

    assert decision.allowed is False
    assert decision.source == "fail_closed"
    assert "ReadTimeout" in decision.error
    assert calls["count"] == 2


def test_malformed_json_fails_closed_without_retry():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, content=b"not json{{{")

    client = _client_with_handler(handler, max_retries=3)
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})

    assert decision.allowed is False
    assert decision.source == "fail_closed"
    assert "malformed JSON" in decision.error
    # a clean (if malformed-body) response means OPA was reached -- no retry
    assert calls["count"] == 1


def test_response_missing_result_key_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    client = _client_with_handler(handler)
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})

    assert decision.allowed is False
    assert decision.source == "fail_closed"
    assert "missing 'result'" in decision.error


def test_clean_non_2xx_is_not_retried():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(500, json={"error": "internal"})

    client = _client_with_handler(handler, max_retries=3)
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})

    assert decision.allowed is False
    assert decision.source == "fail_closed"
    assert "500" in decision.error
    # a real (if unhappy) response from OPA is not retried
    assert calls["count"] == 1


def test_circuit_breaker_trips_after_threshold_and_skips_calls():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ConnectError("connection refused", request=request)

    client = _client_with_handler(
        handler,
        max_retries=0,  # 1 attempt per evaluate() call, to make counting simple
        circuit_breaker_threshold=3,
        circuit_breaker_cooldown_seconds=60.0,
    )

    # 3 consecutive failing calls trips the breaker (threshold=3).
    for _ in range(3):
        decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})
        assert decision.source == "fail_closed"

    assert calls["count"] == 3

    # Breaker should now be open: further calls must not hit the transport.
    for _ in range(5):
        decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})
        assert decision.source == "fail_closed"
        assert "circuit breaker open" in decision.error

    assert calls["count"] == 3  # unchanged -- no new HTTP attempts made


def test_circuit_breaker_recovers_after_cooldown():
    calls = {"count": 0}
    state = {"fail": True}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if state["fail"]:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, json={"result": True})

    client = _client_with_handler(
        handler,
        max_retries=0,
        circuit_breaker_threshold=2,
        circuit_breaker_cooldown_seconds=0.01,
    )

    for _ in range(2):
        client.evaluate("compli_vibe.guardrails.spend_limit", {})
    assert calls["count"] == 2

    # Breaker open: immediate call is skipped, no new attempt.
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})
    assert decision.source == "fail_closed"
    assert calls["count"] == 2

    # Wait out the cooldown, then OPA recovers.
    import time

    time.sleep(0.02)
    state["fail"] = False
    decision = client.evaluate("compli_vibe.guardrails.spend_limit", {})
    assert decision.source == "opa"
    assert decision.allowed is True
    assert calls["count"] == 3


def test_opa_decision_is_a_plain_dataclass_shape():
    decision = OpaDecision(
        allowed=True, raw_result=True, source="opa", error=None, evaluation_ms=1.2
    )
    assert decision.allowed is True
    assert decision.source == "opa"

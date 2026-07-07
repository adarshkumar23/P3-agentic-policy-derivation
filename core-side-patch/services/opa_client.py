# mypy: allow-untyped-defs
"""Thin HTTP client for an already-running, separately-deployed OPA instance.

Scope note (see PATENT.md §0 and §3): deploying, clustering, or otherwise
operating OPA is explicitly out of scope for this repository. This module
only calls an OPA HTTP API that is assumed to already be up somewhere; it is
not itself a policy engine.

Fail-closed by design
----------------------
This client is deliberately **fail-closed**, not fail-open. If OPA cannot be
reached, times out, returns a non-2xx status, or returns a response this
client cannot parse, `OpaClient.evaluate()` returns a decision with
`allowed=False` and `source="fail_closed"` -- it never silently treats an
unreachable/broken policy engine as "allow". This is a deliberate compliance
tradeoff: an OPA outage becomes a deny-everything incident rather than an
unnoticed policy bypass. For a compliance product, "everything stops" is a
loud, recoverable failure; "everything is silently allowed" is not. See
ASSUMPTIONS.md for the high-level statement of this decision; this module is
where it is actually enforced.

Retries and the circuit breaker below exist only to bound how long a caller
on the hot per-agent-action check path waits before that fail-closed answer
comes back -- they never change the fail-closed default itself.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from observability import OPA_CIRCUIT_BREAKER_TRANSITIONS

__all__ = ["OpaDecision", "OpaClient"]


@dataclass(frozen=True)
class OpaDecision:
    """The result of asking OPA (or, on failure, this client) for a decision."""

    allowed: bool
    raw_result: Any
    source: Literal["opa", "fail_closed"]
    error: str | None
    evaluation_ms: float


class OpaClient:
    """Synchronous HTTP client for OPA's `POST /v1/data/<path>` decision API.

    Fail-closed by design (see module docstring): any failure to obtain a
    clean, well-formed decision from OPA -- unreachable host, timeout,
    non-2xx status, or malformed JSON -- results in
    ``OpaDecision(allowed=False, source="fail_closed", ...)``, never a
    silent allow.

    Only connection-level failures (connect errors, timeouts) are retried,
    up to ``max_retries`` attempts with a short bounded backoff. A clean
    non-2xx response *from* OPA is a real answer from a reachable service
    and is not retried -- retrying it could not change the answer, and
    retrying is reserved for cases where the service might not have been
    reached at all.

    A simple circuit breaker also guards this client: after
    ``circuit_breaker_threshold`` consecutive failures, further calls skip
    the HTTP attempt entirely and return fail-closed immediately until
    ``circuit_breaker_cooldown_seconds`` have elapsed. This exists for two
    reasons: it protects a struggling OPA instance from a thundering herd of
    retries during an incident, and it keeps this client's own latency
    bounded, since it sits on the hot path of a per-agent-action check
    endpoint.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 2.0,
        max_retries: int = 2,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_cooldown_seconds: float = 30.0,
        client: httpx.Client | None = None,
        backoff_base_seconds: float = 0.05,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_cooldown_seconds = circuit_breaker_cooldown_seconds
        self.backoff_base_seconds = backoff_base_seconds

        self._client = client or httpx.Client(timeout=timeout_seconds)

        self._consecutive_failures = 0
        self._circuit_open_until: float | None = None

    # -- circuit breaker bookkeeping -----------------------------------

    def _circuit_is_open(self) -> bool:
        if self._circuit_open_until is None:
            return False
        if time.monotonic() >= self._circuit_open_until:
            # Cooldown elapsed: close the circuit and let the next call try.
            # This is the one place the circuit transitions from open back
            # to closed, so it's the one place to count a "closed"
            # transition -- every other call to this method while already
            # open (before cooldown) or already closed (returns False on
            # the line above) is a no-op read, not a transition.
            self._circuit_open_until = None
            self._consecutive_failures = 0
            OPA_CIRCUIT_BREAKER_TRANSITIONS.labels(transition="closed").inc()
            return False
        return True

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.circuit_breaker_threshold:
            # Only the transition into "open" should be counted. Once
            # `_circuit_open_until` is already set, further consecutive
            # failures (which can't happen anyway once open, since
            # `evaluate()` short-circuits via `_circuit_is_open()` before
            # ever calling `_record_failure()` again) would otherwise
            # double-count the same trip.
            was_open = self._circuit_open_until is not None
            self._circuit_open_until = (
                time.monotonic() + self.circuit_breaker_cooldown_seconds
            )
            if not was_open:
                OPA_CIRCUIT_BREAKER_TRANSITIONS.labels(transition="opened").inc()

    def _record_success(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open_until = None

    def _post_with_timeout(self, url: str, input_data: dict) -> httpx.Response:
        """Issue the OPA POST with a timeout enforced independently of the
        underlying transport.

        `httpx.Client(timeout=...)` only bounds real socket I/O -- it has no
        way to interrupt a transport (e.g. a test `httpx.MockTransport`
        handler, or any synchronous callable) that is simply running slow
        Python code past the configured deadline. Without this, a handler
        that sleeps past `timeout_seconds` and then returns a normal 200
        would be treated as a slow-but-successful call rather than a
        timeout -- an accidental fail-*open* for exactly the "OPA is slow
        but not erroring" case this client is supposed to fail closed on.
        Running the call in a worker thread and bounding it with
        `Future.result(timeout=...)` enforces the deadline regardless of
        what the transport underneath is actually doing.
        """
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self._client.post, url, json={"input": input_data})
        try:
            return future.result(timeout=self.timeout_seconds)
        except concurrent.futures.TimeoutError:
            raise httpx.ReadTimeout(
                f"OPA call exceeded timeout_seconds={self.timeout_seconds}s "
                "(enforced independently of the underlying transport)"
            )
        finally:
            # Don't block shutdown on the (possibly still-running) worker
            # thread -- we've already given up on its result.
            executor.shutdown(wait=False)

    # -- public API ------------------------------------------------------

    def evaluate(
        self,
        package: str | None = None,
        input_data: dict | None = None,
        *,
        query_path: str | None = None,
    ) -> OpaDecision:
        """Ask OPA to evaluate a policy against `input_data`.

        Either pass `package` (a dotted Rego package name, e.g.
        `"compli_vibe.guardrails.spend_limit"`; queried at its `allow`
        rule), or pass an explicit `query_path` (e.g.
        `"compli_vibe/guardrails/spend_limit/allow"`) if the decision rule
        isn't named `allow`. Exactly one of the two forms is queried.
        """
        input_data = input_data or {}
        if query_path is not None:
            path = query_path.strip("/")
        elif package is not None:
            path = package.replace(".", "/").strip("/") + "/allow"
        else:
            raise ValueError("evaluate() requires either `package` or `query_path`")

        url = f"{self.base_url}/v1/data/{path}"
        started = time.monotonic()

        if self._circuit_is_open():
            return OpaDecision(
                allowed=False,
                raw_result=None,
                source="fail_closed",
                error=(
                    "circuit breaker open: too many consecutive OPA failures; "
                    "skipping HTTP call during cooldown"
                ),
                evaluation_ms=(time.monotonic() - started) * 1000.0,
            )

        last_error: str | None = None
        attempts = self.max_retries + 1

        for attempt in range(attempts):
            try:
                response = self._post_with_timeout(url, input_data)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < attempts - 1:
                    time.sleep(self.backoff_base_seconds * (2**attempt))
                    continue
                self._record_failure()
                return OpaDecision(
                    allowed=False,
                    raw_result=None,
                    source="fail_closed",
                    error=last_error,
                    evaluation_ms=(time.monotonic() - started) * 1000.0,
                )

            # A response was received: OPA is reachable. Do not retry a
            # clean non-2xx -- it is a real answer, not an unreachability
            # signal.
            if response.status_code < 200 or response.status_code >= 300:
                self._record_failure()
                return OpaDecision(
                    allowed=False,
                    raw_result=None,
                    source="fail_closed",
                    error=(
                        f"OPA returned non-2xx status {response.status_code}: "
                        f"{response.text[:500]!r}"
                    ),
                    evaluation_ms=(time.monotonic() - started) * 1000.0,
                )

            try:
                body = response.json()
            except ValueError as exc:
                self._record_failure()
                return OpaDecision(
                    allowed=False,
                    raw_result=None,
                    source="fail_closed",
                    error=f"malformed JSON from OPA: {exc}",
                    evaluation_ms=(time.monotonic() - started) * 1000.0,
                )

            if not isinstance(body, dict) or "result" not in body:
                self._record_failure()
                return OpaDecision(
                    allowed=False,
                    raw_result=None,
                    source="fail_closed",
                    error=f"OPA response missing 'result' key: {body!r}",
                    evaluation_ms=(time.monotonic() - started) * 1000.0,
                )

            result = body["result"]
            self._record_success()
            return OpaDecision(
                allowed=bool(result),
                raw_result=result,
                source="opa",
                error=None,
                evaluation_ms=(time.monotonic() - started) * 1000.0,
            )

        # Unreachable in practice (loop always returns), but keeps mypy/lint happy.
        self._record_failure()
        return OpaDecision(
            allowed=False,
            raw_result=None,
            source="fail_closed",
            error=last_error or "unknown failure evaluating OPA policy",
            evaluation_ms=(time.monotonic() - started) * 1000.0,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "OpaClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

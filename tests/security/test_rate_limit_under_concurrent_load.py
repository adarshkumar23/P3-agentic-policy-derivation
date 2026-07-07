# mypy: allow-untyped-defs
"""Confirm `TokenBucketRateLimiter` (`core-side-patch/services/rate_limit.py`)
does not permit token double-spending when driven through the FULL HTTP
stack (`/ai-systems/{id}/guardrails/check`) under real concurrent load from
many threads at once for the SAME org -- not just when `TokenBucketRateLimiter`
is called directly in isolation (already covered, sequentially only, by
`tests/unit/test_rate_limit.py`), and not just sequentially against the HTTP
endpoint (already covered by
`tests/security/test_rate_limit_bypass.py::test_rate_limiter_is_actually_wired_into_check_action`,
which only ever fires two requests, one after another).

Method: configure a `TokenBucketRateLimiter` with a small, known capacity
(e.g. 20) and a deliberately negligible refill rate, then fire a burst of
many concurrent requests (`concurrent.futures.ThreadPoolExecutor`, same
pattern as `tests/stress/test_concurrent_check_action.py`) for one org, all
racing to acquire the same in-process bucket's lock
(`_Bucket.allow`/`self.lock` in `services/rate_limit.py`). The number of
requests that get a non-429 (i.e. 200) response must never exceed the
configured capacity plus whatever could have legitimately refilled during
the run's wall-clock time -- i.e. no thread ever "sees" a token that another
thread already consumed (a classic read-then-write race that an unlocked or
incorrectly-locked bucket would exhibit under concurrency).

`_Bucket.allow()` performs its refill-then-compare-then-decrement sequence
entirely inside `with self.lock:`, so this is expected to hold. These tests
exercise that guarantee through the real endpoint (real FastAPI dependency
resolution, real request parsing, real per-request DB session under the
`api/guardrails.py` `_db_lock` -- see that module's comment on why a single
shared SQLite connection needs its own serialization lock, which is an
unrelated, already-known/expected serialization point, not the thing being
tested here) rather than by calling `TokenBucketRateLimiter.allow()`
directly.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

ORG_A = "org-a"

SAMPLE_OBLIGATIONS = [
    {
        "id": "obl-1",
        "text": "Wire transfers shall not exceed $10,000 per transaction.",
        "jurisdiction": "US",
        "framework": "BSA",
        "citation": "31 CFR 1010",
    },
]

ACTION = {
    "action_id": "act-rl",
    "ai_system_id": "sys-1",
    "organization_id": ORG_A,
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}


def _headers(org_id: str) -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": "user-1", "X-Role": "admin"}


def _build_client(rate_limiter: TokenBucketRateLimiter) -> TestClient:
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    registry.register("sys-1", ORG_A, name="Test AI System")
    client = TestClient(app)

    resp = client.post(
        "/ai-systems/sys-1/guardrails",
        json={
            "organization_id": ORG_A,
            "name": "Wire transfer limit",
            "description": "rate-limit concurrency test guardrail",
            "obligations": SAMPLE_OBLIGATIONS,
        },
        headers=_headers(ORG_A),
    )
    assert resp.status_code == 201, resp.text
    return client


def _fire_burst(client: TestClient, n: int) -> tuple[list[int], float]:
    def _one(i: int) -> int:
        payload = {**ACTION, "action_id": f"act-rl-{i}"}
        resp = client.post(
            "/ai-systems/sys-1/guardrails/check",
            json=payload,
            headers=_headers(ORG_A),
        )
        return resp.status_code

    started = time.monotonic()
    statuses: list[int] = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_one, i) for i in range(n)]
        for fut in as_completed(futures):
            statuses.append(fut.result())
    elapsed = time.monotonic() - started
    return statuses, elapsed


class TestNoDoubleSpendUnderConcurrentBurst:
    """Negligible refill rate, so any successes beyond `capacity` in one
    fast burst can only be explained by a double-spend race, not legitimate
    refill."""

    def test_single_burst_never_exceeds_capacity(self):
        capacity = 20
        # Negligible refill: at 0.0001 tokens/sec, even a multi-second burst
        # could not legitimately add a whole extra token.
        limiter = TokenBucketRateLimiter(capacity=capacity, refill_per_second=0.0001)
        client = _build_client(limiter)

        n = 300
        statuses, elapsed = _fire_burst(client, n)
        print(f"\n[rate-limit-concurrency] {n} concurrent requests, capacity={capacity}, "
              f"took {elapsed:.3f}s wall-clock")

        assert len(statuses) == n
        non_429 = [s for s in statuses if s != 429]
        assert all(s == 200 for s in non_429), (
            f"unexpected non-200/429 statuses: {sorted(set(statuses) - {200, 429})}"
        )

        # The maximum number of tokens that could legitimately have been
        # granted is capacity + (elapsed seconds * refill_per_second),
        # rounded up generously. At refill_per_second=0.0001 this bound is
        # for all practical purposes == capacity.
        legitimate_bound = capacity + max(1, int(elapsed * 0.0001) + 1)
        assert len(non_429) <= legitimate_bound, (
            f"{len(non_429)} requests got a non-429 response against a bucket "
            f"configured with capacity={capacity} and negligible refill -- "
            f"this indicates TOKEN DOUBLE-SPENDING under concurrency "
            f"(legitimate bound was {legitimate_bound})"
        )
        # And, since capacity tokens genuinely start available, the lock
        # must not *lose* grants either (an incorrectly-locked bucket could
        # under-count just as easily as over-count under contention).
        assert len(non_429) == capacity, (
            f"expected exactly {capacity} successful (200) responses out of {n} "
            f"concurrent requests against a fresh bucket with negligible refill, "
            f"got {len(non_429)} -- either double-spending (>capacity) or lost "
            f"grants (<capacity) under concurrency"
        )

    def test_repeated_bursts_never_exceed_capacity_no_flakiness(self):
        """Repeat the single-burst check several times (fresh limiter/client
        each time) to raise confidence that the result above isn't a
        lucky/unlucky one-off given the inherent non-determinism of thread
        scheduling."""
        capacity = 20
        for trial in range(5):
            limiter = TokenBucketRateLimiter(capacity=capacity, refill_per_second=0.0001)
            client = _build_client(limiter)
            statuses, _elapsed = _fire_burst(client, 150)
            non_429 = [s for s in statuses if s == 200]
            assert len(non_429) == capacity, (
                f"trial {trial}: expected exactly {capacity} successful responses, "
                f"got {len(non_429)} -- double-spend or lost-grant race detected"
            )

    def test_massive_concurrency_same_bucket_still_bounded(self):
        """A much larger worker count than capacity, to maximize lock
        contention on the single per-org bucket and give any race the best
        possible chance to manifest."""
        capacity = 20
        limiter = TokenBucketRateLimiter(capacity=capacity, refill_per_second=0.0001)
        client = _build_client(limiter)

        n = 500
        statuses, elapsed = _fire_burst(client, n)
        print(f"\n[rate-limit-concurrency] massive burst: {n} threads, capacity={capacity}, "
              f"took {elapsed:.3f}s wall-clock")

        non_429 = [s for s in statuses if s == 200]
        assert len(non_429) == capacity, (
            f"expected exactly {capacity} successful responses under a 500-thread "
            f"burst against a capacity={capacity} bucket, got {len(non_429)}"
        )


class TestRefillIsBoundedNotDoubleCounted:
    """With a real (non-negligible) refill rate, confirm that a second burst
    after a measured delay grants at most `capacity + elapsed * refill_rate`
    additional tokens beyond what the first burst consumed -- i.e. refill
    accounting isn't itself racy in a way that manufactures extra tokens
    under concurrent access.
    """

    def test_second_burst_after_delay_bounded_by_legitimate_refill(self):
        """Note: each request in this suite goes through the real HTTP
        stack (including a real `opa eval` subprocess call), so a burst of
        many concurrent requests takes non-trivial wall-clock time -- during
        which a non-negligible `refill_per_second` legitimately adds tokens
        mid-burst. The bound used below therefore accounts for the actual
        measured elapsed time of *each* burst (not just the inter-burst
        sleep), so this test only fails if MORE tokens were granted than
        could possibly have legitimately existed given real wall-clock time
        -- a genuine double-spend/over-refill signal, not an artifact of
        subprocess latency.
        """
        capacity = 5
        refill_per_second = 5.0  # fast enough to observe within a short sleep
        limiter = TokenBucketRateLimiter(capacity=capacity, refill_per_second=refill_per_second)
        client = _build_client(limiter)

        # First burst: exhaust the bucket. It starts full (capacity tokens),
        # and may legitimately refill a bit more during its own elapsed
        # wall-clock time (the bucket is being drained AND refilled
        # concurrently), capped at `capacity` at any instant.
        first_statuses, elapsed1 = _fire_burst(client, 50)
        first_successes = sum(1 for s in first_statuses if s == 200)
        first_bound = capacity + elapsed1 * refill_per_second + 1  # +1 slack for scheduling jitter
        print(
            f"\n[rate-limit-concurrency] first burst took {elapsed1:.3f}s, "
            f"{first_successes} successes (bound {first_bound:.2f})"
        )
        assert first_successes >= capacity, (
            f"first burst should grant at least the full {capacity}-token "
            f"starting capacity, got {first_successes} -- possible lost grant"
        )
        assert first_successes <= first_bound, (
            f"first burst granted {first_successes} tokens, exceeding the "
            f"legitimate bound of {first_bound:.2f} given {elapsed1:.3f}s elapsed "
            f"at {refill_per_second} tokens/sec -- indicates double-spending "
            f"under concurrency"
        )

        # Sleep a known, short interval, then fire a second burst. The
        # legitimate bound for the second burst is capacity (the bucket is
        # capped) plus whatever refilled during the sleep AND during the
        # second burst's own elapsed time.
        sleep_s = 0.5
        time.sleep(sleep_s)

        second_statuses, elapsed2 = _fire_burst(client, 50)
        second_successes = sum(1 for s in second_statuses if s == 200)
        max_possible_refill = capacity + (sleep_s + elapsed2) * refill_per_second + 1
        print(
            f"\n[rate-limit-concurrency] second burst after {sleep_s}s sleep + "
            f"{elapsed2:.3f}s own elapsed: {second_successes} successes "
            f"(bound {max_possible_refill:.2f})"
        )

        assert second_successes <= max_possible_refill, (
            f"second burst granted {second_successes} tokens, exceeding the "
            f"legitimate refill bound of {max_possible_refill:.2f} for a "
            f"{sleep_s}s delay + {elapsed2:.3f}s own elapsed at "
            f"{refill_per_second} tokens/sec -- indicates double-spending/"
            f"over-refill under concurrency"
        )

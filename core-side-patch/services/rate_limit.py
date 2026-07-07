"""Per-organization token-bucket rate limiting for the check-action endpoint.

This module is deliberately dependency-free (no Redis, no FastAPI) so it can
be imported and profiled in isolation. `check-action` sits on the hot path of
every agent action for every tenant, so the overhead this module adds on top
of whatever OPA itself costs needs to be kept to microseconds, not
milliseconds. See ``tests/unit/test_rate_limit.py`` for a benchmark that
measures and asserts this.

Deployment note: buckets live in a plain in-process ``dict`` guarded by
locks. That is fine for a single-process deployment, but a multi-process or
multi-instance deployment (e.g. several uvicorn workers, or several replicas
behind a load balancer) would each get their *own* independent bucket per
org, effectively multiplying the configured rate limit by the number of
processes/instances. If/when this endpoint is scaled horizontally, this
in-memory limiter should be swapped for one backed by a shared store (e.g.
Redis with a Lua script or ``INCR``+``EXPIRE``, or an equivalent atomic
counter service). This module is the single-process baseline.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Dict


class RateLimitExceeded(Exception):
    """Raised when an org has exhausted its rate-limit budget.

    Intentionally framework-agnostic: this module does not import FastAPI.
    The caller (e.g. a FastAPI dependency wired up elsewhere) is expected to
    catch this and translate it into an HTTP 429 response.
    """

    def __init__(self, org_id: str):
        super().__init__(f"rate limit exceeded for org_id={org_id!r}")
        self.org_id = org_id


class _Bucket:
    """A single token bucket for one organization.

    Uses its own lock rather than a single global lock shared across all
    buckets. Contention analysis: with one global lock, every org's calls
    serialize against every other org's calls even though their buckets are
    logically independent -- under concurrent load from many tenants this
    becomes a single hot lock contended by all traffic to the endpoint. With
    a per-bucket lock, only calls for the *same* org_id ever contend, which
    matches the natural sharding of the workload (per-tenant traffic) and
    keeps lock hold times and contention proportional to a single tenant's
    call rate rather than the aggregate call rate across all tenants. The
    critical section itself is tiny (a subtraction and a comparison), so the
    lock overhead dominates, and minimizing *how often* threads contend for
    the *same* lock is what matters here.
    """

    __slots__ = ("capacity", "refill_per_second", "tokens", "last_refill", "lock")

    def __init__(self, capacity: int, refill_per_second: float):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            if elapsed > 0:
                self.tokens = min(
                    self.capacity, self.tokens + elapsed * self.refill_per_second
                )
                self.last_refill = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


class TokenBucketRateLimiter:
    """A simple, dependency-free, in-process, per-org token-bucket limiter.

    Buckets are created lazily per ``org_id`` the first time ``allow`` is
    called for that org, and then reused (not recreated) on every subsequent
    call. The bucket registry is a plain ``dict[str, _Bucket]`` guarded by a
    lock only for the (rare) creation path; the hot path of consuming a
    token from an already-created bucket does not touch the registry lock.

    This is an in-memory, single-process limiter. A multi-process or
    multi-instance deployment would need a shared store (e.g. Redis) so all
    processes agree on one bucket per org -- see module docstring.
    """

    def __init__(self, capacity: int, refill_per_second: float):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._buckets: Dict[str, _Bucket] = {}
        self._registry_lock = threading.Lock()

    def _get_bucket(self, org_id: str) -> _Bucket:
        bucket = self._buckets.get(org_id)
        if bucket is not None:
            return bucket
        with self._registry_lock:
            bucket = self._buckets.get(org_id)
            if bucket is None:
                bucket = _Bucket(self.capacity, self.refill_per_second)
                self._buckets[org_id] = bucket
            return bucket

    def allow(self, org_id: str) -> bool:
        """Consume a token for ``org_id`` if available.

        Returns True if the call is allowed (a token was consumed), False if
        the org has exhausted its budget.
        """
        return self._get_bucket(org_id).allow()


def rate_limit_dependency(
    limiter: TokenBucketRateLimiter, org_id_getter: Callable[..., str]
) -> Callable[..., None]:
    """Build a small callable usable as a FastAPI ``Depends()`` later.

    ``org_id_getter`` is called with whatever arguments the eventual
    framework wiring passes through (e.g. it might itself be a FastAPI
    dependency that extracts org_id from the request/auth context); this
    module does not know or care about that -- it just needs something
    callable that returns an org_id string.

    The returned callable raises :class:`RateLimitExceeded` when the org has
    exhausted its budget, which the caller (H's workstream) can map to an
    HTTP 429 response without this module importing FastAPI.
    """

    def _dependency(*args, **kwargs) -> None:
        org_id = org_id_getter(*args, **kwargs)
        if not limiter.allow(org_id):
            raise RateLimitExceeded(org_id)

    return _dependency

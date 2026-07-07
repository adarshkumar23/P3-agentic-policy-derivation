# mypy: allow-untyped-defs
"""Focused regression test for finding #2 in ASSUMPTIONS.md's "Concurrency
findings from Workstream N (stress testing) and follow-up fixes" section.

What regressed before: `create_app(...)` in
`core-side-patch/api/guardrails.py` builds its demo persistence layer as
`create_engine("sqlite://", poolclass=StaticPool, connect_args=
{"check_same_thread": False})` -- a single shared DBAPI connection used by
every request. `check_same_thread=False` only disables sqlite3's
thread-affinity check; it does not make concurrent execute/fetch calls on
that one connection from multiple threads safe. Under concurrent
check-action requests this surfaced as corrupted row reads -- observed
concretely as `ValueError: Invalid isoformat string: ''` from an
interleaved cursor fetch. It was fixed by wrapping the `get_db()`
dependency's session lifetime in a module-level `threading.Lock`
(`_db_lock` inside `create_app`), serializing DB access for this demo
in-memory engine.

This test is intentionally narrow -- it is not the full stress battery
(`tests/stress/test_concurrent_check_action.py` already covers realistic
mixed-traffic scenarios in depth). Its only job is to be a small,
unmistakably-named tripwire that reliably reproduces the original failure
signature if the `_db_lock` fix were ever reverted: it fires a large batch
of concurrent check-action requests through the real `create_app(...)`
factory (via `TestClient`, same pattern as the existing stress tests) and
asserts there are zero 5xx responses and zero corrupted-row errors, run in
a loop a few times to make the test itself reliably sensitive to a
reintroduced race rather than only occasionally catching it.
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


def _headers(org_id: str, user_id: str = "user-1", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


SAMPLE_OBLIGATIONS = [
    {
        "id": "obl-1",
        "text": "Wire transfers shall not exceed $10,000 per transaction.",
        "jurisdiction": "US",
        "framework": "BSA",
        "citation": "31 CFR 1010",
    },
]

ALLOWED_ACTION = {
    "action_id": "regression-act-allow",
    "ai_system_id": "sys-1",
    "organization_id": ORG_A,
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}


def _build_client() -> TestClient:
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    rate_limiter = TokenBucketRateLimiter(capacity=100_000, refill_per_second=100_000.0)
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    registry.register("sys-1", ORG_A, name="Test AI System")
    client = TestClient(app)

    resp = client.post(
        "/ai-systems/sys-1/guardrails",
        json={
            "organization_id": ORG_A,
            "name": "Wire transfer limit",
            "description": "regression test guardrail",
            "obligations": SAMPLE_OBLIGATIONS,
        },
        headers=_headers(ORG_A),
    )
    assert resp.status_code == 201, resp.text
    return client


def _fire_batch(client: TestClient, n: int) -> list[tuple[int, str | None]]:
    """Fire `n` concurrent check-action calls. Returns a list of
    (status_code, error_repr_or_None) pairs. Any exception raised while
    making the request or parsing the response body is captured as the
    "corrupted row" signature rather than allowed to blow up the test
    thread silently.
    """

    def _one(i: int):
        payload = {**ALLOWED_ACTION, "action_id": f"{ALLOWED_ACTION['action_id']}-{i}"}
        try:
            resp = client.post(
                "/ai-systems/sys-1/guardrails/check",
                json=payload,
                headers=_headers(ORG_A),
            )
            # Force full body parsing now (this is where the original
            # corrupted-row ValueError surfaced, via a datetime field
            # deserialized from an interleaved cursor fetch).
            resp.json()
            return resp.status_code, None
        except Exception as exc:  # noqa: BLE001 - deliberately broad: this is exactly what we're hunting for
            return 599, f"{type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_one, i) for i in range(n)]
        return [fut.result() for fut in as_completed(futures)]


def test_concurrent_check_action_never_corrupts_shared_sqlite_connection():
    """Regression test for the shared-SQLite-StaticPool-connection race
    (ASSUMPTIONS.md, "Concurrency findings ..." -> finding #2).

    Drives 100+ concurrent check-action requests through the real
    `create_app(...)` factory (same shared `sqlite://` + `StaticPool`
    engine as production demo wiring) several times in a row, and asserts:
    - zero 5xx responses
    - zero corrupted-row errors (the original failure signature was a
      `ValueError: Invalid isoformat string: ''` raised while
      deserializing a row read via an interleaved cursor fetch on the one
      shared DBAPI connection)

    Run in a loop across multiple fresh clients/engines because this race
    is timing-sensitive; looping makes this regression test itself
    reliably sensitive to a reintroduced bug (e.g. if `_db_lock` in
    `create_app`'s `get_db()` dependency were removed or narrowed) rather
    than only occasionally catching it.
    """
    n_per_batch = 120
    n_iterations = 4

    all_errors: list[str] = []
    all_non_200: list[int] = []

    for iteration in range(n_iterations):
        client = _build_client()
        results = _fire_batch(client, n_per_batch)

        for status, error in results:
            if error is not None:
                all_errors.append(f"iteration {iteration}: {error}")
            if status != 200:
                all_non_200.append(status)

    assert not all_errors, (
        "corrupted-row / exception signature reproduced during concurrent "
        "check-action requests -- this is exactly the shared-SQLite-"
        "StaticPool-connection race documented in ASSUMPTIONS.md's "
        "'Concurrency findings from Workstream N (stress testing) and "
        "follow-up fixes' section (finding #2): "
        "core-side-patch/api/guardrails.py's create_app(...) shares one "
        "DBAPI connection (sqlite:// + StaticPool) across all requests, and "
        "concurrent execute/fetch calls on it without the get_db() "
        "dependency's _db_lock corrupt row reads. Errors observed: "
        f"{all_errors}"
    )
    assert not all_non_200, (
        f"non-200 status codes observed under concurrent load: {sorted(set(all_non_200))} -- "
        "expected zero 5xx (or any non-200) responses across the whole batch"
    )

# mypy: allow-untyped-defs
"""Stress test: sustained high-throughput check-action calls interleaved
across MANY DISTINCT `ai_system_id`s (not one shared guardrail like
`test_concurrent_check_action.py`).

This exercises a different axis of concurrency: many distinct
`AiPolicyGuardrail` rows (one per `ai_system_id`), each looked up by its own
DB query, each backing its own `CompliVibePolicyProvider` instance (a fresh
one per request, per `api/guardrails.py`'s `check_action` handler) and its
own slice of the in-memory receipt store -- fired as one big interleaved
burst rather than N calls all hitting the same guardrail/provider/receipt
list.

Latency measurement honesty note (read before interpreting the numbers in
`STRESS_TEST_RESULTS.md`): this repository's test harness evaluates every
check-action call via `subprocess.run(["opa", "eval", ...])` against the
vendored `opa` CLI (see `api/guardrails.py`'s `_local_opa_eval_handler`),
*not* a live, already-running OPA HTTP server. Every one of the latency
numbers this test records therefore includes real process-spawn overhead
(fork/exec, temp-file write, Python subprocess plumbing) on top of the
actual Rego evaluation -- overhead a real deployment (talking to a
long-running OPA server process over a kept-alive HTTP connection) would
not pay per call. This test states plainly, using its own measured numbers,
whether any sub-millisecond latency target is met at THIS HARNESS'S OWN
level (subprocess overhead included) or only once that overhead is
excluded -- it does not paper over the difference.
"""

from __future__ import annotations

import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

ORGS = ["org-multi-a", "org-multi-b", "org-multi-c"]
N_AI_SYSTEMS = 15  # spread across the 3 orgs above


def _headers(org_id: str, user_id: str = "user-1", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


def _obligations_for(limit: float) -> list[dict]:
    return [
        {
            "id": f"obl-limit-{int(limit)}",
            "text": f"Wire transfers shall not exceed ${limit:,.0f} per transaction.",
            "jurisdiction": "US",
            "framework": "BSA",
            "citation": "31 CFR 1010",
        }
    ]


def _build_multi_system_client() -> tuple[TestClient, list[tuple[str, str, float]]]:
    """Stand up one app with `N_AI_SYSTEMS` distinct ai_system_ids spread
    across `ORGS`, each with its own compiled guardrail with a distinct
    per-system spend limit (so a bug that accidentally shares state between
    two systems' guardrails/providers would show up as a wrong-limit
    decision, not just a generic 5xx).

    Returns (client, [(ai_system_id, org_id, limit), ...]).
    """
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    rate_limiter = TokenBucketRateLimiter(capacity=1_000_000, refill_per_second=1_000_000.0)
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    client = TestClient(app)

    systems: list[tuple[str, str, float]] = []
    for i in range(N_AI_SYSTEMS):
        org_id = ORGS[i % len(ORGS)]
        ai_system_id = f"sys-multi-{i}"
        limit = 1000.0 * (i + 1)  # distinct limit per system: 1000, 2000, ...
        registry.register(ai_system_id, org_id, name=f"Multi Test System {i}")

        resp = client.post(
            f"/ai-systems/{ai_system_id}/guardrails",
            json={
                "organization_id": org_id,
                "name": f"Wire transfer limit {i}",
                "description": "high-throughput stress test guardrail",
                "obligations": _obligations_for(limit),
            },
            headers=_headers(org_id),
        )
        assert resp.status_code == 201, resp.text
        systems.append((ai_system_id, org_id, limit))

    return client, systems


def _percentiles(durations_s: list[float]) -> dict[str, float]:
    """Compute p50/p95/p99 (in milliseconds) from a list of durations in
    seconds, via manual sorting (robust for any sample size, unlike
    `statistics.quantiles` at very small n).
    """
    ordered = sorted(durations_s)
    n = len(ordered)

    def _pct(p: float) -> float:
        if n == 1:
            return ordered[0] * 1000.0
        idx = min(n - 1, int(round(p / 100.0 * (n - 1))))
        return ordered[idx] * 1000.0

    return {"p50_ms": _pct(50), "p95_ms": _pct(95), "p99_ms": _pct(99)}


class TestHighThroughputMultiAiSystem:
    def test_sustained_burst_across_many_distinct_ai_systems(self):
        client, systems = _build_multi_system_client()

        total_requests = 750
        # Each request goes to a system chosen round-robin, with an amount
        # that is deterministically either just under or just over that
        # system's own configured limit, so we can assert the *correct*
        # per-system decision came back -- not just "a decision".
        jobs = []
        for i in range(total_requests):
            ai_system_id, org_id, limit = systems[i % len(systems)]
            allow = (i % 2 == 0)
            amount = limit * 0.5 if allow else limit * 2.0
            jobs.append((i, ai_system_id, org_id, amount, allow))

        durations: list[float] = []
        results: list[tuple[int, int, bool | None, bool]] = []

        def _one(job):
            i, ai_system_id, org_id, amount, expected_allow = job
            payload = {
                "action_id": f"act-multi-{i}",
                "ai_system_id": ai_system_id,
                "organization_id": org_id,
                "action_type": "wire_transfer",
                "amount": amount,
                "currency": "USD",
                "timestamp": "2026-01-01T00:00:00Z",
            }
            started = time.perf_counter()
            resp = client.post(
                f"/ai-systems/{ai_system_id}/guardrails/check",
                json=payload,
                headers=_headers(org_id),
            )
            elapsed = time.perf_counter() - started
            allowed = resp.json().get("allowed") if resp.status_code == 200 else None
            return i, resp.status_code, allowed, expected_allow, elapsed

        wall_started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = [pool.submit(_one, job) for job in jobs]
            for fut in as_completed(futures):
                i, status, allowed, expected_allow, elapsed = fut.result()
                durations.append(elapsed)
                results.append((i, status, allowed, expected_allow))
        wall_elapsed = time.perf_counter() - wall_started

        # -- correctness: no 5xx, ever; the right per-system decision came back
        statuses = [status for _, status, _, _ in results]
        assert all(200 <= s < 300 for s in statuses), (
            f"non-2xx status seen in high-throughput multi-ai-system burst: "
            f"{sorted(set(statuses))}"
        )
        mismatches = [
            (i, allowed, expected) for i, _, allowed, expected in results if allowed != expected
        ]
        assert not mismatches, (
            f"{len(mismatches)} of {total_requests} requests got the wrong allow/deny "
            f"decision for their ai_system_id's configured limit -- possible cross-system "
            f"state bleed under concurrency; sample: {mismatches[:5]}"
        )

        pct = _percentiles(durations)
        throughput_rps = total_requests / wall_elapsed

        print(
            f"\n[stress] {total_requests} requests across {N_AI_SYSTEMS} distinct "
            f"ai_system_ids ({len(ORGS)} orgs), 32 workers:\n"
            f"  wall clock: {wall_elapsed:.3f}s\n"
            f"  throughput: {throughput_rps:.1f} req/s\n"
            f"  per-request latency (subprocess-per-call opa eval INCLUDED): "
            f"p50={pct['p50_ms']:.3f}ms p95={pct['p95_ms']:.3f}ms p99={pct['p99_ms']:.3f}ms\n"
            f"  NOTE: this harness shells out to `opa eval` via subprocess per call "
            f"(see api/guardrails.py's _local_opa_eval_handler) -- these numbers include "
            f"that subprocess-spawn overhead, which a real deployment talking to a "
            f"long-running OPA server process would not pay. At THIS harness's own level, "
            f"the sub-millisecond target is {'MET' if pct['p50_ms'] < 1.0 else 'NOT met'} "
            f"(p50={pct['p50_ms']:.3f}ms); it is only meaningful as a production latency "
            f"claim once subprocess overhead is excluded."
        )

        # Sanity bound only -- generous enough to never be a source of
        # flakiness under shared-machine contention (see task brief), tight
        # enough to catch a genuine hang/regression.
        assert pct["p99_ms"] < 5000.0, f"p99 latency unexpectedly high: {pct['p99_ms']:.1f}ms"
        assert throughput_rps > 1.0, f"throughput implausibly low: {throughput_rps:.2f} req/s"

# mypy: allow-untyped-defs
"""Confirm org-scoping and per-org Rego package isolation hold under
CONCURRENT cross-org load through the full HTTP check-action stack -- not
just sequentially.

`tests/unit/test_tenant_isolation.py` already proves package isolation with
sequential `opa eval` calls directly against a bundle directory.
`tests/unit/test_guardrail_api.py::TestCheckAction::test_cross_org_404` (and
siblings) already prove sequential cross-org 404s through the HTTP API. This
module drives the SAME kind of proof through the real
`/ai-systems/{id}/guardrails/check` endpoint, but with many threads racing
at once across multiple distinct orgs (with genuinely different financial
limits, so a leaked/contaminated evaluation is observable as a wrong
allow/deny, not just a wrong id), plus concurrent cross-org access attempts
interleaved with legitimate same-org traffic.

Three orgs, three distinct AI systems, three distinct compiled Rego
packages, three distinct (and strictly increasing) financial limits:

    org-a -> sys-org-a -> limit $10,000  (strictest)
    org-b -> sys-org-b -> limit $50,000
    org-c -> sys-org-c -> limit $100,000 (most permissive)

For each org we pick two action amounts that straddle *that org's own*
limit (`limit - 1000` expected ALLOW, `limit + 1000` expected DENY). Many of
these straddling amounts also happen to be on the wrong side of one of the
*other* orgs' limits (e.g. org-b's "own allow" amount of $49,000 would be a
DENY under org-a's $10,000 limit, and org-c's "own allow" amount of $99,000
would be a DENY under both org-a's and org-b's limits) -- so any thread
whose response reflects a DIFFERENT org's limit than the one it actually
requested is directly observable as a wrong allow/deny value, not just a
coincidence.
"""

from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

ORGS = ["org-a", "org-b", "org-c"]
AI_SYSTEM_FOR_ORG = {"org-a": "sys-org-a", "org-b": "sys-org-b", "org-c": "sys-org-c"}
LIMIT_FOR_ORG = {"org-a": 10_000, "org-b": 50_000, "org-c": 100_000}


def _headers(org_id: str) -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": "user-1", "X-Role": "admin"}


def _obligations_for_limit(limit: int) -> list[dict]:
    return [
        {
            "id": f"obl-limit-{limit}",
            "text": f"A single transaction shall not exceed ${limit} per transaction.",
            "jurisdiction": "US",
            "framework": "BSA/AML",
            "citation": "31 CFR 1010",
        }
    ]


def _build_client() -> TestClient:
    """Stand up one app with all three orgs' AI systems + guardrails
    registered, generously rate-limited so concurrency assertions are about
    org-isolation correctness, not about hitting the (separately-tested)
    429 path.
    """
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    rate_limiter = TokenBucketRateLimiter(capacity=1_000_000, refill_per_second=1_000_000.0)
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)

    client = TestClient(app)
    for org_id in ORGS:
        ai_system_id = AI_SYSTEM_FOR_ORG[org_id]
        registry.register(ai_system_id, org_id, name=f"Test AI System for {org_id}")
        resp = client.post(
            f"/ai-systems/{ai_system_id}/guardrails",
            json={
                "organization_id": org_id,
                "name": f"Financial limit for {org_id}",
                "description": "concurrent cross-org isolation test guardrail",
                "obligations": _obligations_for_limit(LIMIT_FOR_ORG[org_id]),
            },
            headers=_headers(org_id),
        )
        assert resp.status_code == 201, resp.text
    return client


def _check_action(client: TestClient, *, org_id: str, ai_system_id: str, amount: float, action_id: str):
    return client.post(
        f"/ai-systems/{ai_system_id}/guardrails/check",
        json={
            "action_id": action_id,
            "ai_system_id": ai_system_id,
            "organization_id": org_id,
            "action_type": "wire_transfer",
            "amount": amount,
            "currency": "USD",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        headers=_headers(org_id),
    )


class TestConcurrentInterleavedOrgsNoLimitBleed:
    def test_concurrent_straddling_amounts_across_orgs_always_correct(self):
        """Many threads, each randomly picking one of the three orgs and one
        of that org's two straddling amounts (own-limit-minus-1000 expected
        allow, own-limit-plus-1000 expected deny), fired all at once. Every
        single response must reflect THAT request's own org's limit -- never
        a different (stricter or more permissive) org's limit leaking in.
        """
        client = _build_client()
        rng = random.Random(1234)

        n = 300
        jobs = []
        for i in range(n):
            org_id = rng.choice(ORGS)
            limit = LIMIT_FOR_ORG[org_id]
            under = rng.choice([True, False])
            amount = float(limit - 1000) if under else float(limit + 1000)
            jobs.append((i, org_id, amount, under))

        def _one(job):
            i, org_id, amount, under = job
            resp = _check_action(
                client,
                org_id=org_id,
                ai_system_id=AI_SYSTEM_FOR_ORG[org_id],
                amount=amount,
                action_id=f"act-{org_id}-{i}",
            )
            return i, org_id, amount, under, resp.status_code, (
                resp.json().get("allowed") if resp.status_code == 200 else None
            )

        started = time.monotonic()
        results = []
        with ThreadPoolExecutor(max_workers=40) as pool:
            futures = [pool.submit(_one, job) for job in jobs]
            for fut in as_completed(futures):
                results.append(fut.result())
        elapsed = time.monotonic() - started
        print(f"\n[cross-org-concurrency] {n} interleaved requests across {len(ORGS)} orgs "
              f"took {elapsed:.3f}s wall-clock")

        assert len(results) == n
        contamination = []
        for i, org_id, amount, under, status, allowed in results:
            expected_allowed = under  # amount = limit - 1000 -> allow; limit + 1000 -> deny
            if status != 200:
                contamination.append((i, org_id, amount, "non-200 status", status))
                continue
            if allowed is not expected_allowed:
                contamination.append((i, org_id, amount, "expected", expected_allowed, "got", allowed))

        assert not contamination, (
            f"cross-org contamination or unexpected status detected under concurrent "
            f"load: {contamination}"
        )

    def test_concurrent_same_amount_different_orgs_diverges_correctly(self):
        """Fire the SAME action amount ($30,000) at all three orgs
        concurrently, many times over, interleaved. $30,000 must be DENIED
        under org-a's $10,000 limit but ALLOWED under org-b's $50,000 and
        org-c's $100,000 limits -- every single response, every single time,
        regardless of thread interleaving.
        """
        client = _build_client()
        amount = 30_000.0
        expected = {"org-a": False, "org-b": True, "org-c": True}

        n_per_org = 40
        jobs = [(org_id, i) for org_id in ORGS for i in range(n_per_org)]
        random.Random(99).shuffle(jobs)

        def _one(job):
            org_id, i = job
            resp = _check_action(
                client,
                org_id=org_id,
                ai_system_id=AI_SYSTEM_FOR_ORG[org_id],
                amount=amount,
                action_id=f"act-same-amount-{org_id}-{i}",
            )
            return org_id, resp.status_code, (
                resp.json().get("allowed") if resp.status_code == 200 else None
            )

        results = []
        with ThreadPoolExecutor(max_workers=30) as pool:
            futures = [pool.submit(_one, job) for job in jobs]
            for fut in as_completed(futures):
                results.append(fut.result())

        assert len(results) == len(jobs)
        for org_id, status, allowed in results:
            assert status == 200, f"org {org_id} got non-200 status {status}"
            assert allowed is expected[org_id], (
                f"org {org_id} (amount=${amount:.0f}) expected allowed={expected[org_id]} "
                f"but got allowed={allowed} -- cross-org limit contamination under "
                f"concurrent load"
            )


class TestConcurrentCrossOrgAccessAttemptsAlways404:
    def test_concurrent_cross_org_attempts_interleaved_with_legitimate_traffic(self):
        """Fire concurrent cross-org access attempts (org-a's credentials
        against org-b's/org-c's ai_system_id, and so on for every ordered
        pair) simultaneously with a stream of legitimate same-org requests.
        Every cross-org attempt must still get 404, and every legitimate
        request must still get its own org's correct allow/deny -- even
        while both classes of request are in flight at the same time.
        """
        client = _build_client()
        rng = random.Random(42)

        jobs = []
        # Cross-org attempts: every ordered pair of distinct orgs, repeated
        # several times to increase the chance of overlapping in-flight
        # execution with legitimate traffic.
        for _rep in range(20):
            for org_id in ORGS:
                for other_org in ORGS:
                    if other_org == org_id:
                        continue
                    jobs.append(("cross", org_id, AI_SYSTEM_FOR_ORG[other_org]))

        # Legitimate same-org traffic, interleaved.
        for i in range(120):
            org_id = rng.choice(ORGS)
            jobs.append(("legit", org_id, AI_SYSTEM_FOR_ORG[org_id]))

        rng.shuffle(jobs)

        def _one(job, idx):
            kind, org_id, ai_system_id = job
            limit = LIMIT_FOR_ORG[org_id]
            amount = float(limit - 1000)  # own-limit-allow amount when legit
            resp = _check_action(
                client,
                org_id=org_id,
                ai_system_id=ai_system_id,
                amount=amount,
                action_id=f"act-{kind}-{org_id}-{ai_system_id}-{idx}",
            )
            return kind, org_id, ai_system_id, resp.status_code, (
                resp.json().get("allowed") if resp.status_code == 200 else None
            )

        results = []
        with ThreadPoolExecutor(max_workers=40) as pool:
            futures = [pool.submit(_one, job, idx) for idx, job in enumerate(jobs)]
            for fut in as_completed(futures):
                results.append(fut.result())

        assert len(results) == len(jobs)

        cross_failures = [
            r for r in results if r[0] == "cross" and r[3] != 404
        ]
        assert not cross_failures, (
            f"found cross-org access attempt(s) that did NOT get 404 under "
            f"concurrent load -- tenant isolation bypass: {cross_failures}"
        )

        legit_failures = [
            r for r in results if r[0] == "legit" and (r[3] != 200 or r[4] is not True)
        ]
        assert not legit_failures, (
            f"legitimate same-org request(s) failed or got wrong decision while "
            f"cross-org attempts were in flight concurrently: {legit_failures}"
        )

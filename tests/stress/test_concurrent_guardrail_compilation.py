# mypy: allow-untyped-defs
"""Stress test: multiple guardrails being CREATED and RECOMPILED for the
SAME organization simultaneously -- a different DB-concurrency axis than
`tests/stress/test_concurrent_check_action.py` (which hammers
read/decision-path concurrency on ONE already-created guardrail) and
`tests/stress/test_receipt_chain_concurrency.py` (which is about the
in-process receipt-hash chain, not the DB at all).

This exercises concurrent WRITES across MULTIPLE distinct
`ai_policy_guardrails` rows sharing one organization and one `StaticPool`
sqlite engine (see `api/guardrails.py`'s `create_app()` -- `StaticPool` over
`sqlite://` means every `SessionLocal()` shares one single underlying DBAPI
connection, serialized by that module's own `_db_lock`, already fixed for a
documented prior concurrency bug). The specific worry this test targets: a
concurrent create/compile could interleave in a way that persists guardrail
A's compiled Rego alongside guardrail B's provenance (`source_obligation_ids`
/ `constraint_spec_json`), i.e. cross-guardrail data corruption, rather than
each row staying internally self-consistent.

To make cross-contamination detectable rather than just "did it 500", every
guardrail in this test is derived from an obligation with a distinct,
same-digit-count financial limit (so one guardrail's limit string can never
be an accidental substring of another's -- e.g. 100000 vs 1000000 would
collide as substrings, so all limits here are held to the same digit count),
and the test asserts each guardrail's persisted `rego_policy` contains
*only* its own limit and *only* its own `source_obligation_ids`.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi.testclient import TestClient

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.rate_limit import TokenBucketRateLimiter

ORG_A = "org-concurrent-compile"

N_GUARDRAILS = 16
_BASE_LIMIT = 100_000  # 6 digits; step keeps every limit 6 digits, no prefix collisions
_STEP = 37


def _headers(org_id: str = ORG_A, user_id: str = "user-1", role: str = "admin") -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": user_id, "X-Role": role}


def _limit_for(i: int) -> int:
    return _BASE_LIMIT + i * _STEP  # e.g. 100000, 100037, 100074, ... all 6 digits


def _obligations_for(i: int) -> list[dict]:
    limit = _limit_for(i)
    return [
        {
            "id": f"obl-concurrent-{i}",
            "text": f"Wire transfers shall not exceed ${limit} per transaction.",
            "jurisdiction": "US",
            "framework": "BSA",
            "citation": "31 CFR 1010",
        }
    ]


def _build_app_with_registry() -> tuple[TestClient, InMemoryAiSystemRegistry]:
    registry = InMemoryAiSystemRegistry()
    audit = AuditService()
    rate_limiter = TokenBucketRateLimiter(capacity=1_000_000, refill_per_second=1_000_000.0)
    app = create_app(ai_system_registry=registry, audit_service=audit, rate_limiter=rate_limiter)
    for i in range(N_GUARDRAILS):
        registry.register(f"sys-cc-{i}", ORG_A, name=f"Concurrent Compile System {i}")
    return TestClient(app), registry


class TestConcurrentGuardrailCompilation:
    def test_concurrent_creates_across_many_guardrails_same_org_no_cross_contamination(self):
        client, _registry = _build_app_with_registry()

        def _create(i: int):
            resp = client.post(
                f"/ai-systems/sys-cc-{i}/guardrails",
                json={
                    "organization_id": ORG_A,
                    "name": f"concurrent-guardrail-{i}",
                    "obligations": _obligations_for(i),
                },
                headers=_headers(),
            )
            return i, resp

        with ThreadPoolExecutor(max_workers=N_GUARDRAILS) as pool:
            futures = [pool.submit(_create, i) for i in range(N_GUARDRAILS)]
            results = [fut.result() for fut in as_completed(futures)]

        statuses = [resp.status_code for _, resp in results]
        assert all(s == 201 for s in statuses), f"non-201 statuses under concurrent create: {sorted(set(statuses))}"

        # Every guardrail id must be unique -- no accidental row reuse/overwrite.
        bodies = {i: resp.json() for i, resp in results}
        ids = [body["id"] for body in bodies.values()]
        assert len(set(ids)) == N_GUARDRAILS, f"expected {N_GUARDRAILS} unique guardrail ids, got {len(set(ids))}"

        own_limit_strs = {i: f'"max_amount": {float(_limit_for(i))}' for i in range(N_GUARDRAILS)}

        for i, body in bodies.items():
            expected_obl_id = f"obl-concurrent-{i}"
            assert body["ai_system_id"] == f"sys-cc-{i}", (
                f"guardrail for index {i} has wrong ai_system_id {body['ai_system_id']!r} -- "
                "possible cross-request/cross-guardrail data bleed under concurrent writes"
            )
            assert body["source_obligation_ids"] == [expected_obl_id], (
                f"guardrail {i}'s persisted source_obligation_ids {body['source_obligation_ids']!r} "
                f"does not match its own submitted obligation id {expected_obl_id!r} -- provenance "
                "corruption under concurrent DB writes"
            )
            assert own_limit_strs[i] in body["rego_policy"], (
                f"guardrail {i}'s persisted rego_policy does not contain its own limit "
                f"({own_limit_strs[i]!r}) -- rego/provenance mismatch under concurrent writes"
            )
            # No OTHER guardrail's limit leaked into this one's compiled Rego.
            for j, other_limit_str in own_limit_strs.items():
                if j == i:
                    continue
                assert other_limit_str not in body["rego_policy"], (
                    f"guardrail {i}'s rego_policy unexpectedly contains guardrail {j}'s limit "
                    f"({other_limit_str!r}) -- cross-guardrail Rego contamination under "
                    "concurrent creation"
                )

        print(
            f"\n[stress] {N_GUARDRAILS} guardrails created concurrently for the same org "
            f"({ORG_A}): all {N_GUARDRAILS} persisted rows independently verified "
            f"self-consistent (own rego_policy <-> own source_obligation_ids <-> own "
            f"ai_system_id), zero cross-guardrail contamination detected."
        )

    def test_concurrent_recompiles_of_many_guardrails_same_org_stay_consistent(self):
        """After the initial concurrent creates, fire concurrent
        `compile-rego` calls -- multiple recompile requests per guardrail,
        interleaved across all guardrails at once -- and confirm every
        guardrail's *final* persisted state is still internally consistent
        (own rego <-> own provenance), and that recompiling with the
        guardrail's own existing obligation set is idempotent under
        concurrency (every recompile of the same guardrail with the same
        obligations produces the same Rego text).
        """
        client, _registry = _build_app_with_registry()

        created = {}
        for i in range(N_GUARDRAILS):
            resp = client.post(
                f"/ai-systems/sys-cc-{i}/guardrails",
                json={
                    "organization_id": ORG_A,
                    "name": f"concurrent-guardrail-recompile-{i}",
                    "obligations": _obligations_for(i),
                },
                headers=_headers(),
            )
            assert resp.status_code == 201, resp.text
            created[i] = resp.json()

        # 3 concurrent recompile calls per guardrail, all interleaved into one burst.
        jobs = [i for i in range(N_GUARDRAILS) for _ in range(3)]

        def _recompile(i: int):
            resp = client.post(
                f"/ai-guardrails/{created[i]['id']}/compile-rego",
                json={"obligations": _obligations_for(i)},
                headers=_headers(),
            )
            return i, resp

        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futures = [pool.submit(_recompile, i) for i in jobs]
            results = [fut.result() for fut in as_completed(futures)]

        statuses = [resp.status_code for _, resp in results]
        assert all(s == 200 for s in statuses), f"non-200 statuses under concurrent recompile: {sorted(set(statuses))}"

        own_limit_strs = {i: f'"max_amount": {float(_limit_for(i))}' for i in range(N_GUARDRAILS)}

        # Group results by guardrail index and confirm every recompile
        # response for a given guardrail returned the exact same Rego text
        # (idempotent under concurrency) and its own limit only.
        by_index: dict[int, list[dict]] = {}
        for i, resp in results:
            by_index.setdefault(i, []).append(resp.json())

        for i, bodies in by_index.items():
            rego_texts = {b["rego_policy"] for b in bodies}
            assert len(rego_texts) == 1, (
                f"guardrail {i}'s concurrent recompiles produced {len(rego_texts)} distinct "
                f"rego_policy texts instead of one consistent result -- non-idempotent/racy "
                "recompile under concurrency"
            )
            rego_text = next(iter(rego_texts))
            assert own_limit_strs[i] in rego_text
            for j, other_limit_str in own_limit_strs.items():
                if j != i:
                    assert other_limit_str not in rego_text, (
                        f"guardrail {i}'s recompiled rego_policy leaked guardrail {j}'s limit"
                    )
            for b in bodies:
                assert b["source_obligation_ids"] == [f"obl-concurrent-{i}"]

        print(
            f"\n[stress] {len(jobs)} concurrent compile-rego calls across {N_GUARDRAILS} "
            f"guardrails (3 recompiles each, all interleaved): every guardrail's final state "
            f"stayed internally consistent; recompiles were idempotent under concurrency."
        )

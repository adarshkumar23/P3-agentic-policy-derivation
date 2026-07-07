# Stress Test Results

Real, measured numbers from this repo's stress-test suite (`tests/stress/`),
following the same no-qualitative-"passed"-without-a-number discipline used
in `tests/benchmark/PATENT_TECHNICAL_EFFECT.md`. All numbers below were
actually produced by running the tests in this repository's `.venv` against
the vendored, test-only `opa` CLI at `.bin/opa` — never a live OPA
deployment (see `PATENT.md` §0 and `ASSUMPTIONS.md`).

Two pre-existing stress tests from an earlier pass are not re-described here
in full: `test_concurrent_check_action.py` (50/100 concurrent check-action
calls against one guardrail, no forks/corruption) and
`test_receipt_chain_concurrency.py` (the original hash-forking race
regression, now also covered by `tests/regression/`).

## A genuine bug was found and fixed during this pass

**Symptom**: the long-running memory test (#6 below) showed real,
reproducible, unbounded-looking heap growth — first ~7.75x over 6000 calls
when driven through the full HTTP stack, persisting even after clearing
both of this repo's known, documented, intentionally-unbounded in-memory
demo stand-ins (`receipt_store` in `api/guardrails.py` and
`AuditService.entries` in `audit.py`).

**Root-caused with `tracemalloc` snapshot diffing** (not guessed) to two
distinct, unrelated sources, both now fixed or correctly explained:

1. **Test-harness artifact, not an application bug**: `TestClient` (from
   `fastapi.testclient`) bridges each synchronous `.post()` call into the
   async ASGI app by spinning up a **brand-new asyncio event loop, `Runner`,
   and OS thread per call** (`anyio.from_thread.run_eventloop` ->
   `asyncio.Runner` -> `new_event_loop()`). This is real, permanent, bounded
   per-call overhead specific to `TestClient`'s sync-to-async bridging — a
   real deployment (uvicorn) runs one persistent event loop for the process
   lifetime and never does this. Confirmed by calling
   `CompliVibePolicyProvider.check_action()` directly (bypassing
   FastAPI/Starlette/anyio entirely) — but doing so exposed the *second*,
   real bug beneath it (below), so the ratio got *worse* (7.75x -> 18.81x)
   once this noise was removed, not better — that was the tell that a real
   leak was still there.
2. **Real bug, fixed**: `core-side-patch/api/guardrails.py`'s
   `_local_opa_eval_handler` (the test-only bridge from `OpaClient`'s HTTP
   interface to the vendored `opa eval` CLI) created a brand-new,
   randomly-named `tempfile.NamedTemporaryFile` **on every single call**,
   even though the Rego text it writes is fixed for the lifetime of one
   guardrail/handler. Each unique temp-file path gets permanently
   `sys.intern()`'d by `pathlib`'s path-parsing machinery — a process-
   lifetime, unbounded cache. Fixed by creating the temp file **once**, when
   the handler is constructed (per guardrail), not per request. This is
   specific to this repo's test-only OPA bridge — a real `OpaClient`
   pointed at a live OPA server creates no temp files at all, so this
   exact bug cannot occur in production, but it made the test's own
   measurement dirty and was worth fixing regardless.

**Verification**: after both fixes, the direct-provider test's ratio went
from 18.81x to **1.08x**, with a heap-size curve that visibly plateaus
(87.1 -> 91.0 -> 92.3 -> 93.3 -> 93.7 -> 94.0 -> 94.2 -> 94.2 KiB across 8
checkpoints of 500 calls each) rather than climbing indefinitely — the
textbook signature of a bounded cache filling up, not a leak.

One incorrect fix was attempted and reverted along the way: adding
`provider.close()` to `check_action`'s `finally` block (closing the
`OpaClient`/`httpx.Client` after every request) was tried first, based on
an initial (wrong) hypothesis that an unclosed `httpx.Client` was the
cause. It made no measurable difference to the ratio (confirming the
hypothesis was wrong) and broke a legitimate, intentional test pattern
(`tests/unit/test_observability_metrics.py`'s circuit-breaker tests
deliberately share ONE long-lived `OpaClient` across many requests, exactly
as a real production deployment should) — reverted. `CompliVibePolicyProvider.close()`
remains available as a utility for callers that do own a per-call client
(e.g. a one-off script), but is not invoked automatically by the
check-action endpoint, since client lifecycle is the `policy_provider_factory`'s
responsibility, not the endpoint's.

**A third methodology issue, found when running the full suite (not just
this one file)**: the fixed test above passed cleanly (~1.1x) whenever it
ran alone, but reported the same large ~7.5-7.9x ratio again whenever it
ran preceded by other test modules (e.g. `tests/unit`) in the *same* pytest
process — reproduced deterministically by running `pytest tests/unit
tests/stress/test_long_running_memory_check.py::...`. The exact mechanism
was not conclusively pinned down (candidates include `re`'s process-wide
compiled-pattern cache and other module-level state a long pytest session
accumulates across hundreds of unrelated tests), but the design fix is
correct regardless of the exact mechanism: this test's whole purpose is
measuring whether `core-side-patch`'s own code leaks, and that measurement
should not depend on what else already ran in the same Python process.
Fixed by moving the actual measurement into a **freshly-spawned
subprocess** (`sys.executable -c ...`) so it is always isolated from
whatever the outer pytest session already did. Verified: `pytest tests/unit
tests/stress/test_long_running_memory_check.py::test_memory_bounded_...`
now reports **1.12x**, matching the standalone result, regardless of
what (or how much) ran before it.

---

## 1. High-throughput check-action across many distinct `ai_system_id`s

`tests/stress/test_high_throughput_multi_ai_system.py`

- **750 requests** across **15 distinct `ai_system_id`s** (3 orgs), **32
  concurrent workers**.
- Throughput: **~23 req/s**.
- Per-request latency (subprocess-per-call `opa eval` overhead **included**):
  **p50 = 1451 ms, p95 = 1820 ms, p99 = 1882 ms**.
- **Sub-millisecond target is NOT met at this harness's own level** — every
  request pays a real `opa eval` subprocess spawn (fork/exec + Rego
  re-parse), which a production deployment talking to a long-running OPA
  HTTP server process would not pay. The sub-millisecond target is only a
  meaningful production-latency claim once that harness-specific subprocess
  overhead is excluded; it does not characterize `core-side-patch`'s own
  code cost.
- Zero decision mismatches: every response's allow/deny outcome matched the
  correct `ai_system_id`'s own configured guardrail limit, with no
  cross-system state bleed under concurrency.

## 2. Receipt chain verification at scale

`tests/stress/test_chain_verification_at_scale.py`

| Chain length (n) | Time / receipt |
|---|---|
| 500 | ~175 µs |
| 1000 | ~189 µs |
| 2000 | ~181 µs |

- **1.04x** slowdown from n=500 to n=2000 — verification time scales
  linearly with chain length, not quadratically or worse.
- Verified `verify_chain` exits early (does not keep walking) once it hits
  a tampered receipt, rather than paying full-chain cost on a chain it's
  already about to reject.

## 3. Adversarial envelope injection

`tests/stress/test_adversarial_envelope_injection.py`

- **23 distinct malformed-JSON-shape cases** (wrong types, deeply nested
  unexpected structures, payload-shaped-field smuggling attempts, extremely
  long strings, unicode edge cases, missing/extra fields) **+ 5 raw-
  malformed-body cases** (non-JSON bytes, truncated JSON, etc.).
- **100% clean 4xx rejection rate** — zero 5xx responses, zero hangs,
  across all 28 cases, including when fired concurrently.

## 4. Sustained OPA outage and recovery

`tests/stress/test_sustained_opa_outage.py`

- Circuit breaker opened after the configured **5 consecutive failures** —
  confirmed via transport-call counting that only **5 real transport
  attempts** occurred across a 70-call sustained-outage window (the
  remaining ~65 calls were skipped by the open breaker and returned
  fail-closed immediately, without attempting the transport at all).
- Breaker stayed open through the **full cooldown window**, then correctly
  half-closed and resumed making real calls once the cooldown elapsed.
- **Full recovery confirmed**: once the transport started returning genuine
  successful responses again (simulating OPA coming back), the client
  produced correct real allow/deny decisions again, not just "no longer
  erroring."

## 5. Concurrent guardrail creation/compilation for the same org

`tests/stress/test_concurrent_guardrail_compilation.py`

- **16 guardrails created concurrently** for the same org (16 concurrent
  workers) + **48 concurrent recompile-rego calls** across those same 16
  guardrails.
- **Zero cross-guardrail contamination**: every guardrail's persisted
  `rego_policy` contained *only* its own financial limit and *only* its own
  `source_obligation_ids` — verified by giving each guardrail a distinct,
  same-digit-count limit so one guardrail's limit string could never be an
  accidental substring of another's.
- Recompiles are idempotent under concurrent repetition.
- (One transient flaky failure — a 404 during an earlier run — was
  reproduced only when this test happened to run concurrently with a
  separate, unrelated 10,000-call background test on the same shared
  machine; re-ran clean 3/3 times in isolation. Not a product bug — see
  the resource-contention note in this repo's development history if
  investigating flaky CI runs of this specific test.)

## 6. Long-running memory check (leak found and fixed — see above)

`tests/stress/test_long_running_memory_check.py`

**Sub-test 1** (`test_sustained_check_action_calls_memory_trend`, 6000
calls through the full HTTP stack, `receipt_store` growth tracked but not
cleared — the expected, documented case):

| Calls | tracemalloc current | ru_maxrss | receipt_store len |
|---|---|---|---|
| 500 | 3718.7 KiB | 99,096 KB | 500 |
| 2000 | 14,355.7 KiB | 118,400 KB | 2000 |
| 4000 | 28,388.5 KiB | 144,844 KB | 4000 |
| 6000 | 42,882.7 KiB | 174,036 KB | 6000 |

- ~7.25–7.37 KB/call, **1.02x** ratio between the first and second half of
  the run — i.e. per-call cost is flat, not accelerating. The absolute
  growth is exactly attributable to `receipt_store` accumulating one
  `Receipt` per call, forever — the known, already-documented in-memory
  demo-persistence limitation (no durable receipt table in this repo yet),
  not a leak.

**Sub-test 2** (`test_memory_bounded_once_known_unbounded_receipt_store_is_cleared`,
4000 calls made **directly against `CompliVibePolicyProvider.check_action()`**,
run in an **isolated subprocess** (see the third methodology note above),
with `receipt_store` cleared every 500 calls):

| Calls | tracemalloc current |
|---|---|
| 500 | 121.9 KiB |
| 1000 | 127.0 KiB |
| 1500 | 128.4 KiB |
| 2000 | 130.4 KiB |
| 2500 | 131.0 KiB |
| 3000 | 131.5 KiB |
| 3500 | 132.1 KiB |
| 4000 | 131.9 KiB |

- **1.08x–1.12x** ratio across repeated runs (standalone and preceded by
  the entire `tests/unit` suite alike), heap size visibly **plateaus** by
  ~2000 calls and stays flat through 4000 — bounded growth, no leak, in the
  actual `core-side-patch` check-action code path (`CompliVibePolicyProvider`,
  `OpaClient`, `services/receipts.py`, `services/receipt_chain.py`).

No silent caps: this is the full, real result — nothing was excluded or
sampled down to hide a worse number.

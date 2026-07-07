# Assumptions and Open Questions

This document tracks everything in this build that is either carried over
from the P2 project without fresh re-verification in *this* repo, or newly
discovered/decided during this build. Update it as workstreams land; do not
let it go stale.

## Carried over from P2 (pending final verification against complivibe-backend-v5)

These were confirmed verbally during P2's development per the task brief for
this repo. This repo (P3) has no access to the actual `complivibe-backend-v5`
codebase to re-verify them directly — they are reproduced here as
high-confidence interface contracts to code against, flagged as
carried-over rather than freshly verified:

- `require_permission(permission_code: str) -> Callable[..., Membership]` via
  `Depends()` — used unchanged across every new endpoint in
  `core-side-patch/api/guardrails.py`.
- `_get_org_ai_system(ai_system_id, organization_id, db)` in
  `app/ai_governance/services/draft_context_service.py` — used unchanged for
  org-scoping every guardrail/receipt-chain endpoint.
- `AuditService.write_audit_log(self, *, action, entity_type, organization_id,
  actor_user_id=None, entity_id=None, before_json=None, after_json=None,
  metadata_json=None, ip_address=None, user_agent=None)` — used unchanged for
  every state-changing action in this repo.
- Framework Catalog's global-reference-data + per-org-activation pattern —
  referenced conceptually for how `ai_policy_guardrails` should relate to any
  shared/global obligation templates vs. per-org compiled instances.
- The Email Outbox queue/worker pattern — not needed in this repo; no
  change-event mechanism requiring it was identified (guardrail recompilation
  is triggered synchronously via an explicit endpoint, not a queued event).

**Action item before merge into complivibe-backend-v5:** re-verify all four
signatures/behaviors above against the actual current core codebase, not just
this document.

## Newly verified in this repo: the real policy enforcement runtime's interfaces

(See `PATENT.md` §1.1 for the specific third-party toolkit's name, license,
and repository — that document is this repo's sole, legally-required
disclosure location for that name, per the branding boundary in `PATENT.md`
§7; this file intentionally refers to it only generically from here on.)

Fetched directly from the runtime's public source (via `gh api` against its
GitHub repository, not assumed from marketing docs) during this build.
These correct several assumptions in the original task brief:

- **There is no literal `PolicyProviderInterface` ABC.** The real,
  documented extension point is a *structural* protocol,
  `ExternalPolicyBackend` (implicit — no shared base class), satisfied by
  implementing: a `name` property, `evaluate(action: str, context: dict) ->
  PolicyDecisionResult`, and `healthy() -> bool`. Backends register with the
  runtime's own backend registry. There is additionally a standalone ASGI
  policy-provider handler for gateway-style HTTP integration (`POST
  /check`, `GET /health`, `GET /policies`) that does not require importing
  any Python ABC at all — an external policy engine can integrate purely
  over HTTP. `CompliVibePolicyProvider` (Workstream D) is built against the
  `ExternalPolicyBackend` structural protocol, since that is what is
  concretely, verifiably real.
- **The runtime already has its own structured-rule-to-Rego compiler**
  (see `PATENT.md` §1.1(3) for the exact source path). This directly
  narrowed this patent's claim — compiling an already-structured rule/plan
  object into Rego text is prior art, not novel. This repo's derivation
  engine (Workstream B) is scoped to stop at producing the structured
  constraint specification; Rego rendering from that spec is a
  comparatively thin, non-claimed step by design.
- **Ed25519 receipt signing is available as part of the runtime's own
  offline-verifiable-receipt capability** (see `PATENT.md` §1.1(4)), which
  accepts a signing-key seed as a constructor parameter and never fetches
  or generates the key itself. This resolves §0's key-custody requirement:
  the adapter (and therefore the signing key) can run entirely inside the
  customer's own deployment, with CompliVibe's core only ever receiving the
  resulting signed receipt over the network. **Decision: use that
  capability directly for signing (Workstream F) once installable, do not
  build custom Ed25519 signing code long-term.** CompliVibe's core-side
  code in this repo only ever calls chain/signature-verification with the
  already-public public key, never touches a private key.

## PyPI installability checked directly (not assumed)

(Exact package/module names underlying these findings are recorded in
`PATENT.md` §1.1, per this repo's branding boundary — summarized generically
here.)

- The runtime's top-level PyPI distribution **does install**, but its
  importable module is a compliance-tooling surface (CLI + lint/policy-test/
  verify/integrity/prompt-defense/supply-chain checks), not the runtime
  kernel. One of its modules references the runtime's governance and
  identity modules by dotted path as things it expects to be importable at
  runtime for tamper-checking, confirming those module paths are real, but
  it does not vendor them itself.
- A second, separately-named PyPI distribution corresponding to the
  runtime's actual policy/gateway kernel **is a name-reservation
  placeholder** (an `__init__.py` containing only a version string), not the
  functional package whose source is visible in the runtime's GitHub
  monorepo. The real OPA evaluator/backend classes, the gateway policy-
  provider handler, and the backend-registry types referenced in
  `PATENT.md` §1.1 and used as this repo's integration target were read
  directly from the GitHub source tree via `gh api`, not from a pip-
  installed copy — there is currently no way to `pip install` and run
  against the real implementation from a standalone environment.
- **Correction to an earlier finding in this file, made during a later pass
  of this build, with evidence (not a restated assumption):** the offline-
  verifiable-receipts capability **is genuinely installable from PyPI**.
  The earlier claim that no such distribution existed was a search-name
  error, not a real unavailability — the search was for the GitHub
  subdirectory's name, not the package's actual declared project name in
  its own `pyproject.toml`. Fetching that file directly from the runtime's
  GitHub source showed the real PyPI project name differs from the
  directory name; installing under that real name succeeded
  (`pip install <that-name>[crypto]`), and the resulting import exposes a
  complete, working API: a receipt-producing adapter class, a
  receipt dataclass (fields: `receipt_id`, `tool_name`, `agent_did`,
  `cedar_policy_id`, `cedar_decision` — `"allow"`/`"deny"` — `args_hash`,
  `timestamp`, `session_id`, `parent_receipt_hash`, `signature`,
  `signer_public_key`, `error`), a module-level `sign_receipt(receipt,
  private_key_hex)`, `verify_receipt(receipt)`, and
  `verify_receipt_chain(receipts, *, trusted_keys=None)`. This was
  exercised live in this environment, not just imported: a real chain of
  receipts was signed, verified as valid, then a receipt was tampered with
  (`cedar_decision` flipped after signing) and `verify_receipt_chain`
  correctly reported both the invalid signature at the tampered index and
  the resulting broken hash link at the next index — **even without
  passing `trusted_keys`** (an initial test run appeared to show tampering
  going undetected, but that was a test-construction bug on this project's
  side — the replacement value happened to match the field's existing
  value, so nothing had actually changed; re-run with a genuinely different
  value confirmed detection works correctly by default. Recorded here so a
  future reader doesn't have to rediscover this false alarm.). The
  key-custody design (private key supplied by the caller, e.g. the
  customer's own deployment, never fetched or generated by the library)
  is confirmed exactly as assumed. **Decision, superseding the earlier
  "local stand-in" decision below: this repo now depends on and calls the
  real package directly** for signing and chain verification (Workstreams
  F and G) — see the migrated `core-side-patch/services/receipts.py` and
  `core-side-patch/services/receipt_chain.py`. The "customer holds the
  signing key" claim in `PATENT.md` §1.1(4)/Claim 4 describes a real,
  working, verified feature, not an aspirational one.
- **A separate, genuinely important finding surfaced while re-checking
  installability**: the runtime's actual policy/gateway kernel (the
  package providing the OPA evaluator/backend classes and the gateway
  policy-provider handler referenced above) **does install as a real,
  functional package once the correct installation extra is used**
  (`pip install <top-level-distribution>[core]`, which pulls in a
  same-named "-core" sub-distribution) — the earlier finding that this was
  only a name-reservation placeholder was based on installing the bare
  top-level import name directly, which resolves to a **different,
  unrelated third-party PyPI package that happens to claim the exact same
  top-level Python import name**, published by an unrelated author/company
  (a different homepage, different author contact, no relationship to
  Microsoft's project visible in its metadata). Both distributions install
  real files at the same import path; whichever is installed *last* wins
  on disk, and `pip` raises no conflict, warning, or error about this —
  it is invisible unless someone inspects which distribution's `RECORD`
  actually owns the resulting file. This project's own environment ended
  up with the unrelated package's files serving that import name after
  a subsequent, deliberate install of the correct "-core" distribution
  didn't fully overwrite the unrelated package's own additional modules
  alongside it. **This is a real dependency/namespace-confusion risk, not
  a hypothetical one** — flagged in `MERGE_CHECKLIST.md` as something to
  re-verify with an isolated, from-scratch environment (and ideally a
  hash-pinned lockfile naming the exact intended distribution) before this
  repository's integration code is ever pointed at a real installation of
  the runtime, rather than assuming `pip install <the well-known name>`
  alone is safe. This repo's own code does **not** depend on that
  ambiguous package at all — it only depends on the unambiguously-named,
  collision-free receipts package above, so this risk affects the
  eventual `complivibe-backend-v5` merge, not this repo's current test
  suite.

**Consequence:** Workstream D in this repo remains built against a
locally-defined `Protocol`/dataclass shape mirroring the verified GitHub
source for the policy/gateway kernel (that part is still not safely
installable in isolation — see the namespace-collision finding above),
with a clearly marked integration seam for later. Workstreams F and G, by
contrast, are **no longer** local stand-ins — they call the real,
installed receipts package directly, per the correction above.

## Concurrency findings from Workstream N (stress testing) and follow-up fixes

- **Real bug, found and fixed**: `CompliVibePolicyProvider.check_action()`
  (`core-side-patch/services/policy_provider.py`) read
  `self._previous_receipt_hash`, signed a receipt against it, then wrote the
  new hash back, with no lock. Concurrent calls on the same provider
  instance could both read the same parent hash and each sign a receipt
  claiming it — a fork in the chain rather than a line. Reproduced
  concretely in `tests/stress/test_receipt_chain_concurrency.py` (a genuine
  fork was observed against the unfixed code). Fixed with a
  `threading.Lock` around the whole read-sign-write sequence, since the
  signed payload itself embeds the parent hash — locking only the write
  would not have been sufficient.
- **Real bug, found and fixed**: `create_app(...)` in
  `core-side-patch/api/guardrails.py` builds its demo persistence layer as
  `create_engine("sqlite://", poolclass=StaticPool, connect_args=
  {"check_same_thread": False})` — a single shared DBAPI connection across
  every request. `check_same_thread=False` only disables sqlite3's
  thread-affinity check; it does not make concurrent execute/fetch calls on
  that one connection from multiple threads safe. Under concurrent
  check-action requests this surfaced as corrupted row reads (a
  `ValueError: Invalid isoformat string: ''` from an interleaved cursor
  fetch), caught by `tests/stress/test_concurrent_check_action.py`. Fixed
  by wrapping the `get_db()` dependency's session lifetime in a
  module-level `threading.Lock`, serializing DB access for this demo
  in-memory engine. **This is a stand-in-specific fix**: a real deployment
  would use a real connection pool (e.g. Postgres) instead of this
  single-connection SQLite stand-in and would not need this lock at all —
  do not carry the lock forward into the real `complivibe-backend-v5`
  integration; it exists only because this repo's throwaway persistence
  layer is a single SQLite connection.
- **Real bug, found, documented, deliberately NOT fixed (low severity,
  non-exploitable)**: `OpaClient`'s circuit-breaker bookkeeping
  (`_consecutive_failures`, `_circuit_open_until`) is also an unlocked
  read-modify-write, so concurrent failures can lose counter updates and
  shift exactly when the circuit opens/closes relative to a single-threaded
  run. This cannot produce an accidental `allowed=True`, since an allow
  decision is only ever derived from that specific call's own successful
  HTTP response, never from this shared bookkeeping — so it was left
  unfixed per the scoping instruction given to Workstream N (only the
  small, clearly-scoped receipt-chain lock was authorized). If this
  client's circuit-breaker precision becomes operationally important (e.g.
  exact trip-timing SLOs), revisit with a lock or an atomic counter.
- **Recommendation flagged by Workstream O, not actioned (nothing real to
  normalize against yet in this standalone repo)**: the rate limiter
  (`core-side-patch/services/rate_limit.py`) keys strictly on the raw
  `organization_id` string it's given, with zero normalization, and today
  that's the exact same string `permissions.py`'s org-scoping check uses —
  so there is no live skew. But if the real `complivibe-backend-v5`
  org-lookup ever normalizes `organization_id` (case-folds, trims) while
  whatever wires the real rate limiter in keeps using a raw header string,
  that mismatch would let a single org multiply its effective rate-limit
  budget by varying header casing. **Action item before merge**: key the
  real integration's rate limiter off the canonical `organization_id` taken
  from the resolved `Membership`, never off a raw request header.

## Real memory-growth bug found and fixed during the production-polish pass

Found by the long-running memory stress test
(`tests/stress/test_long_running_memory_check.py`) and root-caused with
`tracemalloc` snapshot diffing (see `tests/stress/STRESS_TEST_RESULTS.md`
for full numbers) — not guessed:

1. **Test-harness artifact (not fixed as a bug, correctly explained
   instead)**: `fastapi.testclient.TestClient` spins up a brand-new asyncio
   event loop + `Runner` + OS thread on every single `.post()` call, to
   bridge synchronous test code into the async ASGI app. This produced
   real, bounded, per-call overhead that looked like heap growth under a
   sustained-call test — but it is specific to how `TestClient` bridges
   sync calls, not something a real deployment (uvicorn, one persistent
   event loop for the process lifetime) ever does.
2. **Real bug, fixed**: `core-side-patch/api/guardrails.py`'s
   `_local_opa_eval_handler` (the test-only bridge from `OpaClient` to the
   vendored `opa` CLI) created a fresh, randomly-named
   `tempfile.NamedTemporaryFile` on every call, even though the Rego text
   is fixed per guardrail. Every unique path got permanently
   `sys.intern()`'d by `pathlib` — an unbounded, process-lifetime cache.
   Fixed by creating the temp file once, at handler-construction time.
   Confirmed via a direct-provider (bypassing `TestClient`) test: ratio
   went from 18.81x to 1.08x with a visibly flat/plateaued heap curve.

An earlier attempted fix — adding `provider.close()` (closing the
`OpaClient`/`httpx.Client`) to `check_action`'s `finally` block — was tried
first based on an initial wrong hypothesis, made no measurable difference
(confirming the hypothesis was wrong), and broke a legitimate, intentional
test pattern where `tests/unit/test_observability_metrics.py`'s
circuit-breaker tests deliberately share ONE long-lived `OpaClient` across
many requests — exactly as a real deployment should (a single
connection-pooled client reused across requests, never reconnected per
call). That change was reverted. `CompliVibePolicyProvider.close()` remains
available as a utility for callers that do own a per-call client (e.g. a
one-off script), but the check-action endpoint does not call it — client
lifecycle is the `policy_provider_factory`'s responsibility.

A third, separate methodology issue surfaced once the fixed test was run as
part of the *full* suite rather than alone: the same ~7.5-7.9x ratio
reappeared whenever this test was preceded by other test modules (e.g.
`tests/unit`) in the same pytest process, even though it measured ~1.1x
cleanly every time it ran alone. The exact mechanism was not conclusively
pinned down. Rather than keep chasing every possible contributor, the test
was restructured to run its actual measurement in a freshly-spawned
subprocess, which is correct regardless of the exact mechanism — this
test's whole purpose is measuring whether `core-side-patch`'s own code
leaks, and that should not depend on prior process history. Verified fixed:
1.12x whether run alone or preceded by the entire `tests/unit` suite.

## Open / genuinely undecided (equivalent to P2's outbox-pattern judgment call)

- **Fail-open vs. fail-closed when OPA is unreachable (Workstream C).**
  Decision: **fail closed** — if the OPA HTTP call times out or errors, the
  check-action endpoint returns `deny`. This is the safer default for a
  compliance product (an unreachable policy engine must not silently permit
  agent actions) but it does mean an OPA outage becomes an availability
  incident for every tenant's agents, not just a compliance-monitoring
  incident. Flagging this explicitly as a product/business tradeoff a human
  should confirm, not a purely technical default.
- **Whether `ai_policy_guardrails` needs a global-template / per-org
  activation split** (mirroring Framework Catalog) or whether every guardrail
  is org-owned from creation. This repo takes the simpler org-owned-from-creation
  model for now since no global regulatory-obligation-template table exists
  yet in this standalone repo to activate against; revisit if/when this
  merges alongside the real Framework Catalog data.
- **This repo has no actual `complivibe-backend-v5` codebase to integrate
  against** — it is being built standalone, per the P2 discipline, with the
  carried-over interfaces above treated as contracts. Nothing here has been
  run against the real core codebase.

## Environment constraints acknowledged

- OPA deployment, clustering, and lifecycle are explicitly out of scope for
  this repo (per task brief) — `core-side-patch/services/opa_client.py` is an
  HTTP client only.
- No live installation of the real policy enforcement runtime (named in
  `PATENT.md` §1.1) is available in this build environment to run
  integration tests against; Workstream D's tests exercise the
  `ExternalPolicyBackend` protocol contract with a hand-written stand-in
  implementing the same shape, not the real package. This must be
  re-verified against a real installation of the runtime before production
  use.

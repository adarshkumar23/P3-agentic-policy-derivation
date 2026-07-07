# Runbook

Operational guidance for this repository's components once deployed. All of
this concerns CompliVibe's own derivation/compilation and glue code — it does
not cover operating the separately-deployed OPA instance or the third-party
policy enforcement runtime itself (out of scope per PATENT.md §0; consult
that runtime's own operational docs).

## Receipt chain verification fails in production

`POST /ai-systems/{id}/verify-chain` (backed by
`core-side-patch/services/receipt_chain.py::verify_chain`) returns
`passed=False` with a `failure_index` and `failure_reason`.

1. **Do not treat this as automatically an attack.** First rule out the two
   documented, benign causes:
   - A genuine hash-chain race from a bug that predates the fix in this
     repo's `CompliVibePolicyProvider.check_action()` (see ASSUMPTIONS.md's
     concurrency-findings section) — if the deployed version is older than
     that fix, upgrade first, then re-verify.
   - A partial/incomplete receipt persisted mid-write (e.g. a process crash
     between signing and storage) — check the receipt store's own write
     path logs around the `receipt_id` at `failure_index`.
2. If neither benign cause applies, treat `failure_reason` at face value:
   - `"invalid signature"` at index N: receipt N's payload or signature was
     altered after signing, or its `public_key_hex` doesn't match the key
     that actually signed it. Escalate as a potential integrity incident —
     do not silently re-sign or repair; capture the tampered receipt for
     investigation first.
   - A hash-link mismatch at index N: receipt N's `previous_receipt_hash`
     does not match receipt N-1's `receipt_hash`. Check whether receipts
     were reordered, deleted, or replaced in storage (this is exactly the
     tampering shape `tests/unit/test_receipt_chain.py` demonstrates and
     catches).
3. Everything from `failure_index` onward is unverifiable, not "probably
   fine" — do not resume trusting the chain past that point without
   independent reconciliation against the receipt-producing system's own
   records.

## OPA unreachable

`core-side-patch/services/opa_client.py::OpaClient` is deliberately
fail-closed (see ASSUMPTIONS.md's "Open / genuinely undecided" section for
the tradeoff this represents): every check-action call returns `deny` while
OPA is unreachable, which means an OPA outage is an availability incident for
every tenant's agent actions, not just a compliance-monitoring blip.

1. Check `OpaClient`'s circuit-breaker state indirectly: if `check-action`
   responses report `source="fail_closed"` with an error mentioning "circuit
   breaker open", the client itself has stopped attempting calls during a
   cooldown window (default 30s) — this is expected self-protection, not a
   separate bug.
2. Confirm OPA's own health/liveness first (this repo's client only calls
   it, it doesn't run it — see PATENT.md §0). Once OPA is confirmed healthy
   again, the circuit will half-close on its own after the cooldown elapses;
   no manual reset is needed.
3. If OPA is healthy but the client is still reporting fail-closed, check
   for a network/DNS issue between this service and OPA's `base_url`, or a
   TLS/cert problem — these produce the same generic connect-error path as
   an actual OPA outage.

## Derivation produces invalid or unexpected Rego

`core-side-patch/services/derivation_engine.py::derive_and_compile` is
pattern/regex-based, not full NLU (see
`tests/benchmark/PATENT_TECHNICAL_EFFECT.md`'s scope-honesty section). If a
compiled guardrail behaves unexpectedly:

1. Check `ConstraintSpec.unrecognized_obligation_ids` on the guardrail's
   stored `constraint_spec_json` first — if the relevant obligation is
   listed there, the engine did not extract anything from it at all (this is
   the intended fail-safe: it flags what it can't handle rather than
   guessing), and the guardrail needs a manually-authored addition or an
   obligation-text rewrite that the existing patterns can pick up.
2. If the obligation IS reflected in the constraint spec but the compiled
   Rego's behavior still looks wrong, validate the compiled Rego directly
   with `opa eval` against a hand-built input matching the guardrail's
   expected input shape (`input.action.<field>` — see
   `tests/unit/test_derivation_engine.py` for the exact pattern) before
   assuming the derivation engine itself is at fault; it may be a caller
   passing the wrong envelope shape (see `services/envelope.py`).
3. Recompile via `POST /ai-guardrails/{id}/compile-rego` only after
   confirming the underlying obligation text or the engine's patterns
   actually changed — this endpoint deliberately validates that the
   supplied obligation `source_obligation_ids` match what the guardrail
   already claims provenance from, precisely to prevent silently redefining
   what a guardrail is derived from.

## Rate limit false positives / suspected bypass

See ASSUMPTIONS.md's concurrency-findings section for the one flagged (not
yet exploitable in this standalone repo) integration-time risk: if the real
org-lookup ever normalizes `organization_id` while the rate limiter doesn't,
a single org could get multiple effective buckets. If you observe a tenant
apparently exceeding its configured rate limit, check for exactly this
skew first (varying org-id casing/whitespace across requests) before
assuming a bug in `TokenBucketRateLimiter` itself.

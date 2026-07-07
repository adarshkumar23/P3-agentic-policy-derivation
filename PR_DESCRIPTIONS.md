# PR Descriptions (per workstream)

Suggested PR breakdown if this repository's history is split into separate
pull requests against `complivibe-backend-v5`. Order reflects dependency
order (interface-publishing work first), not necessarily merge order.

## 1. PATENT.md — narrowed claim and prior-art disclosure
Rewrites the patent specification to a single, narrow claim (automated
derivation of a structured constraint spec from regulatory obligations,
with provenance) and discloses the third-party policy enforcement runtime's
existing interception/evaluation/signing/audit-chain/rule-to-Rego-compiler
capabilities as prior art, so the filing doesn't claim what already exists.

## 2. Workstream A — Core DB models
Adds `ai_policy_guardrails` (with `source_obligation_ids` and
`constraint_spec_json` provenance columns — not just the compiled Rego) and
`ai_guardrail_events` (envelope-only, no payload column). Includes
`services/provenance.py` serialization helpers.

## 3. Workstream B — Obligation-to-Rego derivation engine
The claimed novel component: pattern-based extraction of a
`ConstraintSpec` (financial limits, geographic scope, data scope, approval
requirements — each with provenance) from `ObligationRecord` text, then
compilation to per-tenant Rego. Tested against a real `opa eval` CLI in
test-only mode (vendored at `.bin/opa`, not a live deployment).

## 4. Workstream C — OPA HTTP client
A thin, fail-closed-by-design `httpx` client for a separately-deployed OPA
instance, with bounded retries (connection failures only, never a clean
non-2xx) and a circuit breaker. OPA deployment/lifecycle is explicitly out
of scope.

## 5. Workstream D — CompliVibePolicyProvider
Implements the runtime's real, verified `ExternalPolicyBackend` structural
protocol (not the ABC name assumed in the original brief — corrected after
reading the runtime's actual GitHub source). Thin glue: builds an envelope,
asks OPA, optionally asks a caller-supplied signer for a receipt.

## 6. Workstream E — Envelope/payload separation
Two disjoint Pydantic models (`ActionEnvelope`/`ActionPayload`) with no
shared base and `extra="forbid"`, plus a reject-not-strip `build_envelope`
that scrubs values (never echoes them) on rejection.

## 7. Workstream F — Ed25519 receipt signing
A local stand-in (`ReceiptSigner`/`verify_receipt`) matching the real
runtime's offline-verifiable-receipts capability's documented shape exactly
(not installable from any environment checked — see ASSUMPTIONS.md), built
so the private key only ever needs to exist in the customer's deployment;
`verify_receipt`'s signature is structurally incapable of accepting one.

## 8. Workstream G — Receipt chain verification
`verify_chain` walks a full receipt list, distinguishing a broken hash-link
from an invalid signature from a broken chain-root, and reports the exact
`failure_index` rather than a vague pass/fail.

## 9. Workstream H/I/J — Feature endpoints, permission/org-scoping, audit
Six endpoints (create/compile/check/receipt-chain/verify-chain/sdk-snippet)
wired through local stand-ins for the carried-over P2 interfaces
(`require_permission`, `_get_org_ai_system`, `AuditService.write_audit_log`
— see ASSUMPTIONS.md for exact carried-over signatures and the re-verification
action item before merge). Cross-org access returns 404, never 403.

## 10. Workstream K — Rate limiting
A dependency-free, per-org `TokenBucketRateLimiter`, profiled (measured
overhead documented in-code) and thread-safety-tested.

## 11. Workstream L — Multi-tenant Rego isolation
Proves, via real `opa eval` against a bundle containing multiple tenants'
compiled policy simultaneously, that isolation is enforced purely by which
Rego package is queried — no input field can be spoofed to cross tenant
boundaries, since the compiled Rego never reads an org-identifying field
out of `input` at all.

## 12. Workstream M — Benchmark / technical-effect evidence
`tests/benchmark/PATENT_TECHNICAL_EFFECT.md`: a real obligation run through
both the manual-authoring path (17 enumerated steps, concrete cited error
modes) and the automated path (real executed output, validated with real
`opa eval` calls) — the evidentiary basis for PATENT.md §4.

## 13. Workstream N — Stress testing
Found and fixed a genuine receipt-chain hash-forking race
(`CompliVibePolicyProvider` had an unlocked read-modify-write on
`previous_receipt_hash`) and a genuine shared-SQLite-connection race in the
demo persistence layer (fixed with a scoped lock, explicitly NOT meant to
carry forward to a real connection pool). Documented (not fixed, low
severity, non-exploitable) a circuit-breaker bookkeeping race in
`OpaClient`.

## 14. Workstream O — Security review
Adversarial envelope/payload testing (confirms defense-in-depth via
`extra="forbid"` even when the explicit payload-field check is dodged by a
near-miss name), key-never-leaks testing across the full check-action path,
clean `bandit`/`pip-audit` results, and rate-limit-bypass testing (no
exploitable bypass found; one integration-time normalization risk flagged
for the merge into the real org-lookup).

## 15. Workstream P — Tooling and CI
ruff/black/mypy/pre-commit/pip-tools/bandit/pip-audit/pytest-cov, a GitHub
Actions CI pipeline (which vendors its own `opa` CLI since `.bin/opa` is
gitignored), and `structlog`/`prometheus_client` observability scaffolding.

## 16. Workstream Q — Documentation
ASSUMPTIONS.md, MERGE_CHECKLIST.md, RUNBOOK.md, this file. Captures every
carried-over interface, every deliberate design tradeoff (fail-closed OPA,
reject-not-strip envelope construction, customer-side key custody), and
every genuine finding from stress/security review with its resolution
status.

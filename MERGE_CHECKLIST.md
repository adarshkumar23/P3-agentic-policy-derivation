# Merge Checklist

Before this repository's contents are merged into `complivibe-backend-v5`
(as `core-side-patch/` content applied into the real app tree, per the same
standalone-repo discipline used by the P2 project):

## Interface re-verification (see ASSUMPTIONS.md "Carried over from P2")

- [ ] Re-verify `require_permission(permission_code: str) -> Callable[...,
      Membership]` against the real signature in `complivibe-backend-v5`.
      This repo's `core-side-patch/permissions.py` is a local stand-in, not
      the real implementation — replace it, don't merge it as-is.
- [ ] Re-verify `_get_org_ai_system(ai_system_id, organization_id, db)` in
      `app/ai_governance/services/draft_context_service.py` and swap this
      repo's `InMemoryAiSystemRegistry`/`_get_org_ai_system` stand-in for the
      real lookup.
- [ ] Re-verify `AuditService.write_audit_log(...)`'s exact signature and
      swap this repo's in-memory `AuditService` stand-in
      (`core-side-patch/audit.py`) for the real one.
- [ ] Confirm whether `ai_policy_guardrails` should integrate with the real
      Framework Catalog's global-reference-data + per-org-activation
      pattern (this repo assumed org-owned-from-creation; see
      ASSUMPTIONS.md's "Open / genuinely undecided" section).

## Third-party runtime integration (see PATENT.md §1.1, ASSUMPTIONS.md)

- [ ] **Namespace-collision risk (found with evidence, not hypothetical —
      see ASSUMPTIONS.md's "Newly verified" section for the full writeup):
      an unrelated, third-party PyPI package claims the exact same
      top-level Python import name as the runtime's real policy/gateway
      kernel package.** Whichever of the two is installed *last* silently
      wins on disk; `pip` gives no conflict warning. Before pointing any
      real deployment at this integration: install into a clean, isolated
      environment, verify (e.g. via `importlib.metadata` file-ownership
      inspection, the same technique used to discover this) which
      distribution actually owns the resulting import path, and pin the
      exact intended distribution (ideally via a hash-pinned lockfile) —
      do not assume `pip install <the well-known top-level name>` alone is
      safe.
- [ ] Replace `core-side-patch/services/policy_provider.py`'s local
      `PolicyDecisionResult` dataclass and `ExternalPolicyBackend`-shaped
      class with a real registration against the runtime's actual backend
      registry, once the namespace-collision risk above is resolved for the
      target environment.
- [x] ~~Replace `core-side-patch/services/receipts.py`'s local stand-in with
      the real offline-verifiable-receipts capability~~ — **done in this
      pass.** The real package is genuinely installable under its actual
      PyPI project name (see ASSUMPTIONS.md) and does not share the
      namespace-collision risk above (its own import name is unambiguous
      and collision-free). `core-side-patch/services/receipts.py` and
      `core-side-patch/services/receipt_chain.py` now import and call it
      directly. The key-custody boundary is preserved and was re-verified
      against the real package's actual behavior, not assumed: the private
      key is supplied by the caller and the verification path never
      accepts one.
- [ ] Point `core-side-patch/services/opa_client.py`'s `OpaClient` at a real,
      separately-deployed OPA instance's `base_url` — this repo's tests use
      a local `opa eval` CLI subprocess behind an `httpx.MockTransport`
      (`core-side-patch/api/guardrails.py::_local_opa_eval_handler`) purely
      as a stand-in for that live HTTP deployment.

## Persistence

- [ ] Replace `core-side-patch/api/guardrails.py`'s demo in-memory
      `sqlite://` + `StaticPool` engine with the real
      `complivibe-backend-v5` database session/engine. **Do not carry
      forward the `threading.Lock` added around `get_db()`** — it exists
      solely to serialize access to a single-connection SQLite stand-in and
      is not needed (and would hurt throughput) against a real connection
      pool.
- [ ] Add a real Alembic (or equivalent) migration for `ai_policy_guardrails`
      and `ai_guardrail_events` (`core-side-patch/models.py`).
- [ ] Decide on real receipt persistence (this repo used an in-memory
      per-`ai_system_id` list, `receipt_store`, in
      `core-side-patch/api/guardrails.py` — not durable).

## Security / rate-limiting

- [ ] Key the real rate limiter off the canonical `organization_id` from
      the resolved `Membership`, not a raw request header — see
      ASSUMPTIONS.md's concurrency-findings section for why this matters if
      the real org-lookup ever normalizes org ids and the rate limiter
      doesn't.
- [ ] Re-run `bandit`/`pip-audit` against the merged tree as a whole (this
      repo's own scan, `tests/security/SECURITY_REVIEW.md`, only covered
      `core-side-patch/` in isolation).

## Branding

- [ ] Re-run the branding grep sweep against the merged tree: no mention of
      the real third-party runtime's name outside `PATENT.md`'s prior-art
      disclosure section. (`grep -rniE "microsoft|agent[_-]governance[_-]toolkit|agentmesh" --include="*.py" --include="*.md" --include="*.yml" --include="*.yaml" --include="*.toml" .` should return nothing outside `PATENT.md`.)

## Tests

- [ ] All tests in `tests/` (`unit`, `benchmark`, `stress`, `security`) pass
      against the merged tree, not just standalone.
- [ ] CI (`.github/workflows/ci.yml`) passes end to end in the real repo's
      CI environment.

# mypy: allow-untyped-defs
"""HTTP surface for guardrail derivation/compilation and check-action
(Workstreams H, I, J combined -- I and J are wiring concerns on this same
endpoint file, per the task brief).

Endpoints:
    POST   /ai-systems/{ai_system_id}/guardrails
    POST   /ai-guardrails/{guardrail_id}/compile-rego
    POST   /ai-systems/{ai_system_id}/guardrails/check
    GET    /ai-systems/{ai_system_id}/receipt-chain
    POST   /ai-systems/{ai_system_id}/verify-chain
    GET    /ai-governance/policy-provider/sdk-snippet

Every endpoint keyed on `ai_system_id` (and `compile-rego`, keyed on a
guardrail that itself belongs to one organization) is wired through:

- `require_permission(...)` (see `permissions.py`) for a `Membership`.
- `_get_org_ai_system(...)` (see `permissions.py`) for org-scoped lookup,
  translating "not found" *and* "found but belongs to another org" into the
  same HTTP 404 -- never a 403 -- per the carried-over P2 convention of not
  leaking cross-org existence (see ASSUMPTIONS.md).
- `AuditService.write_audit_log(...)` (see `audit.py`) for every
  state-changing call.

Persistence / test-seam notes
------------------------------
This standalone repo has no real request-scoped SQLAlchemy `Session`
factory, no real `ai_system` table, and no live OPA/receipt-signing
deployment to point at. `create_app(...)` below is a factory (not a single
module-level `app`) specifically so tests can inject fully isolated
instances of all of these per test, while still exercising the exact same
route/dependency wiring that would be used in production. See the
docstrings on each parameter for the production-vs-this-repo split.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Callable

import httpx
from audit import AuditService
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from models import AiGuardrailEvent, AiPolicyGuardrail, Base
from observability import (
    CHAIN_VERIFICATION_RESULTS,
    CHECK_ACTION_DECISIONS,
    CHECK_ACTION_LATENCY,
    REGO_COMPILATION_RESULTS,
)
from permissions import InMemoryAiSystemRegistry, Membership, _get_org_ai_system, require_permission
from pydantic import BaseModel
from services.derivation_engine import ObligationRecord, derive_and_compile, rego_package_slug
from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider
from services.rate_limit import RateLimitExceeded, TokenBucketRateLimiter, rate_limit_dependency
from services.receipts import Receipt, ReceiptSigner
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

__all__ = ["create_app"]


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class ObligationIn(BaseModel):
    id: str
    text: str
    jurisdiction: str | None = None
    framework: str | None = None
    citation: str | None = None
    control_ids: list[str] = []

    def to_record(self) -> ObligationRecord:
        return ObligationRecord(
            id=self.id,
            text=self.text,
            jurisdiction=self.jurisdiction,
            framework=self.framework,
            citation=self.citation,
            control_ids=tuple(self.control_ids),
        )


class CreateGuardrailRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    obligations: list[ObligationIn]


class CompileRegoRequest(BaseModel):
    obligations: list[ObligationIn]


class CheckActionRequest(BaseModel):
    # Intentionally untyped/passthrough: this is the raw action dict handed
    # to `CompliVibePolicyProvider.check_action`, which itself enforces the
    # envelope/payload split (see services/envelope.py) and raises
    # `ValueError` -- translated to HTTP 400 below -- if payload-shaped
    # fields are present. Modeling this as `dict[str, Any]` here would just
    # duplicate that validation less strictly, so it is left to the
    # provider.
    model_config = {"extra": "allow"}


def _guardrail_response(guardrail: AiPolicyGuardrail) -> dict:
    """Shape a guardrail for an API response.

    Provenance ids are fine to return (that's the point of the patent
    claim); the full obligation *text* is not persisted on the guardrail
    itself and is therefore never leaked here either.
    """
    return {
        "id": guardrail.id,
        "organization_id": guardrail.organization_id,
        "ai_system_id": guardrail.ai_system_id,
        "name": guardrail.name,
        "description": guardrail.description,
        "rego_package": guardrail.rego_package,
        "rego_policy": guardrail.rego_policy,
        "source_obligation_ids": list(guardrail.source_obligation_ids),
        "compiled_at": guardrail.compiled_at.isoformat() if guardrail.compiled_at else None,
        "is_active": guardrail.is_active,
    }


# ---------------------------------------------------------------------------
# Local, test-only OPA transport: evaluates via the vendored `opa` CLI
# instead of a live OPA HTTP deployment.
#
# See ASSUMPTIONS.md / core-side-patch/services/opa_client.py's own
# docstring: standing up and operating a real OPA server is explicitly out
# of scope for this repo. `OpaClient` is an HTTP client only, and normally
# expects a real OPA base_url. Since this standalone repo has no live OPA
# deployment to point the check-action endpoint at, this transport wraps
# the same vendored `opa eval` subprocess the rest of this repo's tests use
# (see tests/unit/_opa_test_util.py) behind an httpx.MockTransport, so
# `OpaClient`'s real HTTP-request/response code path is still exercised
# end-to-end. Production wiring should construct `OpaClient` with a real
# `base_url` instead of this transport.
# ---------------------------------------------------------------------------


def _local_opa_eval_handler(rego_text: str) -> Callable[[httpx.Request], httpx.Response]:
    """Build a per-guardrail (not per-request) `httpx.MockTransport` handler.

    `rego_text` is fixed for the lifetime of a given handler (it's the
    compiled Rego for one guardrail), so the backing temp file is created
    ONCE here, not per request. An earlier version created a fresh, randomly
    -named `tempfile.NamedTemporaryFile` (and `pathlib.Path(...).unlink()`'d
    it) on every single call -- functionally correct, but each unique
    filename gets permanently `sys.intern()`'d by `pathlib`'s path-parsing
    machinery, an unbounded, process-lifetime cache. Confirmed via a
    `tracemalloc` snapshot diff (see ASSUMPTIONS.md and
    `tests/stress/STRESS_TEST_RESULTS.md`) as a real, if small
    (tens of bytes/call), contributor to heap growth under sustained load --
    entirely specific to this repo's test-only bridge to the vendored `opa`
    CLI (a real `OpaClient` pointed at a live OPA server creates no temp
    files at all), but worth eliminating since it costs nothing to do so.
    """
    rego_file = tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False)
    rego_file.write(rego_text)
    rego_file.close()
    rego_path = rego_file.name

    def _handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        # `CompliVibePolicyProvider.check_action()` already nests the
        # envelope under an "action" key to match the derivation engine's
        # compiled Rego, which reads `input.action.<field>` (see
        # services/policy_provider.py and services/derivation_engine.py).
        # `body["input"]` here is therefore already `{"action": {...}}` --
        # pass it straight through, no re-wrapping.
        input_data = body.get("input", {})

        prefix = "/v1/data/"
        path = request.url.path
        rel = path[len(prefix):] if path.startswith(prefix) else path
        query = "data." + rel.replace("/", ".")

        proc = subprocess.run(
            ["opa", "eval", "--format", "json", "--input", "/dev/stdin", "--data", rego_path, query],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return httpx.Response(500, text=proc.stderr)
        result = json.loads(proc.stdout)
        expressions = result.get("result", [{}])[0].get("expressions", [{}])
        value = expressions[0].get("value") if expressions else None
        return httpx.Response(200, json={"result": value})

    return _handler


def _default_policy_provider_factory(
    rego_package: str,
    rego_policy: str,
    *,
    sign_receipt_fn,
    previous_receipt_hash: str | None,
) -> CompliVibePolicyProvider:
    opa_client = OpaClient(
        base_url="http://local-opa.test",
        client=httpx.Client(transport=httpx.MockTransport(_local_opa_eval_handler(rego_policy))),
    )
    return CompliVibePolicyProvider(
        opa_client,
        rego_package,
        sign_receipt_fn=sign_receipt_fn,
        previous_receipt_hash=previous_receipt_hash,
    )


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    *,
    ai_system_registry: InMemoryAiSystemRegistry | None = None,
    audit_service: AuditService | None = None,
    rate_limiter: TokenBucketRateLimiter | None = None,
    signing_key_hex: str = "cd" * 32,
    policy_provider_factory: Callable[..., CompliVibePolicyProvider] = _default_policy_provider_factory,
) -> FastAPI:
    """Build a fully-wired FastAPI app exposing the guardrail endpoints.

    A factory (rather than one module-level `app`) so tests can inject
    fully isolated state per test:

    - `ai_system_registry`: see `permissions.InMemoryAiSystemRegistry` --
      this repo's stand-in for a real `ai_system` table.
    - `audit_service`: see `audit.AuditService` -- this repo's in-memory
      stand-in for the real, carried-over P2 audit service.
    - `rate_limiter`: defaults to a generous bucket; tests that want to
      exercise the 429 path should pass a `TokenBucketRateLimiter` with a
      tiny capacity.
    - `signing_key_hex`: seeds a demo `ReceiptSigner` used by the
      check-action endpoint. In production this key must be supplied and
      held entirely within the *customer's* deployment (see
      `services/receipts.py`'s key-custody boundary/Claim 4) -- this
      endpoint signing its own receipts with a key it holds itself is only
      appropriate for this standalone repo's demo/test wiring, and is
      flagged here rather than silently done.
    - `policy_provider_factory`: swap in a different `CompliVibePolicyProvider`
      construction path (e.g. a real OPA `base_url` in production) without
      touching route logic.
    """
    ai_system_registry = ai_system_registry or InMemoryAiSystemRegistry()
    audit_service = audit_service or AuditService()
    rate_limiter = rate_limiter or TokenBucketRateLimiter(capacity=1000, refill_per_second=1000.0)
    signer = ReceiptSigner(signing_key_hex=signing_key_hex)

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    # `StaticPool` over `sqlite://` means every `SessionLocal()` shares one
    # single underlying DBAPI connection. `check_same_thread=False` only
    # disables sqlite3's own thread-affinity check -- it does not make
    # concurrent execute/fetch calls on that one connection from multiple
    # threads safe. Under concurrent requests (see
    # tests/stress/test_concurrent_check_action.py) that showed up as
    # corrupted row reads (e.g. "Invalid isoformat string: ''" from an
    # interleaved cursor fetch). This lock serializes DB access for the
    # lifetime of this demo in-memory engine; a real deployment would use a
    # real connection pool (e.g. Postgres) instead of this single-connection
    # SQLite stand-in and would not need this lock.
    _db_lock = threading.Lock()

    # In-memory receipt chain store, keyed by ai_system_id. This repo has
    # no durable receipt-storage table (Workstream F/G own the receipt
    # *shape*, not persistence); a simple in-process dict is enough to
    # exercise endpoints (d)/(e) below end to end.
    receipt_store: dict[str, list[Receipt]] = {}

    def get_db():
        with _db_lock:
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

    def get_registry() -> InMemoryAiSystemRegistry:
        return ai_system_registry

    def get_audit() -> AuditService:
        return audit_service

    router = APIRouter()

    # -- (a) create guardrail ------------------------------------------------

    @router.post("/ai-systems/{ai_system_id}/guardrails", status_code=201)
    def create_guardrail(
        ai_system_id: str,
        body: CreateGuardrailRequest,
        membership: Membership = Depends(require_permission("ai_guardrail.create")),
        db: Session = Depends(get_db),
        registry: InMemoryAiSystemRegistry = Depends(get_registry),
        audit: AuditService = Depends(get_audit),
    ):
        if body.organization_id != membership.organization_id:
            # The caller's own org claim (header) disagrees with the body's
            # claimed organization_id -- not a cross-org *existence* leak
            # (that's the ai_system_id check below), just a bad request.
            raise HTTPException(status_code=403, detail="organization_id does not match caller's membership")

        ai_system = _get_org_ai_system(ai_system_id, membership.organization_id, db=registry)
        if ai_system is None:
            raise HTTPException(status_code=404, detail="ai_system not found")

        obligations = [o.to_record() for o in body.obligations]
        try:
            spec, rego_text = derive_and_compile(obligations, org_id=body.organization_id)
        except ValueError as exc:
            # derive_and_compile validates its own Rego output before
            # returning it (see services/derivation_engine.py's
            # validate_rego_syntax) -- a ValueError here means the
            # derivation engine produced syntactically invalid Rego, which
            # must never be persisted. Surface it as a clear client error,
            # not an unhandled 500.
            REGO_COMPILATION_RESULTS.labels(result="failure").inc()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception:
            REGO_COMPILATION_RESULTS.labels(result="failure").inc()
            raise
        REGO_COMPILATION_RESULTS.labels(result="success").inc()
        rego_package = f"complivibe.guardrails.org_{rego_package_slug(body.organization_id)}"

        guardrail = AiPolicyGuardrail.from_constraint_spec(
            organization_id=body.organization_id,
            ai_system_id=ai_system_id,
            name=body.name,
            description=body.description,
            rego_policy=rego_text,
            rego_package=rego_package,
            constraint_spec=spec,
            compiled_at=datetime.now(timezone.utc),
        )
        db.add(guardrail)
        db.commit()
        db.refresh(guardrail)

        audit.write_audit_log(
            action="guardrail.created",
            entity_type="ai_policy_guardrail",
            organization_id=body.organization_id,
            actor_user_id=membership.user_id,
            entity_id=guardrail.id,
            after_json=_guardrail_response(guardrail),
        )
        return _guardrail_response(guardrail)

    # -- (b) recompile guardrail ---------------------------------------------

    @router.post("/ai-guardrails/{guardrail_id}/compile-rego")
    def compile_rego(
        guardrail_id: str,
        body: CompileRegoRequest,
        membership: Membership = Depends(require_permission("ai_guardrail.recompile")),
        db: Session = Depends(get_db),
        audit: AuditService = Depends(get_audit),
    ):
        guardrail = db.get(AiPolicyGuardrail, guardrail_id)
        # Same 404-not-403 convention as ai_system_id lookups: a guardrail
        # that belongs to another org must look identical, from the
        # caller's point of view, to a guardrail that does not exist.
        if guardrail is None or guardrail.organization_id != membership.organization_id:
            raise HTTPException(status_code=404, detail="guardrail not found")

        submitted_ids = {o.id for o in body.obligations}
        existing_ids = set(guardrail.source_obligation_ids)
        if submitted_ids != existing_ids:
            # Recompiling from a stable, previously-agreed obligation set,
            # not silently redefining what a guardrail is derived from --
            # see module docstring / task brief for the rationale. A caller
            # that wants to change the obligation set backing a guardrail
            # should create a new guardrail, not recompile this one.
            raise HTTPException(
                status_code=400,
                detail=(
                    "submitted obligation ids do not match this guardrail's "
                    f"existing source_obligation_ids; expected {sorted(existing_ids)!r}, "
                    f"got {sorted(submitted_ids)!r}"
                ),
            )

        obligations = [o.to_record() for o in body.obligations]
        try:
            spec, rego_text = derive_and_compile(obligations, org_id=guardrail.organization_id)
        except ValueError as exc:
            REGO_COMPILATION_RESULTS.labels(result="failure").inc()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception:
            REGO_COMPILATION_RESULTS.labels(result="failure").inc()
            raise
        REGO_COMPILATION_RESULTS.labels(result="success").inc()

        before = _guardrail_response(guardrail)
        from services.provenance import serialize_constraint_spec, source_obligation_ids_from_spec

        guardrail.rego_policy = rego_text
        guardrail.constraint_spec_json = serialize_constraint_spec(spec)
        guardrail.source_obligation_ids = source_obligation_ids_from_spec(spec)
        guardrail.compiled_at = datetime.now(timezone.utc)
        db.add(guardrail)
        db.commit()
        db.refresh(guardrail)

        audit.write_audit_log(
            action="guardrail.recompiled",
            entity_type="ai_policy_guardrail",
            organization_id=guardrail.organization_id,
            actor_user_id=membership.user_id,
            entity_id=guardrail.id,
            before_json=before,
            after_json=_guardrail_response(guardrail),
        )
        return _guardrail_response(guardrail)

    # -- (c) check-action -----------------------------------------------------

    def _rate_limit_guard(
        membership: Membership = Depends(require_permission("ai_guardrail.check")),
    ) -> Membership:
        guard = rate_limit_dependency(rate_limiter, lambda: membership.organization_id)
        try:
            guard()
        except RateLimitExceeded as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        return membership

    @router.post("/ai-systems/{ai_system_id}/guardrails/check")
    def check_action(
        ai_system_id: str,
        body: CheckActionRequest,
        membership: Membership = Depends(_rate_limit_guard),
        db: Session = Depends(get_db),
        registry: InMemoryAiSystemRegistry = Depends(get_registry),
        audit: AuditService = Depends(get_audit),
    ):
        ai_system = _get_org_ai_system(ai_system_id, membership.organization_id, db=registry)
        if ai_system is None:
            raise HTTPException(status_code=404, detail="ai_system not found")

        guardrail = (
            db.query(AiPolicyGuardrail)
            .filter(
                AiPolicyGuardrail.ai_system_id == ai_system_id,
                AiPolicyGuardrail.organization_id == membership.organization_id,
                AiPolicyGuardrail.is_active.is_(True),
            )
            .order_by(AiPolicyGuardrail.created_at.desc())
            .first()
        )
        if guardrail is None:
            raise HTTPException(status_code=404, detail="no active guardrail configured for this ai_system")

        existing_chain = receipt_store.get(ai_system_id, [])
        previous_hash = existing_chain[-1].receipt_hash if existing_chain else None

        provider = policy_provider_factory(
            guardrail.rego_package,
            guardrail.rego_policy,
            sign_receipt_fn=signer.sign_receipt,
            previous_receipt_hash=previous_hash,
        )

        raw_action = body.model_dump()
        timestamp = raw_action.get("timestamp") or datetime.now(timezone.utc).isoformat()

        started = time.monotonic()
        try:
            result = provider.check_action(raw_action, timestamp=timestamp)
        except ValueError as exc:
            # Payload-shaped fields present in the raw action -- see
            # services/envelope.py's build_envelope(). This is a client
            # error (bad request shape), not a server error.
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            CHECK_ACTION_LATENCY.observe(time.monotonic() - started)
            # NOTE: `provider`'s underlying `OpaClient` is NOT closed here.
            # The default `policy_provider_factory` builds a fresh one per
            # request (needed because this repo's test-only OPA transport is
            # bound to one guardrail's Rego text), but `policy_provider_factory`
            # is a pluggable seam, and other factories deliberately share ONE
            # long-lived `OpaClient` across many requests -- exactly as a
            # real production deployment should (a single connection-pooled
            # client reused across requests, not reconnected per call). See
            # `tests/unit/test_observability_metrics.py`'s
            # `_unreachable_policy_provider_factory` for a factory that does
            # this on purpose, specifically so the circuit breaker's
            # consecutive-failure state persists across requests. Closing
            # here would break that. Ownership/lifecycle of the `OpaClient`
            # is the factory's responsibility, not this endpoint's -- see
            # `services/policy_provider.py::CompliVibePolicyProvider.close()`
            # for callers (e.g. a one-off script) that DO own a per-call
            # client and should close it themselves.

        decision_label = "allow" if result.decision.allowed else "deny"
        CHECK_ACTION_DECISIONS.labels(decision=decision_label).inc()

        event = AiGuardrailEvent(
            guardrail_id=guardrail.id,
            organization_id=membership.organization_id,
            ai_system_id=ai_system_id,
            decision=decision_label,
            reason=result.decision.reason,
            action_envelope_json=result.envelope.model_dump(),
            receipt_id=result.receipt.receipt_id if result.receipt else None,
            evaluation_ms=result.decision.latency_ms,
        )
        db.add(event)
        db.commit()

        if result.receipt is not None:
            receipt_store.setdefault(ai_system_id, []).append(result.receipt)

        audit.write_audit_log(
            action="guardrail.checked",
            entity_type="ai_guardrail_event",
            organization_id=membership.organization_id,
            actor_user_id=membership.user_id,
            entity_id=event.id,
            after_json={"decision": decision_label, "reason": result.decision.reason},
        )

        return {
            "allowed": result.decision.allowed,
            "reason": result.decision.reason,
            "receipt_id": result.receipt.receipt_id if result.receipt else None,
        }

    # -- (d) receipt chain ------------------------------------------------

    @router.get("/ai-systems/{ai_system_id}/receipt-chain")
    def get_receipt_chain(
        ai_system_id: str,
        membership: Membership = Depends(require_permission("ai_guardrail.read")),
        registry: InMemoryAiSystemRegistry = Depends(get_registry),
    ):
        ai_system = _get_org_ai_system(ai_system_id, membership.organization_id, db=registry)
        if ai_system is None:
            raise HTTPException(status_code=404, detail="ai_system not found")

        return {"ai_system_id": ai_system_id, "receipts": [asdict(r) for r in receipt_store.get(ai_system_id, [])]}

    # -- (e) verify chain ---------------------------------------------------

    @router.post("/ai-systems/{ai_system_id}/verify-chain")
    def verify_chain_endpoint(
        ai_system_id: str,
        membership: Membership = Depends(require_permission("ai_guardrail.read")),
        registry: InMemoryAiSystemRegistry = Depends(get_registry),
    ):
        ai_system = _get_org_ai_system(ai_system_id, membership.organization_id, db=registry)
        if ai_system is None:
            raise HTTPException(status_code=404, detail="ai_system not found")

        # services/receipt_chain.py is assumed-interface (see task brief /
        # ASSUMPTIONS.md): another workstream (G) may land it concurrently.
        # If it isn't present yet, degrade to a clear 501 rather than
        # failing the whole app's import.
        try:
            from services.receipt_chain import verify_chain
        except ImportError as exc:
            raise HTTPException(
                status_code=501,
                detail=(
                    "chain verification is not available yet: "
                    "services.receipt_chain has not landed in this build"
                ),
            ) from exc

        result = verify_chain(receipt_store.get(ai_system_id, []))
        CHAIN_VERIFICATION_RESULTS.labels(result="passed" if result.passed else "failed").inc()
        return asdict(result)

    # -- (f) SDK snippet (customer-facing, no branding) ----------------------

    @router.get("/ai-governance/policy-provider/sdk-snippet")
    def sdk_snippet():
        # CUSTOMER FACING: zero mention of any third-party toolkit or
        # package name anywhere in this string -- see PATENT.md's branding
        # rule at the end of the document. Generic terms only.
        snippet = """\
# Integrating your agent framework with the policy enforcement runtime

import httpx

def check_action(action: dict, *, org_id: str, user_id: str, ai_system_id: str) -> dict:
    \"\"\"Call this before executing an agent action, from within your own
    agent framework's pre-execution hook.\"\"\"
    response = httpx.post(
        f"https://your-deployment.example.com/ai-systems/{ai_system_id}/guardrails/check",
        json=action,
        headers={
            "X-Org-Id": org_id,
            "X-User-Id": user_id,
            "X-Role": "agent-runtime",
        },
        timeout=2.0,
    )
    response.raise_for_status()
    decision = response.json()
    if not decision["allowed"]:
        raise PermissionError(f"action denied: {decision['reason']}")
    return decision
"""
        return {"language": "python", "snippet": snippet}

    app = FastAPI(title="CompliVibe AI Guardrails API")
    app.include_router(router)
    app.state.audit_service = audit_service
    app.state.ai_system_registry = ai_system_registry
    app.state.rate_limiter = rate_limiter
    app.state.receipt_store = receipt_store
    return app

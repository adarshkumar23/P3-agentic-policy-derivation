# mypy: allow-untyped-defs
"""CompliVibePolicyProvider: this repo's external-policy-backend adapter.

Scope note (see PATENT.md §1.1(2) and ASSUMPTIONS.md's "Newly verified"
section): the real third-party policy enforcement runtime (named by its
actual identity only in PATENT.md's prior-art disclosure, per this repo's
branding boundary) does not expose a literal `PolicyProviderInterface` ABC.
Its actual, verified extension point is a *structural* protocol --
satisfied by any object exposing a `name` property, an `evaluate(action,
context) -> PolicyDecisionResult` method, and a `healthy() -> bool` method.
`CompliVibePolicyProvider` below is built against that verified structural
protocol, not an invented ABC name, and does not import the runtime itself
(not installable from any verified environment -- see ASSUMPTIONS.md); it
defines a local `PolicyDecisionResult` dataclass matching the same field
shape so registering with the real runtime's backend registry is a one-line
swap once it is actually installable.

This module is intentionally thin glue: it does not intercept actions, does
not evaluate Rego itself (that's `services.opa_client.OpaClient`, talking to
a separately-deployed OPA), and does not hold a signing key (that's
`services.receipts.ReceiptSigner`, meant to run in the customer's own
deployment -- see the `sign_receipt_fn` parameter below). It only: builds a
safe envelope from a raw action, asks OPA for a decision, asks the
caller-supplied signer (if any) to produce a receipt, and returns a
decision result plus enough detail to log an `AiGuardrailEvent`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from services.envelope import ActionEnvelope, build_envelope
from services.opa_client import OpaClient
from services.receipts import Receipt

__all__ = [
    "PolicyDecisionResult",
    "CheckActionResult",
    "CompliVibePolicyProvider",
]


@dataclass(frozen=True)
class PolicyDecisionResult:
    """Mirrors the real policy enforcement runtime's `PolicyDecisionResult`
    field shape (see PATENT.md §1.1(2) for the verified source):
    `allowed`, `reason`, `backend`, `latency_ms`, `raw_response`.
    """

    allowed: bool
    reason: str
    backend: str
    latency_ms: float
    raw_response: Any = None


@dataclass(frozen=True)
class CheckActionResult:
    """This repo's own return shape for a full check-action call: the
    protocol-shaped decision plus what the caller needs to log an
    `AiGuardrailEvent` and store a receipt (Workstream A / H own that
    persistence; this dataclass just carries the pieces to it).
    """

    decision: PolicyDecisionResult
    envelope: ActionEnvelope
    receipt: Receipt | None


class _SupportsSignReceipt(Protocol):
    def __call__(
        self,
        *,
        decision: str,
        reasons: list[str],
        envelope_hash: str,
        previous_receipt_hash: str | None,
        timestamp: str,
    ) -> Receipt: ...


class CompliVibePolicyProvider:
    """This repo's implementation of the policy enforcement runtime's `ExternalPolicyBackend`
    structural protocol: a `name` property, `evaluate(action, context)`, and
    `healthy()`.

    Receipt signing is optional and deliberately not owned here: `
    sign_receipt_fn`, if provided, is expected to be a callable that runs
    the signing operation inside the *customer's* deployment (e.g. backed
    by `services.receipts.ReceiptSigner` instantiated with a key that never
    leaves that deployment, or -- once the seam in `services/receipts.py`
    is closed -- the real runtime's own signing capability). If no signer
    is supplied, `evaluate()` still returns a decision; it just skips
    receipt creation, since CompliVibe's core has no signing key of its own
    to fall back on.
    """

    def __init__(
        self,
        opa_client: OpaClient,
        rego_package: str,
        sign_receipt_fn: _SupportsSignReceipt | None = None,
        previous_receipt_hash: str | None = None,
    ) -> None:
        self._opa_client = opa_client
        self._rego_package = rego_package
        self._sign_receipt_fn = sign_receipt_fn
        self._previous_receipt_hash = previous_receipt_hash
        # Guards the read-modify-write of `_previous_receipt_hash` below.
        # Without this lock, two threads calling `check_action` concurrently
        # on the same provider instance can both read the same
        # `_previous_receipt_hash` before either writes its update, each
        # signing a receipt that claims the same parent -- a fork in the
        # hash chain rather than a single unbroken line. Found and
        # demonstrated by tests/stress/test_receipt_chain_concurrency.py.
        self._chain_lock = threading.Lock()

    @property
    def name(self) -> str:
        return "complivibe-derived-guardrail"

    def evaluate(self, action: str, context: dict) -> PolicyDecisionResult:
        """Satisfies the policy enforcement runtime's `ExternalPolicyBackend.evaluate(action,
        context)` shape. `context` is expected to already be envelope-safe
        (callers should build it via `services.envelope.build_envelope`
        before calling this, or call `check_action` below, which does that
        for you and also produces a receipt).
        """
        opa_decision = self._opa_client.evaluate(package=self._rego_package, input_data=context)
        reason = "" if opa_decision.allowed else (opa_decision.error or "denied by policy")
        return PolicyDecisionResult(
            allowed=opa_decision.allowed,
            reason=reason,
            backend=self.name,
            latency_ms=opa_decision.evaluation_ms,
            raw_response=opa_decision.raw_result,
        )

    def close(self) -> None:
        """Close the underlying `OpaClient` (and its `httpx.Client`).

        `check_action` (see `core-side-patch/api/guardrails.py`) constructs
        a fresh `CompliVibePolicyProvider`/`OpaClient`/`httpx.Client` per
        request (the per-guardrail Rego package varies, so the client
        can't trivially be shared across requests in this repo's
        test-harness wiring). An unclosed `httpx.Client` holds a real
        connection-pool object with a reference cycle in its internal
        transport stack -- relying on `__del__`/GC alone to reap it lets
        many of them pile up as live-but-unreachable garbage between full
        GC passes, which showed up as real, measurable heap growth under
        sustained load (see `tests/stress/test_long_running_memory_check.py`).
        Callers that construct a per-request provider MUST close it (e.g.
        in a `finally` block) once the request is done.
        """
        self._opa_client.close()

    def __enter__(self) -> "CompliVibePolicyProvider":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def healthy(self) -> bool:
        # A lightweight liveness check: evaluate a trivial, always-defined
        # query shape against the configured package. Any failure surfaces
        # as a non-"opa" source in the underlying client, which we treat as
        # unhealthy -- consistent with this repo's fail-closed posture.
        probe = self._opa_client.evaluate(package=self._rego_package, input_data={})
        return probe.source == "opa"

    def check_action(
        self, raw_action: dict, *, timestamp: str
    ) -> CheckActionResult:
        """The higher-level, envelope-aware entry point Workstream H's
        check-action endpoint should call: builds a safe envelope from the
        raw action (rejecting any payload-shaped fields -- see
        `services.envelope.build_envelope`), evaluates it, and -- if a
        signer was configured -- produces a chained receipt.
        """
        envelope = build_envelope(raw_action)
        # `services.derivation_engine.compile_constraint_spec` generates Rego
        # that reads `input.action.<field>` (e.g. `input.action.amount`), not
        # a flat `input.<field>` -- so the envelope must be nested under an
        # "action" key here to match the compiled policy's actual input
        # contract, not just passed through as-is.
        context = {"action": envelope.model_dump()}
        decision = self.evaluate(action=envelope.action_type, context=context)

        receipt: Receipt | None = None
        if self._sign_receipt_fn is not None:
            envelope_hash = _hash_envelope(envelope)
            reasons = [decision.reason] if decision.reason else []
            # The read of `_previous_receipt_hash`, the signing call that
            # embeds it as this receipt's parent, and the write-back of the
            # new `receipt_hash` must all happen as one atomic unit -- a
            # hash chain has an inherently sequential dependency between
            # consecutive links, so concurrent calls on the same provider
            # instance are serialized here rather than racing on
            # `_previous_receipt_hash`. See the lock's definition in
            # `__init__` for the race this closes.
            with self._chain_lock:
                receipt = self._sign_receipt_fn(
                    decision="allow" if decision.allowed else "deny",
                    reasons=reasons,
                    envelope_hash=envelope_hash,
                    previous_receipt_hash=self._previous_receipt_hash,
                    timestamp=timestamp,
                )
                self._previous_receipt_hash = receipt.receipt_hash

        return CheckActionResult(decision=decision, envelope=envelope, receipt=receipt)


def _hash_envelope(envelope: ActionEnvelope) -> str:
    import hashlib
    import json

    canonical = json.dumps(envelope.model_dump(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

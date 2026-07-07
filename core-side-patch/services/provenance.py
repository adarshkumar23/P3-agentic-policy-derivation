# mypy: allow-untyped-defs
"""Helpers for turning a derivation-engine ConstraintSpec into the two
provenance-bearing fields persisted on `AiPolicyGuardrail`
(see `models.py` and PATENT.md Claim 1: "retaining a reference to its
source obligation record").

Kept separate from `derivation_engine.py` because these functions are
purely about *persistence shape* (dict/list serialization for a JSON
column), not about deriving or compiling policy — the derivation engine
itself is not aware of how (or whether) its output gets stored.
"""

from __future__ import annotations

from services.derivation_engine import ConstraintSpec


def _financial_limit_to_dict(limit) -> dict:
    return {
        "max_amount": limit.max_amount,
        "currency": limit.currency,
        "per": limit.per,
        "source_obligation_ids": list(limit.source_obligation_ids),
    }


def _geographic_scope_to_dict(scope) -> dict | None:
    if scope is None:
        return None
    return {
        "allowed_regions": list(scope.allowed_regions),
        "residency_required": scope.residency_required,
        "source_obligation_ids": list(scope.source_obligation_ids),
    }


def _data_scope_to_dict(scope) -> dict | None:
    if scope is None:
        return None
    return {
        "restricted_categories": list(scope.restricted_categories),
        "cross_border_transfer_allowed": scope.cross_border_transfer_allowed,
        "source_obligation_ids": list(scope.source_obligation_ids),
    }


def _approval_requirement_to_dict(req) -> dict:
    return {
        "required": req.required,
        "min_approvers": req.min_approvers,
        "source_obligation_ids": list(req.source_obligation_ids),
    }


def serialize_constraint_spec(spec: ConstraintSpec) -> dict:
    """Serialize a ConstraintSpec into a JSON-able dict snapshot.

    This is the payload stored in `AiPolicyGuardrail.constraint_spec_json`
    so that a guardrail's provenance (which obligation(s) produced which
    financial limit / geographic scope / data scope / approval requirement)
    is inspectable without recompiling the Rego from scratch.
    """
    return {
        "source_obligation_ids": list(spec.source_obligation_ids),
        "financial_limits": [_financial_limit_to_dict(limit) for limit in spec.financial_limits],
        "geographic_scope": _geographic_scope_to_dict(spec.geographic_scope),
        "data_scope": _data_scope_to_dict(spec.data_scope),
        "approval_requirements": [
            _approval_requirement_to_dict(req) for req in spec.approval_requirements
        ],
        "unrecognized_obligation_ids": list(spec.unrecognized_obligation_ids),
    }


def source_obligation_ids_from_spec(spec: ConstraintSpec) -> list[str]:
    """Return the obligation ids a ConstraintSpec (and hence its compiled
    Rego) was derived from, in stable order, deduplicated.

    This is the value stored in `AiPolicyGuardrail.source_obligation_ids` —
    the top-level provenance field required by the narrowed patent claim.
    `spec.source_obligation_ids` already covers this (it's set to the full
    input obligation list in `derive_constraint_spec`), but we route through
    this helper so callers have one seam to depend on regardless of how the
    engine's internal representation evolves.
    """
    return list(dict.fromkeys(spec.source_obligation_ids))

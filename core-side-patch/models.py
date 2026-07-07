# mypy: allow-untyped-defs
"""Core DB models for CompliVibe-authored AI guardrails (Workstream A).

`AiPolicyGuardrail` is the persistence shape for the output of
`services.derivation_engine.derive_and_compile`: it stores the compiled
Rego text *and* the provenance that produced it (which regulatory
obligation record(s) each part of the constraint spec was derived from —
see PATENT.md Claim 1, "retaining a reference to its source obligation
record"). Storing only the compiled Rego, with no link back to the
obligations that produced it, would not support that claim.

`AiGuardrailEvent` is a check-action audit row. It intentionally stores
only the safe action *envelope*, never the action *payload* (see
Workstream E for that split) — this module must not grow payload-shaped
columns. Receipt storage itself belongs to Workstream F; this model only
keeps a pointer (`receipt_id`) to a receipt stored elsewhere.

Everything here is glue around CompliVibe's own data (obligations,
guardrails, check-action events); nothing in this module talks to, wraps,
or reimplements the third-party policy enforcement runtime.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from services.derivation_engine import ConstraintSpec
from services.provenance import serialize_constraint_spec, source_obligation_ids_from_spec

__all__ = [
    "Base",
    "AiPolicyGuardrail",
    "AiGuardrailEvent",
    "serialize_constraint_spec",
    "source_obligation_ids_from_spec",
]


def _uuid_str() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class AiPolicyGuardrail(Base):
    """A compiled, tenant-scoped guardrail derived from one or more
    regulatory obligations.

    `source_obligation_ids` and `constraint_spec_json` together are the
    provenance record: they let a guardrail's Rego be traced back to the
    obligation text that produced it, and let the constraint spec that
    produced the Rego be inspected without recompiling it.
    """

    __tablename__ = "ai_policy_guardrails"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)

    organization_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ai_system_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text(), nullable=True)

    rego_policy: Mapped[str] = mapped_column(Text(), nullable=False)
    rego_package: Mapped[str] = mapped_column(String(255), nullable=False)

    # Provenance fields (patent Claim 1: "retaining a reference to its
    # source obligation record"). Do not remove without an equivalent
    # replacement -- a schema that only stores the compiled Rego would not
    # support the provenance claim.
    source_obligation_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    constraint_spec_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    compiled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    @classmethod
    def from_constraint_spec(
        cls,
        *,
        organization_id: str,
        ai_system_id: str,
        name: str,
        rego_policy: str,
        rego_package: str,
        constraint_spec: ConstraintSpec,
        description: str | None = None,
        compiled_at: datetime | None = None,
    ) -> "AiPolicyGuardrail":
        """Build a guardrail row from a compiled ConstraintSpec, populating
        the provenance fields via the `services.provenance` helpers.
        """
        return cls(
            organization_id=organization_id,
            ai_system_id=ai_system_id,
            name=name,
            description=description,
            rego_policy=rego_policy,
            rego_package=rego_package,
            source_obligation_ids=source_obligation_ids_from_spec(constraint_spec),
            constraint_spec_json=serialize_constraint_spec(constraint_spec),
            compiled_at=compiled_at,
        )


class AiGuardrailEvent(Base):
    """One row per check-action call evaluated against a guardrail.

    `action_envelope_json` must only ever contain the safe envelope
    (see Workstream E) -- never the action payload. `receipt_id` is a
    pointer to a signed receipt owned and stored by Workstream F; this
    table does not own receipt content.
    """

    __tablename__ = "ai_guardrail_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)

    guardrail_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("ai_policy_guardrails.id"), nullable=False, index=True
    )

    organization_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ai_system_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)

    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text(), nullable=True)

    action_envelope_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    receipt_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    evaluation_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

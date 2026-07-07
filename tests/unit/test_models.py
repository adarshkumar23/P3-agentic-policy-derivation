"""Tests for the core DB models (Workstream A).

Uses an in-memory SQLite engine to validate schema creation, provenance
round-tripping from a real `derive_and_compile()` call, and basic
tenant-scoped query filtering. Deep tenant-isolation testing belongs to
Workstream L; this is a sanity check only.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from models import AiGuardrailEvent, AiPolicyGuardrail, Base
from services.derivation_engine import ObligationRecord, derive_and_compile, rego_package_slug


@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def obligations() -> list[ObligationRecord]:
    return [
        ObligationRecord(
            id="obl-1",
            text="Transaction amounts shall not exceed $10,000 per transaction.",
            jurisdiction="US",
            framework="Reg-E",
            citation="12 CFR 1005",
            control_ids=("CTRL-1",),
        ),
        ObligationRecord(
            id="obl-2",
            text=(
                "Personal data shall not leave the territory of India and shall not be "
                "transferred outside the territory of India."
            ),
            jurisdiction="India",
            framework="RBI",
            citation="RBI/2018-19/157",
            control_ids=("CTRL-2",),
        ),
        ObligationRecord(
            id="obl-3",
            text="High-value transactions require prior approval from two approvers.",
            jurisdiction="US",
            framework="Internal",
            citation=None,
            control_ids=(),
        ),
    ]


def test_guardrail_provenance_round_trips(engine, obligations):
    org_id = "org-abc-123"
    spec, rego_text = derive_and_compile(obligations, org_id)

    guardrail = AiPolicyGuardrail.from_constraint_spec(
        organization_id=org_id,
        ai_system_id="ai-system-1",
        name="Core banking guardrail",
        rego_policy=rego_text,
        rego_package=f"complivibe.guardrails.org_{rego_package_slug(org_id)}",
        constraint_spec=spec,
        description="Derived from Reg-E, RBI data localization, and internal approval obligations.",
        compiled_at=datetime.now(timezone.utc),
    )

    with Session(engine) as session:
        session.add(guardrail)
        session.commit()
        guardrail_id = guardrail.id

    with Session(engine) as session:
        fetched = session.get(AiPolicyGuardrail, guardrail_id)
        assert fetched is not None
        assert fetched.organization_id == org_id
        assert fetched.rego_policy == rego_text
        assert fetched.rego_package == f"complivibe.guardrails.org_{rego_package_slug(org_id)}"

        # Provenance: source_obligation_ids must match what derivation produced.
        assert set(fetched.source_obligation_ids) == set(spec.source_obligation_ids)
        assert fetched.source_obligation_ids == list(spec.source_obligation_ids)

        # constraint_spec_json must be inspectable without recompiling.
        snapshot = fetched.constraint_spec_json
        assert snapshot["source_obligation_ids"] == list(spec.source_obligation_ids)
        assert len(snapshot["financial_limits"]) == len(spec.financial_limits)
        assert snapshot["financial_limits"][0]["source_obligation_ids"] == ["obl-1"]
        assert snapshot["geographic_scope"]["source_obligation_ids"] == ["obl-2"]
        assert snapshot["approval_requirements"][0]["source_obligation_ids"] == ["obl-3"]

        assert fetched.is_active is True
        assert fetched.created_at is not None
        assert fetched.updated_at is not None


def test_guardrail_event_insert_and_org_scoped_query(engine, obligations):
    org_a = "org-a"
    org_b = "org-b"

    spec_a, rego_a = derive_and_compile(obligations, org_a)
    guardrail_a = AiPolicyGuardrail.from_constraint_spec(
        organization_id=org_a,
        ai_system_id="ai-system-1",
        name="Guardrail A",
        rego_policy=rego_a,
        rego_package=f"complivibe.guardrails.org_{rego_package_slug(org_a)}",
        constraint_spec=spec_a,
    )

    spec_b, rego_b = derive_and_compile(obligations, org_b)
    guardrail_b = AiPolicyGuardrail.from_constraint_spec(
        organization_id=org_b,
        ai_system_id="ai-system-2",
        name="Guardrail B",
        rego_policy=rego_b,
        rego_package=f"complivibe.guardrails.org_{rego_package_slug(org_b)}",
        constraint_spec=spec_b,
    )

    with Session(engine) as session:
        session.add_all([guardrail_a, guardrail_b])
        session.commit()

        event_a = AiGuardrailEvent(
            guardrail_id=guardrail_a.id,
            organization_id=org_a,
            ai_system_id="ai-system-1",
            decision="deny",
            reason="amount exceeds limit",
            action_envelope_json={"action_type": "wire_transfer", "amount": 50000, "currency": "USD"},
            receipt_id="receipt-1",
            evaluation_ms=1.23,
        )
        event_b = AiGuardrailEvent(
            guardrail_id=guardrail_b.id,
            organization_id=org_b,
            ai_system_id="ai-system-2",
            decision="allow",
            reason=None,
            action_envelope_json={"action_type": "wire_transfer", "amount": 100, "currency": "USD"},
            receipt_id="receipt-2",
            evaluation_ms=0.98,
        )
        session.add_all([event_a, event_b])
        session.commit()

        # Multi-tenant sanity check: org-scoped queries only return that org's rows.
        rows_a = session.scalars(
            select(AiGuardrailEvent).where(AiGuardrailEvent.organization_id == org_a)
        ).all()
        assert len(rows_a) == 1
        assert rows_a[0].organization_id == org_a
        assert rows_a[0].decision == "deny"
        assert "payload" not in rows_a[0].action_envelope_json

        guardrails_a = session.scalars(
            select(AiPolicyGuardrail).where(AiPolicyGuardrail.organization_id == org_a)
        ).all()
        assert len(guardrails_a) == 1
        assert guardrails_a[0].organization_id == org_a

        rows_b = session.scalars(
            select(AiGuardrailEvent).where(AiGuardrailEvent.organization_id == org_b)
        ).all()
        assert len(rows_b) == 1
        assert rows_b[0].organization_id == org_b

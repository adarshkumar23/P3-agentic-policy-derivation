"""Tests for the obligation-to-Rego derivation engine (Workstream B).

These tests validate the compiled Rego both syntactically and semantically
using the local `opa eval` CLI in test-only mode (vendored at .bin/opa) —
never a live OPA deployment, per the task's scope boundary.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from services.derivation_engine import (
    ObligationRecord,
    derive_and_compile,
    derive_constraint_spec,
)

OPA_AVAILABLE = shutil.which("opa") is not None


def _opa_eval(rego_text: str, input_data: dict, query: str) -> dict:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
        f.write(rego_text)
        rego_path = f.name
    try:
        proc = subprocess.run(
            [
                "opa",
                "eval",
                "--format",
                "json",
                "--input",
                "/dev/stdin",
                "--data",
                rego_path,
                query,
            ],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0, f"opa eval failed: {proc.stderr}"
        result = json.loads(proc.stdout)
        expressions = result["result"][0]["expressions"]
        return expressions[0]["value"]
    finally:
        Path(rego_path).unlink(missing_ok=True)


FINANCIAL_OBLIGATION = ObligationRecord(
    id="obl-1",
    text="A single transaction shall not exceed $10,000 per transaction without prior approval.",
    jurisdiction="US",
    framework="BSA/AML",
)
RESIDENCY_OBLIGATION = ObligationRecord(
    id="obl-2",
    text="Personal data collected from customers shall not leave the territory of India; "
    "data localization is required and cross-border transfer is prohibited from being "
    "transferred outside the territory of India.",
    jurisdiction="India",
    framework="DPDP",
)
UNRECOGNIZED_OBLIGATION = ObligationRecord(
    id="obl-3",
    text="The organization should maintain a general culture of compliance awareness.",
)


class TestDeriveConstraintSpec:
    def test_financial_limit_extraction_has_provenance(self):
        spec = derive_constraint_spec([FINANCIAL_OBLIGATION])
        assert len(spec.financial_limits) == 1
        limit = spec.financial_limits[0]
        assert limit.max_amount == 10000
        assert limit.currency == "USD"
        assert limit.per == "transaction"
        assert limit.source_obligation_ids == ("obl-1",)

    def test_approval_requirement_extraction(self):
        spec = derive_constraint_spec([FINANCIAL_OBLIGATION])
        assert len(spec.approval_requirements) == 1
        assert spec.approval_requirements[0].required is True
        assert spec.approval_requirements[0].source_obligation_ids == ("obl-1",)

    def test_residency_and_data_scope_extraction(self):
        spec = derive_constraint_spec([RESIDENCY_OBLIGATION])
        assert spec.geographic_scope is not None
        assert spec.geographic_scope.residency_required is True
        assert "India" in spec.geographic_scope.allowed_regions
        assert spec.data_scope is not None
        assert "pii" in spec.data_scope.restricted_categories
        assert spec.data_scope.cross_border_transfer_allowed is False

    def test_unrecognized_obligation_is_flagged_not_dropped(self):
        spec = derive_constraint_spec([UNRECOGNIZED_OBLIGATION])
        assert spec.unrecognized_obligation_ids == ("obl-3",)
        assert spec.financial_limits == ()
        assert spec.geographic_scope is None

    def test_source_obligation_ids_cover_all_inputs(self):
        spec = derive_constraint_spec([FINANCIAL_OBLIGATION, RESIDENCY_OBLIGATION, UNRECOGNIZED_OBLIGATION])
        assert spec.source_obligation_ids == ("obl-1", "obl-2", "obl-3")


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa CLI not available")
class TestCompiledRegoSemantics:
    def test_financial_limit_denies_over_threshold(self):
        _, rego_text = derive_and_compile([FINANCIAL_OBLIGATION], org_id="acme")
        result = _opa_eval(
            rego_text,
            {"action": {"amount": 15000, "currency": "USD", "requires_approval": True, "approved_by": ["u1"]}},
            "data.complivibe.guardrails.org_acme.allow",
        )
        assert result is False

    def test_financial_limit_allows_under_threshold_with_approval(self):
        _, rego_text = derive_and_compile([FINANCIAL_OBLIGATION], org_id="acme")
        result = _opa_eval(
            rego_text,
            {"action": {"amount": 500, "currency": "USD", "requires_approval": True, "approved_by": ["u1"]}},
            "data.complivibe.guardrails.org_acme.allow",
        )
        assert result is True

    def test_missing_approval_denies(self):
        _, rego_text = derive_and_compile([FINANCIAL_OBLIGATION], org_id="acme")
        result = _opa_eval(
            rego_text,
            {"action": {"amount": 500, "currency": "USD", "requires_approval": True, "approved_by": []}},
            "data.complivibe.guardrails.org_acme.allow",
        )
        assert result is False

    def test_cross_border_transfer_of_restricted_category_denies(self):
        _, rego_text = derive_and_compile([RESIDENCY_OBLIGATION], org_id="globex")
        result = _opa_eval(
            rego_text,
            {
                "action": {
                    "amount": 0,
                    "cross_border": True,
                    "data_categories": ["pii"],
                    "destination_region": "Singapore",
                }
            },
            "data.complivibe.guardrails.org_globex.allow",
        )
        assert result is False

    def test_domestic_transfer_allowed(self):
        _, rego_text = derive_and_compile([RESIDENCY_OBLIGATION], org_id="globex")
        result = _opa_eval(
            rego_text,
            {
                "action": {
                    "amount": 0,
                    "cross_border": False,
                    "data_categories": ["pii"],
                    "destination_region": "India",
                }
            },
            "data.complivibe.guardrails.org_globex.allow",
        )
        assert result is True

    def test_two_tenants_produce_distinct_packages(self):
        _, rego_a = derive_and_compile([FINANCIAL_OBLIGATION], org_id="tenant-a")
        _, rego_b = derive_and_compile([FINANCIAL_OBLIGATION], org_id="tenant-b")
        assert "package complivibe.guardrails.org_tenant_a" in rego_a
        assert "package complivibe.guardrails.org_tenant_b" in rego_b
        assert "org_tenant_b" not in rego_a

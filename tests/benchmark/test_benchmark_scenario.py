"""CI-executable encoding of the Workstream M technical-effect benchmark.

See tests/benchmark/PATENT_TECHNICAL_EFFECT.md for the full write-up (manual
vs. automated step comparison, provenance argument, scope-honesty notes).
This file exists only to keep the specific obligation/rego/opa-eval scenario
documented there from silently rotting: it re-derives, re-compiles, and
re-validates the same RBI data-localization obligation used in the doc, and
fails CI if the derivation engine's behavior on that scenario ever changes.

This is intentionally a thin duplicate of the deny/allow assertions already
covered generically in tests/unit/test_derivation_engine.py — it is scoped to
the *specific* obligation text quoted in the benchmark document, not to the
engine's pattern coverage in general.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from services.derivation_engine import ObligationRecord, derive_and_compile

OPA_AVAILABLE = shutil.which("opa") is not None

RBI_OBLIGATION = ObligationRecord(
    id="obl-rbi-2018-dpss",
    text=(
        "All data relating to payment systems operated by payment system operators "
        "shall be stored only in India; this data shall not leave the territory of India "
        "except for the limited purpose of processing a cross-border transaction, and "
        "personal data collected from customers is prohibited from being transferred "
        "outside the territory of India."
    ),
    jurisdiction="India",
    framework=(
        "RBI Storage of Payment System Data (PSS Act, 2007) Circular "
        "DPSS.CO.OD No.1810/06.08.005/2017-2018"
    ),
    citation="RBI/2017-18/153 DPSS.CO.OD.No.1810/06.08.005/2017-18, dated April 6, 2018",
    control_ids=("CTRL-DATA-RESIDENCY-01",),
)


def _opa_eval(rego_text: str, input_data: dict, query: str) -> dict:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
        f.write(rego_text)
        rego_path = f.name
    try:
        proc = subprocess.run(
            ["opa", "eval", "--format", "json", "--input", "/dev/stdin", "--data", rego_path, query],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0, f"opa eval failed: {proc.stderr}"
        result = json.loads(proc.stdout)
        return result["result"][0]["expressions"][0]["value"]
    finally:
        Path(rego_path).unlink(missing_ok=True)


class TestBenchmarkScenarioDerivation:
    def test_derivation_produces_provenance_tagged_spec(self):
        from services.derivation_engine import derive_constraint_spec

        spec = derive_constraint_spec([RBI_OBLIGATION])
        assert spec.geographic_scope is not None
        assert spec.geographic_scope.residency_required is True
        assert spec.geographic_scope.allowed_regions == ("India",)
        assert spec.geographic_scope.source_obligation_ids == ("obl-rbi-2018-dpss",)
        assert spec.data_scope is not None
        assert spec.data_scope.cross_border_transfer_allowed is False
        assert "pii" in spec.data_scope.restricted_categories
        assert spec.data_scope.source_obligation_ids == ("obl-rbi-2018-dpss",)
        assert spec.unrecognized_obligation_ids == ()

    def test_compiled_rego_is_scoped_to_tenant_package(self):
        _, rego_text = derive_and_compile([RBI_OBLIGATION], org_id="acme-bank")
        assert "package complivibe.guardrails.org_acme_bank" in rego_text


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa CLI not available")
class TestBenchmarkScenarioOpaValidation:
    def test_cross_border_transfer_to_singapore_is_denied(self):
        _, rego_text = derive_and_compile([RBI_OBLIGATION], org_id="acme-bank")
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
            "data.complivibe.guardrails.org_acme_bank.allow",
        )
        assert result is False

    def test_domestic_india_transfer_is_allowed(self):
        _, rego_text = derive_and_compile([RBI_OBLIGATION], org_id="acme-bank")
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
            "data.complivibe.guardrails.org_acme_bank.allow",
        )
        assert result is True

"""Tests for `services.derivation_engine.validate_rego_syntax` and its
wiring into `derive_and_compile`.

Before this hardening, nothing verified the Rego text `compile_constraint_spec`
produces is actually syntactically valid before handing it back to a caller
for persistence/use -- a bug in the string-template renderer could silently
produce Rego that only fails much later, at OPA evaluation time. This module
proves:

1. Rego actually produced by the real derivation engine (exercised via the
   existing obligation fixtures) passes validation.
2. Deliberately malformed Rego (hand-constructed) is caught, with a clear
   error message, not silently accepted.
3. `derive_and_compile` itself now raises `ValueError` if it would otherwise
   return invalid Rego (proven by monkeypatching the renderer to produce
   broken output), rather than silently handing it back.
"""

from __future__ import annotations

import pytest

from services.derivation_engine import (
    ObligationRecord,
    compile_constraint_spec,
    derive_and_compile,
    derive_constraint_spec,
    validate_rego_syntax,
)

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


class TestValidateRegoSyntaxOnValidInput:
    def test_derivation_engine_output_is_valid(self):
        spec = derive_constraint_spec([FINANCIAL_OBLIGATION])
        rego_text = compile_constraint_spec(spec, org_id="acme-corp")
        ok, error = validate_rego_syntax(rego_text)
        assert ok is True
        assert error is None

    def test_derivation_engine_output_with_geo_and_data_scope_is_valid(self):
        spec = derive_constraint_spec([RESIDENCY_OBLIGATION])
        rego_text = compile_constraint_spec(spec, org_id="acme-corp")
        ok, error = validate_rego_syntax(rego_text)
        assert ok is True
        assert error is None

    def test_derive_and_compile_returns_normally_for_valid_output(self):
        spec, rego_text = derive_and_compile([FINANCIAL_OBLIGATION, RESIDENCY_OBLIGATION], org_id="acme-corp")
        assert "package complivibe.guardrails.org_acme_corp" in rego_text


class TestValidateRegoSyntaxOnMalformedInput:
    def test_unbalanced_brace_is_caught(self):
        malformed = """\
package complivibe.guardrails.org_acme

import rego.v1

default allow := false

deny contains reason if {
\tinput.action.amount > 0
\treason := "missing closing brace"
"""
        ok, error = validate_rego_syntax(malformed)
        assert ok is False
        assert error is not None
        assert error.strip() != ""

    def test_bad_keyword_is_caught(self):
        malformed = """\
package complivibe.guardrails.org_acme

import rego.v1

default allow := flase

deny contains reason if {
\tinput.action.amount > 0
\treason := "typo'd keyword"
}
"""
        ok, error = validate_rego_syntax(malformed)
        assert ok is False
        assert error is not None

    def test_garbage_input_is_caught(self):
        ok, error = validate_rego_syntax("this is not rego at all { ] ) ( ")
        assert ok is False
        assert error is not None

    def test_valid_looking_but_undefined_package_declaration_still_parses_cleanly(self):
        # Sanity: a trivially valid, minimal module (no deny/allow rules at
        # all) is still valid Rego -- validate_rego_syntax only checks
        # syntax/compilation, not this repo's own conventions about what a
        # guardrail package must contain.
        ok, error = validate_rego_syntax("package complivibe.guardrails.org_acme\n")
        assert ok is True
        assert error is None


class TestDeriveAndCompileRejectsInvalidRego:
    def test_derive_and_compile_raises_value_error_if_renderer_produces_broken_rego(self, monkeypatch):
        """Simulate a bug in the renderer (e.g. a future edit that breaks
        `compile_constraint_spec`) by monkeypatching it to return
        deliberately invalid Rego, and confirm `derive_and_compile` refuses
        to hand it back rather than silently returning it for persistence.
        """
        import services.derivation_engine as derivation_engine

        def _broken_compile(spec, org_id):
            return "package complivibe.guardrails.org_acme\n\ndeny contains reason if {\n\tinput.x\n"

        monkeypatch.setattr(derivation_engine, "compile_constraint_spec", _broken_compile)

        with pytest.raises(ValueError) as exc_info:
            derivation_engine.derive_and_compile([FINANCIAL_OBLIGATION], org_id="acme-corp")

        assert "invalid Rego" in str(exc_info.value) or "rego_parse_error" in str(exc_info.value).lower()

    def test_error_message_does_not_include_raw_rendered_source_line(self):
        """validate_rego_syntax's error message should carry code/message/row
        location, not opa's own `details.line` field (which can echo back a
        raw source line) -- keep the surfaced message compact and free of
        arbitrary source content."""
        malformed = "package p\n\nx := {\n"
        ok, error = validate_rego_syntax(malformed)
        assert ok is False
        # The error should describe the problem generically, not dump the
        # literal broken source line back at the caller.
        assert "x := {" not in error

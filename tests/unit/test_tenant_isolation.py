"""Runtime tenant-isolation proofs for compiled Rego (Workstream L).

`tests/unit/test_derivation_engine.py::test_two_tenants_produce_distinct_packages`
already proves that two orgs get *different package name strings* in their
compiled Rego. That is a shallow, string-level check. This module goes
further and proves *runtime* isolation with the real `opa eval` CLI
(vendored at `.bin/opa`, test-only, never a live OPA deployment):

  1. Two tenants, compiled from substantively different obligations (a
     $10,000 limit for acme-corp vs. a $500,000 limit for globex-inc), are
     bundled together into the SAME directory -- exactly as a real
     multi-tenant OPA deployment would bundle every tenant's policy -- and
     each package's `allow` decision is independently correct for an action
     that acme-corp's limit denies but globex-inc's limit permits.

  2. Supplying acme-corp's or globex-inc's org-id-like string as *input
     data* (as opposed to as the query package path) has no effect on
     which package's rules apply -- the compiled Rego never reads an
     org-id-like field out of `input` to decide which rule set governs, so
     there is no way to spoof cross-tenant evaluation via input.

  3. Querying a package path for an org_id that was never compiled/bundled
     returns an *undefined* result (opa eval exits 0 with no "result" key),
     never an accidental `allow`. Callers wiring this into a real
     check-action endpoint (Workstream D/H) MUST treat undefined/error
     results as deny, consistent with the fail-closed decision already
     documented in ASSUMPTIONS.md for OPA-unreachable scenarios.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from services.derivation_engine import ObligationRecord, derive_and_compile

from _opa_test_util import opa_eval_bundle_dir

OPA_AVAILABLE = shutil.which("opa") is not None

# Deliberately worded WITHOUT any approval-trigger keywords ("approval",
# "sign-off", etc.) so the compiled Rego for each tenant contains only the
# financial-limit deny rule -- keeping the isolation check focused on the
# one axis (amount limit) that differs between the two tenants.
ACME_OBLIGATION = ObligationRecord(
    id="acme-obl-1",
    text="A single transaction shall not exceed $10,000 per transaction.",
    jurisdiction="US",
    framework="BSA/AML",
)
GLOBEX_OBLIGATION = ObligationRecord(
    id="globex-obl-1",
    text="A single transaction shall not exceed $500,000 per transaction.",
    jurisdiction="US",
    framework="BSA/AML",
)

ACME_ORG_ID = "acme-corp"
GLOBEX_ORG_ID = "globex-inc"
ACME_PACKAGE = "data.complivibe.guardrails.org_acme_corp"
GLOBEX_PACKAGE = "data.complivibe.guardrails.org_globex_inc"

# An action that violates acme-corp's $10,000 limit but is comfortably
# within globex-inc's $500,000 limit.
STRADDLING_ACTION = {"action": {"amount": 50000, "currency": "USD"}}


@pytest.fixture()
def bundle_dir():
    """A directory containing BOTH tenants' compiled Rego, as a real
    multi-tenant OPA deployment would bundle every tenant's policy
    together for a single `opa eval` / `opa run` invocation."""
    _, acme_rego = derive_and_compile([ACME_OBLIGATION], org_id=ACME_ORG_ID)
    _, globex_rego = derive_and_compile([GLOBEX_OBLIGATION], org_id=GLOBEX_ORG_ID)

    # Sanity-check substantive difference before doing anything runtime --
    # if this fails, the fixture itself is broken and every test below is
    # moot.
    assert "10000.0" in acme_rego or "10000" in acme_rego
    assert "500000.0" in globex_rego or "500000" in globex_rego

    tmp = tempfile.mkdtemp(prefix="tenant-bundle-")
    (Path(tmp) / "org_acme_corp.rego").write_text(acme_rego)
    (Path(tmp) / "org_globex_inc.rego").write_text(globex_rego)
    yield tmp, acme_rego, globex_rego
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa CLI not available")
class TestRuntimeTenantIsolation:
    def test_acme_package_denies_action_that_violates_only_acmes_limit(self, bundle_dir):
        tmp, _, _ = bundle_dir
        result = opa_eval_bundle_dir(tmp, STRADDLING_ACTION, f"{ACME_PACKAGE}.allow")
        assert result["ok"] is True
        assert result["value"] is False, (
            "acme-corp's own $10,000 limit must deny a $50,000 action even "
            "when globex-inc's more permissive $500,000-limit package is "
            "bundled alongside it"
        )

    def test_globex_package_allows_same_action_under_its_own_limit(self, bundle_dir):
        tmp, _, _ = bundle_dir
        result = opa_eval_bundle_dir(tmp, STRADDLING_ACTION, f"{GLOBEX_PACKAGE}.allow")
        assert result["ok"] is True
        assert result["value"] is True, (
            "globex-inc's package must be evaluated independently under its "
            "own $500,000 limit, uncontaminated by acme-corp's stricter rule "
            "even though both are bundled in the same directory"
        )

    def test_deny_reason_names_the_correct_tenant_limit(self, bundle_dir):
        tmp, _, _ = bundle_dir
        result = opa_eval_bundle_dir(tmp, STRADDLING_ACTION, f"{ACME_PACKAGE}.deny")
        assert result["ok"] is True
        reasons = result["value"]
        assert reasons, "expected at least one deny reason from acme-corp's package"
        assert any("10000" in r for r in reasons)
        assert not any("500000" in r for r in reasons)

    def test_spoofed_org_id_in_input_has_no_effect_on_acme_query(self, bundle_dir):
        """Set input.action.organization_id to globex-inc's org_id while
        querying acme-corp's package path. If the compiled Rego contained
        any rule that branched on an org-id-like input field, this could
        leak globex's more permissive limit into acme's evaluation. It
        must not: the package path in the query is the sole isolation
        boundary."""
        tmp, _, _ = bundle_dir
        spoofed_action = {
            "action": {
                "amount": 50000,
                "currency": "USD",
                "organization_id": GLOBEX_ORG_ID,
                "ai_system_id": GLOBEX_ORG_ID,
            }
        }
        result = opa_eval_bundle_dir(tmp, spoofed_action, f"{ACME_PACKAGE}.allow")
        assert result["ok"] is True
        assert result["value"] is False, (
            "spoofing organization_id/ai_system_id in input must NOT cause "
            "acme-corp's package to apply globex-inc's more permissive limit"
        )

    def test_spoofed_org_id_in_input_has_no_effect_on_globex_query(self, bundle_dir):
        """Symmetric spoof: claim to be acme-corp while querying globex-inc's
        package with an amount that would violate acme's stricter limit but
        is fine under globex's own limit. Must still allow."""
        tmp, _, _ = bundle_dir
        spoofed_action = {
            "action": {
                "amount": 50000,
                "currency": "USD",
                "organization_id": ACME_ORG_ID,
                "ai_system_id": ACME_ORG_ID,
            }
        }
        result = opa_eval_bundle_dir(tmp, spoofed_action, f"{GLOBEX_PACKAGE}.allow")
        assert result["ok"] is True
        assert result["value"] is True, (
            "spoofing organization_id/ai_system_id in input must NOT cause "
            "globex-inc's package to apply acme-corp's stricter limit"
        )

    def test_compiled_rego_never_reads_an_org_id_like_field_from_input(self, bundle_dir):
        """Static confirmation backing the two spoof tests above: the
        compiled Rego source for both tenants contains no reference to any
        org-id/tenant-id-shaped input field at all. Isolation is enforced
        purely by which package is queried, never by data the caller
        supplies in `input`."""
        _, acme_rego, globex_rego = bundle_dir
        for rego_text in (acme_rego, globex_rego):
            for needle in ("organization_id", "ai_system_id", "org_id", "tenant_id", "input.action.org"):
                assert needle not in rego_text, (
                    f"compiled Rego unexpectedly references {needle!r} -- this would be a "
                    "cross-tenant spoofing vector since input is caller-controlled"
                )

    def test_query_against_uncompiled_org_package_is_undefined_not_allow(self, bundle_dir):
        """A package name constructed from an org_id that was never
        actually compiled/bundled (e.g. an attacker-guessed slug, or a
        typo'd org_id) must not resolve to an accidental allow. `opa eval`
        returns an undefined result (no "result" key, exit 0) rather than
        an error or a truthy value for an unknown package path.

        Requirement for whoever wires this into the real check-action
        endpoint (Workstream D/H): an undefined or error result from OPA
        MUST be treated as deny, exactly like the documented fail-closed
        behavior for an unreachable OPA instance (see ASSUMPTIONS.md,
        "Fail-open vs. fail-closed when OPA is unreachable"). Never
        interpret "no result" as "no violation" / allow.
        """
        tmp, _, _ = bundle_dir
        result = opa_eval_bundle_dir(
            tmp, STRADDLING_ACTION, "data.complivibe.guardrails.org_nonexistent_org.allow"
        )
        assert result["ok"] is True, f"opa eval unexpectedly failed: {result['raw_stderr']}"
        assert result["value"] is None, (
            "querying an uncompiled tenant's package path must be undefined, not a value -- "
            f"got {result['value']!r}"
        )
        assert result["value"] is not True

    def test_query_against_uncompiled_org_deny_is_also_undefined(self, bundle_dir):
        tmp, _, _ = bundle_dir
        result = opa_eval_bundle_dir(
            tmp, STRADDLING_ACTION, "data.complivibe.guardrails.org_nonexistent_org.deny"
        )
        assert result["ok"] is True
        assert result["value"] is None

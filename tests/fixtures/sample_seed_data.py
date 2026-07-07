# mypy: allow-untyped-defs
"""Realistic seed data for 3 sample CompliVibe customer setups.

This module has no `test_` functions of its own -- it is a data fixture,
imported by `tests/fixtures/test_human_workflow_walkthrough.py` and
`tests/fixtures/test_multi_tenant_seed_sanity.py`. Every obligation's text
below was verified, while writing this fixture, to actually produce a
non-empty, meaningful `ConstraintSpec` via
`services.derivation_engine.derive_constraint_spec` (i.e. none of these
obligation ids ever land in `unrecognized_obligation_ids`) -- this is not
just plausible-sounding compliance prose, it is text engineered to trip the
engine's real regex patterns for financial limits, geographic/residency
scope, data scope + cross-border restriction, and approval requirements
(see `core-side-patch/services/derivation_engine.py`).

Three fictional organizations, deliberately varied in domain and
jurisdiction:

    1. Meridian Trust Bank      -- a retail/commercial US bank (wire
       transfers, BSA/AML-style obligations).
    2. Carewell Diagnostics AI  -- a healthcare AI vendor (diagnostic
       assistant, HIPAA-style obligations, PHI/biometric data scope).
    3. Zephyr Cross-Border Pay  -- a cross-border fintech/remittance
       provider (RBI-style data localization, FEMA-style remittance limits).

Each org has one `ai_system` and several realistic guardrails (each backed
by one or more `ObligationRecord`-shaped obligation dicts). Only some of
these guardrails are actually exercised end-to-end by the walkthrough/
sanity tests (a single ai_system only ever has ONE active guardrail at a
time -- see `api/guardrails.py`'s `check_action`, which picks the
most-recently-created active guardrail for an ai_system); the rest are
included here to demonstrate realistic coverage of all four guardrail
categories the derivation engine actually supports (financial_limits,
geographic_scope, data_scope, approval_requirements) per org, as the task
brief requires. `PRIMARY_GUARDRAIL_INDEX` on each org marks which guardrail
is the one actually created (and exercised) in the walkthrough/sanity
tests.

Note on category naming: the task brief that produced this fixture also
mentioned "action_scope" as a possible guardrail category. The derivation
engine (`ConstraintSpec`) has no such category -- only `financial_limits`,
`geographic_scope`, `data_scope`, and `approval_requirements` exist as real,
derivable constraint kinds. This fixture does not invent fake support for
"action_scope"; it sticks to the four categories the engine actually
recognizes.
"""

from __future__ import annotations

from typing import Any


def obligation(
    id: str,
    text: str,
    *,
    jurisdiction: str | None = None,
    framework: str | None = None,
    citation: str | None = None,
    control_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Build an `ObligationIn`/`ObligationRecord`-shaped dict.

    Used both as the JSON body sent to `POST .../guardrails` (matches
    `api.guardrails.ObligationIn`) and, via `.to_record()`-equivalent
    unpacking, as `services.derivation_engine.ObligationRecord` kwargs in
    tests that want to call `derive_constraint_spec` directly.
    """
    return {
        "id": id,
        "text": text,
        "jurisdiction": jurisdiction,
        "framework": framework,
        "citation": citation,
        "control_ids": control_ids or [],
    }


def action_envelope(
    action_id: str,
    *,
    ai_system_id: str,
    organization_id: str,
    action_type: str,
    timestamp: str,
    amount: float | None = None,
    currency: str | None = None,
    destination_region: str | None = None,
    data_categories: list[str] | None = None,
    cross_border: bool = False,
    requires_approval: bool = False,
    approved_by: list[str] | None = None,
) -> dict[str, Any]:
    """Build an `ActionEnvelope`-shaped dict (see
    `core-side-patch/services/envelope.py`). Field set matches exactly --
    no payload-only fields (`raw_request_body`, `customer_pii`, `documents`,
    `credentials`) are ever included here, consistent with the envelope/
    payload trust boundary that module documents.
    """
    return {
        "action_id": action_id,
        "ai_system_id": ai_system_id,
        "organization_id": organization_id,
        "action_type": action_type,
        "amount": amount,
        "currency": currency,
        "destination_region": destination_region,
        "data_categories": data_categories or [],
        "cross_border": cross_border,
        "requires_approval": requires_approval,
        "approved_by": approved_by or [],
        "timestamp": timestamp,
    }


# ===========================================================================
# Org 1: Meridian Trust Bank (US retail/commercial bank)
# ===========================================================================

MERIDIAN_ORG_ID = "meridian-trust-bank"
MERIDIAN_AI_SYSTEM_ID = "meridian-wire-agent"

MERIDIAN_GUARDRAILS = [
    {
        # PRIMARY -- this is the guardrail actually created/exercised in
        # the walkthrough and multi-tenant sanity tests for this org.
        #
        # Modeled on BSA/AML wire-transfer monitoring requirements (31 CFR
        # 1010) combined with a dual-control internal control: a
        # transaction-level dollar limit, AND (via the same obligation's
        # "dual control" language, plus a companion obligation naming an
        # explicit two-approver threshold) an approval-count requirement.
        # Bundling both obligations into one guardrail is realistic: a
        # bank's wire-transfer control is very rarely "just" a limit or
        # "just" an approval rule -- it's both at once.
        "name": "Wire Transfer Limit & Dual Control",
        "description": (
            "Caps single outbound wire transfers and requires dual "
            "control / two-approver sign-off above a daily threshold."
        ),
        "obligations": [
            obligation(
                "meridian-obl-wire-limit",
                "Outbound wire transfers initiated by the automated payments "
                "agent shall not exceed $25,000 per transaction without dual "
                "control.",
                jurisdiction="US",
                framework="BSA/AML",
                citation="31 CFR 1010",
            ),
            obligation(
                "meridian-obl-approval-threshold",
                "Any payment instruction exceeding the daily threshold of "
                "$100,000 requires prior approval from two approvers before "
                "execution.",
                jurisdiction="US",
                framework="BSA/AML",
                citation="31 CFR 1010",
            ),
        ],
    },
    {
        # Modeled on US bank data-localization-adjacent operational
        # resilience expectations (no single US "data localization"
        # statute the way RBI has one, but many banks' own core-banking
        # outsourcing/BCP policies impose an equivalent internal
        # obligation) -- kept here as a realistic geographic_scope example
        # for a US bank, distinct from Zephyr's actual RBI-driven one.
        "name": "Core Banking Data Residency",
        "description": "Keeps core banking transaction records within US territory.",
        "obligations": [
            obligation(
                "meridian-obl-residency",
                "Core banking transaction records shall remain within the "
                "territory of United States, and must not be processed by "
                "any offshore system.",
                jurisdiction="US",
                framework="Internal BCP / vendor-outsourcing policy",
                citation="OCC Bulletin 2013-29 (third-party risk analog)",
            ),
        ],
    },
    {
        # Modeled on GLBA Safeguards Rule protections for customer
        # nonpublic personal information (NPI/PII) collected during
        # onboarding.
        "name": "Customer PII Cross-Border Restriction",
        "description": "Blocks cross-border transfer of customer PII collected at onboarding.",
        "obligations": [
            obligation(
                "meridian-obl-pii",
                "Customer personally identifiable information collected "
                "during onboarding shall not be transferred outside the "
                "United States without a data processing agreement.",
                jurisdiction="US",
                framework="GLBA",
                citation="16 CFR 314",
            ),
        ],
    },
]

MERIDIAN_PRIMARY_GUARDRAIL_INDEX = 0

# Action envelopes for Meridian's PRIMARY guardrail (limit $25,000 /
# $100,000, min_approvers=2). Timestamps are strictly increasing so the
# resulting receipt chain has a well-defined order.
MERIDIAN_ACTIONS = {
    # ALLOWED: comfortably under the $25,000 limit, no approval requested.
    "allowed_under_limit": action_envelope(
        "meridian-act-allow-1",
        ai_system_id=MERIDIAN_AI_SYSTEM_ID,
        organization_id=MERIDIAN_ORG_ID,
        action_type="wire_transfer",
        amount=15_000.0,
        currency="USD",
        timestamp="2026-01-01T09:00:00+00:00",
    ),
    # BLOCKED: exceeds the $25,000 per-transaction limit. Expected deny
    # reason references "25000" (the specific limit violated), not a vague
    # error.
    "blocked_over_limit": action_envelope(
        "meridian-act-deny-1",
        ai_system_id=MERIDIAN_AI_SYSTEM_ID,
        organization_id=MERIDIAN_ORG_ID,
        action_type="wire_transfer",
        amount=30_000.0,
        currency="USD",
        timestamp="2026-01-01T09:05:00+00:00",
    ),
    # BOUNDARY (should ALLOW): under the dollar limit, approval requested,
    # and exactly 2 approvers supplied -- meets min_approvers=2.
    "boundary_approval_sufficient": action_envelope(
        "meridian-act-boundary-ok",
        ai_system_id=MERIDIAN_AI_SYSTEM_ID,
        organization_id=MERIDIAN_ORG_ID,
        action_type="wire_transfer",
        amount=18_000.0,
        currency="USD",
        requires_approval=True,
        approved_by=["compliance-officer-1", "compliance-officer-2"],
        timestamp="2026-01-01T09:10:00+00:00",
    ),
    # BOUNDARY (should BLOCK): same amount/approval flag as above, but only
    # ONE approver -- short of min_approvers=2.
    "boundary_approval_insufficient": action_envelope(
        "meridian-act-boundary-deny",
        ai_system_id=MERIDIAN_AI_SYSTEM_ID,
        organization_id=MERIDIAN_ORG_ID,
        action_type="wire_transfer",
        amount=18_000.0,
        currency="USD",
        requires_approval=True,
        approved_by=["compliance-officer-1"],
        timestamp="2026-01-01T09:15:00+00:00",
    ),
}


# ===========================================================================
# Org 2: Carewell Diagnostics AI (healthcare AI vendor)
# ===========================================================================

CAREWELL_ORG_ID = "carewell-diagnostics-ai"
CAREWELL_AI_SYSTEM_ID = "carewell-diagnosis-agent"

CAREWELL_GUARDRAILS = [
    {
        # PRIMARY. Modeled on HIPAA's Privacy Rule restrictions on
        # disclosure/transfer of protected health information (PHI)
        # outside the country in which it was collected -- a data_scope
        # guardrail with cross-border transfer forbidden.
        "name": "PHI Cross-Border Transfer Restriction",
        "description": "Blocks cross-border transfer of protected health data generated by the diagnostic assistant.",
        "obligations": [
            obligation(
                "carewell-obl-phi",
                "Health data generated by the diagnostic assistant shall "
                "not be transferred outside the country of origin under any "
                "circumstance.",
                jurisdiction="US",
                framework="HIPAA",
                citation="45 CFR 164.502",
            ),
        ],
    },
    {
        # Modeled on FDA Software-as-a-Medical-Device (SaMD) expectations
        # that AI-generated diagnostic output be reviewed by a licensed
        # clinician before being acted on -- an approval_requirements
        # guardrail.
        "name": "Clinician Sign-off for AI Diagnoses",
        "description": "Requires a licensed physician's review/sign-off before an AI diagnosis reaches the patient record.",
        "obligations": [
            obligation(
                "carewell-obl-signoff",
                "Any AI-generated diagnostic recommendation requires human "
                "review and sign-off from a licensed physician before being "
                "released to the patient record.",
                jurisdiction="US",
                framework="HIPAA/FDA SaMD",
                citation="21 CFR 820 (QSR analog)",
            ),
        ],
    },
    {
        # Modeled on CMS program-integrity expectations for automated
        # claims submission -- a financial_limits guardrail.
        "name": "Billing Claim Amount Limit",
        "description": "Caps automated reimbursement claims submitted without supervisory review.",
        "obligations": [
            obligation(
                "carewell-obl-claim-limit",
                "Reimbursement claims submitted by the automated billing "
                "agent must not exceed $5,000 per transaction without "
                "supervisory review.",
                jurisdiction="US",
                framework="CMS",
                citation="42 CFR 424",
            ),
        ],
    },
    {
        # Modeled on HIPAA's heightened treatment of biometric identifiers
        # used for patient authentication -- another data_scope example,
        # distinct restricted_category ("biometric") from the PHI one
        # above.
        "name": "Biometric Authentication Data Restriction",
        "description": "Blocks cross-border transfer of biometric identifiers used for patient authentication.",
        "obligations": [
            obligation(
                "carewell-obl-biometric",
                "Biometric identifiers used for patient authentication "
                "shall not be transferred outside the country of origin.",
                jurisdiction="US",
                framework="HIPAA",
                citation="45 CFR 164.312",
            ),
        ],
    },
]

CAREWELL_PRIMARY_GUARDRAIL_INDEX = 2  # the financial-limit one, for a clean allow/deny numeric test

CAREWELL_ACTIONS = {
    # ALLOWED: claim amount comfortably under the $5,000 limit.
    "allowed_under_limit": action_envelope(
        "carewell-act-allow-1",
        ai_system_id=CAREWELL_AI_SYSTEM_ID,
        organization_id=CAREWELL_ORG_ID,
        action_type="billing_claim_submission",
        amount=1_200.0,
        currency="USD",
        timestamp="2026-01-01T10:00:00+00:00",
    ),
    # BLOCKED: claim amount exceeds the $5,000 limit.
    "blocked_over_limit": action_envelope(
        "carewell-act-deny-1",
        ai_system_id=CAREWELL_AI_SYSTEM_ID,
        organization_id=CAREWELL_ORG_ID,
        action_type="billing_claim_submission",
        amount=7_500.0,
        currency="USD",
        timestamp="2026-01-01T10:05:00+00:00",
    ),
}

# A second, non-primary guardrail's worth of envelopes (data_scope), kept
# here for completeness / documentation of realistic PHI cross-border
# traffic -- not exercised by the walkthrough/sanity tests since only one
# guardrail is active per ai_system at a time, but demonstrates what an
# ALLOW vs. BLOCK looks like for this org's data_scope guardrail.
CAREWELL_PHI_ACTIONS = {
    # ALLOWED: health data processed, but stays within the country of
    # origin (cross_border=False) -- the deny rule only fires when
    # cross_border is true.
    "allowed_domestic_processing": action_envelope(
        "carewell-act-phi-allow-1",
        ai_system_id=CAREWELL_AI_SYSTEM_ID,
        organization_id=CAREWELL_ORG_ID,
        action_type="diagnostic_data_processing",
        data_categories=["health"],
        cross_border=False,
        timestamp="2026-01-01T10:10:00+00:00",
    ),
    # BLOCKED: same health data category, but flagged as a cross-border
    # transfer -- must be denied under the PHI cross-border restriction.
    "blocked_cross_border_transfer": action_envelope(
        "carewell-act-phi-deny-1",
        ai_system_id=CAREWELL_AI_SYSTEM_ID,
        organization_id=CAREWELL_ORG_ID,
        action_type="diagnostic_data_processing",
        data_categories=["health"],
        cross_border=True,
        timestamp="2026-01-01T10:15:00+00:00",
    ),
}


# ===========================================================================
# Org 3: Zephyr Cross-Border Pay (cross-border fintech / remittance)
# ===========================================================================

ZEPHYR_ORG_ID = "zephyr-crossborder-pay"
ZEPHYR_AI_SYSTEM_ID = "zephyr-remittance-agent"

ZEPHYR_GUARDRAILS = [
    {
        # Modeled on RBI data-localization circulars requiring payment
        # system data to be stored/processed within India -- a
        # geographic_scope guardrail.
        "name": "Payment Data Localization (RBI)",
        "description": "Requires payment transaction records to stay within Indian territory.",
        "obligations": [
            obligation(
                "zephyr-obl-residency",
                "Payment transaction records shall remain within the "
                "territory of India, consistent with data localization "
                "requirements for payment system data.",
                jurisdiction="IN",
                framework="RBI",
                citation="RBI/2017-18/153",
            ),
        ],
    },
    {
        # Modeled on RBI/FEMA maker-checker requirements for cross-border
        # remittance instructions above a threshold -- an
        # approval_requirements guardrail with an explicit two-approver
        # minimum.
        "name": "Cross-Border Remittance Dual Control",
        "description": "Requires maker-checker dual control for cross-border remittance instructions.",
        "obligations": [
            obligation(
                "zephyr-obl-maker-checker",
                "Cross-border remittance instructions above the threshold "
                "require maker-checker dual control with a minimum of two "
                "approvers.",
                jurisdiction="IN",
                framework="RBI/FEMA",
                citation="FEMA 1999, Master Direction on Remittances",
            ),
        ],
    },
    {
        # PRIMARY. Modeled on FEMA's Liberalized Remittance Scheme (LRS)
        # per-transaction limits for retail cross-border remittances -- a
        # financial_limits guardrail.
        "name": "Retail Remittance Amount Limit",
        "description": "Caps a single retail cross-border remittance absent enhanced due diligence.",
        "obligations": [
            obligation(
                "zephyr-obl-remit-limit",
                "A single retail cross-border remittance shall not exceed "
                "$2,000 per transaction absent enhanced due diligence.",
                jurisdiction="IN",
                framework="FEMA",
                citation="FEMA Liberalized Remittance Scheme",
            ),
        ],
    },
    {
        # Modeled on RBI restrictions on transferring Indian resident
        # customers' financial account information outside India except as
        # permitted by circular -- a data_scope guardrail, distinct
        # restricted_category ("financial") from either of Carewell's.
        "name": "Indian Customer Account Data Cross-Border Restriction",
        "description": "Blocks cross-border transfer of Indian resident customers' account information.",
        "obligations": [
            obligation(
                "zephyr-obl-account-data",
                "Account information relating to Indian resident customers "
                "shall not be transferred outside the territory of India "
                "except as permitted by RBI circulars.",
                jurisdiction="IN",
                framework="RBI",
                citation="RBI Master Direction on Digital Payment Security",
            ),
        ],
    },
]

ZEPHYR_PRIMARY_GUARDRAIL_INDEX = 2  # the financial-limit one, for a clean allow/deny numeric test

ZEPHYR_ACTIONS = {
    # ALLOWED: remittance amount comfortably under the $2,000 LRS-style
    # limit.
    "allowed_under_limit": action_envelope(
        "zephyr-act-allow-1",
        ai_system_id=ZEPHYR_AI_SYSTEM_ID,
        organization_id=ZEPHYR_ORG_ID,
        action_type="cross_border_remittance",
        amount=800.0,
        currency="USD",
        timestamp="2026-01-01T11:00:00+00:00",
    ),
    # BLOCKED: remittance amount exceeds the $2,000 limit.
    "blocked_over_limit": action_envelope(
        "zephyr-act-deny-1",
        ai_system_id=ZEPHYR_AI_SYSTEM_ID,
        organization_id=ZEPHYR_ORG_ID,
        action_type="cross_border_remittance",
        amount=5_000.0,
        currency="USD",
        timestamp="2026-01-01T11:05:00+00:00",
    ),
}


# ===========================================================================
# Convenience aggregate: every sample org in one place, for the multi-tenant
# sanity test (Part 3c), which needs all orgs coexisting simultaneously.
# ===========================================================================

SAMPLE_ORGS = [
    {
        "org_id": MERIDIAN_ORG_ID,
        "org_name": "Meridian Trust Bank",
        "ai_system_id": MERIDIAN_AI_SYSTEM_ID,
        "ai_system_name": "Meridian Wire Transfer Agent",
        "guardrails": MERIDIAN_GUARDRAILS,
        "primary_guardrail_index": MERIDIAN_PRIMARY_GUARDRAIL_INDEX,
        "actions": MERIDIAN_ACTIONS,
    },
    {
        "org_id": CAREWELL_ORG_ID,
        "org_name": "Carewell Diagnostics AI",
        "ai_system_id": CAREWELL_AI_SYSTEM_ID,
        "ai_system_name": "Carewell Diagnosis Agent",
        "guardrails": CAREWELL_GUARDRAILS,
        "primary_guardrail_index": CAREWELL_PRIMARY_GUARDRAIL_INDEX,
        "actions": CAREWELL_ACTIONS,
    },
    {
        "org_id": ZEPHYR_ORG_ID,
        "org_name": "Zephyr Cross-Border Pay",
        "ai_system_id": ZEPHYR_AI_SYSTEM_ID,
        "ai_system_name": "Zephyr Remittance Agent",
        "guardrails": ZEPHYR_GUARDRAILS,
        "primary_guardrail_index": ZEPHYR_PRIMARY_GUARDRAIL_INDEX,
        "actions": ZEPHYR_ACTIONS,
    },
]

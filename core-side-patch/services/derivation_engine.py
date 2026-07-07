# mypy: allow-untyped-defs
"""Obligation-to-Rego derivation engine.

This is the novel component of this patent filing (see PATENT.md §3). It is
intentionally the *only* piece of this repository that turns unstructured
regulatory obligation text into anything executable. Everything downstream
of this module (the OPA client, the policy provider adapter, receipt
signing) is glue around a third-party enforcement runtime and is not
claimed as novel.

Pipeline:
    ObligationRecord(s)  --derive_constraint_spec-->  ConstraintSpec
    ConstraintSpec        --compile_constraint_spec-->  Rego policy text

Both stages retain provenance: every element of a ConstraintSpec records
which source obligation(s) it was derived from, and the compiled Rego is
never handed back without that ConstraintSpec attached, so a guardrail's
compiled policy can always be traced back to the regulatory text that
produced it (see Workstream A's `ai_policy_guardrails` schema).

Extraction is deliberately rule-based (regex/keyword pattern matching over
obligation text), not a black-box model call: the whole point of this
patent claim is a specific, inspectable, reproducible derivation, and a
rule-based approach is what makes Workstream M's benchmark reproducible.
It intentionally does not attempt full natural-language understanding —
see `UNRECOGNIZED` handling below, and ASSUMPTIONS.md for scope limits.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Structured obligation input
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ObligationRecord:
    """A single regulatory obligation as held in CompliVibe's obligation graph."""

    id: str
    text: str
    jurisdiction: str | None = None
    framework: str | None = None
    citation: str | None = None
    control_ids: tuple[str, ...] = ()


# --------------------------------------------------------------------------
# Derived constraint specification (structured, provenance-tagged)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FinancialLimit:
    max_amount: float
    currency: str
    per: str  # e.g. "transaction", "day"
    source_obligation_ids: tuple[str, ...]


@dataclass(frozen=True)
class GeographicScope:
    allowed_regions: tuple[str, ...]
    residency_required: bool
    source_obligation_ids: tuple[str, ...]


@dataclass(frozen=True)
class DataScope:
    restricted_categories: tuple[str, ...]
    cross_border_transfer_allowed: bool
    source_obligation_ids: tuple[str, ...]


@dataclass(frozen=True)
class ApprovalRequirement:
    required: bool
    min_approvers: int
    source_obligation_ids: tuple[str, ...]


@dataclass(frozen=True)
class ConstraintSpec:
    source_obligation_ids: tuple[str, ...]
    financial_limits: tuple[FinancialLimit, ...] = ()
    geographic_scope: GeographicScope | None = None
    data_scope: DataScope | None = None
    approval_requirements: tuple[ApprovalRequirement, ...] = ()
    unrecognized_obligation_ids: tuple[str, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------
# Stage 1: obligation text -> constraint spec
# --------------------------------------------------------------------------

_CURRENCY_SYMBOLS = {"$": "USD", "₹": "INR", "€": "EUR", "£": "GBP"}

_AMOUNT_RE = re.compile(
    r"(?P<symbol>[$₹€£]|USD|INR|EUR|GBP)\s?(?P<amount>[\d,]+(?:\.\d+)?)",
    re.IGNORECASE,
)
_LIMIT_KEYWORDS = re.compile(r"\b(shall not exceed|must not exceed|limit(?:ed)? to|threshold of)\b", re.IGNORECASE)
_PER_PERIOD_RE = re.compile(r"\bper\s+(transaction|day|month|year)\b", re.IGNORECASE)

_RESIDENCY_KEYWORDS = re.compile(
    r"\b(data localization|data residency|shall not leave|stored within the territory|"
    r"processed within|shall remain within)\b",
    re.IGNORECASE,
)
_REGION_RE = re.compile(r"\bwithin(?: the (?:territory|jurisdiction) of)?\s+([A-Z][a-zA-Z ]{2,30})\b")

_DATA_CATEGORY_KEYWORDS = {
    "pii": re.compile(r"\b(personal(ly identifiable)? (data|information)|PII)\b", re.IGNORECASE),
    "financial": re.compile(r"\b(financial data|account information|transaction data)\b", re.IGNORECASE),
    "health": re.compile(r"\b(health data|medical records?|PHI)\b", re.IGNORECASE),
    "biometric": re.compile(r"\bbiometric\b", re.IGNORECASE),
}
_CROSS_BORDER_FORBIDDEN_RE = re.compile(
    r"\b(shall not be transferred (outside|across)|no cross-border transfer|"
    r"prohibited from (being )?transfer\w* outside)\b",
    re.IGNORECASE,
)

_APPROVAL_KEYWORDS = re.compile(
    r"\b(prior approval|human review|sign-?off|dual control|maker-?checker|requires approval)\b",
    re.IGNORECASE,
)
_MIN_APPROVERS_RE = re.compile(r"\b(\d+|two|three)\s+approvers?\b", re.IGNORECASE)
_WORD_NUMBERS = {"two": 2, "three": 3}


def _normalize_currency(symbol: str) -> str:
    return _CURRENCY_SYMBOLS.get(symbol, symbol.upper())


def derive_constraint_spec(obligations: list[ObligationRecord]) -> ConstraintSpec:
    """Derive a structured, provenance-tagged constraint spec from obligation text.

    Each obligation is scanned independently against pattern families
    (financial, geographic, data-scope, approval). An obligation may
    contribute to more than one family. An obligation matching none of the
    families is recorded in `unrecognized_obligation_ids` rather than
    silently dropped, so callers can see exactly what the engine could not
    derive from and route it to manual authoring instead.
    """
    financial_limits: list[FinancialLimit] = []
    geo_regions: list[str] = []
    geo_residency_required = False
    geo_sources: list[str] = []
    data_categories: list[str] = []
    data_cross_border_allowed = True
    data_sources: list[str] = []
    approval_required = False
    approval_min = 0
    approval_sources: list[str] = []
    unrecognized: list[str] = []

    for obligation in obligations:
        text = obligation.text
        matched_any = False

        amount_match = _AMOUNT_RE.search(text)
        if amount_match and _LIMIT_KEYWORDS.search(text):
            matched_any = True
            period_match = _PER_PERIOD_RE.search(text)
            financial_limits.append(
                FinancialLimit(
                    max_amount=float(amount_match.group("amount").replace(",", "")),
                    currency=_normalize_currency(amount_match.group("symbol")),
                    per=period_match.group(1).lower() if period_match else "transaction",
                    source_obligation_ids=(obligation.id,),
                )
            )

        if _RESIDENCY_KEYWORDS.search(text):
            matched_any = True
            geo_residency_required = True
            geo_sources.append(obligation.id)
            region_match = _REGION_RE.search(text)
            if region_match:
                region = region_match.group(1).strip()
                if region not in geo_regions:
                    geo_regions.append(region)
            elif obligation.jurisdiction and obligation.jurisdiction not in geo_regions:
                geo_regions.append(obligation.jurisdiction)

        for category, pattern in _DATA_CATEGORY_KEYWORDS.items():
            if pattern.search(text):
                matched_any = True
                if category not in data_categories:
                    data_categories.append(category)
                data_sources.append(obligation.id)
                if _CROSS_BORDER_FORBIDDEN_RE.search(text):
                    data_cross_border_allowed = False

        if _APPROVAL_KEYWORDS.search(text):
            matched_any = True
            approval_required = True
            approval_sources.append(obligation.id)
            min_match = _MIN_APPROVERS_RE.search(text)
            if min_match:
                raw = min_match.group(1).lower()
                count = _WORD_NUMBERS.get(raw, None)
                if count is None:
                    count = int(raw)
                approval_min = max(approval_min, count)
            else:
                approval_min = max(approval_min, 1)

        if not matched_any:
            unrecognized.append(obligation.id)

    all_ids = tuple(o.id for o in obligations)

    geographic_scope = None
    if geo_sources:
        geographic_scope = GeographicScope(
            allowed_regions=tuple(dict.fromkeys(geo_regions)),
            residency_required=geo_residency_required,
            source_obligation_ids=tuple(dict.fromkeys(geo_sources)),
        )

    data_scope = None
    if data_sources:
        data_scope = DataScope(
            restricted_categories=tuple(dict.fromkeys(data_categories)),
            cross_border_transfer_allowed=data_cross_border_allowed,
            source_obligation_ids=tuple(dict.fromkeys(data_sources)),
        )

    approval_requirements: tuple[ApprovalRequirement, ...] = ()
    if approval_sources:
        approval_requirements = (
            ApprovalRequirement(
                required=approval_required,
                min_approvers=approval_min,
                source_obligation_ids=tuple(dict.fromkeys(approval_sources)),
            ),
        )

    return ConstraintSpec(
        source_obligation_ids=all_ids,
        financial_limits=tuple(financial_limits),
        geographic_scope=geographic_scope,
        data_scope=data_scope,
        approval_requirements=approval_requirements,
        unrecognized_obligation_ids=tuple(unrecognized),
    )


# --------------------------------------------------------------------------
# Stage 2: constraint spec -> Rego policy text
# --------------------------------------------------------------------------


def _rego_string_list(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(f'"{v}"' for v in values) + "]"


_NON_IDENT_RE = re.compile(r"[^a-zA-Z0-9_]")


def rego_package_slug(org_id: str) -> str:
    """Sanitize an org_id into a valid Rego package-name segment.

    Rego package identifiers must be `[a-zA-Z_][a-zA-Z0-9_]*` — org_ids
    containing hyphens or other separators (e.g. UUIDs) are not valid as-is.
    This is a pure rename for the package path; the original org_id is
    still what callers key persistence and lookups on (Workstream L).
    """
    slug = _NON_IDENT_RE.sub("_", org_id)
    if slug and slug[0].isdigit():
        slug = f"_{slug}"
    return slug


def compile_constraint_spec(spec: ConstraintSpec, org_id: str) -> str:
    """Compile a ConstraintSpec into Rego, isolated to a per-tenant package.

    See PATENT.md §1.1(3): rendering an already-structured spec into Rego
    syntax is not itself the novel step (the Agent Governance Toolkit's own
    `rego_builder.py` already does the analogous thing for its own rule
    model) — this function exists so the derivation engine's output is
    directly usable, but the claimed contribution is `derive_constraint_spec`
    above, not this renderer.
    """
    lines = [
        f"package complivibe.guardrails.org_{rego_package_slug(org_id)}",
        "",
        "import rego.v1",
        "",
        "default allow := false",
        "",
        "deny contains reason if {",
        '\tinput.action.amount > 0',
        "\tsome limit in financial_limits",
        "\tinput.action.currency == limit.currency",
        "\tinput.action.amount > limit.max_amount",
        '\treason := sprintf("amount %v %v exceeds limit %v %v (%v)", '
        "[input.action.amount, input.action.currency, limit.max_amount, limit.currency, limit.per])",
        "}",
        "",
        "financial_limits := " + _render_financial_limits(spec.financial_limits),
        "",
    ]

    if spec.geographic_scope is not None and spec.geographic_scope.allowed_regions:
        allowed = _rego_string_list(spec.geographic_scope.allowed_regions)
        lines += [
            "deny contains reason if {",
            "\tinput.action.destination_region",
            f"\tnot input.action.destination_region in {allowed}",
            '\treason := sprintf("destination region %v is outside permitted regions %v", '
            f'[input.action.destination_region, {allowed}])',
            "}",
            "",
        ]

    if spec.data_scope is not None and not spec.data_scope.cross_border_transfer_allowed:
        restricted = _rego_string_list(spec.data_scope.restricted_categories)
        lines += [
            "deny contains reason if {",
            "\tinput.action.cross_border == true",
            f"\tsome category in input.action.data_categories",
            f"\tcategory in {restricted}",
            '\treason := sprintf("cross-border transfer of restricted category %v is not permitted", [category])',
            "}",
            "",
        ]

    if spec.approval_requirements and spec.approval_requirements[0].required:
        min_approvers = spec.approval_requirements[0].min_approvers
        lines += [
            "deny contains reason if {",
            "\tinput.action.requires_approval == true",
            f"\tcount(object.get(input.action, \"approved_by\", [])) < {min_approvers}",
            '\treason := "insufficient approvals for a requires-approval action"',
            "}",
            "",
        ]

    lines += [
        "allow if {",
        "\tcount(deny) == 0",
        "}",
        "",
    ]
    return "\n".join(lines)


def _render_financial_limits(limits: tuple[FinancialLimit, ...]) -> str:
    if not limits:
        return "[]"
    entries = []
    for limit in limits:
        entries.append(
            "{"
            f'"currency": "{limit.currency}", '
            f'"max_amount": {limit.max_amount}, '
            f'"per": "{limit.per}"'
            "}"
        )
    return "[" + ", ".join(entries) + "]"


def validate_rego_syntax(rego_text: str) -> tuple[bool, str | None]:
    """Validate that `rego_text` is syntactically valid, compilable Rego.

    Uses `opa check --strict` (a real `opa` binary must be on `PATH` -- this
    repo's test suite vendors one at `.bin/opa` and puts it on `PATH` via
    `conftest.py`; a production deployment must have a real `opa` binary
    available to this process) to parse and compile-check the module
    without needing any `input` data at all, which is exactly what's needed
    here: this only checks that the *shape* of the Rego is valid, not
    anything about a particular decision.

    Returns `(True, None)` if `opa check` succeeds, or `(False, <message>)`
    with a clear, human-readable summary of `opa`'s own parse/compile
    error(s) if it does not. Never raises for a syntax problem in
    `rego_text` itself -- only for an environment problem (no `opa` binary
    available, or the subprocess call itself misbehaving).

    This exists because, before this function, nothing in this module
    verified the Rego string `compile_constraint_spec` renders is even
    syntactically valid before it was handed back to a caller for
    persistence/use -- a bug in the string-template renderer (e.g. an
    unbalanced brace introduced by a future edit) would have silently
    produced bad Rego that only failed much later, at OPA evaluation time,
    far from the guardrail-creation/recompile call site that actually
    caused it.
    """
    opa_path = shutil.which("opa")
    if opa_path is None:
        raise RuntimeError(
            "cannot validate Rego syntax: no `opa` binary found on PATH "
            "(see conftest.py for this repo's test-time vendored .bin/opa; "
            "a production deployment must have a real `opa` binary "
            "available to this process)"
        )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
        f.write(rego_text)
        rego_path = f.name
    try:
        proc = subprocess.run(
            [opa_path, "check", "--strict", "--format", "json", rego_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            return True, None

        # `opa check --format json` writes its JSON error report to
        # stderr, not stdout (verified directly against the vendored `opa`
        # binary -- unlike `opa eval`, which writes results to stdout).
        # Try both, preferring whichever one actually parses as the
        # expected `{"errors": [...]}` shape, so this doesn't silently
        # break if a different `opa` build ever swaps which stream it uses.
        message = ""
        parsed: dict = {}
        for stream in (proc.stderr, proc.stdout):
            text = stream.strip()
            if not text:
                continue
            try:
                candidate = json.loads(text)
            except ValueError:
                continue
            if isinstance(candidate, dict) and candidate.get("errors"):
                parsed = candidate
                break
        errors = parsed.get("errors") or []
        if errors:
            # Deliberately omit each error's "details"/"line" field here --
            # that field can echo back a raw line of the *rendered* Rego
            # source, and this message is surfaced all the way up to an API
            # error response (see api/guardrails.py); code + message +
            # location is enough to act on without also carrying arbitrary
            # source-line content into a client-facing string.
            message = "; ".join(
                f"{e.get('code', 'rego_error')}: {e.get('message', '(no message)')} "
                f"(row {e.get('location', {}).get('row', '?')})"
                for e in errors
            )
        if not message:
            message = f"opa check exited with status {proc.returncode} and produced no error detail"
        return False, message
    finally:
        Path(rego_path).unlink(missing_ok=True)


def derive_and_compile(obligations: list[ObligationRecord], org_id: str) -> tuple[ConstraintSpec, str]:
    """Convenience entry point: derive, then compile, returning both.

    Callers (Workstream A/H) should persist both the returned ConstraintSpec
    (as provenance metadata) and the compiled Rego text.

    Before returning, the compiled Rego is validated with
    `validate_rego_syntax` (see above) -- if it is not syntactically valid,
    compilable Rego, this raises `ValueError` immediately rather than
    handing back (and letting a caller persist) Rego that would only fail
    much later when OPA actually tries to evaluate it.
    """
    spec = derive_constraint_spec(obligations)
    rego_text = compile_constraint_spec(spec, org_id)

    valid, error = validate_rego_syntax(rego_text)
    if not valid:
        raise ValueError(
            "derivation engine produced syntactically invalid Rego; refusing "
            f"to return it. `opa check` reported: {error}"
        )

    return spec, rego_text

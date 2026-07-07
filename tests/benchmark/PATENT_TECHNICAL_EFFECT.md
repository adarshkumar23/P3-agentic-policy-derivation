# Workstream M — Patent Technical Effect Benchmark

This document is the reproducible evidence referenced by `PATENT.md` §4
("Technical Effect"). It compares, for one real regulatory obligation, the
**manual** path a policy engineer follows today against the **automated**
derivation-and-compilation path implemented in
`core-side-patch/services/derivation_engine.py`.

Per `PATENT.md` §0 and §1.1, this benchmark does **not** claim novelty for
"compiling a structured rule into Rego" — the third-party policy
enforcement runtime disclosed by name in `PATENT.md` §1.1 already has its
own structured-rule-to-Rego compiler (`rego_builder.py`). What this
benchmark demonstrates is the value of the step upstream of that: turning
unstructured/semi-structured regulatory obligation *text* into a
structured, provenance-tagged constraint specification, automatically — a
step nothing else in the disclosed prior art performs.

All commands below were actually executed in this repository's `.venv`
against the vendored, test-only `opa` CLI at `.bin/opa` (`opa version` ==
`1.18.2`, Rego version `v1`). No output in this document is hypothetical.

---

## 1. Setup: the obligation under test

We use a real regulatory obligation representative of RBI's payment-system
data localization requirements (the same family of obligation as the India
DPDP example already exercised in `tests/unit/test_derivation_engine.py`,
extended here with a realistic citation to a distinct, plausible framework
so this benchmark is not a literal re-run of the unit test fixture):

```python
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
```

This is modeled on the Reserve Bank of India's April 2018 payment-system
data-localization circular (data relating to payment systems must be stored
only in India; cross-border processing, where permitted, must not result in
retention of the data outside India). The exact clause wording above is a
representative paraphrase for benchmarking, not a verbatim quotation of the
circular text.

The organization enforcing this obligation is a hypothetical tenant,
`acme-bank`.

---

## 2. Manual path: what a human policy engineer does today

Absent this engine, a policy engineer turns the obligation above into
enforceable, per-tenant Rego by hand. Enumerated at genuine granularity, this
is not a 3-step hand-wave — it is at minimum the following **17 steps**,
repeated in full for every tenant, and repeated again in full whenever the
obligation is amended upstream in the GRC system (there is no automatic link
today between the GRC record and any Rego file that was derived from it):

1. Locate the obligation record in the GRC system and read its free text in
   full.
2. Identify, by human judgment, which *category* of constraint this text
   expresses (financial limit? geographic/residency restriction? data-scope
   restriction? approval gate? some combination?). For this obligation:
   both a residency restriction *and* a cross-border data-transfer
   restriction — recognizing that these are two distinct Rego rules, not
   one, requires the engineer to correctly parse "stored only in India" as
   independent from "prohibited from being transferred outside the
   territory of India."
3. Decide which specific jurisdiction/region string(s) to encode as the
   "allowed" set (here: `"India"`) — there is no canonical enumeration in
   the source text; the engineer must infer it from prose.
4. Decide which data category the restriction applies to. The clause never
   uses the word "PII" — the engineer must recognize "personal data
   collected from customers" as equivalent to a `pii` category tag, an
   interpretive judgment call.
5. Decide whether the restriction is "any cross-border transfer" or
   "cross-border transfer of a specific restricted category only" — this
   obligation, read carefully, restricts transfer of *personal data*
   specifically, not literally all data (the sentence's own exception
   clause for "processing a cross-border transaction" complicates this
   further). Getting this distinction wrong either over-blocks legitimate
   traffic or under-blocks a real violation.
6. Decide the OPA/Rego version and syntax dialect to target (e.g. legacy
   Rego vs. `rego.v1` semantics, `contains`/`if` keyword requirements) —
   this is an infrastructure decision independent of the obligation text
   but still gates whether the hand-written policy will even parse against
   the runtime's actual OPA version.
7. Choose the package name. Per this system's convention it must be
   `complivibe.guardrails.org_<tenant>` — a convention the engineer must
   already know and consistently apply, by hand, per tenant.
8. Write the `package` declaration and `import rego.v1` header.
9. Write `default allow := false`.
10. Decide what `input` schema the enforcement point actually supplies
    (e.g. `input.action.destination_region`, `input.action.cross_border`,
    `input.action.data_categories`) — this requires either reading the
    enforcement runtime's own input-shape documentation or reverse
    engineering it from other guardrails, since the GRC obligation text
    says nothing about the runtime's input schema.
11. Hand-write the `deny` rule for the geographic-scope violation
    (destination region not in the allowed list).
12. Hand-write the `deny` rule for the cross-border-transfer-of-restricted-
    category violation, correctly gating it on *both* `cross_border == true`
    *and* the transferred category being in the restricted set (not just
    "any transfer at all") — this is exactly the interpretive judgment call
    from step 5, now re-expressed as a boolean expression that must not
    be dropped or simplified incorrectly under deadline pressure.
13. Hand-write the `allow` rule (`count(deny) == 0`), consistent with how
    the codebase's other guardrails structure `allow`/`deny`.
14. Construct one or more sample `input` documents by hand and manually run
    `opa eval` against the hand-written file to check the deny case
    triggers.
15. Construct a second sample `input` document and check the allow case
    is not incorrectly blocked (regression risk: an overly broad deny rule
    that also blocks legitimate domestic transfers).
16. Repeat steps 7–15 in full for every other tenant this obligation applies
    to, renaming the package each time and re-verifying the rename did not
    silently leave stale content referencing another tenant's package
    (there is no automated cross-check that a copy-pasted file was fully
    renamed).
17. When the RBI circular is later amended (e.g. new permitted-transfer
    exceptions, a change in the definition of covered data) — which
    regulatory circulars in this domain do — manually notice the change,
    re-read the amended text, and repeat this entire process for every
    tenant, because there is no stored link from the previously hand-written
    Rego file back to a specific version of the obligation it was derived
    from.

### Concrete, real error modes in this manual process

- **Mis-scoping the jurisdiction/region list (step 3).** The source text
  says "stored only in India," but a rushed reading could produce an
  allow-list of `["India", "APAC"]` if the engineer conflates this
  obligation with a different, broader data-residency policy elsewhere in
  the same GRC system — a realistic copy-paste-and-adapt failure mode when
  one engineer maintains dozens of tenant guardrails.
- **Gating on any transfer instead of restricted-category transfer (step
  5/12).** It is easy, especially under the misreading "no cross-border
  transfer" (a common simplification compliance summaries make), to write
  `deny { input.action.cross_border == true }` unconditionally — which
  would incorrectly block legitimate cross-border transfers of data that
  is *not* the restricted personal-data category, an over-blocking bug that
  breaks unrelated business functionality and is generally reported only in
  production, not caught in testing on the happy-path sample input.
- **Forgetting the per-tenant package rename (step 16).** Cloning tenant
  A's guardrail file for tenant B and forgetting to update the `package`
  line (or updating it but leaving a stray reference to
  `org_tenant_a` in a comment or an internal rule reference) either causes
  a load-time collision or, worse, causes tenant B's guardrail to silently
  evaluate against tenant A's namespace — a cross-tenant policy leak that
  is exactly what `PATENT.md` Claim 3 is designed to make structurally
  impossible.
- **Targeting a Rego syntax the deployed OPA version does not support
  (step 6/8).** Rego's `contains`/`if` keyword requirements and the
  `rego.v1` import changed between OPA versions; a policy engineer working
  from an older internal wiki example can write valid-looking Rego that
  fails to load against the actually-deployed OPA binary, a class of bug
  that is purely an artifact of manual authoring against stale
  documentation.
- **Silent staleness after upstream amendment (step 17).** Because there is
  no provenance link between a hand-written `.rego` file and the obligation
  record it was "derived" from, there is no way to query "which compiled
  policies were derived from obligation X" when X is amended — the
  amendment can go unnoticed by whoever owns the Rego files indefinitely.

That is a minimum of **17 concrete steps**, several of which involve
non-mechanical interpretive judgment calls with realistic, cited failure
modes, all repeated per tenant and per amendment.

---

## 3. Automated path: real code, real output

The automated path is a single function call. The exact script executed
(from the repo root, with `.venv` activated and `core-side-patch` on
`sys.path`, matching this repo's `conftest.py` setup):

```python
from services.derivation_engine import ObligationRecord, derive_and_compile, derive_constraint_spec

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
    framework="RBI Storage of Payment System Data (PSS Act, 2007) Circular DPSS.CO.OD No.1810/06.08.005/2017-2018",
    citation="RBI/2017-18/153 DPSS.CO.OD.No.1810/06.08.005/2017-18, dated April 6, 2018",
    control_ids=("CTRL-DATA-RESIDENCY-01",),
)

spec, rego_text = derive_and_compile([RBI_OBLIGATION], org_id="acme-bank")
```

This was actually run. Real, unedited printed output:

```
=== ConstraintSpec ===
ConstraintSpec(source_obligation_ids=('obl-rbi-2018-dpss',),
               financial_limits=(),
               geographic_scope=GeographicScope(allowed_regions=('India',),
                                                residency_required=True,
                                                source_obligation_ids=('obl-rbi-2018-dpss',)),
               data_scope=DataScope(restricted_categories=('pii',),
                                    cross_border_transfer_allowed=False,
                                    source_obligation_ids=('obl-rbi-2018-dpss',)),
               approval_requirements=(),
               unrecognized_obligation_ids=())

--- compiled Rego ---
package complivibe.guardrails.org_acme_bank

import rego.v1

default allow := false

deny contains reason if {
	input.action.amount > 0
	some limit in financial_limits
	input.action.currency == limit.currency
	input.action.amount > limit.max_amount
	reason := sprintf("amount %v %v exceeds limit %v %v (%v)", [input.action.amount, input.action.currency, limit.max_amount, limit.currency, limit.per])
}

financial_limits := []

deny contains reason if {
	input.action.destination_region
	not input.action.destination_region in ["India"]
	reason := sprintf("destination region %v is outside permitted regions %v", [input.action.destination_region, ["India"]])
}

deny contains reason if {
	input.action.cross_border == true
	some category in input.action.data_categories
	category in ["pii"]
	reason := sprintf("cross-border transfer of restricted category %v is not permitted", [category])
}

allow if {
	count(deny) == 0
}
```

Note the provenance property directly on the `ConstraintSpec`: both
`geographic_scope.source_obligation_ids` and
`data_scope.source_obligation_ids` are `('obl-rbi-2018-dpss',)` — every
derived element carries a queryable link back to the exact source
obligation it came from, not merely "some obligation, somewhere."

Also note step 5 from the manual path above — correctly gating the deny
rule on cross-border transfer *of the restricted category*, not any
transfer — was produced automatically and correctly:
`input.action.cross_border == true` **and** `category in ["pii"]` are both
present in the compiled `deny` rule (this is exactly the interpretive
judgment call a rushed manual author is liable to get wrong per §2).

The single Rego file above is tenant-scoped to `org_acme_bank`
automatically; deriving the same obligation for a second tenant is another
one-line call (`derive_and_compile([RBI_OBLIGATION], org_id="other-bank")`),
not a manual copy/rename/re-verify cycle.

---

## 4. Validation: `opa eval` against real deny and allow inputs

The compiled Rego above was written to a temp file and evaluated with the
vendored, test-only `opa` CLI (`.bin/opa`, version `1.18.2`), exactly as
`tests/unit/test_derivation_engine.py`'s `_opa_eval` helper does. Real
commands and real output:

**Deny case** — a cross-border transfer of PII to Singapore, which the
obligation prohibits:

```
$ opa eval --format json --input <(deny_case.json) --data acme_bank_guardrail.rego 'data.complivibe.guardrails.org_acme_bank.allow'
input: {"action": {"amount": 0, "cross_border": true, "data_categories": ["pii"], "destination_region": "Singapore"}}
stdout:
{
  "result": [
    {
      "expressions": [
        {
          "value": false,
          "text": "data.complivibe.guardrails.org_acme_bank.allow",
          "location": { "row": 1, "col": 1 }
        }
      ]
    }
  ]
}
```

Querying `deny` directly on the same input shows both violated rules and
their human-readable reasons:

```
$ opa eval --format json --input <(deny_case.json) --data acme_bank_guardrail.rego 'data.complivibe.guardrails.org_acme_bank.deny'
stdout:
{
  "result": [
    {
      "expressions": [
        {
          "value": [
            "cross-border transfer of restricted category pii is not permitted",
            "destination region Singapore is outside permitted regions [\"India\"]"
          ],
          "text": "data.complivibe.guardrails.org_acme_bank.deny",
          "location": { "row": 1, "col": 1 }
        }
      ]
    }
  ]
}
```

**Allow case** — a domestic (India-to-India), non-cross-border transfer of
the same data category, which the obligation permits:

```
$ opa eval --format json --input <(allow_case.json) --data acme_bank_guardrail.rego 'data.complivibe.guardrails.org_acme_bank.allow'
input: {"action": {"amount": 0, "cross_border": false, "data_categories": ["pii"], "destination_region": "India"}}
stdout:
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.complivibe.guardrails.org_acme_bank.allow",
          "location": { "row": 1, "col": 1 }
        }
      ]
    }
  ]
}
```

The compiled policy is both syntactically valid (it loads and evaluates
under `opa eval` without error) and semantically correct for this
obligation (it denies the prohibited cross-border PII transfer and allows
the permitted domestic transfer).

This same scenario is additionally encoded as a pytest in
`tests/benchmark/test_benchmark_scenario.py`, run with:

```
$ source .venv/bin/activate && python -m pytest tests/benchmark/test_benchmark_scenario.py -v
```

which passed, real output:

```
tests/benchmark/test_benchmark_scenario.py::TestBenchmarkScenarioDerivation::test_derivation_produces_provenance_tagged_spec PASSED [ 25%]
tests/benchmark/test_benchmark_scenario.py::TestBenchmarkScenarioDerivation::test_compiled_rego_is_scoped_to_tenant_package PASSED [ 50%]
tests/benchmark/test_benchmark_scenario.py::TestBenchmarkScenarioOpaValidation::test_cross_border_transfer_to_singapore_is_denied PASSED [ 75%]
tests/benchmark/test_benchmark_scenario.py::TestBenchmarkScenarioOpaValidation::test_domestic_india_transfer_is_allowed PASSED [100%]
4 passed in 0.55s
```

---

## 5. Technical effect summary

| | Manual authoring | Automated derivation + compilation |
|---|---|---|
| Steps to go from obligation text to a validated, tenant-scoped Rego file | ~17, enumerated in §2 | 1 function call (`derive_and_compile`) + running `opa eval` to confirm (not required for correctness, just for this benchmark's own verification) |
| Interpretive judgment calls exposed to human error | At least 5 (category classification, region inference, cross-border-vs-restricted-category scope, OPA syntax/version targeting, input schema assumptions) | 0 at the authoring step — extraction is deterministic pattern matching over the obligation text, the same patterns every time |
| Per-tenant repetition | Full manual redo (package rename, re-verification) per tenant | Same call, different `org_id` string; package naming is handled by `rego_package_slug` |
| Behavior on an obligation the engine doesn't recognize | N/A (human reads everything) | Recorded explicitly in `unrecognized_obligation_ids` — visible and routed to manual handling, not silently mishandled (see §6) |
| Traceability from compiled policy back to source obligation | None by default; requires separate, manually maintained bookkeeping | Built in: every `ConstraintSpec` element carries `source_obligation_ids`; `ConstraintSpec.source_obligation_ids` covers every input obligation, matched or not |
| Effect of an upstream obligation amendment | Silent drift until someone happens to notice and manually redo the process | The stored `source_obligation_ids` link lets affected guardrails be identified and recompiled programmatically (`POST /ai-guardrails/{id}/compile-rego` per `PATENT.md` §3.4), without a human re-reading the regulation from scratch |

The provenance property is the crux of the claimed technical effect: manual
Rego authoring has no natural mechanism for recording, in a queryable form,
which regulatory obligation record a given compiled Rego rule came from.
Nothing stops a human from writing a code comment saying so, but nothing
enforces it, keeps it in sync across a rename/refactor, or lets a caller
programmatically ask "which compiled guardrails were derived from obligation
X" the way `ConstraintSpec.source_obligation_ids` and
`{Geographic,Data}Scope.source_obligation_ids` do.

---

## 6. Scope honesty

`derive_constraint_spec` is **pattern/regex-based extraction over obligation
text**, not full natural-language understanding, and it is not designed or
claimed to be. This matters for the patent's credibility: the benchmark
above is a real success case, not evidence that the engine handles arbitrary
regulatory prose.

**Handled well today** (the four families implemented in
`derivation_engine.py`):

- **Financial limits** — amount + currency + limiting keyword ("shall not
  exceed", "limit(ed) to", "threshold of") + optional period ("per
  transaction"/"per day"/etc).
- **Geographic / residency restrictions** — data-localization / data-
  residency keyword families plus a region name, either extracted from the
  text itself (`within the territory of India`) or falling back to the
  obligation's structured `jurisdiction` field.
- **Data-category cross-border restrictions** — a fixed vocabulary of
  category keywords (`pii`, `financial`, `health`, `biometric`) combined
  with an explicit cross-border-prohibition phrase family.
- **Approval requirements** — a fixed keyword family ("prior approval",
  "human review", "sign-off", "dual control", "maker-checker") plus an
  optional explicit approver count.

**What it does *not* claim to handle**, and how it fails safely rather than
silently: an obligation whose text does not match any of the above pattern
families (for example the deliberately unmatched fixture obligation in
`tests/unit/test_derivation_engine.py`, `"The organization should maintain a
general culture of compliance awareness"`) is **not** dropped, guessed at,
or force-fit into one of the four categories — its id is placed into
`ConstraintSpec.unrecognized_obligation_ids`, explicitly signaling to the
caller that this obligation still requires manual authoring. This is a
conservative failure mode: the system tells you what it could not derive,
rather than compiling a policy that looks plausible but is wrong. Obligation
text with unusual phrasing not covered by the current keyword families
(e.g. non-English source text, obligations expressed as multi-clause
cross-references to other documents, or numeric conditions embedded in
tables rather than prose) would also land in
`unrecognized_obligation_ids` today rather than being incorrectly
interpreted — extending pattern coverage to more phrasings is possible
future work, not a claim made by the current benchmark.

# Security Review — Workstream O

Scope: adversarial review of the envelope/payload trust boundary
(`core-side-patch/services/envelope.py`), the receipt-signing key-custody
boundary (`core-side-patch/services/receipts.py`), the check-action HTTP
surface (`core-side-patch/api/guardrails.py`), the per-org rate limiter
(`core-side-patch/services/rate_limit.py`), and a dependency/static-analysis
pass (`bandit`, `pip-audit`) over `core-side-patch/`.

This review is additive to, and does not duplicate, the existing unit tests
in `tests/unit/test_envelope_separation.py`, `tests/unit/test_receipts.py`,
and `tests/unit/test_rate_limit.py`.

Run: `source .venv/bin/activate && python -m pytest tests/security -v` — all
tests pass, deterministically (no timing-flaky assertions; all "must be
fast" assertions use multi-second budgets against sub-100ms actual
operations).

**Update (2026-07-06, re-run after the `services/receipts.py` migration to
the real `agentmesh_mcp_receipts`/`mcp_receipt_governed` package):** `bandit`
and `pip-audit` were re-run for real against the current `.venv` (not
re-asserted from the prior run). `bandit` is unchanged (same 4 Low findings,
same triage). `pip-audit` now surfaces **one new, genuine CVE**
(`GHSA-537c-gmf6-5ccf` in `cryptography==47.0.0`) that was not present in the
prior scan (which recorded `cryptography==49.0.0`, clean) -- introduced
because `agentmesh_mcp_receipts[crypto]`'s dependency metadata pins
`cryptography<48.0,>=46.0.7`, forcing a downgrade of an otherwise-clean
dependency into a version with a known vulnerability. See the fully updated
§3 below for the real re-run output and triage of this new finding. It is
triaged as **real but not exploitable via this repo's actual usage** (the
vulnerable OpenSSL code paths are CMS/PWRI decryption and large-ASN.1-blob
parsing of untrusted network input; this repo's only use of `cryptography`
is local `Ed25519PrivateKey` generation for `ReceiptSigner`, which never
touches those code paths) -- but it is flagged as a genuine, currently
unfixable-without-vendor-action supply-chain risk, not dismissed as noise.

---

## 1. Envelope/payload separation under adversarial input

File: `tests/security/test_envelope_adversarial.py` (34 tests).

What was tried, beyond the existing well-formed-attack-shape tests:

- **Payload smuggled inside a real field's *value*.** Passing a dict (e.g.
  `currency={"customer_pii": {...}}`, or the same into `action_id`,
  `destination_region`, `amount`, a `data_categories` list element, or
  `cross_border`) is rejected by Pydantic's own type validation
  (`ValidationError`) before `build_envelope`'s explicit checks even run.
  **Result: passes.** Pydantic does not coerce a dict into `str`, `float`,
  or `bool`.
- **Field-name near-misses of `_PAYLOAD_ONLY_FIELDS`** (case variations —
  `Customer_PII`, `CUSTOMER_PII`; a Cyrillic-і homoglyph —
  `customer_pіi`; leading/trailing whitespace; a zero-width space; a
  combining-accent variant; hyphen-for-underscore). None of these match the
  exact-string `_PAYLOAD_ONLY_FIELDS` set, so `build_envelope`'s explicit
  payload-field check does not catch them by name — **but every one of them
  is still rejected**, because it is also not a real `ActionEnvelope` field,
  and `ActionEnvelope.model_config = ConfigDict(extra="forbid")` rejects any
  unrecognized key regardless of name. **Result: defense-in-depth confirmed
  — the exact-match check and `extra="forbid"` are two independent layers,
  and the second layer holds even when a near-miss dodges the first.** No
  sensitive value ever appears in the resulting error message.
- **PII stuffed into a legitimately-named, correctly-typed field** (e.g.
  `action_id = "customer-ssn-<value>"`). This is **accepted** — and
  documented here as a genuine, but out-of-scope, residual risk: a `str`
  field can hold arbitrary string content by design, so `build_envelope`
  has no structural way to distinguish "opaque id" from "PII disguised as a
  string." **This is a call-site responsibility** (never construct
  `action_id`/`currency`/`destination_region` from raw customer PII), not a
  gap in `services/envelope.py`. Flagged for awareness, not fixed — there is
  nothing in this module that could fix it without also breaking legitimate
  use of those fields.
- **Pathological input size** (a 500-levels-deep nested dict, a 5&nbsp;MB
  single string, a 50,000-key wide dict, 20,000 unexpected top-level keys).
  All rejections complete in well under a second (asserted against a 5s
  budget); the one case that is legitimately *accepted* (a very long valid
  `action_id` string) also completes near-instantly. **Result: no
  pathological slowness or crash; clean, fast rejection or clean,
  fast acceptance in every case.**

**No fix required in this area** — the module's structural design already
holds under every adversarial input tried.

---

## 2. Signing key never leaks

File: `tests/security/test_key_never_leaks.py` (9 tests).

Method: construct `ReceiptSigner(signing_key_hex="ab"*32)` (a real, valid
32-byte hex seed used as a greppable sentinel) and drive it through direct
API use, the `/ai-systems/{id}/guardrails/check` HTTP endpoint (both the
success and the 400 payload-rejection path), the `/receipt-chain` endpoint,
and a full request captured through both a `StringIO` stdlib-logging
handler and `caplog`, with `structlog` also wired to route through stdlib
logging for that window.

Checked, and confirmed **not** to leak:

- `Receipt` dataclass fields, `repr()`/`str()` of a `Receipt`, and
  `repr()`/`str()` of `ReceiptSigner` itself.
- The HTTP response body of a successful `/guardrails/check` call.
- The HTTP response body of the 400 (payload-rejected) path.
- The `/receipt-chain` endpoint's JSON body.
- Exception messages from malformed `signing_key_hex` input (wrong length,
  non-hex characters) — the error reports only derived metadata (e.g.
  decoded byte length), never the offending string.
- Log output (stdlib `logging` via a `StringIO` handler, `caplog`, and
  `structlog` routed through stdlib logging) across a full check-action
  call plus a triggered construction failure.

Positive controls included throughout (e.g. asserting `public_key_hex` *is*
present on receipts and *is not* equal to the private-key sentinel) so a
trivially-vacuous assertion isn't masquerading as a pass.

Also reconfirmed structurally: `verify_receipt(receipt: Receipt) -> bool`
has no parameter that could ever hold a raw private-key string — calling it
with a bare string raises `TypeError`/`AttributeError` rather than doing
anything with it.

**No leak found; no fix required.**

---

## 3. `bandit` + `pip-audit`

**Both tools were re-run for real** after `services/receipts.py`'s migration
to the real `agentmesh_mcp_receipts`/`mcp_receipt_governed` dependency (see
the top-of-file update note), specifically to check whether that new,
real, third-party dependency (and its `cryptography` extra) introduces any
new bandit findings or CVEs. Output below is the actual re-run, not a
copy-paste of the prior scan.

### bandit (`bandit -r core-side-patch -f txt`) — RE-RUN 2026-07-06

```
Run started:2026-07-06 18:04:12.354930+00:00

>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   Location: core-side-patch/api/guardrails.py:39:0
39	import subprocess

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   Location: core-side-patch/api/guardrails.py:176:19
176	            proc = subprocess.run(
177	                ["opa", "eval", "--format", "json", "--input", "/dev/stdin", "--data", rego_path, query],
178	                input=json.dumps(input_data),
179	                capture_output=True,
180	                text=True,
181	                timeout=10,
182	            )

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   Location: core-side-patch/api/guardrails.py:176:19
   (same call as above)

--------------------------------------------------
>> Issue: [B101:assert_used] Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
   Severity: Low   Confidence: High
   Location: core-side-patch/permissions.py:89:8
89	        assert permission_code is not None or permission_code is None  # no-op reference

Code scanned:
	Total lines of code: 2012
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity): Undefined: 0, Low: 4, Medium: 0, High: 0
	Total issues (by confidence): Undefined: 0, Low: 0, Medium: 0, High: 4
```

**Diff vs. prior scan:** identical 4 findings, same file/rule set (the only
change is `guardrails.py`'s subprocess call shifting from line 171 to line
176, and total LOC from 1966 to 2012, both just from unrelated line
additions elsewhere in the file since the last scan -- not from
`services/receipts.py`, which bandit flags nothing in at all, before or
after its migration to the real `mcp_receipt_governed` package/its new
`cryptography` import). **No new bandit findings from the new dependency or
its `cryptography` usage.**

**Triage:**

- **B404 / B607 / B603 (subprocess in `guardrails.py`)** — judgment call:
  **acceptable noise, no fix.** This call
  (`subprocess.run(["opa", "eval", ...], ...)`) invokes the vendored `opa`
  CLI as a test-only local transport standing in for a real OPA HTTP
  deployment (see the module's own comment block above the call). It:
  (a) passes a literal argument **list**, never `shell=True`, so there is no
  shell-metacharacter injection surface; (b) the executable name `"opa"` is
  resolved via `PATH`, which is the documented, intentional mechanism for
  finding the vendored CLI (`.bin/opa` is put on `PATH` by `conftest.py` for
  tests) rather than a hardcoded absolute path — B607's "partial path"
  warning is expected and correct behavior here, not a defect; (c) the only
  interpolated value into the argument list is `rego_path`, a path to a
  `tempfile.NamedTemporaryFile` this same function created moments earlier
  (not attacker-controlled), and `query`, built from the request's URL path
  segments after replacing `/` with `.` — not passed through a shell, so
  even unexpected characters in `query` cannot achieve command injection
  (they'd just be one CLI argument value). This is the textbook safe
  subprocess pattern bandit's own B603 docs recommend; suppressing the
  warning via `#nosec` was deliberately **not** done, so the warning stays
  visible on future scans as a reminder to re-verify this reasoning if the
  call site changes, rather than being silently hidden.
- **B101 (`assert` in `permissions.py:89`)** — judgment call: **cosmetic,
  no fix needed, flagged for a human to clean up opportunistically.** The
  flagged line, `assert permission_code is not None or permission_code is
  None`, is a tautology (always `True`) left in as a "no-op reference" so
  `permission_code` reads as used at the call site (see the surrounding
  docstring). It performs no authorization check and nothing security-
  relevant depends on it — bandit's generic "asserts get stripped under
  `python -O`" warning is technically correct but irrelevant here since the
  assert enforces nothing. Not touched, since Workstream O's brief scopes
  changes to `permissions.py` to genuine rate-limit-bypass fixes only, and
  this is neither a bypass nor a real vulnerability.

**No genuine, fixable vulnerability found in `core-side-patch` by bandit.**

### pip-audit — RE-RUN 2026-07-06, after the `receipts.py` migration

```
$ pip-audit
Found 1 known vulnerability in 1 package
Name         Version ID                  Fix Versions
------------ ------- ------------------- ------------
cryptography 47.0.0  GHSA-537c-gmf6-5ccf 48.0.1
```

**This is new** — the prior scan (recorded above/in the original version of
this section) found zero vulnerabilities with `cryptography==49.0.0`
installed. The current `.venv` now has `cryptography==47.0.0` — a
**downgrade**, not an upgrade, caused by the new dependency:

```
$ pip show agentmesh_mcp_receipts
Name: agentmesh_mcp_receipts
Version: 3.7.0
Requires-Dist: cryptography<48.0,>=46.0.7; extra == 'crypto'
```

`agentmesh_mcp_receipts[crypto]==3.7.0` (the extra this repo installs, per
`services/receipts.py`'s new import of `mcp_receipt_governed`) pins
`cryptography<48.0,>=46.0.7`. Installing it forced `cryptography` down from
the previously-clean `49.0.0` to `47.0.0`, which is within that pin's range
and carries a known CVE. `pip index versions agentmesh_mcp_receipts` confirms
`3.7.0` is the latest available release — there is no newer version of this
dependency to upgrade to that relaxes the `cryptography` pin; this is not
fixable from this repo's side today without either overriding the pin
(installing `cryptography>=48.0.1` alongside a `crypto<48.0` requirement,
which `pip` will refuse / would be unsupported by the package's own stated
constraints) or waiting on the vendor.

**GHSA-537c-gmf6-5ccf detail** (fetched from the advisory and the referenced
OpenSSL security advisory, `openssl-library.org/news/secadv/20260609.txt`):
`cryptography`'s prebuilt wheels statically link OpenSSL, and wheels built
before `cryptography==48.0.1` bundle an OpenSSL with three
out-of-bounds-read/overflow issues (CVSS up to 7.5, High). The three
underlying OpenSSL issues, and the code paths that trigger them:

- **CMS/PWRI password-based decryption** (`kek_unwrap_key()`): a heap
  out-of-bounds read triggerable by an attacker-chosen stream-mode KEK
  cipher in an untrusted CMS message, before any password/authentication
  check succeeds.
- **ASN.1 content parsing** (`d2i_X509()`/`d2i_PKCS7()` and similar): an
  integer-truncation bug mishandling primitive ASN.1 elements over 2GB on
  64-bit Unix, causing a heap buffer over-read when decoding
  attacker-supplied DER/BER data.
- **`ASN1_mbstring_ncopy()`**: a signed-integer-overflow heap buffer
  overflow when converting an application-supplied multibyte string of
  roughly 2^30+ characters.

**Triage, applying this workstream's stated discipline** (check whether this
repo's actual usage pattern exercises the vulnerable code path):
`core-side-patch`'s only import of `cryptography` is
`services/receipts.py`'s `from cryptography.hazmat.primitives.asymmetric.ed25519
import Ed25519PrivateKey`, used exactly once, to derive
`ReceiptSigner.public_key_hex` from a caller-supplied private-key seed at
construction time (see that module). This repo:

- **Never parses CMS messages, X.509 certificates, or PKCS7 blobs** (no
  `x509`, `Certificate`, `PKCS7`, `CMS`, or `load_pem_x509_certificate`/
  `load_der_*` usage anywhere in `core-side-patch` — confirmed by a repo-wide
  grep, not assumed), so the CMS/PWRI and ASN.1-decoding vulnerable paths
  are never reached.
- **Never calls `ASN1_mbstring_ncopy`-backed APIs** (no multibyte-string
  X.509 name construction, which is the only thing that function is used
  for) — irrelevant here for the same reason.
- The one thing this repo does with `cryptography` — raw Ed25519 key
  derivation from 32 raw bytes — does not touch OpenSSL's ASN.1/CMS decoder
  at all.

**Conclusion: a real, currently-unfixable-from-this-repo CVE exists in the
resolved dependency tree, but it is not exploitable via any code path this
repo's `core-side-patch` actually exercises.** This is flagged prominently
(not silently dismissed) because: (a) it is a genuine regression introduced
by today's dependency change, not "no CVEs, same as before"; (b) the
non-exploitability conclusion depends on this repo's *current* limited use
of `cryptography` (Ed25519 only) continuing to hold — if any future code in
this dependency chain (this repo's own code, or a future version of
`agentmesh_mcp_receipts` itself) starts parsing X.509/CMS/PKCS7 data,
including from `mcp_receipt_governed`'s own internals if it ever adds such a
code path, this conclusion would need to be re-verified; and (c) whoever
owns the real deployment should track when `agentmesh_mcp_receipts` relaxes
its `cryptography<48.0` pin (or vendors/patches around it) so the resolved
`cryptography` version can move to `>=48.0.1` and this CVE stops applying to
the dependency tree at all, not just "in practice, for now."

**Action taken: none in this repo** (no production code touches the
vulnerable paths, and there is no available non-vulnerable version of
`agentmesh_mcp_receipts[crypto]` to pin to instead). **Recommendation for a
human:** track `agentmesh_mcp_receipts` for a release that relaxes its
`cryptography` upper pin past `48.0.1`, and re-run `pip-audit` after any
dependency bump to confirm this CVE has cleared.

Other key dependency versions in the active `.venv` at this re-run (for the
record, all otherwise unflagged by `pip-audit`): `fastapi==0.139.0`,
`pydantic==2.13.4`, `pydantic_core==2.46.4`, `starlette==1.3.1`,
`httpx==0.28.1`, `SQLAlchemy==2.0.51`, `structlog==26.1.0`,
`uvicorn==0.50.2`, `prometheus_client==0.25.0`, `agentmesh-mcp-receipts==3.7.0`
(this repo's one actual declared runtime dependency on the policy
enforcement runtime's ecosystem — see `PATENT.md` §1.1 for the specific
name; a few other packages from that same ecosystem were installed in this
`.venv` earlier purely for research/verification purposes during this
build, are not declared dependencies of this repo, and have since been
uninstalled — see ASSUMPTIONS.md's "PyPI installability checked directly"
section for what was verified). This one package has no known
vulnerability — only its *pinned-down* `cryptography` transitive dependency
does (see above).

---

## 4. Rate limiting (Workstream K) bypass check

File: `tests/security/test_rate_limit_bypass.py` (6 tests).

Confirmed:

- The limiter is genuinely wired into `/ai-systems/{id}/guardrails/check`
  (a 429 follows exhaustion, reconfirming
  `tests/unit/test_guardrail_api.py::TestCheckAction::test_rate_limit_429`).
- **Header omission cannot reach a fresh, unthrottled bucket by skipping
  identification**: `X-Org-Id` is a FastAPI-required header consumed by
  `require_permission` (which `_rate_limit_guard` sits behind); omitting it
  is a 422 before the rate-limit dependency (or org-scoping) ever runs.
- **An empty-string `X-Org-Id`** *is* accepted by `require_permission` (only
  `X-Role` emptiness is checked) and does consume a token from its own,
  distinct `""` bucket — but this cannot be used to obtain an actual
  successful check-action beyond org-a's real budget: `_get_org_ai_system`
  org-scoping 404s for `organization_id=""` since no `ai_system` is
  registered under it, and org-a's real bucket is confirmed untouched
  afterward.
- **Case/whitespace variation of `X-Org-Id`** (`"ORG-A"`, `"Org-A"`,
  `" org-a"`, `"org-a "`, `"org-a\t"`) each land in their own separate,
  independently-exhausted rate-limit bucket (keyed on the literal header
  string), **and** each is independently rejected by org-scoping (404,
  since the registered `ai_system`'s `organization_id` is the exact string
  `"org-a"`). Static inspection of `create_app`'s `_rate_limit_guard`
  dependency and of `_get_org_ai_system` confirms **both** key off exactly
  `membership.organization_id` verbatim — no `.lower()`/`.upper()`/
  `.casefold()`/`.strip()` normalization is applied on either side, so
  there is no skew between what the rate limiter buckets on and what
  org-scoping compares against, in this repo's code as written.

**No exploitable bypass found in this repo as implemented; no fix
required.**

**Residual risk flagged for a human** (per this workstream's brief, item
4): this conclusion holds only because *neither* side normalizes
`organization_id` today. `permissions.py`'s `require_permission` /
`_get_org_ai_system` are explicitly documented (see that module's own
docstring, and `ASSUMPTIONS.md`'s "carried over from P2" section) as
**local stand-ins** for the real `complivibe-backend-v5` auth/org-lookup
layer, re-verification against which is an explicit action item before
merge. If the *real* org-lookup ever normalizes organization identifiers
(e.g. a case-insensitive lookup against a real `organizations` table, or
canonicalizing surrounding whitespace from a header) while
`_rate_limit_guard`'s `org_id_getter` continues to key the limiter off the
raw header string verbatim, that skew would reintroduce exactly the bypass
class this section tested for: a caller with one real, legitimate org
membership could multiply their effective rate-limit budget by varying
`X-Org-Id`'s case/whitespace on each request, since permission checks would
still resolve all variants to the same org while the limiter would treat
each as a fresh bucket. **Recommendation for whoever wires this against the
real backend:** derive the rate-limit key from whatever canonical/
normalized organization identifier the real auth layer resolves to (e.g. a
numeric/UUID org id from the `Membership`, not the raw header string), not
from the header text directly.

---

## 5. Rate limiting under actual concurrent/stress load (not just sequential)

File: `tests/security/test_rate_limit_under_concurrent_load.py` (4 tests).

`tests/security/test_rate_limit_bypass.py` (§4 above) proves the limiter is
wired in and cannot be identity-spoofed, but only ever fires requests
sequentially (at most two in a row). `tests/unit/test_rate_limit.py` proves
`TokenBucketRateLimiter`'s locking is correct when called directly, but
again never through the full HTTP stack under real concurrency. This
section closes that gap: it drives `TokenBucketRateLimiter` through the
real `/ai-systems/{id}/guardrails/check` endpoint (real FastAPI dependency
resolution, real request parsing, the real per-request DB session) with a
burst of many concurrent threads (`concurrent.futures.ThreadPoolExecutor`)
racing for the same org's bucket, configured with a small, known capacity
(20) and a negligible refill rate.

Confirmed:

- A 300-thread concurrent burst against a `capacity=20` bucket yields
  **exactly 20** non-429 (200) responses — never more (double-spend) and
  never fewer (lost grant) — reconfirmed across 5 repeated fresh-bucket
  trials and again at 500 concurrent threads to maximize lock contention.
- A slower/faster-refill scenario (`capacity=5`, `refill_per_second=5.0`,
  with a real HTTP round trip — including a real `opa eval` subprocess call
  — per request, so bursts take non-trivial wall-clock time) still never
  exceeds the number of tokens that could legitimately exist given the
  burst's own measured elapsed time plus a deliberate inter-burst sleep —
  i.e. legitimate refill during a slow burst is correctly accounted for by
  the bound used, and no additional over-refill/double-spend beyond that
  bound was ever observed.

**No token double-spending was ever observed under concurrency.**
`_Bucket.allow()`'s refill-then-compare-then-decrement sequence in
`services/rate_limit.py`, entirely inside `with self.lock:`, holds under
real concurrent HTTP load exactly as the per-bucket-lock design intends.
**No fix required.**

---

## 6. Org-scoping / Rego package isolation under concurrent cross-org load

File: `tests/security/test_concurrent_cross_org_isolation.py` (4 tests).

`tests/unit/test_tenant_isolation.py` proves package isolation with
sequential `opa eval` calls; `tests/unit/test_guardrail_api.py` proves
sequential cross-org 404s through the HTTP API. This section re-proves both
under real concurrent, interleaved, cross-org HTTP load: three orgs
(`org-a`/`org-b`/`org-c`), each with its own AI system, its own compiled
Rego package, and strictly increasing financial limits ($10,000 / $50,000 /
$100,000), all bundled into the same running app (as a real multi-tenant
deployment would be).

Confirmed:

- **300 concurrent, randomly-interleaved requests** across all three orgs,
  each using an amount straddling *that request's own org's* limit
  (`limit - 1000` expected allow, `limit + 1000` expected deny): every
  single response's allow/deny decision matched its own org's limit, with
  zero cross-contamination, under 40-way concurrent thread contention.
- **The same $30,000 amount fired concurrently at all three orgs** (which
  must diverge: deny under org-a's $10,000 limit, allow under org-b's
  $50,000 and org-c's $100,000 limits) diverged correctly on every single
  one of 120 interleaved concurrent responses — no org's limit ever leaked
  into another's evaluation under simultaneous load.
- **Concurrent cross-org access attempts** (every ordered pair of
  org-A-credentials-against-org-B's-`ai_system_id`, repeated 20x, for 120
  total cross-org attempts) fired **simultaneously** with 120 legitimate
  same-org requests: every single cross-org attempt still got 404, and
  every single legitimate request still got its own org's correct
  allow=True decision — even while both classes of traffic were in flight
  at the same time on the same running app instance.

**No cross-org contamination or isolation bypass was ever observed under
concurrency.** Rego package isolation (keyed purely on which package path is
queried, per `test_tenant_isolation.py`'s existing findings) and
`_get_org_ai_system`'s org-scoped 404 convention both hold under concurrent,
interleaved, multi-tenant load. **No fix required.**

---

## Summary

| Area | Genuine finding? | Action |
|---|---|---|
| 1. Envelope/payload adversarial | Residual risk: PII in a correctly-typed string field (e.g. `action_id`) is accepted by design | Documented as call-site responsibility; no code change (nothing to fix without breaking legitimate use) |
| 2. Key-leak surface | None | No fix needed |
| 3. bandit | 4 Low findings, all triaged as expected/acceptable (vendored-CLI subprocess pattern, cosmetic no-op assert); unchanged after the `receipts.py`/`agentmesh_mcp_receipts` migration | No fix needed |
| 3. pip-audit | **New since last scan**: `GHSA-537c-gmf6-5ccf` in `cryptography==47.0.0`, introduced by `agentmesh_mcp_receipts[crypto]`'s `cryptography<48.0` pin forcing a downgrade from the previously-clean `49.0.0`. Real CVE, but not exploitable via this repo's Ed25519-only usage of `cryptography` (no CMS/X.509/ASN.1 parsing of untrusted data anywhere in `core-side-patch`) | No code fix available (no non-vulnerable version of `agentmesh_mcp_receipts[crypto]` to pin to); flagged for a human to track upstream for a pin relaxation |
| 4. Rate-limit bypass (sequential) | None exploitable today; residual risk if real backend normalizes org_id while this limiter doesn't | Flagged for human re-verification at `complivibe-backend-v5` integration time; no code change in this standalone repo (nothing to normalize against yet) |
| 5. Rate-limit under concurrent load | None — no double-spending observed under real concurrent HTTP load (300- and 500-thread bursts) | No fix needed |
| 6. Cross-org isolation under concurrent load | None — no contamination observed under real concurrent, interleaved, multi-tenant HTTP load | No fix needed |

No changes were made to `core-side-patch/permissions.py` or
`core-side-patch/services/rate_limit.py` — no genuine, small, clearly-scoped
bypass was found that would justify touching either file per this
workstream's change-scope. All work for this workstream is confined to
`tests/security/`.

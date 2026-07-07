# mypy: allow-untyped-defs
"""Structural (type-level) trust boundary between what may be transmitted to
CompliVibe's core / OPA for policy evaluation (`ActionEnvelope`) and what must
never leave the customer's own environment (`ActionPayload`).

Per PATENT.md §0/§3, this repository only derives and hands off policy; it
never evaluates policy itself and never needs, and must never construct, a
network representation of an `ActionPayload`. That model exists purely so the
separation is concrete and testable here, not because this repo transmits it
anywhere.

Design choices:

* `ActionEnvelope` and `ActionPayload` are two independent `pydantic.BaseModel`
  subclasses with no shared base other than `BaseModel` itself, and no
  overlapping field names. There is no `ActionBase` (or similar) they both
  inherit from — that would create a single seam where a field added "to the
  base" could silently start flowing into both the transmitted envelope and
  the untransmitted payload.
* Both models use `model_config = ConfigDict(extra="forbid")`. Passing a
  payload-only key into `ActionEnvelope(**data)` is a validation error, not a
  value that gets silently dropped.
* `build_envelope()` **rejects** (raises `ValueError`) rather than silently
  stripping payload-shaped keys out of `raw`. This is a deliberate choice: if
  a caller accidentally passes `raw_request_body` / `customer_pii` /
  `documents` / `credentials` into `build_envelope`, that is almost always a
  bug at the call site (e.g. someone forwarded the whole request object
  instead of extracting the envelope fields) and we want that bug to be loud
  at the boundary, not quietly "fixed" by dropping the sensitive keys and
  continuing — a caller that silently has its payload stripped may believe
  its payload was safely handled elsewhere when it was actually just
  discarded, or worse, may retry with a "cleaned" raw dict that still
  originated from an untrusted merge upstream. A hard failure forces the bug
  to be fixed at the source.
* Because rejecting means the offending value could otherwise end up quoted
  back in an exception message (and from there into a log line), the error
  path here is scrubbed: `build_envelope` never lets the *value* of a
  rejected payload field flow into the exception message, `repr()`, or a
  Pydantic `ValidationError`. Only the field *names* are reported.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# Field names that only make sense as part of the sensitive payload, and must
# never be accepted into an envelope under any name.
_PAYLOAD_ONLY_FIELDS = frozenset(
    {"raw_request_body", "customer_pii", "documents", "credentials"}
)


class ActionEnvelope(BaseModel):
    """Fields safe to transmit to CompliVibe's core / OPA for policy
    evaluation. Contains only action metadata needed to evaluate policy —
    never the underlying sensitive request payload.
    """

    model_config = ConfigDict(extra="forbid")

    action_id: str
    ai_system_id: str
    organization_id: str
    action_type: str
    amount: float | None = None
    currency: str | None = None
    destination_region: str | None = None
    data_categories: list[str] = []
    cross_border: bool = False
    requires_approval: bool = False
    approved_by: list[str] = []
    timestamp: str


class ActionPayload(BaseModel):
    """The sensitive material that must stay in the customer's own
    environment. Intentionally shares no base class or field names with
    `ActionEnvelope`. Nothing in this repository may serialize an instance of
    this class into anything sent over the network — any function that would
    do so is a bug.
    """

    model_config = ConfigDict(extra="forbid")

    raw_request_body: dict = {}
    customer_pii: dict | None = None
    documents: list[dict] = []
    credentials: dict | None = None


def build_envelope(raw: dict) -> ActionEnvelope:
    """Construct an `ActionEnvelope` strictly from the allowed envelope field
    set.

    If `raw` contains any key that only makes sense as payload (see
    `_PAYLOAD_ONLY_FIELDS`), this function **rejects** the call by raising
    `ValueError` rather than silently stripping those keys and proceeding.
    See the module docstring for why reject-over-strip was chosen here.

    The raised error message intentionally names only the *offending field
    names*, never their values, so that logging this exception (e.g. via
    `logging.exception` or `str(exc)`/`repr(exc)` in a log line) cannot leak
    sensitive payload contents such as PII or credentials.
    """
    offending = sorted(_PAYLOAD_ONLY_FIELDS & raw.keys())
    if offending:
        raise ValueError(
            "build_envelope() received payload-only field(s) "
            f"{offending!r}; payload data must never be passed to "
            "build_envelope() or transmitted to CompliVibe. Extract only "
            "envelope fields at the call site."
        )

    # Any other unexpected key is still rejected by ActionEnvelope's own
    # `extra=\"forbid\"` config, but again without echoing values.
    allowed_fields = set(ActionEnvelope.model_fields)
    unexpected = sorted(set(raw.keys()) - allowed_fields)
    if unexpected:
        raise ValueError(
            f"build_envelope() received unrecognized field(s) {unexpected!r}"
        )

    return ActionEnvelope(**raw)

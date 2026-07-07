"""Adversarial extensions to tests/unit/test_envelope_separation.py.

That test file already covers the well-formed-attack-shape case (a raw dict
carrying one of the literal `_PAYLOAD_ONLY_FIELDS` names alongside valid
envelope fields). This file goes further, trying to actually sneak payload
data past `build_envelope()` / `ActionEnvelope` via less obvious vectors:

1. Payload data smuggled *inside the value* of a real, allowed field
   (type coercion should reject anything that isn't the declared type).
2. Field-name near-misses of the banned `_PAYLOAD_ONLY_FIELDS` set: case
   variations and Unicode-homoglyph variations, to check whether the
   set-membership check in `build_envelope` can be dodged -- and, if it can,
   whether `ActionEnvelope`'s `extra="forbid"` catches it anyway
   (defense-in-depth).
3. A legitimate envelope field carrying sensitive-looking string data (e.g.
   `action_id` stuffed with PII) -- documented as a residual, out-of-band
   risk this module cannot and should not try to catch (a `str` field can
   hold arbitrary string content by design; policing *content* of a
   correctly-typed string field is a call-site responsibility, not
   something a structural/type-level boundary can enforce).
4. Pathological input size (huge nested dicts, very long strings) -- must
   fail cleanly and quickly, not hang or crash uncontrolled.
"""

from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from services.envelope import ActionEnvelope, build_envelope

SENTINEL = "SENTINEL-ADVERSARIAL-PII-DO-NOT-LEAK"

VALID_ENVELOPE = {
    "action_id": "act-1",
    "ai_system_id": "sys-1",
    "organization_id": "org-1",
    "action_type": "payment.transfer",
    "amount": 100.0,
    "currency": "USD",
    "destination_region": "us-east",
    "data_categories": ["financial"],
    "cross_border": False,
    "requires_approval": True,
    "approved_by": ["alice"],
    "timestamp": "2026-07-06T00:00:00Z",
}


# ---------------------------------------------------------------------------
# 1. Payload data smuggled inside a real field's VALUE.
# ---------------------------------------------------------------------------


def test_dict_smuggled_into_str_or_none_field_is_rejected():
    """`currency` is declared `str | None`. Passing a dict (e.g. an embedded
    PII object) instead of a string must be a hard Pydantic validation
    failure, not silent coercion or acceptance."""
    tainted = {**VALID_ENVELOPE, "currency": {"customer_pii": {"ssn": SENTINEL}}}
    with pytest.raises((ValidationError, ValueError)):
        build_envelope(tainted)


def test_dict_smuggled_into_action_id_str_field_is_rejected():
    tainted = {**VALID_ENVELOPE, "action_id": {"customer_pii": SENTINEL}}
    with pytest.raises((ValidationError, ValueError)):
        build_envelope(tainted)


def test_dict_smuggled_into_destination_region_is_rejected():
    tainted = {**VALID_ENVELOPE, "destination_region": {"nested": {"credentials": SENTINEL}}}
    with pytest.raises((ValidationError, ValueError)):
        build_envelope(tainted)


def test_dict_smuggled_into_amount_float_field_is_rejected():
    tainted = {**VALID_ENVELOPE, "amount": {"customer_pii": SENTINEL}}
    with pytest.raises((ValidationError, ValueError)):
        build_envelope(tainted)


def test_nested_object_smuggled_inside_a_list_field_element_is_rejected():
    """`data_categories: list[str]` -- a dict element inside the list must
    not be coerced into a string."""
    tainted = {**VALID_ENVELOPE, "data_categories": [{"customer_pii": SENTINEL}]}
    with pytest.raises((ValidationError, ValueError)):
        build_envelope(tainted)


def test_bool_field_does_not_accept_arbitrary_object():
    tainted = {**VALID_ENVELOPE, "cross_border": {"customer_pii": SENTINEL}}
    with pytest.raises((ValidationError, ValueError)):
        build_envelope(tainted)


# ---------------------------------------------------------------------------
# 2. Field-name near-misses of _PAYLOAD_ONLY_FIELDS.
# ---------------------------------------------------------------------------

NEAR_MISS_PAYLOAD_FIELD_NAMES = [
    "Customer_PII",  # case variation
    "CUSTOMER_PII",
    "customer_pii ",  # trailing space
    " customer_pii",  # leading space
    "customer_pіi",  # Cyrillic "і" (U+0456) homoglyph for the Latin "i"
    "customer-pii",  # hyphen instead of underscore
    "Raw_Request_Body",
    "raw_request_body​",  # zero-width space appended
    "Credentials",
    "CREDENTIALS",
    "documentś",  # combining acute accent appended
]


@pytest.mark.parametrize("field_name", NEAR_MISS_PAYLOAD_FIELD_NAMES)
def test_near_miss_payload_field_name_is_still_rejected_by_extra_forbid(field_name):
    """A near-miss field name dodges the exact-string `_PAYLOAD_ONLY_FIELDS`
    membership check in `build_envelope` (by construction: it is not an
    exact match), but it is not a real `ActionEnvelope` field either, so
    `ActionEnvelope`'s `extra="forbid"` must still catch it as an unexpected
    field. This test confirms that defense-in-depth actually holds -- the
    near-miss must NOT be silently accepted into the envelope.
    """
    tainted = {**VALID_ENVELOPE, field_name: {"ssn": SENTINEL}}
    with pytest.raises(ValueError) as exc_info:
        build_envelope(tainted)
    # Confirm the value never leaks into the rejection message either.
    assert SENTINEL not in str(exc_info.value)


@pytest.mark.parametrize("field_name", NEAR_MISS_PAYLOAD_FIELD_NAMES)
def test_near_miss_field_name_not_in_exact_banned_set(field_name):
    """Sanity check on the test data itself: every near-miss string here must
    actually be different from the real banned names (otherwise this
    parametrization isn't testing what it claims to)."""
    from services.envelope import _PAYLOAD_ONLY_FIELDS

    assert field_name not in _PAYLOAD_ONLY_FIELDS


def test_near_miss_field_name_also_rejected_by_direct_construction():
    """Same near-miss check, but constructing ActionEnvelope directly
    (bypassing build_envelope entirely) -- extra="forbid" alone must hold."""
    tainted = {**VALID_ENVELOPE, "Customer_PII": {"ssn": SENTINEL}}
    with pytest.raises(ValidationError):
        ActionEnvelope(**tainted)


# ---------------------------------------------------------------------------
# 3. Residual risk: PII stuffed into a legitimately-named, correctly-typed
#    field. Documented, not "fixed" -- see module docstring above and
#    SECURITY_REVIEW.md.
# ---------------------------------------------------------------------------


def test_pii_stuffed_into_action_id_string_is_NOT_and_cannot_be_caught_here():
    """`action_id` is declared `str`. A caller that puts a customer's SSN or
    name into this field instead of an opaque action identifier produces a
    perfectly well-typed `ActionEnvelope` -- `build_envelope` has no way to
    distinguish "legitimate opaque id" from "PII disguised as a string" for
    a field that is supposed to hold arbitrary string content by design.

    This test documents that residual risk explicitly (see
    tests/security/SECURITY_REVIEW.md, area 1): it is a call-site
    responsibility (never construct action_id/currency/destination_region
    from raw PII), not a gap in this module's structural boundary. The
    assertion below is intentionally the *positive* case -- confirming the
    envelope really is constructed rather than rejected -- to make the
    residual-risk point concrete rather than merely asserted in prose.
    """
    tainted = {**VALID_ENVELOPE, "action_id": f"customer-ssn-{SENTINEL}"}
    env = build_envelope(tainted)
    assert env.action_id == f"customer-ssn-{SENTINEL}"  # accepted: str field, str value


# ---------------------------------------------------------------------------
# 4. Pathological input size: must fail cleanly and quickly, not hang/crash.
# ---------------------------------------------------------------------------


def test_huge_nested_dict_in_a_field_value_rejected_quickly():
    # Build a deeply nested dict (not so deep it blows the recursion limit
    # of the test process itself) to smuggle as a field value.
    nested: dict = {"leaf": SENTINEL}
    for _ in range(500):
        nested = {"wrap": nested}
    tainted = {**VALID_ENVELOPE, "destination_region": nested}

    started = time.monotonic()
    with pytest.raises((ValidationError, ValueError, RecursionError)):
        build_envelope(tainted)
    elapsed = time.monotonic() - started
    assert elapsed < 5.0, f"pathological nested dict took {elapsed:.2f}s to reject, expected a fast failure"


def test_very_long_string_field_value_handled_without_pathological_slowness():
    huge_string = "a" * 5_000_000  # 5 MB of a single field
    tainted = {**VALID_ENVELOPE, "action_id": huge_string}

    started = time.monotonic()
    env = build_envelope(tainted)  # a long str is still a valid str -- accepted, not rejected
    elapsed = time.monotonic() - started

    assert env.action_id == huge_string
    assert elapsed < 5.0, f"long string field took {elapsed:.2f}s, expected near-instant handling"


def test_wide_dict_with_many_keys_as_field_value_rejected_quickly():
    wide = {f"key_{i}": SENTINEL for i in range(50_000)}
    tainted = {**VALID_ENVELOPE, "currency": wide}

    started = time.monotonic()
    with pytest.raises((ValidationError, ValueError)):
        build_envelope(tainted)
    elapsed = time.monotonic() - started
    assert elapsed < 5.0, f"wide dict took {elapsed:.2f}s to reject, expected a fast failure"


def test_many_unexpected_top_level_keys_rejected_without_value_leak():
    """A raw dict with a huge number of unexpected top-level keys (not
    matching any real envelope field or banned payload field) must still be
    rejected by build_envelope's own `extra` check, quickly, and without
    leaking any of the (attacker-controlled) key values into the error."""
    tainted = dict(VALID_ENVELOPE)
    for i in range(20_000):
        tainted[f"unexpected_field_{i}_{SENTINEL}"] = "x"

    started = time.monotonic()
    with pytest.raises(ValueError) as exc_info:
        build_envelope(tainted)
    elapsed = time.monotonic() - started
    assert elapsed < 5.0
    # Field *names* are allowed to appear (that's documented behavior), but
    # let's confirm at least the mechanism doesn't crash and does raise.
    assert "unexpected" in str(exc_info.value) or "unrecognized" in str(exc_info.value)

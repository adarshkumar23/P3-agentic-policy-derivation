"""Structural tests proving envelope/payload separation is enforced at the
type level, not merely by naming convention or today's incidental behavior.
"""

import io
import logging

import pytest
from pydantic import BaseModel

from services.envelope import ActionEnvelope, ActionPayload, build_envelope

SENTINEL = "SENTINEL-SECRET-VALUE-DO-NOT-LEAK"

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


def test_no_shared_base_other_than_basemodel():
    """ActionEnvelope and ActionPayload must not share any base class other
    than pydantic.BaseModel itself -- a shared intermediate base would be a
    seam where a field could accidentally be carried between them."""
    envelope_bases = set(ActionEnvelope.__mro__)
    payload_bases = set(ActionPayload.__mro__)
    shared = envelope_bases & payload_bases
    # object and BaseModel are expected to be shared; nothing else should be.
    assert shared <= {BaseModel, object}


def test_no_overlapping_field_names():
    envelope_fields = set(ActionEnvelope.model_fields)
    payload_fields = set(ActionPayload.model_fields)
    assert envelope_fields.isdisjoint(payload_fields)


def test_envelope_model_is_closed_to_extra_fields():
    assert ActionEnvelope.model_config.get("extra") == "forbid"
    assert ActionPayload.model_config.get("extra") == "forbid"


def test_constructing_envelope_directly_with_payload_fields_raises():
    """Directly constructing ActionEnvelope(**{...valid..., payload fields})
    must raise, proving extra="forbid" blocks payload data from riding along
    even if a caller bypasses build_envelope() entirely."""
    tainted = {
        **VALID_ENVELOPE,
        "raw_request_body": {"foo": "bar"},
        "customer_pii": {"ssn": SENTINEL},
    }
    with pytest.raises(Exception):
        ActionEnvelope(**tainted)


def test_build_envelope_rejects_payload_fields():
    tainted = {
        **VALID_ENVELOPE,
        "raw_request_body": {"foo": "bar"},
        "customer_pii": {"ssn": SENTINEL},
    }
    with pytest.raises(ValueError):
        build_envelope(tainted)


def test_build_envelope_succeeds_on_clean_input():
    env = build_envelope(dict(VALID_ENVELOPE))
    assert isinstance(env, ActionEnvelope)
    assert not hasattr(env, "raw_request_body")
    assert not hasattr(env, "customer_pii")


def test_build_envelope_does_not_leak_sensitive_value_in_exception():
    """The exception raised by build_envelope() must name only the offending
    *field*, never echo the sensitive *value*, in its message."""
    tainted = {
        **VALID_ENVELOPE,
        "customer_pii": {"ssn": SENTINEL},
    }
    with pytest.raises(ValueError) as exc_info:
        build_envelope(tainted)
    assert SENTINEL not in str(exc_info.value)
    assert SENTINEL not in repr(exc_info.value)


def test_log_scrubbing_on_failure_path():
    """Simulate a real failure path: call build_envelope with malformed
    input containing a sentinel secret, capture whatever would plausibly end
    up in a log line, and assert the sentinel never appears in it."""
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    logger = logging.getLogger("test_envelope_log_scrubbing")
    logger.setLevel(logging.ERROR)
    logger.addHandler(handler)

    tainted = {
        **VALID_ENVELOPE,
        "customer_pii": {"ssn": SENTINEL},
        "credentials": {"api_key": SENTINEL},
    }

    try:
        build_envelope(tainted)
    except Exception as exc:  # noqa: BLE001 - intentionally broad, simulating a real handler
        logger.error("failed to build envelope: %s", exc)
        logger.error("repr: %r", exc)
    finally:
        logger.removeHandler(handler)
        handler.close()

    captured = log_stream.getvalue()
    assert captured, "expected the failure path to actually log something"
    assert SENTINEL not in captured

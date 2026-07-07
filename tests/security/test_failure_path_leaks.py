"""Failure-path leak tests: confirm no payload/envelope content leaks into
exception messages, log lines, or HTTP error responses when a subsystem
*fails*, as opposed to the happy path.

`tests/security/test_envelope_adversarial.py` already covers adversarial
well-formed-attack-shape input to `build_envelope()` itself (the envelope
construction boundary). This module goes further: it triggers a real
failure in three different downstream subsystems -- OPA, the Rego
derivation/compilation engine, and the demo DB layer -- each carrying a
sentinel value riding along in an otherwise-legitimate call, and confirms
the sentinel never surfaces anywhere in the resulting error surface.

Style note: log capture uses the same `io.StringIO`-backed
`logging.StreamHandler` pattern as
`tests/unit/test_envelope_separation.py::test_log_scrubbing_on_failure_path`.
"""

from __future__ import annotations

import io
import logging

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.guardrails import create_app
from audit import AuditService
from permissions import InMemoryAiSystemRegistry
from services.opa_client import OpaClient
from services.policy_provider import CompliVibePolicyProvider

SENTINEL = "SENTINEL-FAILURE-PATH-DO-NOT-LEAK"

ORG_A = "org-a"


def _headers(org_id: str = ORG_A) -> dict:
    return {"X-Org-Id": org_id, "X-User-Id": "user-1", "X-Role": "admin"}


def _capture_logger(name: str) -> tuple[logging.Logger, io.StringIO, logging.Handler]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger(name)
    logger.setLevel(logging.ERROR)
    logger.addHandler(handler)
    return logger, stream, handler


# ---------------------------------------------------------------------------
# 1. OPA failure during check_action -- sentinel embedded in a legitimate
#    envelope field (action_id).
# ---------------------------------------------------------------------------


VALID_ACTION_WITH_SENTINEL = {
    "action_id": f"act-{SENTINEL}",
    "ai_system_id": "sys-1",
    "organization_id": "org-1",
    "action_type": "wire_transfer",
    "amount": 100.0,
    "currency": "USD",
    "timestamp": "2026-01-01T00:00:00Z",
}


class TestOpaFailureDoesNotLeakSentinel:
    def _run_and_capture(self, handler) -> tuple[object, str]:
        provider = CompliVibePolicyProvider(
            OpaClient(
                base_url="http://opa.test",
                max_retries=0,
                client=httpx.Client(transport=httpx.MockTransport(handler)),
            ),
            "complivibe.guardrails.org_acme",
        )
        logger, stream, log_handler = _capture_logger("test_opa_failure_leak")
        try:
            result = provider.check_action(
                dict(VALID_ACTION_WITH_SENTINEL), timestamp="2026-01-01T00:00:00Z"
            )
            # A fail-closed OPA decision does not raise -- log it the way a
            # real caller plausibly would (mirrors
            # test_envelope_separation's pattern for the raising case).
            logger.error("check_action decision: %s", result.decision)
            return result, stream.getvalue()
        except Exception as exc:  # noqa: BLE001 - intentionally broad, simulating a real caller
            logger.error("check_action failed: %s", exc)
            logger.error("repr: %r", exc)
            return exc, stream.getvalue()
        finally:
            logger.removeHandler(log_handler)
            log_handler.close()

    def test_connection_refused_does_not_leak_sentinel(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        result, captured = self._run_and_capture(handler)
        assert SENTINEL not in captured
        # Connection-refused is not a ValueError -- check_action does not
        # raise for it (OpaClient fails closed internally), so `result`
        # here is the CheckActionResult, not an exception.
        assert result.decision.allowed is False
        assert SENTINEL not in (result.decision.reason or "")
        assert SENTINEL not in repr(result.decision.raw_response)

    def test_malformed_json_response_does_not_leak_sentinel(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not json{{{")

        result, captured = self._run_and_capture(handler)
        assert SENTINEL not in captured
        assert result.decision.allowed is False
        assert SENTINEL not in (result.decision.reason or "")
        assert SENTINEL not in repr(result.decision.raw_response)

    def test_non_2xx_opa_response_does_not_leak_sentinel(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal opa error")

        result, captured = self._run_and_capture(handler)
        assert SENTINEL not in captured
        assert result.decision.allowed is False
        assert SENTINEL not in (result.decision.reason or "")


# ---------------------------------------------------------------------------
# 2. Rego compilation/derivation failure -- sentinel embedded in the
#    obligation text that (via a monkeypatched renderer) ends up in the
#    invalid Rego the derivation engine would otherwise have returned.
# ---------------------------------------------------------------------------


SAMPLE_OBLIGATIONS = [
    {
        "id": "obl-1",
        "text": "Wire transfers shall not exceed $10,000 per transaction.",
        "jurisdiction": "US",
        "framework": "BSA",
    }
]


class TestRegoCompilationFailureDoesNotLeakSentinel:
    def _build_app_with_guardrail(self):
        registry = InMemoryAiSystemRegistry()
        audit = AuditService()
        app = create_app(ai_system_registry=registry, audit_service=audit)
        registry.register("sys-1", ORG_A, name="Test AI System")
        client = TestClient(app, raise_server_exceptions=False)
        created = client.post(
            "/ai-systems/sys-1/guardrails",
            json={"organization_id": ORG_A, "name": "n", "obligations": SAMPLE_OBLIGATIONS},
            headers=_headers(),
        )
        assert created.status_code == 201, created.text
        return client, created.json()

    def test_compile_rego_with_deliberately_invalid_output_returns_422_without_sentinel(
        self, monkeypatch
    ):
        """The derivation engine's own template renderer never lets raw
        obligation text flow into rendered Rego (see
        services/derivation_engine.py) -- financial/geo/data-scope content
        comes from fixed vocabularies and parsed numeric/keyword matches,
        not obligation free text verbatim. So, per the task brief, this
        monkeypatches the renderer to simulate what would happen if it ever
        *did* leak a sentinel into invalid Rego, and exercises the real
        `derive_and_compile` -> `validate_rego_syntax` -> HTTP 422 path
        end-to-end to confirm that error path itself never echoes the
        sentinel back to the caller.
        """
        import services.derivation_engine as derivation_engine

        # Build the app and create the guardrail with the *real* renderer
        # first -- only the compile-rego call itself should exercise the
        # broken renderer, not guardrail creation/setup.
        client, guardrail = self._build_app_with_guardrail()

        def _broken_compile(spec, org_id):
            # Deliberately invalid Rego (missing closing brace) with the
            # sentinel embedded directly in the broken source line, to
            # prove the resulting error message doesn't echo raw source.
            return (
                f"package complivibe.guardrails.org_acme\n\n"
                f'deny contains reason if {{\n\treason := "leaked-{SENTINEL}"\n'
            )

        monkeypatch.setattr(derivation_engine, "compile_constraint_spec", _broken_compile)

        logger, stream, log_handler = _capture_logger("test_rego_failure_leak")
        try:
            resp = client.post(
                f"/ai-guardrails/{guardrail['id']}/compile-rego",
                json={"obligations": SAMPLE_OBLIGATIONS},
                headers=_headers(),
            )
            logger.error("compile-rego failed: status=%s body=%s", resp.status_code, resp.text)
        finally:
            logger.removeHandler(log_handler)
            log_handler.close()

        assert resp.status_code == 422, resp.text
        assert SENTINEL not in resp.text
        assert SENTINEL not in stream.getvalue()

    def test_create_guardrail_with_deliberately_invalid_output_returns_422_without_sentinel(
        self, monkeypatch
    ):
        import services.derivation_engine as derivation_engine

        def _broken_compile(spec, org_id):
            return f'package p\n\ndeny contains reason if {{\n\treason := "leaked-{SENTINEL}"\n'

        monkeypatch.setattr(derivation_engine, "compile_constraint_spec", _broken_compile)

        registry = InMemoryAiSystemRegistry()
        audit = AuditService()
        app = create_app(ai_system_registry=registry, audit_service=audit)
        registry.register("sys-1", ORG_A, name="Test AI System")
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/ai-systems/sys-1/guardrails",
            json={"organization_id": ORG_A, "name": "n", "obligations": SAMPLE_OBLIGATIONS},
            headers=_headers(),
        )
        assert resp.status_code == 422, resp.text
        assert SENTINEL not in resp.text


# ---------------------------------------------------------------------------
# 3. DB write failure during POST .../guardrails/check.
# ---------------------------------------------------------------------------


class TestDbWriteFailureDoesNotLeakSentinel:
    def test_db_commit_failure_on_check_action_returns_500_without_sentinel(self, monkeypatch):
        registry = InMemoryAiSystemRegistry()
        audit = AuditService()
        app = create_app(ai_system_registry=registry, audit_service=audit)
        registry.register("sys-1", ORG_A, name="Test AI System")
        client = TestClient(app, raise_server_exceptions=False)

        created = client.post(
            "/ai-systems/sys-1/guardrails",
            json={"organization_id": ORG_A, "name": "n", "obligations": SAMPLE_OBLIGATIONS},
            headers=_headers(),
        )
        assert created.status_code == 201, created.text

        # Inject the failure only after the guardrail is already persisted,
        # so it's isolated to the check-action call's own db.commit().
        def _failing_commit(self, *args, **kwargs):
            raise RuntimeError(f"simulated db commit failure, envelope sentinel {SENTINEL}")

        monkeypatch.setattr(Session, "commit", _failing_commit)

        logger, stream, log_handler = _capture_logger("test_db_failure_leak")
        try:
            resp = client.post(
                "/ai-systems/sys-1/guardrails/check",
                json={
                    "action_id": f"act-{SENTINEL}",
                    "ai_system_id": "sys-1",
                    "organization_id": ORG_A,
                    "action_type": "wire_transfer",
                    "amount": 50.0,
                    "currency": "USD",
                    "timestamp": "2026-01-01T00:00:00Z",
                },
                headers=_headers(),
            )
            logger.error("check-action failed: status=%s body=%s", resp.status_code, resp.text)
        finally:
            logger.removeHandler(log_handler)
            log_handler.close()

        assert resp.status_code == 500
        assert SENTINEL not in resp.text
        assert SENTINEL not in stream.getvalue()

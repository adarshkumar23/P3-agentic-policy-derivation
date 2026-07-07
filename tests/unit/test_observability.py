"""Smoke tests for the shared observability scaffolding (Workstream P).

These are intentionally shallow: they confirm `configure_logging()` does
not raise in either environment mode, and that the shared Prometheus
metric objects are importable and of the expected type. Deeper
integration (e.g. verifying an endpoint actually increments
`CHECK_ACTION_DECISIONS`) belongs to whichever workstream owns that
endpoint.
"""

from __future__ import annotations

import pytest
from observability import (
    CHECK_ACTION_DECISIONS,
    CHECK_ACTION_LATENCY,
    configure_logging,
)
from prometheus_client import Counter, Histogram


def test_configure_logging_production_mode_runs_without_error() -> None:
    configure_logging("production")


def test_configure_logging_development_mode_runs_without_error() -> None:
    configure_logging("development")


def test_configure_logging_defaults_to_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENV", "production")
    configure_logging()
    monkeypatch.setenv("ENV", "development")
    configure_logging()


def test_check_action_latency_is_histogram() -> None:
    assert isinstance(CHECK_ACTION_LATENCY, Histogram)


def test_check_action_decisions_is_counter() -> None:
    assert isinstance(CHECK_ACTION_DECISIONS, Counter)

"""Minimal observability scaffolding shared across workstreams.

Provides:

- `configure_logging()` — sets up `structlog` for JSON output in
  production and human-friendly console output in development, keyed
  off the `ENV` environment variable (`production` vs. anything else,
  default `development`).
- A small set of Prometheus metric primitives that other workstreams'
  code (e.g. Workstream H's check-action endpoint) can import directly
  rather than each defining their own registry entries.

This module intentionally stays small: it is not a full observability
platform, just enough shared plumbing to keep logging/metrics
consistent across the codebase.
"""

from __future__ import annotations

import logging
import os

import structlog
from prometheus_client import Counter, Histogram

__all__ = [
    "configure_logging",
    "CHECK_ACTION_LATENCY",
    "CHECK_ACTION_DECISIONS",
    "REGO_COMPILATION_RESULTS",
    "CHAIN_VERIFICATION_RESULTS",
    "OPA_CIRCUIT_BREAKER_TRANSITIONS",
]


def configure_logging(env: str | None = None) -> None:
    """Configure `structlog` (and stdlib `logging`) for the current environment.

    Args:
        env: Override for the environment name. Defaults to the `ENV`
            environment variable, falling back to `"development"`.
            When `env == "production"`, logs are rendered as JSON
            suitable for ingestion by log pipelines. Otherwise, logs
            are rendered with a human-friendly console renderer
            (colors, aligned key=value pairs).
    """
    resolved_env = (env or os.environ.get("ENV", "development")).lower()
    is_production = resolved_env == "production"

    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO,
        force=True,
    )

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    processors: list[structlog.types.Processor]
    if is_production:
        processors = [
            *shared_processors,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors = [
            *shared_processors,
            structlog.dev.set_exc_info,
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ---------------------------------------------------------------------------
# Prometheus metrics
#
# Scoped generically so any check-action-style endpoint (Workstream H, or
# others) can import and use them without redefining metric names.
# ---------------------------------------------------------------------------

CHECK_ACTION_LATENCY = Histogram(
    "check_action_latency_seconds",
    "Latency of check-action policy evaluation requests, in seconds.",
    # Prometheus's default buckets (5ms, 10ms, ... up to 10s) are much too
    # coarse at the low end for this endpoint: an in-process OPA decision
    # (real deployment) should land sub-millisecond, and even this repo's
    # own test harness -- which shells out to the vendored `opa` CLI via a
    # subprocess per call, which a real deployment does not do -- observes
    # calls in the tens-to-low-hundreds of milliseconds. These buckets keep
    # fine resolution from 0.1ms up through 1s so p50/p95/p99 are actually
    # derivable at both the production (sub-ms) and this-repo's-test-harness
    # (tens-of-ms) scales, rather than every observation landing in one
    # bucket.
    buckets=(0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

CHECK_ACTION_DECISIONS = Counter(
    "check_action_decisions_total",
    "Count of check-action decisions, labeled by outcome.",
    labelnames=["decision"],
)

REGO_COMPILATION_RESULTS = Counter(
    "rego_compilation_results_total",
    "Count of guardrail derivation/Rego-compilation attempts, labeled by result.",
    labelnames=["result"],
)

CHAIN_VERIFICATION_RESULTS = Counter(
    "chain_verification_results_total",
    "Count of receipt chain verification runs, labeled by result.",
    labelnames=["result"],
)

OPA_CIRCUIT_BREAKER_TRANSITIONS = Counter(
    "opa_circuit_breaker_transitions_total",
    "Count of OPA client circuit-breaker state transitions, labeled by transition.",
    labelnames=["transition"],
)

# mypy: allow-untyped-defs
"""Local stand-in for complivibe-backend-v5's audit-logging service
(Workstream J).

See ASSUMPTIONS.md's "Carried over from P2" section:
``AuditService.write_audit_log(self, *, action, entity_type,
organization_id, actor_user_id=None, entity_id=None, before_json=None,
after_json=None, metadata_json=None, ip_address=None, user_agent=None)`` is
carried over verbatim, unverified against the real
``complivibe-backend-v5`` codebase (this repo has no access to it), as a
high-confidence interface contract. The real implementation almost
certainly persists to a durable `audit_log` table; this stand-in instead
appends to an in-memory list, which is enough for every caller in this repo
(`api/guardrails.py`) to depend on the exact same call contract and for
tests to assert an entry was written for each state-changing action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuditService:
    """In-memory stand-in for the real, carried-over P2 `AuditService`.

    `entries` accumulates one dict per `write_audit_log` call, in call
    order. Nothing here is persisted beyond the lifetime of this instance --
    a real implementation would write to a durable audit_log table instead.
    """

    entries: list[dict] = field(default_factory=list)

    def write_audit_log(
        self,
        *,
        action: str,
        entity_type: str,
        organization_id: str,
        actor_user_id: str | None = None,
        entity_id: str | None = None,
        before_json: Any | None = None,
        after_json: Any | None = None,
        metadata_json: Any | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.entries.append(
            {
                "action": action,
                "entity_type": entity_type,
                "organization_id": organization_id,
                "actor_user_id": actor_user_id,
                "entity_id": entity_id,
                "before_json": before_json,
                "after_json": after_json,
                "metadata_json": metadata_json,
                "ip_address": ip_address,
                "user_agent": user_agent,
            }
        )

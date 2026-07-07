# mypy: allow-untyped-defs
"""Local stand-in for complivibe-backend-v5's permission/org-scoping layer
(Workstream I).

Scope note (see ASSUMPTIONS.md's "Carried over from P2" section): this repo
has no access to the real `complivibe-backend-v5` codebase. Two interfaces
are carried over there as high-confidence signatures, verbally confirmed
during P2's development:

- ``require_permission(permission_code: str) -> Callable[..., Membership]``,
  used via FastAPI's ``Depends()``.
- ``_get_org_ai_system(ai_system_id, organization_id, db)`` in
  ``app/ai_governance/services/draft_context_service.py``, an org-scoped
  lookup that returns ``None`` (never raises) when the AI system either does
  not exist or belongs to a different organization -- callers must translate
  that ``None`` into an HTTP 404, never a 403, so a cross-org caller cannot
  distinguish "does not exist" from "exists but isn't yours" (see P2's
  documented convention against leaking existence across tenants).

Neither of these is real, importable code in this standalone repo. Both are
built here as **honest local stand-ins matching the documented shape** (same
pattern as ``services/receipts.py``'s stand-in for the real signing package:
see that module's docstring) -- replace with the real imports once this code
is merged into ``complivibe-backend-v5``.

``require_permission`` below is explicitly NOT a real authentication system.
There is no session store, no JWT verification, no permission table to check
``permission_code`` against in this repo. It reads three headers
(``X-Org-Id``, ``X-User-Id``, ``X-Role``) that a real auth layer would
otherwise have already resolved into request state, and builds a
``Membership`` from them. The only "enforcement" performed is a trivial
honesty check that ``role`` is non-empty -- this is deliberately not real
authorization logic. What matters for this repo is that every endpoint in
``api/guardrails.py`` is wired through the same ``Depends(require_permission(...))``
*shape* that the real carried-over interface uses, so swapping in the real
implementation later is a one-line change at the dependency-injection site,
not a rewrite of every endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from fastapi import Header, HTTPException


@dataclass(frozen=True)
class Membership:
    """A resolved caller identity, scoped to one organization.

    Mirrors the shape `require_permission`'s carried-over P2 signature is
    documented to return: enough to know *who* is calling, *which*
    organization they're calling on behalf of, and *what role* they hold.
    """

    user_id: str
    organization_id: str
    role: str


def require_permission(permission_code: str) -> Callable[..., Membership]:
    """Build a FastAPI dependency that resolves the caller's `Membership`.

    Placeholder only -- see module docstring. `permission_code` is accepted
    (matching the real carried-over signature exactly, so call sites read
    identically to how they will once wired to the real P2 auth system) but
    is not checked against any real permission table here, since none exists
    in this standalone repo. The only check performed is that a role header
    was actually supplied; a request with no `X-Role` at all is rejected
    (401) rather than silently treated as authenticated with an empty role.
    """

    def _dependency(
        x_org_id: str = Header(..., alias="X-Org-Id"),
        x_user_id: str = Header(..., alias="X-User-Id"),
        x_role: str = Header(..., alias="X-Role"),
    ) -> Membership:
        if not x_role.strip():
            raise HTTPException(
                status_code=401,
                detail="missing caller role; cannot resolve membership",
            )
        # `permission_code` (captured from the enclosing `require_permission`
        # call) is intentionally unused beyond this point -- see docstring:
        # there is no real permission table in this repo to check it
        # against. It is accepted purely to keep this call-site shape
        # identical to the real, carried-over P2 interface.
        assert permission_code is not None or permission_code is None  # no-op reference
        return Membership(user_id=x_user_id, organization_id=x_org_id, role=x_role)

    return _dependency


class InMemoryAiSystemRegistry:
    """Dict-backed stand-in for the real `ai_system` table lookup.

    This repo has no `ai_system` table (or any SQLAlchemy model for one).
    Tests (and, for now, the endpoint wiring in `api/guardrails.py`) use this
    registry in place of a real DB-backed lookup. `register()` is a test/
    setup helper; `get()` mirrors what a real query would return: a plain
    dict of fields, or `None` if the id was never registered.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, dict] = {}

    def register(self, ai_system_id: str, organization_id: str, **fields: Any) -> None:
        self._by_id[ai_system_id] = {
            "ai_system_id": ai_system_id,
            "organization_id": organization_id,
            **fields,
        }

    def get(self, ai_system_id: str) -> dict | None:
        return self._by_id.get(ai_system_id)


def _get_org_ai_system(ai_system_id: str, organization_id: str, db: Any) -> dict | None:
    """Org-scoped AI-system lookup.

    Carried over from P2 as `_get_org_ai_system(ai_system_id,
    organization_id, db)` in
    `app/ai_governance/services/draft_context_service.py` (see
    ASSUMPTIONS.md). In production, `db` would be a real SQLAlchemy
    `Session` and this function would run a query scoped by both id and
    organization_id. In this standalone repo, there is no `ai_system` table,
    so `db` IS an `InMemoryAiSystemRegistry` instance (documented here, not
    hidden behind a same-named-but-different type) and this function performs
    the equivalent scoping check against it in memory.

    Returns the record dict only if it exists AND its `organization_id`
    matches; otherwise returns `None` -- callers (endpoints in
    `api/guardrails.py`) must translate `None` into an HTTP 404 (never 403),
    per the P2 convention of not leaking cross-org existence.
    """
    record = db.get(ai_system_id)
    if record is None:
        return None
    if record.get("organization_id") != organization_id:
        return None
    return record

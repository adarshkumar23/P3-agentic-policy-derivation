# mypy: allow-untyped-defs
"""Real integration with the policy enforcement runtime's offline-verifiable-
receipt signing capability.

Scope note (see PATENT.md §0, §1.1(4), §1.1(5), and Claim 4, plus
ASSUMPTIONS.md's "Newly verified" section): an earlier pass of this build
concluded the runtime's receipt-signing capability was not installable from
any environment checked, and built a local, hand-rolled Ed25519 stand-in
instead. That conclusion was **wrong** -- it was a package-name search error,
not a real unavailability. The real capability is genuinely on PyPI under
its actual declared project name (not the name of the GitHub subdirectory
that was searched for originally) and was exercised live during this build:
real signing, real verification, and real tamper detection (a flipped
`cedar_decision` after signing was correctly caught as both an invalid
signature and, on the following receipt, a broken hash link). See
ASSUMPTIONS.md for the exact evidence. This module now calls that real
package directly (`mcp_receipt_governed`) instead of reimplementing Ed25519
signing.

Key-custody boundary (this is the point of this module, see Claim 4)
---------------------------------------------------------------------
`ReceiptSigner` holds a private Ed25519 key (a caller-supplied 32-byte hex
seed, `signing_key_hex`) and is the *only* thing in this module that ever
touches a private key -- it is a thin wrapper around the real package's own
`sign_receipt(receipt, private_key_hex)` function, which likewise only ever
takes the key as a caller-supplied parameter and never fetches or generates
one itself. `ReceiptSigner` is meant to run inside the **customer's** own
deployment -- CompliVibe's core never generates, stores, or receives a
private signing key. `verify_receipt()` below is a module-level, key-free
function: it takes only a `Receipt` (which carries a *public* key,
`public_key_hex`) and returns a bool. Its signature has no parameter
anywhere that could hold a private key.

What is and isn't cryptographically covered
--------------------------------------------
The real package's canonical signed payload covers the receipt's decision,
its tool/agent/policy identifiers, its timestamp, and its
`parent_receipt_hash` chain link -- but **not** free-text reason/error
strings (its own `error` field is deliberately excluded from what gets
signed, and this wrapper's `reasons` field is likewise just descriptive
metadata riding alongside the signed decision). `verify_receipt()` verifies
the decision and chain linkage; it does not and cannot make `reasons` text
tamper-evident on its own. Do not treat `reasons` as an integrity-protected
field.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp_receipt_governed import GovernanceReceipt
from mcp_receipt_governed import sign_receipt as _real_sign_receipt
from mcp_receipt_governed import verify_receipt as _real_verify_receipt

__all__ = ["Receipt", "ReceiptSigner", "verify_receipt"]

# Fixed, domain-generic values for the real package's Cedar-oriented fields
# that this repo has no use for: our decisions come from OPA/Rego (see
# services/opa_client.py, services/derivation_engine.py), not from the real
# package's own Cedar policy evaluation -- we only use it as a signing and
# hash-chaining primitive for a decision this repo already made elsewhere.
_TOOL_NAME = "complivibe.guardrail.check_action"
_AGENT_DID = "complivibe-core"
_CEDAR_POLICY_ID = "n/a-rego-derived-elsewhere"


@dataclass(frozen=True)
class Receipt:
    """A single signed, chainable decision receipt.

    Field shape kept stable for this repo's existing call sites
    (`services.policy_provider`, `services.receipt_chain`,
    `core-side-patch/api/guardrails.py`); internally backed by the real
    `mcp_receipt_governed.GovernanceReceipt` shape (see module docstring).
    """

    receipt_id: str
    timestamp: str
    envelope_hash: str
    decision: str
    reasons: list[str]
    previous_receipt_hash: str | None
    signature: str  # hex-encoded Ed25519 signature
    receipt_hash: str  # hex-encoded sha256 payload hash (real package's `payload_hash()`)
    public_key_hex: str


def _timestamp_to_float(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp).timestamp()


def _to_governance_receipt(receipt: Receipt) -> GovernanceReceipt:
    """Reconstruct the real `GovernanceReceipt` a `Receipt` was derived from,
    using the same fixed domain-generic field values `sign_receipt` used, so
    `canonical_payload()`/`payload_hash()` recompute identically.
    """
    return GovernanceReceipt(
        receipt_id=receipt.receipt_id,
        tool_name=_TOOL_NAME,
        agent_did=_AGENT_DID,
        cedar_policy_id=_CEDAR_POLICY_ID,
        cedar_decision="allow" if receipt.decision == "allow" else "deny",
        args_hash=receipt.envelope_hash,
        timestamp=_timestamp_to_float(receipt.timestamp),
        parent_receipt_hash=receipt.previous_receipt_hash,
        signature=receipt.signature,
        signer_public_key=receipt.public_key_hex,
    )


class ReceiptSigner:
    """Thin wrapper around the real package's signing primitive. Holds a
    private Ed25519 key; the only thing in this module that does. Meant to
    run inside the customer's own deployment, never inside CompliVibe's
    core.
    """

    def __init__(self, signing_key_hex: str) -> None:
        seed = bytes.fromhex(signing_key_hex)
        if len(seed) != 32:
            raise ValueError(
                f"signing_key_hex must decode to exactly 32 bytes, got {len(seed)}"
            )
        self._signing_key_hex = signing_key_hex
        # Derived once, eagerly, purely for caller convenience/inspection
        # (e.g. registering the public key as a trusted signer elsewhere).
        # Not used internally for signing -- the real package's own
        # `sign_receipt` re-derives the public key from the private key on
        # every call, independently of this attribute.
        self.public_key_hex = (
            Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
        )

    def sign_receipt(
        self,
        *,
        decision: str,
        reasons: list[str],
        envelope_hash: str,
        previous_receipt_hash: str | None,
        timestamp: str,
    ) -> Receipt:
        """Sign a new receipt, chaining it to `previous_receipt_hash` (the
        prior receipt's `receipt_hash`, or `None` if this is the first
        receipt in a chain).
        """
        unsigned = GovernanceReceipt(
            tool_name=_TOOL_NAME,
            agent_did=_AGENT_DID,
            cedar_policy_id=_CEDAR_POLICY_ID,
            cedar_decision="allow" if decision == "allow" else "deny",
            args_hash=envelope_hash,
            timestamp=_timestamp_to_float(timestamp),
            parent_receipt_hash=previous_receipt_hash,
        )
        signed = _real_sign_receipt(unsigned, self._signing_key_hex)

        return Receipt(
            receipt_id=signed.receipt_id,
            timestamp=timestamp,
            envelope_hash=envelope_hash,
            decision=decision,
            reasons=list(reasons),
            previous_receipt_hash=previous_receipt_hash,
            signature=signed.signature,
            receipt_hash=signed.payload_hash(),
            public_key_hex=signed.signer_public_key,
        )


def verify_receipt(receipt: Receipt) -> bool:
    """Verify a single receipt's Ed25519 signature and its self-reported
    `receipt_hash`, using only `receipt.public_key_hex` -- a **public** key
    carried on the receipt itself. Delegates the actual cryptographic check
    to the real package's `verify_receipt`.

    No parameter of this function can ever hold a private key (see module
    docstring and Claim 4).

    Returns `False` (never raises) for any malformed input or bad signature.
    """
    try:
        governance_receipt = _to_governance_receipt(receipt)
    except (ValueError, TypeError, OSError):
        return False

    if not _real_verify_receipt(governance_receipt):
        return False

    return governance_receipt.payload_hash() == receipt.receipt_hash

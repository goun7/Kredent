"""
Core data models for Kredent: agent identity (did:key), signed attestations,
and reputation.

Kredent identifiers are W3C ``did:key`` DIDs. A did:key is *self-resolving*: the
verification key is embedded in the identifier itself, so no registry, resolver
or network access is required to verify a signature. That property is the reason
``kredent verify`` works fully offline.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# A did:key Ed25519 identifier: did:key:z6Mk... (base58btc, multicodec 0xed01).
AGENT_ID_REGEX = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$")

# Legacy Roboseal identifier form, accepted on read for migration tolerance.
LEGACY_AGENT_ID_REGEX = re.compile(r"^did:agent:68:key:[a-zA-Z0-9_-]+$")

DEFAULT_SCHEMA_URI = "https://kredent.dev/schemas/v1/agent-id.json"

KEY_TYPE_ED25519 = "Ed25519VerificationKey2020"


@dataclass
class VerificationKey:
    """A public verification key bound to an agent identity."""

    kid: str
    key_type: str = KEY_TYPE_ED25519
    public_key_multibase: str = ""
    purposes: List[str] = field(default_factory=lambda: ["attestation"])
    expires_at: Optional[str] = None
    revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kid": self.kid,
            "type": self.key_type,
            "public_key_multibase": self.public_key_multibase,
            "purposes": list(self.purposes),
            "expires_at": self.expires_at,
            "revoked": self.revoked,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationKey":
        return cls(
            kid=data["kid"],
            key_type=data.get("type", KEY_TYPE_ED25519),
            public_key_multibase=data["public_key_multibase"],
            purposes=list(data.get("purposes", ["attestation"])),
            expires_at=data.get("expires_at"),
            revoked=bool(data.get("revoked", False)),
        )


@dataclass
class AgentID:
    """The identity document of an autonomous agent.

    The ``agent_id`` is a did:key, which is deterministically derived from the
    agent's Ed25519 public key. The document additionally carries the
    operational ``controller`` (a legal or organisational anchor) and the
    agent's declared ``capabilities``.
    """

    agent_id: str
    version: str = "1.0.0"
    created_at: str = ""
    controller: str = "did:legal:unknown"
    keys: List[VerificationKey] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    schema_uri: str = DEFAULT_SCHEMA_URI
    attestations: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not (AGENT_ID_REGEX.match(self.agent_id) or LEGACY_AGENT_ID_REGEX.match(self.agent_id)):
            raise ValueError(f"Invalid Kredent agent identifier: {self.agent_id!r}")
        if not self.keys:
            raise ValueError("AgentID must contain at least one verification key")

    # -- helpers ---------------------------------------------------------

    @property
    def is_legacy(self) -> bool:
        return bool(LEGACY_AGENT_ID_REGEX.match(self.agent_id)) and not AGENT_ID_REGEX.match(
            self.agent_id
        )

    def get_key(self, kid: Optional[str] = None) -> Optional[VerificationKey]:
        """Return the first non-revoked key, optionally filtered by ``kid``."""
        for k in self.keys:
            if k.revoked:
                continue
            if kid is None or k.kid == kid:
                return k
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "$schema": self.schema_uri,
            "agent_id": self.agent_id,
            "version": self.version,
            "created_at": self.created_at,
            "controller": self.controller,
            "keys": [k.to_dict() for k in self.keys],
            "capabilities": list(self.capabilities),
            "attestations": list(self.attestations),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentID":
        keys = [VerificationKey.from_dict(k) for k in data.get("keys", [])]
        return cls(
            agent_id=data["agent_id"],
            version=data.get("version", "1.0.0"),
            created_at=data.get("created_at", _now_iso()),
            controller=data.get("controller", "did:legal:unknown"),
            keys=keys,
            capabilities=list(data.get("capabilities", [])),
            schema_uri=data.get("$schema", DEFAULT_SCHEMA_URI),
            attestations=list(data.get("attestations", [])),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AgentID":
        return cls.from_dict(json.loads(json_str))


@dataclass
class AttestationProof:
    """A W3C Data-Integrity-style proof attached to an attestation."""

    type: str = "Ed25519Signature2020"
    cryptosuite: str = "kredent-ed25519-jcs-2026"
    verification_method: str = ""
    created: str = ""
    proof_purpose: str = "assertionMethod"
    proof_value: str = ""  # base64url of the 64-byte Ed25519 signature

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "cryptosuite": self.cryptosuite,
            "verification_method": self.verification_method,
            "created": self.created,
            "proof_purpose": self.proof_purpose,
            "proof_value": self.proof_value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttestationProof":
        return cls(
            type=data.get("type", "Ed25519Signature2020"),
            cryptosuite=data.get("cryptosuite", "kredent-ed25519-jcs-2026"),
            verification_method=data.get("verification_method", ""),
            created=data.get("created", ""),
            proof_purpose=data.get("proof_purpose", "assertionMethod"),
            proof_value=data.get("proof_value", ""),
        )


@dataclass
class Attestation:
    """A signed claim made by an agent.

    An attestation is the unit of accountable behaviour in Kredent: an agent
    asserts that it performed (or observed) something, and binds that assertion
    to its key with an Ed25519 signature. Third parties can verify the
    signature offline, because the signing key is recoverable from the
    ``issuer`` did:key.
    """

    id: str = ""
    type: str = "KredentAttestation"
    issuer: str = ""  # did:key of the attesting agent
    kid: str = "sig-ed25519-primary"
    claim: Dict[str, Any] = field(default_factory=dict)
    issued_at: str = ""
    expires_at: Optional[str] = None
    nonce: str = ""
    proof: Optional[AttestationProof] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "kid": self.kid,
            "claim": self.claim,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }
        if self.proof is not None:
            out["proof"] = self.proof.to_dict()
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Attestation":
        proof = data.get("proof")
        return cls(
            id=data.get("id", ""),
            type=data.get("type", "KredentAttestation"),
            issuer=data.get("issuer", ""),
            kid=data.get("kid", "sig-ed25519-primary"),
            claim=dict(data.get("claim", {})),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at"),
            nonce=data.get("nonce", ""),
            proof=AttestationProof.from_dict(proof) if isinstance(proof, dict) else None,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Attestation":
        return cls.from_dict(json.loads(json_str))


@dataclass
class ReputationScore:
    """The computed reputation of an agent over an evaluation window."""

    score: float
    base_score: float
    reliability: float
    accuracy: float
    stability: float
    contradiction_rate: float
    volume_damping: float
    tier: str  # TIER_A | TIER_B | TIER_C | QUARANTINED
    total_transactions: int
    total_claims: int
    refuted_claims: int
    attestations_verified: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "base_score": round(self.base_score, 4),
            "reliability": round(self.reliability, 4),
            "accuracy": round(self.accuracy, 4),
            "stability": round(self.stability, 4),
            "contradiction_rate": round(self.contradiction_rate, 4),
            "volume_damping": round(self.volume_damping, 4),
            "tier": self.tier,
            "total_transactions": self.total_transactions,
            "total_claims": self.total_claims,
            "refuted_claims": self.refuted_claims,
            "attestations_verified": self.attestations_verified,
        }


@dataclass
class VerificationResult:
    """Outcome of verifying a signature or an attestation."""

    valid: bool
    status_code: int
    error_code: Optional[str] = None
    agent_id: Optional[str] = None
    created_epoch: Optional[int] = None
    message: str = ""


@dataclass
class CalibrationEvent:
    """An entry in the reputation ledger.

    ``event_type`` is one of ``claim`` (a new attestation was recorded),
    ``confirmation`` (an attestation was independently verified) or
    ``contradiction`` (an attestation was refuted).
    """

    event_id: str
    agent_id: str
    event_type: str
    claim_ref: str
    evidence_hash: str
    timestamp: str
    challenger: Optional[str] = None
    arbitration_receipt: Optional[str] = None
    score_impact: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "event_type": self.event_type,
            "claim_ref": self.claim_ref,
            "evidence_hash": self.evidence_hash,
            "timestamp": self.timestamp,
            "challenger": self.challenger,
            "arbitration_receipt": self.arbitration_receipt,
            "score_impact": self.score_impact,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CalibrationEvent":
        return cls(
            event_id=data["event_id"],
            agent_id=data["agent_id"],
            event_type=data["event_type"],
            claim_ref=data["claim_ref"],
            evidence_hash=data["evidence_hash"],
            timestamp=data["timestamp"],
            challenger=data.get("challenger"),
            arbitration_receipt=data.get("arbitration_receipt"),
            score_impact=float(data.get("score_impact", 0.0)),
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "AgentID",
    "VerificationKey",
    "Attestation",
    "AttestationProof",
    "ReputationScore",
    "VerificationResult",
    "CalibrationEvent",
    "AGENT_ID_REGEX",
    "LEGACY_AGENT_ID_REGEX",
]

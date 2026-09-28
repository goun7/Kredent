"""
Core data models for Roboseal protocol.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import json
import re

AGENT_ID_REGEX = re.compile(r"^did:agent:68:key:[a-zA-Z0-9_-]+$")
DIGEST_REGEX = re.compile(r"^sha-256=:[a-zA-Z0-9+/=]+:$")


@dataclass
class VerificationKey:
    kid: str
    key_type: str  # "Ed25519VerificationKey2020"
    public_key_multibase: str
    purposes: List[str]
    expires_at: Optional[str] = None
    revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kid": self.kid,
            "type": self.key_type,
            "public_key_multibase": self.public_key_multibase,
            "purposes": self.purposes,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationKey":
        return cls(
            kid=data["kid"],
            key_type=data.get("type", "Ed25519VerificationKey2020"),
            public_key_multibase=data["public_key_multibase"],
            purposes=data.get("purposes", ["call-signing"]),
            expires_at=data.get("expires_at"),
            revoked=data.get("revoked", False),
        )


@dataclass
class AgentID:
    agent_id: str
    version: str
    created_at: str
    controller: str
    keys: List[VerificationKey]
    capabilities: List[str]
    schema_uri: str = "https://roboseal.org/schemas/v1/agent-id.json"
    attestations: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not AGENT_ID_REGEX.match(self.agent_id):
            raise ValueError(f"Invalid Roboseal AgentID format: {self.agent_id}")
        if not self.keys:
            raise ValueError("AgentID must contain at least one verification key")

    def get_key(self, kid: Optional[str] = None) -> Optional[VerificationKey]:
        for k in self.keys:
            if not k.revoked:
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
            "capabilities": self.capabilities,
            "attestations": self.attestations,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentID":
        keys = [VerificationKey.from_dict(k) for k in data.get("keys", [])]
        return cls(
            agent_id=data["agent_id"],
            version=data.get("version", "1.0.0"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            controller=data["controller"],
            keys=keys,
            capabilities=data.get("capabilities", []),
            schema_uri=data.get("$schema", "https://roboseal.org/schemas/v1/agent-id.json"),
            attestations=data.get("attestations", []),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AgentID":
        data = json.loads(json_str)
        return cls.from_dict(data)


@dataclass
class CallSignature:
    agent_id: str
    kid: str
    method: str
    authority: str
    target_uri: str
    content_digest: str
    created: int
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "kid": self.kid,
            "method": self.method,
            "authority": self.authority,
            "target_uri": self.target_uri,
            "content_digest": self.content_digest,
            "created": self.created,
            "signature": self.signature,
        }


@dataclass
class CalibrationEvent:
    event_id: str
    agent_id: str
    event_type: str  # "claim", "confirmation", "contradiction"
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


@dataclass
class ReputationScore:
    score: float
    base_score: float
    reliability: float
    accuracy: float
    stability: float
    contradiction_rate: float
    volume_damping: float
    tier: str  # "TIER_A", "TIER_B", "TIER_C", "QUARANTINED"
    total_transactions: int
    total_claims: int
    refuted_claims: int

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
        }


@dataclass
class VerificationResult:
    valid: bool
    status_code: int
    error_code: Optional[str] = None
    agent_id: Optional[str] = None
    created_epoch: Optional[int] = None
    message: str = ""

"""
Roboseal: Autonomous Agent Identity & Verifiable Reputation Protocol.
IETF RFC 9421 HTTP Message Signatures & Ed25519 AgentID.
"""

from roboseal.models import (
    AgentID,
    VerificationKey,
    CallSignature,
    CalibrationEvent,
    ReputationScore,
    VerificationResult,
)
from roboseal.crypto import (
    generate_keypair,
    encode_multibase_pubkey,
    decode_multibase_pubkey,
    sign_detached,
    verify_detached,
)
from roboseal.canonical import (
    compute_content_digest,
    build_signature_base,
    format_signature_headers,
)
from roboseal.verifier import (
    verify_http_request,
    ReplayCache,
)
from roboseal.reputation import (
    compute_reputation_score,
    detect_collusion_cycle,
    evaluate_agent_tier,
)
from roboseal.ledger import CalibrationLedger

__version__ = "1.0.0"

__all__ = [
    "AgentID",
    "VerificationKey",
    "CallSignature",
    "CalibrationEvent",
    "ReputationScore",
    "VerificationResult",
    "generate_keypair",
    "encode_multibase_pubkey",
    "decode_multibase_pubkey",
    "sign_detached",
    "verify_detached",
    "compute_content_digest",
    "build_signature_base",
    "format_signature_headers",
    "verify_http_request",
    "ReplayCache",
    "compute_reputation_score",
    "detect_collusion_cycle",
    "evaluate_agent_tier",
    "CalibrationLedger",
]

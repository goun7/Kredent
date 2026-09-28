"""
Kredent: identity and verifiable reputation for autonomous agents.

An agent holds an Ed25519 key. Its public identity is a W3C ``did:key``, which
embeds the verification key in the identifier itself — no registry, no
resolver, no network. The agent signs claims over that key; anyone can verify
them offline. Reputation is a deterministic function of a public ledger of those
claims, so it can be recomputed and audited rather than trusted on faith.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .models import (
    AgentID,
    Attestation,
    AttestationProof,
    CalibrationEvent,
    ReputationScore,
    VerificationKey,
    VerificationResult,
)
from .crypto import (
    b58decode,
    b58encode,
    decode_multibase_pubkey,
    did_from_multibase,
    encode_multibase_pubkey,
    generate_keypair,
    generate_seed,
    is_did_key,
    keypair_from_seed,
    multibase_from_did,
    derive_public_key,
    pubkey_from_did,
    sign,
    verify,
    verification_method_from_did,
)
from .canonical import (
    canonical_json,
    canonical_json_bytes,
    compute_content_digest,
    build_signature_base,
    format_signature_headers,
    parse_signature_input,
    parse_signature_header,
)
from .attest import (
    canonical_attestation_bytes,
    create_agent_id,
    create_attestation,
    unsigned_payload,
    verify_attestation,
)
from .reputation import (
    apply_eigentrust_weights,
    compute_reputation_score,
    compute_volume_damping,
    detect_collusion_cycle,
    evaluate_agent_tier,
    reputation_from_events,
)
from .ledger import CalibrationLedger
from .verifier import ReplayCache, verify_http_request

__all__ = [
    # models
    "AgentID",
    "Attestation",
    "AttestationProof",
    "CalibrationEvent",
    "ReputationScore",
    "VerificationKey",
    "VerificationResult",
    # crypto
    "b58decode",
    "b58encode",
    "decode_multibase_pubkey",
    "did_from_multibase",
    "derive_public_key",
    "encode_multibase_pubkey",
    "generate_keypair",
    "generate_seed",
    "is_did_key",
    "keypair_from_seed",
    "multibase_from_did",
    "pubkey_from_did",
    "sign",
    "verify",
    "verification_method_from_did",
    # canonical
    "canonical_json",
    "canonical_json_bytes",
    "compute_content_digest",
    "build_signature_base",
    "format_signature_headers",
    "parse_signature_input",
    "parse_signature_header",
    # attest
    "canonical_attestation_bytes",
    "create_agent_id",
    "create_attestation",
    "unsigned_payload",
    "verify_attestation",
    # reputation
    "apply_eigentrust_weights",
    "compute_reputation_score",
    "compute_volume_damping",
    "detect_collusion_cycle",
    "evaluate_agent_tier",
    "reputation_from_events",
    # ledger + verifier
    "CalibrationLedger",
    "ReplayCache",
    "verify_http_request",
]

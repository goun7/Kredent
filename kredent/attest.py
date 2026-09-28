"""
Attestation issuance and verification — the core of Kredent.

An attestation is a signed claim. Its security model is deliberately simple and
auditable:

* The signer holds a 32-byte Ed25519 seed. It never leaves the agent's own
  machine (or its secrets store).
* The public identity is a W3C ``did:key``, which is *self-resolving*: the
  verification key is embedded in the identifier, so a verifier needs no
  registry, no resolver and no network to recover it.
* The signature is made over the JCS-canonical serialization of the attestation
  with the ``proof`` block detached, following the W3C Data Integrity approach.
* Anyone, anywhere, can therefore verify ``kredent verify <attestation>``
  offline, with zero dependencies beyond the Python standard library.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from .canonical import canonical_json_bytes, sha256_hex
from .crypto import (
    ED25519_KEY_LEN,
    ED25519_SIG_LEN,
    decode_multibase_pubkey,
    did_from_multibase,
    encode_multibase_pubkey,
    keypair_from_seed,
    multibase_from_did,
    pubkey_from_did,
    sign,
    verify,
    verification_method_from_did,
)
from .models import Attestation, AttestationProof, AgentID, VerificationKey, VerificationResult

DEFAULT_KID = "sig-ed25519-primary"

_ATTESTATION_TYPE = "KredentAttestation"
_PROOF_TYPE = "Ed25519Signature2020"
_CRYPTOSUITE = "kredent-ed25519-jcs-2026"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _new_nonce() -> str:
    return secrets.token_hex(8)


def _attestation_id(issuer_multibase: str, canonical_payload: bytes, nonce: str) -> str:
    """Deterministic, content-addressed attestation id."""
    digest = hashlib.sha256(canonical_payload).hexdigest()
    return f"att:{issuer_multibase}:{digest[:16]}:{nonce}"


def unsigned_payload(attestation: Attestation) -> Dict[str, Any]:
    """The attestation document minus the ``proof`` and ``id`` fields.

    This is exactly the set of bytes a signature is computed over (after JCS
    canonicalization).

    ``id`` is deliberately excluded from the signed payload: it is a
    content-addressed lookup key *derived from* the signed bytes and the nonce,
    so it cannot also be an input to its own signature. Its integrity is
    guaranteed separately, by re-deriving it during verification.
    """
    data = attestation.to_dict()
    data.pop("proof", None)
    data.pop("id", None)
    return data


def canonical_attestation_bytes(attestation: Attestation) -> bytes:
    """JCS-canonical bytes of the attestation without its proof block."""
    return canonical_json_bytes(unsigned_payload(attestation))


def create_attestation(
    seed: bytes,
    claim: Dict[str, Any],
    issuer: Optional[str] = None,
    kid: str = DEFAULT_KID,
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    nonce: Optional[str] = None,
    attestation_type: str = _ATTESTATION_TYPE,
) -> Attestation:
    """Create and sign an attestation with a 32-byte Ed25519 seed.

    ``claim`` is an arbitrary JSON object describing what the agent asserts —
    for example ``{"action": "deployed", "service": "billing-api", "version":
    "1.4.2"}``. It is the content that becomes non-repudiable.

    The ``issuer`` did:key is normally derived from ``seed``. It may be passed
    explicitly (for instance to attach a counter-attestation issued under a
    different, already-published key); when given, it must resolve to the same
    public key as ``seed``.
    """
    if len(seed) != ED25519_KEY_LEN:
        raise ValueError(f"Ed25519 seed must be {ED25519_KEY_LEN} bytes")

    _, raw_pub, multibase_pub, derived_did = keypair_from_seed(seed)

    if issuer is None:
        issuer = derived_did
    else:
        # The caller-supplied issuer must bind to the same key.
        if pubkey_from_did(issuer) != raw_pub:
            raise ValueError("issuer did:key does not match the signing seed")

    if not claim or not isinstance(claim, dict):
        raise ValueError("attestation claim must be a non-empty JSON object")

    nonce = nonce if nonce is not None else _new_nonce()
    issued_at = issued_at if issued_at is not None else _now_iso()

    provisional = Attestation(
        type=attestation_type,
        issuer=issuer,
        kid=kid,
        claim=dict(claim),
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )

    canonical = canonical_attestation_bytes(provisional)
    signature = sign(seed, canonical)
    attestation_id = _attestation_id(multibase_pub, canonical, nonce)

    provisional.id = attestation_id
    provisional.proof = AttestationProof(
        type=_PROOF_TYPE,
        cryptosuite=_CRYPTOSUITE,
        verification_method=verification_method_from_did(issuer),
        created=issued_at,
        proof_purpose="assertionMethod",
        proof_value=_b64url(signature),
    )
    return provisional


def verify_attestation(
    attestation: Union[Attestation, Dict[str, Any], str, bytes],
    *,
    now: Optional[datetime] = None,
    check_expiry: bool = True,
    allow_unsupported_proof: bool = False,
) -> VerificationResult:
    """Independently verify a Kredent attestation, fully offline.

    Returns a :class:`VerificationResult` whose ``valid`` flag is True only if
    every check passed:

    * the document is structurally well-formed,
    * the issuer is a ``did:key`` and the proof references a matching
      verification method,
    * the signature is a valid Ed25519 signature over the canonical document,
    * the attestation id matches its content (integrity),
    * the attestation has not expired.

    No network access, registry or resolver is contacted. The public key is
    recovered from the ``did:key`` identifier itself.
    """
    if isinstance(attestation, (str, bytes)):
        if isinstance(attestation, bytes):
            try:
                text = attestation.decode("utf-8")
            except UnicodeDecodeError:
                return VerificationResult(
                    valid=False, status_code=400, error_code="MALFORMED_DOCUMENT",
                    message="Attestation bytes are not valid UTF-8",
                )
        else:
            text = attestation
        try:
            attestation = Attestation.from_json(text)
        except Exception as exc:
            return VerificationResult(
                valid=False, status_code=400, error_code="MALFORMED_DOCUMENT",
                message=f"Could not parse attestation JSON: {exc}",
            )
    elif isinstance(attestation, dict):
        try:
            attestation = Attestation.from_dict(attestation)
        except Exception as exc:
            return VerificationResult(
                valid=False, status_code=400, error_code="MALFORMED_DOCUMENT",
                message=f"Could not parse attestation document: {exc}",
            )
    elif not isinstance(attestation, Attestation):
        return VerificationResult(
            valid=False, status_code=400, error_code="MALFORMED_DOCUMENT",
            message=f"Unsupported attestation input type: {type(attestation).__name__}",
        )

    issuer = attestation.issuer

    # 1. Structural checks -------------------------------------------------
    if not issuer:
        return VerificationResult(
            valid=False, status_code=400, error_code="MISSING_ISSUER",
            message="Attestation has no issuer",
        )
    if not issuer.startswith("did:key:"):
        return VerificationResult(
            valid=False, status_code=400, error_code="UNSUPPORTED_ISSUER_METHOD",
            agent_id=issuer,
            message=f"Only did:key issuers are supported, got {issuer.split(':', 2)[1] if ':' in issuer else issuer!r}",
        )
    try:
        raw_pub = pubkey_from_did(issuer)
    except ValueError as exc:
        return VerificationResult(
            valid=False, status_code=400, error_code="INVALID_ISSUER_DID",
            agent_id=issuer, message=f"Unresolvable did:key: {exc}",
        )

    proof = attestation.proof
    if proof is None:
        return VerificationResult(
            valid=False, status_code=400, error_code="MISSING_PROOF",
            agent_id=issuer, message="Attestation carries no proof block",
        )

    if proof.type != _PROOF_TYPE or proof.cryptosuite != _CRYPTOSUITE:
        if not allow_unsupported_proof:
            return VerificationResult(
                valid=False, status_code=400, error_code="UNSUPPORTED_PROOF_TYPE",
                agent_id=issuer,
                message=f"Unsupported proof type/cryptosuite: {proof.type}/{proof.cryptosuite}",
            )

    # 2. Verification-method binding --------------------------------------
    expected_vm = verification_method_from_did(issuer)
    if proof.verification_method and proof.verification_method != expected_vm:
        return VerificationResult(
            valid=False, status_code=401, error_code="KEY_BINDING_MISMATCH",
            agent_id=issuer,
            message="proof.verification_method does not bind to the issuer did:key",
        )

    # 3. Signature ---------------------------------------------------------
    try:
        signature = _b64url_decode(proof.proof_value)
    except Exception:
        return VerificationResult(
            valid=False, status_code=400, error_code="MALFORMED_PROOF_VALUE",
            agent_id=issuer, message="proof_value is not valid base64url",
        )

    if len(signature) != ED25519_SIG_LEN:
        return VerificationResult(
            valid=False, status_code=400, error_code="MALFORMED_PROOF_VALUE",
            agent_id=issuer,
            message=f"Expected a {ED25519_SIG_LEN}-byte Ed25519 signature, got {len(signature)}",
        )

    canonical = canonical_attestation_bytes(attestation)
    if not verify(raw_pub, canonical, signature):
        return VerificationResult(
            valid=False, status_code=401, error_code="INVALID_SIGNATURE",
            agent_id=issuer,
            message="Ed25519 signature does not match the canonical document",
        )

    # 4. Content-addressed id integrity -----------------------------------
    multibase_pub = multibase_from_did(issuer)
    expected_id = _attestation_id(multibase_pub, canonical, attestation.nonce)
    if attestation.id and attestation.id != expected_id:
        return VerificationResult(
            valid=False, status_code=401, error_code="ID_INTEGRITY_FAILURE",
            agent_id=issuer,
            message="Attestation id does not match its signed content",
        )
    if not attestation.id:
        # Tolerate documents that omit the id; the signature still binds content.
        attestation.id = expected_id

    # 5. Expiry ------------------------------------------------------------
    if check_expiry and attestation.expires_at:
        now_dt = now if now is not None else datetime.now(timezone.utc)
        try:
            exp = _parse_iso(attestation.expires_at)
        except ValueError:
            return VerificationResult(
                valid=False, status_code=400, error_code="MALFORMED_EXPIRY",
                agent_id=issuer, message="expires_at is not a valid ISO-8601 timestamp",
            )
        if now_dt > exp:
            return VerificationResult(
                valid=False, status_code=401, error_code="ATTESTATION_EXPIRED",
                agent_id=issuer,
                message=f"Attestation expired at {attestation.expires_at}",
            )

    return VerificationResult(
        valid=True,
        status_code=200,
        agent_id=issuer,
        message="Attestation verified: signature valid over canonical document",
    )


def _parse_iso(ts: str) -> datetime:
    text = ts.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Identity document helpers
# ---------------------------------------------------------------------------


def create_agent_id(
    seed: bytes,
    controller: str = "did:legal:unknown",
    capabilities: Optional[list] = None,
    kid: str = DEFAULT_KID,
    created_at: Optional[str] = None,
) -> AgentID:
    """Build a Kredent identity document for the key derived from ``seed``."""
    if len(seed) != ED25519_KEY_LEN:
        raise ValueError(f"Ed25519 seed must be {ED25519_KEY_LEN} bytes")

    _, raw_pub, multibase_pub, did = keypair_from_seed(seed)
    return AgentID(
        agent_id=did,
        version="1.0.0",
        created_at=created_at or _now_iso(),
        controller=controller,
        keys=[
            VerificationKey(
                kid=kid,
                public_key_multibase=multibase_pub,
                purposes=["attestation", "call-signing"],
            )
        ],
        capabilities=list(capabilities if capabilities is not None else ["tool-call"]),
    )


__all__ = [
    "create_attestation",
    "verify_attestation",
    "canonical_attestation_bytes",
    "unsigned_payload",
    "create_agent_id",
    "DEFAULT_KID",
]

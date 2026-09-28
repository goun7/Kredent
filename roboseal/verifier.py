"""
Edge verifier for Roboseal RFC 9421 HTTP Message Signatures.
"""

from typing import Dict, Optional, Tuple
import time
import hashlib
import threading
from roboseal.models import VerificationResult
from roboseal.canonical import (
    compute_content_digest,
    build_signature_base,
    parse_signature_input,
    parse_signature_header,
)
from roboseal.crypto import (
    verify_detached,
    load_public_key_from_bytes,
)


class ReplayCache:
    """
    In-memory replay cache with time-to-live (TTL) expiration.
    Stores cryptographic hashes of signatures to prevent replay attacks.
    """

    def __init__(self, ttl_seconds: int = 360) -> None:
        self.ttl_seconds = ttl_seconds
        self._entries: Dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, signature_digest: str, now: Optional[float] = None) -> bool:
        """
        Returns True if signature_digest is fresh and added.
        Returns False if signature_digest already exists (replay).
        """
        curr_time = now if now is not None else time.time()
        with self._lock:
            # Prune expired entries
            expired = [k for k, exp in self._entries.items() if exp <= curr_time]
            for k in expired:
                del self._entries[k]

            if signature_digest in self._entries:
                return False

            self._entries[signature_digest] = curr_time + self.ttl_seconds
            return True

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def verify_http_request(
    method: str,
    authority: str,
    target_uri: str,
    headers: Dict[str, str],
    raw_body: bytes,
    public_key_raw: bytes,
    replay_cache: Optional[ReplayCache] = None,
    now: Optional[float] = None,
    max_drift_seconds: int = 180,
) -> VerificationResult:
    """
    Validates an incoming HTTP request signed via Roboseal RFC 9421.
    """
    curr_time = now if now is not None else time.time()

    # Normalize header keys to lowercase
    norm_headers = {k.lower(): v for k, v in headers.items()}

    agent_id = norm_headers.get("agent-id")
    content_digest_hdr = norm_headers.get("content-digest")
    sig_input_hdr = norm_headers.get("signature-input")
    signature_hdr = norm_headers.get("signature")
    date_hdr = norm_headers.get("date")

    if not all([agent_id, content_digest_hdr, sig_input_hdr, signature_hdr, date_hdr]):
        return VerificationResult(
            valid=False,
            status_code=400,
            error_code="MISSING_SIGNATURE_HEADERS",
            message="One or more required RFC 9421 signature headers are missing",
        )

    # 1. Content-Digest Verification
    expected_digest = compute_content_digest(raw_body)
    if content_digest_hdr != expected_digest:
        return VerificationResult(
            valid=False,
            status_code=401,
            error_code="DIGEST_MISMATCH",
            agent_id=agent_id,
            message="Body digest does not match Content-Digest header",
        )

    # 2. Parse Signature-Input & Timestamp Validation
    try:
        sig_params_data = parse_signature_input(sig_input_hdr)
    except Exception as e:
        return VerificationResult(
            valid=False,
            status_code=400,
            error_code="MALFORMED_SIGNATURE_INPUT",
            agent_id=agent_id,
            message=f"Failed to parse Signature-Input: {str(e)}",
        )

    created_epoch = sig_params_data.get("created")
    if created_epoch is None:
        return VerificationResult(
            valid=False,
            status_code=400,
            error_code="MISSING_CREATED_TIMESTAMP",
            agent_id=agent_id,
            message="Signature-Input does not contain 'created' epoch timestamp",
        )

    if abs(curr_time - created_epoch) > max_drift_seconds:
        return VerificationResult(
            valid=False,
            status_code=401,
            error_code="SIGNATURE_EXPIRED",
            agent_id=agent_id,
            created_epoch=created_epoch,
            message=f"Signature created timestamp drift exceeds {max_drift_seconds}s limit",
        )

    # 3. Parse Signature
    try:
        raw_sig = parse_signature_header(signature_hdr)
    except Exception as e:
        return VerificationResult(
            valid=False,
            status_code=400,
            error_code="MALFORMED_SIGNATURE",
            agent_id=agent_id,
            message=f"Failed to parse Signature: {str(e)}",
        )

    # 4. Replay Prevention
    if replay_cache is not None:
        sig_hash = hashlib.sha256(raw_sig).hexdigest()
        if not replay_cache.check_and_add(sig_hash, now=curr_time):
            return VerificationResult(
                valid=False,
                status_code=401,
                error_code="REPLAY_ATTACK_DETECTED",
                agent_id=agent_id,
                created_epoch=created_epoch,
                message="Duplicate signature detected within replay prevention window",
            )

    # 5. Build Canonical Signature Base
    raw_params = sig_params_data["raw_params"]
    sig_base = build_signature_base(
        method=method,
        authority=authority,
        target_uri=target_uri,
        content_digest=content_digest_hdr,
        date_str=date_hdr,
        signature_params=raw_params,
    )

    # 6. Verify Ed25519 Cryptographic Signature
    try:
        pub_key = load_public_key_from_bytes(public_key_raw)
        is_valid = verify_detached(pub_key, sig_base, raw_sig)
    except Exception as e:
        return VerificationResult(
            valid=False,
            status_code=401,
            error_code="INVALID_PUBLIC_KEY",
            agent_id=agent_id,
            message=f"Failed to load or verify with public key: {str(e)}",
        )

    if not is_valid:
        return VerificationResult(
            valid=False,
            status_code=401,
            error_code="INVALID_SIGNATURE",
            agent_id=agent_id,
            created_epoch=created_epoch,
            message="Ed25519 signature verification failed",
        )

    return VerificationResult(
        valid=True,
        status_code=200,
        agent_id=agent_id,
        created_epoch=created_epoch,
        message="Signature verified successfully",
    )

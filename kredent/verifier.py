"""
RFC 9421 HTTP request verification.

This module is retained for the case where an agent must authenticate a live
HTTP call to a gateway, rather than issue a self-standing attestation. An
attestation says "I did X"; a request signature says "I am the one making this
call, right now". Both have a place, and they share the same key.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Dict, Optional

from .canonical import (
    build_signature_base,
    compute_content_digest,
    parse_signature_header,
    parse_signature_input,
)
from .crypto import ED25519_KEY_LEN, verify as verify_ed25519
from .models import VerificationResult

DEFAULT_MAX_DRIFT_SECONDS = 180
DEFAULT_REPLAY_TTL_SECONDS = 360


class ReplayCache:
    """In-memory replay cache with TTL expiry.

    A captured signature is only replayable within the clock-drift window, so
    the cache only needs to remember signatures for slightly longer than that.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_REPLAY_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self._entries: Dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, signature_digest: str, now: Optional[float] = None) -> bool:
        """Return True if fresh and recorded; False if it was seen before."""
        curr_time = now if now is not None else time.time()
        with self._lock:
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
    max_drift_seconds: int = DEFAULT_MAX_DRIFT_SECONDS,
) -> VerificationResult:
    """Validate an incoming RFC 9421-signed HTTP request."""
    curr_time = now if now is not None else time.time()

    norm_headers = {str(k).lower(): v for k, v in headers.items()}

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

    # 1. Body integrity
    expected_digest = compute_content_digest(raw_body)
    if content_digest_hdr != expected_digest:
        return VerificationResult(
            valid=False,
            status_code=401,
            error_code="DIGEST_MISMATCH",
            agent_id=agent_id,
            message="Body digest does not match Content-Digest header",
        )

    # 2. Parse Signature-Input and check the timestamp
    try:
        sig_params_data = parse_signature_input(sig_input_hdr)
    except Exception as exc:
        return VerificationResult(
            valid=False,
            status_code=400,
            error_code="MALFORMED_SIGNATURE_INPUT",
            agent_id=agent_id,
            message=f"Failed to parse Signature-Input: {exc}",
        )

    created_epoch = sig_params_data.get("created")
    if created_epoch is None:
        return VerificationResult(
            valid=False,
            status_code=400,
            error_code="MISSING_CREATED_TIMESTAMP",
            agent_id=agent_id,
            message="Signature-Input does not contain a 'created' epoch timestamp",
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

    # 3. Parse the signature value
    try:
        raw_sig = parse_signature_header(signature_hdr)
    except Exception as exc:
        return VerificationResult(
            valid=False,
            status_code=400,
            error_code="MALFORMED_SIGNATURE",
            agent_id=agent_id,
            message=f"Failed to parse Signature: {exc}",
        )

    # 4. Replay prevention
    if replay_cache is not None:
        sig_hash = hashlib.sha256(raw_sig).hexdigest()
        if not replay_cache.check_and_add(sig_hash, now=curr_time):
            return VerificationResult(
                valid=False,
                status_code=401,
                error_code="REPLAY_ATTACK_DETECTED",
                agent_id=agent_id,
                created_epoch=created_epoch,
                message="Duplicate signature detected within the replay prevention window",
            )

    # 5. Rebuild the canonical base and check the signature
    raw_params = sig_params_data["raw_params"]
    sig_base = build_signature_base(
        method=method,
        authority=authority,
        target_uri=target_uri,
        content_digest=content_digest_hdr,
        date_str=date_hdr,
        signature_params=raw_params,
    )

    try:
        if len(public_key_raw) != ED25519_KEY_LEN:
            raise ValueError(
                f"Expected a {ED25519_KEY_LEN}-byte Ed25519 public key, "
                f"got {len(public_key_raw)}"
            )
        is_valid = verify_ed25519(public_key_raw, sig_base, raw_sig)
    except Exception as exc:
        return VerificationResult(
            valid=False,
            status_code=401,
            error_code="INVALID_PUBLIC_KEY",
            agent_id=agent_id,
            message=f"Failed to load or verify with public key: {exc}",
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


__all__ = ["verify_http_request", "ReplayCache"]

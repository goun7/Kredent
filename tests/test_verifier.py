"""
Tests for the RFC 9421 edge verifier and replay-attack protection.

These cover the request-signature path: an agent authenticating a live HTTP call
to a gateway, as opposed to issuing a self-standing attestation.
"""

import time
from datetime import datetime, timezone

import pytest

from kredent.canonical import (
    build_signature_base,
    compute_content_digest,
    format_signature_headers,
)
from kredent.crypto import keypair_from_seed, sign
from kredent.verifier import ReplayCache, verify_http_request

AUTHORITY = "api.agentshelf.org"
TARGET_URI = "https://api.agentshelf.org/v1/solve"


def _signed_request(seed, body, epoch=None):
    now_epoch = epoch if epoch is not None else int(time.time())
    date_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    _, raw_pub, multibase_pub, did = keypair_from_seed(seed)
    agent_id = did

    digest = compute_content_digest(body)
    sig_params = (
        f'("@method" "@authority" "@target-uri" "content-digest" "date");'
        f'created={now_epoch};keyid="sig-ed25519-primary";alg="ed25519"'
    )
    sig_base = build_signature_base(
        method="POST",
        authority=AUTHORITY,
        target_uri=TARGET_URI,
        content_digest=digest,
        date_str=date_str,
        signature_params=sig_params,
    )
    headers = format_signature_headers(
        agent_id=agent_id,
        kid="sig-ed25519-primary",
        method="POST",
        authority=AUTHORITY,
        target_uri=TARGET_URI,
        raw_body=body,
        signature_bytes=sign(seed, sig_base),
        created_epoch=now_epoch,
        date_str=date_str,
    )
    return headers, raw_pub


def test_verifier_valid_request(sample_seed):
    body = b'{"sku": "6204-2RSH", "qty": 100}'
    headers, raw_pub = _signed_request(sample_seed, body)

    result = verify_http_request(
        method="POST",
        authority=AUTHORITY,
        target_uri=TARGET_URI,
        headers=headers,
        raw_body=body,
        public_key_raw=raw_pub,
    )
    assert result.valid is True
    assert result.status_code == 200
    assert result.error_code is None


def test_verifier_body_mismatch(sample_seed):
    orig_body = b'{"qty": 100}'
    tampered_body = b'{"qty": 1000}'
    headers, raw_pub = _signed_request(sample_seed, orig_body)

    result = verify_http_request(
        method="POST",
        authority=AUTHORITY,
        target_uri=TARGET_URI,
        headers=headers,
        raw_body=tampered_body,
        public_key_raw=raw_pub,
    )
    assert result.valid is False
    assert result.status_code == 401
    assert result.error_code == "DIGEST_MISMATCH"


def test_verifier_expired_drift(sample_seed):
    body = b'{"test": 1}'
    old_epoch = int(time.time()) - 500  # beyond the 180s window
    headers, raw_pub = _signed_request(sample_seed, body, epoch=old_epoch)

    result = verify_http_request(
        method="POST",
        authority=AUTHORITY,
        target_uri=TARGET_URI,
        headers=headers,
        raw_body=body,
        public_key_raw=raw_pub,
    )
    assert result.valid is False
    assert result.status_code == 401
    assert result.error_code == "SIGNATURE_EXPIRED"


def test_verifier_replay_protection(sample_seed):
    body = b'{"transfer": 50}'
    headers, raw_pub = _signed_request(sample_seed, body)

    cache = ReplayCache(ttl_seconds=60)
    first = verify_http_request(
        method="POST", authority=AUTHORITY, target_uri=TARGET_URI,
        headers=headers, raw_body=body, public_key_raw=raw_pub, replay_cache=cache,
    )
    assert first.valid is True

    second = verify_http_request(
        method="POST", authority=AUTHORITY, target_uri=TARGET_URI,
        headers=headers, raw_body=body, public_key_raw=raw_pub, replay_cache=cache,
    )
    assert second.valid is False
    assert second.error_code == "REPLAY_ATTACK_DETECTED"


def test_verifier_missing_headers(sample_seed):
    result = verify_http_request(
        method="POST",
        authority=AUTHORITY,
        target_uri=TARGET_URI,
        headers={"Agent-ID": "did:key:z6Mkabc"},
        raw_body=b"x",
        public_key_raw=b"0" * 32,
    )
    assert result.valid is False
    assert result.error_code == "MISSING_SIGNATURE_HEADERS"


def test_verifier_malformed_signature_input(sample_seed):
    body = b"{}"
    headers, raw_pub = _signed_request(sample_seed, body)
    headers["Signature-Input"] = "garbage"

    result = verify_http_request(
        method="POST", authority=AUTHORITY, target_uri=TARGET_URI,
        headers=headers, raw_body=body, public_key_raw=raw_pub,
    )
    assert result.valid is False
    assert result.error_code in ("MALFORMED_SIGNATURE_INPUT", "MISSING_CREATED_TIMESTAMP")


def test_verifier_invalid_signature(sample_seed):
    body = b'{"a":1}'
    headers, raw_pub = _signed_request(sample_seed, body)
    # Corrupt the signature value while keeping the structure valid.
    import base64

    inner = headers["Signature"][len("sig1=:"):-1]
    corrupted = base64.b64encode(bytes(64)).decode("ascii")
    headers["Signature"] = f"sig1=:{corrupted}:"

    result = verify_http_request(
        method="POST", authority=AUTHORITY, target_uri=TARGET_URI,
        headers=headers, raw_body=body, public_key_raw=raw_pub,
    )
    assert result.valid is False
    assert result.error_code == "INVALID_SIGNATURE"


def test_verifier_invalid_public_key(sample_seed):
    body = b"{}"
    headers, _ = _signed_request(sample_seed, body)

    result = verify_http_request(
        method="POST", authority=AUTHORITY, target_uri=TARGET_URI,
        headers=headers, raw_body=body, public_key_raw=b"0" * 31,
    )
    assert result.valid is False
    assert result.error_code == "INVALID_PUBLIC_KEY"


def test_replay_cache_expires():
    cache = ReplayCache(ttl_seconds=10)
    assert cache.check_and_add("x", now=100.0) is True
    assert cache.check_and_add("x", now=100.0) is False
    # After the TTL, the entry is gone.
    assert cache.check_and_add("x", now=200.0) is True


def test_replay_cache_clear():
    cache = ReplayCache()
    cache.check_and_add("y", now=1.0)
    cache.clear()
    assert cache.check_and_add("y", now=1.0) is True

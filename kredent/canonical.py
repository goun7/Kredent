"""
Canonicalization for Kredent.

Two canonicalization concerns live here:

1. **JCS — JSON Canonicalization Scheme (RFC 8785).** Used to produce a
   deterministic byte serialization of an attestation before signing and before
   verifying. Determinism across implementations is what makes a signature
   portable: the verifier must reconstruct *exactly* the bytes the signer
   signed, otherwise the signature is meaningless.

2. **RFC 9421 HTTP Message Signatures.** Retained from the Roboseal lineage for
   signing whole HTTP calls; it remains useful when an agent must authenticate a
   request to a gateway rather than issue a self-standing attestation.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Tuple

# ---------------------------------------------------------------------------
# JCS (RFC 8785) — deterministic JSON serialization
# ---------------------------------------------------------------------------
# The implementation covers the subset of JSON that Kredent documents use:
# objects with string keys, arrays, strings, booleans, null, and integers or
# floats that are finite and Python-representable. It follows RFC 8785 for
# sorting (by Unicode code point) and number serialization.


def _jcs_sort_key(key: str) -> str:
    # RFC 8785 §3.2.3: sort by UTF-16 code unit values. For the BMP-only keys
    # Kredent uses, Python's code-point ordering coincides with UTF-16 ordering.
    return key


def _serialize_number(value: Any) -> str:
    if isinstance(value, bool):
        # Handled by the caller; guard against bool being an int subclass.
        raise TypeError("bool is not a JCS number")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("JCS cannot serialize NaN or Infinity")
        # RFC 8785 §3.2.2.2: shortest round-trip representation.
        if value == int(value) and abs(value) < 1e21:
            return str(int(value))
        return repr(value)
    raise TypeError(f"Unsupported JCS number type: {type(value).__name__}")


def _jcs_serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _serialize_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _jcs_sort_key(kv[0]))
        parts = []
        for k, v in items:
            if not isinstance(k, str):
                raise TypeError("JCS requires string keys")
            parts.append(json.dumps(k, ensure_ascii=False) + ":" + _jcs_serialize(v))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"Unsupported JCS type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize a JSON-compatible value to its RFC 8785 canonical form."""
    return _jcs_serialize(value)


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical JCS serialization encoded as UTF-8 bytes."""
    return canonical_json(value).encode("utf-8")


def compute_content_digest(raw_body: bytes) -> str:
    """RFC 9421 Content-Digest header value using SHA-256: ``sha-256=:<b64>:``."""
    digest_bytes = hashlib.sha256(raw_body).digest()
    b64_digest = base64.b64encode(digest_bytes).decode("ascii")
    return f"sha-256=:{b64_digest}:"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_signature_base(
    method: str,
    authority: str,
    target_uri: str,
    content_digest: str,
    date_str: str,
    signature_params: str,
) -> bytes:
    """The deterministic RFC 9421 signature base string."""
    lines = [
        f'"@method": {method.upper()}',
        f'"@authority": {authority.lower()}',
        f'"@target-uri": {target_uri}',
        f'"content-digest": {content_digest}',
        f'"date": {date_str}',
        f'"@signature-params": {signature_params}',
    ]
    return "\n".join(lines).encode("utf-8")


def format_signature_headers(
    agent_id: str,
    kid: str,
    method: str,
    authority: str,
    target_uri: str,
    raw_body: bytes,
    signature_bytes: bytes,
    created_epoch: int,
    date_str: str,
) -> Dict[str, str]:
    """Construct the outbound RFC 9421-compliant HTTP headers."""
    content_digest = compute_content_digest(raw_body)
    sig_b64 = base64.b64encode(signature_bytes).decode("ascii")
    signature_params = (
        f'("@method" "@authority" "@target-uri" "content-digest" "date");'
        f'created={created_epoch};keyid="{kid}";alg="ed25519"'
    )
    return {
        "Agent-ID": agent_id,
        "Content-Digest": content_digest,
        "Date": date_str,
        "Signature-Input": f"sig1={signature_params}",
        "Signature": f"sig1=:{sig_b64}:",
    }


def parse_signature_input(sig_input_val: str) -> Dict[str, Any]:
    """Parse ``sig1=(...);created=...;keyid="...";alg="..."``."""
    if not sig_input_val.startswith("sig1="):
        raise ValueError("Malformed Signature-Input header: missing sig1 label")

    raw_params = sig_input_val[len("sig1="):]
    result: Dict[str, Any] = {"raw_params": raw_params}

    if "created=" in raw_params:
        part = raw_params.split("created=")[1].split(";")[0]
        result["created"] = int(part)
    if 'keyid="' in raw_params:
        part = raw_params.split('keyid="')[1].split('"')[0]
        result["keyid"] = part
    if 'alg="' in raw_params:
        part = raw_params.split('alg="')[1].split('"')[0]
        result["alg"] = part
    return result


def parse_signature_header(sig_val: str) -> bytes:
    """Parse ``sig1=:<base64>:`` into raw signature bytes."""
    if not sig_val.startswith("sig1=:"):
        raise ValueError("Malformed Signature header: missing sig1 label prefix")
    trimmed = sig_val[len("sig1=:"):]
    if not trimmed.endswith(":"):
        raise ValueError("Malformed Signature header: missing closing colon")
    return base64.b64decode(trimmed[:-1])


__all__ = [
    "canonical_json",
    "canonical_json_bytes",
    "compute_content_digest",
    "sha256_hex",
    "build_signature_base",
    "format_signature_headers",
    "parse_signature_input",
    "parse_signature_header",
]

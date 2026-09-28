"""
IETF RFC 9421 HTTP Message Signatures canonicalization and formatting.
"""

from typing import Dict, Any, Tuple
import hashlib
import base64
import time
from datetime import datetime, timezone


def compute_content_digest(raw_body: bytes) -> str:
    """
    Computes RFC 9421 Content-Digest header value using SHA-256.
    Format: sha-256=:<base64>:
    """
    digest_bytes = hashlib.sha256(raw_body).digest()
    b64_digest = base64.b64encode(digest_bytes).decode("ascii")
    return f"sha-256=:{b64_digest}:"


def build_signature_base(
    method: str,
    authority: str,
    target_uri: str,
    content_digest: str,
    date_str: str,
    signature_params: str,
) -> bytes:
    """
    Builds the deterministic RFC 9421 signature base string.
    """
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
    """
    Constructs the set of outbound RFC 9421 compliant HTTP headers.
    """
    content_digest = compute_content_digest(raw_body)
    sig_b64 = base64.b64encode(signature_bytes).decode("ascii")
    signature_params = (
        f'("@method" "@authority" "@target-uri" "content-digest" "date");'
        f'created={created_epoch};keyid="{kid}";alg="ed25519"'
    )

    headers = {
        "Agent-ID": agent_id,
        "Content-Digest": content_digest,
        "Date": date_str,
        "Signature-Input": f"sig1={signature_params}",
        "Signature": f"sig1=:{sig_b64}:",
    }
    return headers


def parse_signature_input(sig_input_val: str) -> Dict[str, Any]:
    """
    Parses 'sig1=("@method" ...);created=1789262700;keyid="sig-1";alg="ed25519"'.
    """
    if not sig_input_val.startswith("sig1="):
        raise ValueError("Malformed Signature-Input header: missing sig1 label")

    raw_params = sig_input_val[len("sig1="):]
    result: Dict[str, Any] = {"raw_params": raw_params}

    # Extract created
    if "created=" in raw_params:
        part = raw_params.split("created=")[1].split(";")[0]
        result["created"] = int(part)

    # Extract keyid
    if 'keyid="' in raw_params:
        part = raw_params.split('keyid="')[1].split('"')[0]
        result["keyid"] = part

    # Extract alg
    if 'alg="' in raw_params:
        part = raw_params.split('alg="')[1].split('"')[0]
        result["alg"] = part

    return result


def parse_signature_header(sig_val: str) -> bytes:
    """
    Parses 'sig1=:k28Fn3vO...xW4qP9==:' into raw signature bytes.
    """
    if not sig_val.startswith("sig1=:"):
        raise ValueError("Malformed Signature header: missing sig1 label prefix")
    trimmed = sig_val[len("sig1=:"):]
    if not trimmed.endswith(":"):
        raise ValueError("Malformed Signature header: missing closing colon")
    b64_str = trimmed[:-1]
    return base64.b64decode(b64_str)

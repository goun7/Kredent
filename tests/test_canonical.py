"""
Tests for canonicalization: RFC 8785 JCS and RFC 9421 HTTP message signatures.
"""

import base64
import hashlib

import pytest

from kredent.canonical import (
    build_signature_base,
    canonical_json,
    compute_content_digest,
    format_signature_headers,
    parse_signature_header,
    parse_signature_input,
)


def test_compute_content_digest():
    raw_body = b'{"target": "6204-2RSH", "min_qty": 200}'
    digest = compute_content_digest(raw_body)
    assert digest.startswith("sha-256=:")
    assert digest.endswith(":")

    expected_b64 = base64.b64encode(hashlib.sha256(raw_body).digest()).decode("ascii")
    assert digest == f"sha-256=:{expected_b64}:"


def test_build_signature_base():
    sig_base = build_signature_base(
        method="POST",
        authority="api.agentshelf.org",
        target_uri="https://api.agentshelf.org/v1/solve",
        content_digest="sha-256=:testdigest=:",
        date_str="Sun, 13 Sep 2026 01:25:00 GMT",
        signature_params='("@method" "@authority" "@target-uri" "content-digest" "date");created=1789262700;keyid="k1";alg="ed25519"',
    )
    text = sig_base.decode("utf-8")
    assert '"@method": POST' in text
    assert '"@authority": api.agentshelf.org' in text
    assert '"@target-uri": https://api.agentshelf.org/v1/solve' in text
    assert '"content-digest": sha-256=:testdigest=:' in text
    assert '"date": Sun, 13 Sep 2026 01:25:00 GMT' in text
    assert '"@signature-params": ("@method"' in text


def test_parse_signature_input():
    header = 'sig1=("@method" "@authority");created=1789262700;keyid="sig-ed25519-primary";alg="ed25519"'
    parsed = parse_signature_input(header)
    assert parsed["created"] == 1789262700
    assert parsed["keyid"] == "sig-ed25519-primary"
    assert parsed["alg"] == "ed25519"


def test_parse_signature_input_rejects_missing_label():
    with pytest.raises(ValueError):
        parse_signature_input('("@method");created=1')


def test_parse_signature_header():
    raw = b"12345678" * 8
    b64 = base64.b64encode(raw).decode("ascii")
    assert parse_signature_header(f"sig1=:{b64}:") == raw


def test_parse_signature_header_rejects_malformed():
    with pytest.raises(ValueError):
        parse_signature_header("nolabel")
    with pytest.raises(ValueError):
        parse_signature_header("sig1=:abc")


def test_format_signature_headers_is_self_consistent():
    headers = format_signature_headers(
        agent_id="did:key:z6Mkabc",
        kid="k1",
        method="POST",
        authority="api.example.com",
        target_uri="https://api.example.com/v1/x",
        raw_body=b'{"a":1}',
        signature_bytes=b"s" * 64,
        created_epoch=1789262700,
        date_str="Sun, 13 Sep 2026 01:25:00 GMT",
    )
    assert headers["Agent-ID"] == "did:key:z6Mkabc"
    assert headers["Signature-Input"].startswith("sig1=")
    assert headers["Signature"].startswith("sig1=:")
    # The digest header must match the body actually sent.
    assert headers["Content-Digest"] == compute_content_digest(b'{"a":1}')


# ---------------------------------------------------------------------------
# JCS (RFC 8785)
# ---------------------------------------------------------------------------


def test_canonical_json_sorts_keys():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_sorts_recursively():
    assert canonical_json({"z": {"d": 1, "b": 2}}) == '{"z":{"b":2,"d":1}}'


def test_canonical_json_handles_nested_arrays_and_types():
    doc = {"list": [3, 1, 2], "flag": True, "nothing": None, "s": "x"}
    assert canonical_json(doc) == '{"flag":true,"list":[3,1,2],"nothing":null,"s":"x"}'


def test_canonical_json_integrals_omit_decimal_point():
    assert canonical_json({"x": 4.0}) == '{"x":4}'


def test_canonical_json_rejects_nan_and_infinity():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"x": float("inf")})


def test_canonical_json_rejects_non_string_keys():
    with pytest.raises(TypeError):
        canonical_json({1: "x"})

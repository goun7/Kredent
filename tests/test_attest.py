"""
Tests for attestation issuance and verification — the core value of Kredent.

These tests are deliberately thorough about failure modes. An identity primitive
that accepts forged documents is worse than none, so every forgery path here is
asserted to be rejected.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from kredent import (
    create_agent_id,
    create_attestation,
    generate_seed,
    keypair_from_seed,
    verify_attestation,
)
from kredent.attest import canonical_attestation_bytes, unsigned_payload
from kredent.canonical import canonical_json


def _claim():
    return {"action": "deployed", "service": "billing-api", "version": "1.4.2"}


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------


def test_attestation_basic_shape(sample_seed):
    att = create_attestation(sample_seed, _claim())
    _, _, mb, did = keypair_from_seed(sample_seed)

    assert att.issuer == did
    assert att.type == "KredentAttestation"
    assert att.claim == _claim()
    assert att.proof is not None
    assert att.proof.type == "Ed25519Signature2020"
    assert att.proof.verification_method == f"{did}#{mb}"
    assert att.proof.proof_value  # non-empty
    assert att.id.startswith(f"att:{mb}:")


def test_attestation_id_is_content_addressed(sample_seed):
    """Two attestations of the same claim differ only by nonce, so ids differ."""
    a = create_attestation(sample_seed, _claim())
    b = create_attestation(sample_seed, _claim())
    assert a.id != b.id
    # Recomputing with the same nonce reproduces the same id.
    c = create_attestation(sample_seed, _claim(), nonce=a.nonce)
    assert c.id == a.id


def test_attestation_issuer_must_match_seed(sample_seed):
    other = generate_seed()
    _, _, _, other_did = keypair_from_seed(other)
    with pytest.raises(ValueError):
        create_attestation(sample_seed, _claim(), issuer=other_did)


def test_attestation_rejects_empty_claim(sample_seed):
    with pytest.raises(ValueError):
        create_attestation(sample_seed, {})
    with pytest.raises(ValueError):
        create_attestation(sample_seed, "not a dict")


def test_attestation_rejects_bad_seed():
    with pytest.raises(ValueError):
        create_attestation(b"short", _claim())


def test_attestation_can_be_pre_dated_and_expired(sample_seed):
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = create_attestation(sample_seed, _claim(), issued_at=past)
    assert old.issued_at == past
    expiring = create_attestation(sample_seed, _claim(), expires_at=future)
    assert expiring.expires_at == future


# ---------------------------------------------------------------------------
# Verification — happy paths
# ---------------------------------------------------------------------------


def test_verify_valid_attestation(sample_seed):
    att = create_attestation(sample_seed, _claim())
    result = verify_attestation(att)
    assert result.valid is True
    assert result.agent_id == att.issuer
    assert result.error_code is None


def test_verify_accepts_json_string(sample_seed):
    att = create_attestation(sample_seed, _claim())
    assert verify_attestation(att.to_json()).valid is True


def test_verify_accepts_dict(sample_seed):
    att = create_attestation(sample_seed, _claim())
    assert verify_attestation(json.loads(att.to_json())).valid is True


def test_verify_accepts_bytes(sample_seed):
    att = create_attestation(sample_seed, _claim())
    assert verify_attestation(att.to_json().encode("utf-8")).valid is True


def test_verify_is_offline_and_keyless(sample_seed):
    """The public key is recovered from the did:key; nothing else is needed."""
    att = create_attestation(sample_seed, _claim())
    doc = json.loads(att.to_json())
    # Strip every convenience field; only the document is supplied.
    assert verify_attestation(doc).valid is True
    assert verify_attestation(doc).agent_id.startswith("did:key:z6Mk")


# ---------------------------------------------------------------------------
# Verification — forgery must fail
# ---------------------------------------------------------------------------


def _tamper(att, mutate):
    doc = json.loads(att.to_json())
    mutate(doc)
    return doc


def test_tampered_claim_rejected(sample_seed):
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(att, lambda d: d["claim"].update({"version": "99.0.0"}))
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "INVALID_SIGNATURE"


def test_tampered_issuer_rejected(sample_seed):
    other = generate_seed()
    _, _, _, other_did = keypair_from_seed(other)
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(att, lambda d: d.__setitem__("issuer", other_did))
    r = verify_attestation(doc)
    assert r.valid is False
    # The proof still points at the original key, so the issuer/proof binding
    # fails before the signature is even examined.
    assert r.error_code == "KEY_BINDING_MISMATCH"


def test_fully_forged_attestation_rejected():
    """A document signed by one key but presented under another agent's did:key.

    ``create_attestation`` refuses to build such a document, so the forgery is
    constructed by hand: sign with the forger's key, then relabel the issuer.
    """
    import copy

    forger = generate_seed()
    victim = generate_seed()
    _, _, _, victim_did = keypair_from_seed(victim)

    signed = create_attestation(forger, _claim())
    forged = copy.deepcopy(signed)
    forged.issuer = victim_did
    forged.proof.verification_method = f"{victim_did}#{victim_did[8:]}"

    r = verify_attestation(forged)
    assert r.valid is False
    assert r.error_code == "INVALID_SIGNATURE"


def test_tampered_id_rejected(sample_seed):
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(att, lambda d: d.__setitem__("id", "att:zAAAA:deadbeef:00000000"))
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "ID_INTEGRITY_FAILURE"


def test_swapped_signature_rejected(sample_seed):
    """A valid signature from a *different* key must not verify here."""
    other = generate_seed()
    forged = create_attestation(other, _claim())
    att = create_attestation(sample_seed, _claim())
    doc = json.loads(att.to_json())
    doc["proof"]["proof_value"] = forged.proof.proof_value
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "INVALID_SIGNATURE"


def test_missing_proof_rejected(sample_seed):
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(att, lambda d: d.pop("proof"))
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "MISSING_PROOF"


def test_missing_issuer_rejected(sample_seed):
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(att, lambda d: d.pop("issuer"))
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "MISSING_ISSUER"


def test_non_didkey_issuer_rejected(sample_seed):
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(att, lambda d: d.__setitem__("issuer", "did:web:acme.com"))
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "UNSUPPORTED_ISSUER_METHOD"


def test_malformed_proof_value_rejected(sample_seed):
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(att, lambda d: d["proof"].__setitem__("proof_value", "!!!not-base64!!!"))
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "MALFORMED_PROOF_VALUE"


def test_unbound_verification_method_rejected(sample_seed):
    other = generate_seed()
    _, _, _, other_did = keypair_from_seed(other)
    att = create_attestation(sample_seed, _claim())
    doc = _tamper(
        att,
        lambda d: d["proof"].__setitem__("verification_method", f"{other_did}#{other_did[8:]}"),
    )
    r = verify_attestation(doc)
    assert r.valid is False
    assert r.error_code == "KEY_BINDING_MISMATCH"


def test_expired_attestation_rejected(sample_seed):
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    att = create_attestation(sample_seed, _claim(), expires_at=past)
    r = verify_attestation(att)
    assert r.valid is False
    assert r.error_code == "ATTESTATION_EXPIRED"


def test_expiry_check_can_be_disabled(sample_seed):
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    att = create_attestation(sample_seed, _claim(), expires_at=past)
    r = verify_attestation(att, check_expiry=False)
    assert r.valid is True


def test_expiry_evaluated_against_supplied_now(sample_seed):
    future = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    att = create_attestation(sample_seed, _claim(), expires_at=future)
    later = datetime.now(timezone.utc) + timedelta(days=30)
    r = verify_attestation(att, now=later)
    assert r.valid is False
    assert r.error_code == "ATTESTATION_EXPIRED"


def test_malformed_expiry_rejected(sample_seed):
    att = create_attestation(sample_seed, _claim(), expires_at="not-a-date")
    r = verify_attestation(att)
    assert r.valid is False
    assert r.error_code == "MALFORMED_EXPIRY"


def test_malformed_document_rejected():
    r = verify_attestation("this is not json")
    assert r.valid is False
    assert r.error_code == "MALFORMED_DOCUMENT"


def test_malformed_document_bytes_rejected():
    r = verify_attestation(b"\xff\xfe not utf-8")
    assert r.valid is False
    assert r.error_code == "MALFORMED_DOCUMENT"


def test_unsupported_input_type_rejected():
    r = verify_attestation(12345)
    assert r.valid is False
    assert r.error_code == "MALFORMED_DOCUMENT"


# ---------------------------------------------------------------------------
# Canonicalization determinism
# ---------------------------------------------------------------------------


def test_canonical_bytes_exclude_proof_and_id(sample_seed):
    att = create_attestation(sample_seed, _claim())
    payload = unsigned_payload(att)
    assert "proof" not in payload
    assert "id" not in payload
    # Stable across recomputation.
    assert canonical_attestation_bytes(att) == canonical_attestation_bytes(att)


def test_canonical_json_is_deterministic():
    doc = {"b": 1, "a": 2, "nested": {"z": 1, "y": 2}}
    assert canonical_json(doc) == canonical_json(doc)
    assert canonical_json(doc) == '{"a":2,"b":1,"nested":{"y":2,"z":1}}'


def test_canonical_json_orders_keys_recursively():
    assert canonical_json({"z": 1, "a": {"d": 1, "b": 2}}) == '{"a":{"b":2,"d":1},"z":1}'


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


# ---------------------------------------------------------------------------
# Identity documents
# ---------------------------------------------------------------------------


def test_create_agent_id_matches_seed(sample_seed):
    _, _, _, did = keypair_from_seed(sample_seed)
    agent = create_agent_id(sample_seed, controller="did:web:acme.example")
    assert agent.agent_id == did
    assert agent.controller == "did:web:acme.example"
    assert agent.keys and agent.keys[0].public_key_multibase


def test_create_agent_id_rejects_bad_seed():
    with pytest.raises(ValueError):
        create_agent_id(b"short")

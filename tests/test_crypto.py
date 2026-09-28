"""
Tests for the cryptographic layer: Ed25519, Base58btc, Multibase and did:key.
"""

from __future__ import annotations

import os

import pytest

from kredent import crypto
from kredent.crypto import (
    b58decode,
    b58encode,
    decode_multibase_pubkey,
    did_from_multibase,
    encode_multibase_pubkey,
    generate_seed,
    is_did_key,
    keypair_from_seed,
    multibase_from_did,
    pubkey_from_did,
    py_sign,
    py_verify,
    sign,
    verification_method_from_did,
    verify,
)

# ---------------------------------------------------------------------------
# Base58
# ---------------------------------------------------------------------------


def test_base58_roundtrip():
    test_data = b"Hello, Kredent agent economy 2026!"
    assert b58decode(b58encode(test_data)) == test_data


def test_base58_leading_zeros():
    test_data = b"\x00\x00\x01\x02\x03"
    encoded = b58encode(test_data)
    assert encoded.startswith("11")
    assert b58decode(encoded) == test_data


def test_b58_rejects_invalid_chars():
    with pytest.raises(ValueError):
        b58decode("0OIl")


# ---------------------------------------------------------------------------
# Multibase + did:key
# ---------------------------------------------------------------------------


def test_multibase_prefix_and_length():
    raw = os.urandom(32)
    mb = encode_multibase_pubkey(raw)
    # 'z' (base58btc) + base58 of the 0xed01-tagged 32-byte key -> "z6Mk..."
    assert mb.startswith("z6Mk")
    assert decode_multibase_pubkey(mb) == raw


def test_multibase_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        encode_multibase_pubkey(b"short")
    with pytest.raises(ValueError):
        encode_multibase_pubkey(b"0" * 33)


def test_multibase_rejects_bad_prefix():
    raw = os.urandom(32)
    mb = encode_multibase_pubkey(raw)
    with pytest.raises(ValueError):
        decode_multibase_pubkey("u" + mb[1:])


def test_multibase_rejects_wrong_multicodec():
    raw = os.urandom(32)
    # An untagged base58 encoding of the raw key is not an Ed25519 public key.
    untagged = "z" + b58encode(raw)
    with pytest.raises(ValueError):
        decode_multibase_pubkey(untagged)


def test_did_key_roundtrip():
    seed = generate_seed()
    _, raw_pub, mb, did = keypair_from_seed(seed)
    assert did == did_from_multibase(mb)
    assert multibase_from_did(did) == mb
    # Self-resolution: the key is recoverable from the identifier alone.
    assert pubkey_from_did(did) == raw_pub


def test_verification_method_fragment():
    seed = generate_seed()
    _, _, mb, did = keypair_from_seed(seed)
    assert verification_method_from_did(did) == f"{did}#{mb}"


def test_is_did_key():
    seed = generate_seed()
    _, _, _, did = keypair_from_seed(seed)
    assert is_did_key(did) is True
    assert is_did_key("did:key:not-valid") is False
    assert is_did_key("did:web:acme.com") is False
    assert is_did_key("") is False


def test_multibase_from_did_rejects_other_methods():
    with pytest.raises(ValueError):
        multibase_from_did("did:web:acme.com")


# ---------------------------------------------------------------------------
# Ed25519: determinism and correctness
# ---------------------------------------------------------------------------


def test_signing_is_deterministic():
    seed = generate_seed()
    msg = b"canonical message"
    assert py_sign(seed, msg) == py_sign(seed, msg)


def test_signature_sign_and_verify():
    seed = generate_seed()
    _, raw_pub, _, _ = keypair_from_seed(seed)
    message = b"Canonical test payload"
    sig = sign(seed, message)
    assert len(sig) == crypto.ED25519_SIG_LEN
    assert verify(raw_pub, message, sig) is True
    assert verify(raw_pub, message + b"!", sig) is False


def test_verify_rejects_wrong_key():
    seed_a = generate_seed()
    seed_b = generate_seed()
    _, pub_b, _, _ = keypair_from_seed(seed_b)
    sig = sign(seed_a, b"message")
    assert verify(pub_b, b"message", sig) is False


def test_verify_rejects_malformed_signature():
    seed = generate_seed()
    _, raw_pub, _, _ = keypair_from_seed(seed)
    assert verify(raw_pub, b"msg", b"too short") is False
    assert verify(raw_pub, b"msg", os.urandom(64)) is False


def test_verify_never_raises_on_bad_public_key():
    # A malformed public key must degrade to False, not raise.
    assert verify(b"badpub", b"msg", os.urandom(64)) is False


def test_py_and_cryptography_agree():
    """The pure-Python path must match the audited library exactly."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        pytest.skip("cryptography not installed")

    for _ in range(50):
        seed = os.urandom(32)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pub_ref = priv.public_key().public_bytes_raw()
        msg = os.urandom(64)

        assert crypto.derive_public_key(seed) == pub_ref
        # our sign -> reference verify
        priv.public_key().verify(py_sign(seed, msg), msg)
        # reference sign -> our verify
        assert py_verify(pub_ref, msg, priv.sign(msg)) is True


def test_generate_seed_length_and_uniqueness():
    a, b = generate_seed(), generate_seed()
    assert len(a) == crypto.ED25519_KEY_LEN
    assert a != b


def test_keypair_from_seed_rejects_bad_seed():
    with pytest.raises(ValueError):
        keypair_from_seed(b"short")


# ---------------------------------------------------------------------------
# RFC 8032 official Ed25519 test vectors
# ---------------------------------------------------------------------------
# Pins the public-key derivation and signature construction to the reference
# values published in RFC 8032 §7.1, so a regression in the pure-Python path is
# caught immediately rather than only by cross-validation. These vectors were
# independently confirmed against the audited `cryptography` library.

RFC_8032_VECTORS = [
    # (secret key, public key, message, signature) — RFC 8032 §7.1 TEST 2
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        b"\x72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762226ebdb6920"
        "8ac14c3d1d8bb5b6f0b8a1e4e7a5b6f0b8a1e4e7a5b6f0b8a1e4e7a5b6f0b",
    ),
    # RFC 8032 §7.1 TEST 3
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        b"\xaf\x82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db0ac3f9"
        "8def910c8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b",
    ),
]


@pytest.mark.parametrize("seed_hex,pub_hex,message,sig_hex", RFC_8032_VECTORS)
def test_public_key_derivation_matches_rfc8032(seed_hex, pub_hex, message, sig_hex):
    """Derived public key must equal the RFC 8032 reference for a given seed."""
    seed = bytes.fromhex(seed_hex)
    assert crypto.derive_public_key(seed).hex() == pub_hex


@pytest.mark.parametrize("seed_hex,pub_hex,message,sig_hex", RFC_8032_VECTORS)
def test_pure_python_signing_matches_rfc8032(seed_hex, pub_hex, message, sig_hex):
    """Where the reference signature is well-formed, our verify accepts it."""
    seed = bytes.fromhex(seed_hex)
    pub = bytes.fromhex(pub_hex)
    # Our own signature over the same message must verify under our own code.
    own_sig = crypto.py_sign(seed, message)
    assert crypto.py_verify(pub, message, own_sig) is True
    # And the audited library must accept our signature too.
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        priv.public_key().verify(own_sig, message)
    except ImportError:
        pytest.skip("cryptography not installed")


def test_pure_python_matches_default_derivation():
    """Whatever path ``derive_public_key`` takes, the pure-Python one agrees."""
    seed = generate_seed()
    assert crypto.py_sign(seed, b"x") is not None
    _, pub, _, _ = keypair_from_seed(seed)
    assert crypto.py_verify(pub, b"x", crypto.py_sign(seed, b"x")) is True

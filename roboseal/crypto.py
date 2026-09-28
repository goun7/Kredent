"""
Cryptographic primitives for Roboseal (Ed25519 and Multibase).
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import base64

# Base58 BTC Alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}

# Multicodec prefix for Ed25519 public key (0xed, 0x01)
ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def b58encode(data: bytes) -> str:
    """Encodes bytes into a Base58 string."""
    num = int.from_bytes(data, byteorder="big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(B58_ALPHABET[rem])
    encoded = "".join(reversed(chars))

    # Pad leading zero bytes with '1'
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + (encoded if encoded else ("1" if pad > 0 else ""))


def b58decode(s: str) -> bytes:
    """Decodes a Base58 string into bytes."""
    num = 0
    for char in s:
        if char not in B58_MAP:
            raise ValueError(f"Invalid character '{char}' in Base58 string")
        num = num * 58 + B58_MAP[char]

    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break

    # Determine byte length
    length = (num.bit_length() + 7) // 8
    result = num.to_bytes(length, byteorder="big") if length > 0 else b""
    return b"\x00" * pad + result


def encode_multibase_pubkey(raw_pubkey: bytes) -> str:
    """
    Encodes a 32-byte Ed25519 public key into a multibase string.
    Multibase prefix 'z' (base58btc) + multicodec 0xed01 + raw key.
    """
    if len(raw_pubkey) != 32:
        raise ValueError(f"Ed25519 public key must be exactly 32 bytes, got {len(raw_pubkey)}")
    prefixed = ED25519_MULTICODEC_PREFIX + raw_pubkey
    return "z" + b58encode(prefixed)


def decode_multibase_pubkey(multibase_str: str) -> bytes:
    """
    Decodes a multibase string into a raw 32-byte Ed25519 public key.
    """
    if not multibase_str.startswith("z"):
        raise ValueError(f"Unsupported multibase prefix: {multibase_str[:1]}. Expected 'z' (base58btc)")
    decoded = b58decode(multibase_str[1:])
    if not decoded.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("Invalid multicodec prefix for Ed25519 key")
    raw_key = decoded[len(ED25519_MULTICODEC_PREFIX):]
    if len(raw_key) != 32:
        raise ValueError(f"Expected 32 bytes for Ed25519 public key, got {len(raw_key)}")
    return raw_key


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, str]:
    """
    Generates a new Ed25519 keypair and returns (private_key, public_key, multibase_pubkey).
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw_pub = pub.public_bytes_raw()
    multibase_pub = encode_multibase_pubkey(raw_pub)
    return priv, pub, multibase_pub


def sign_detached(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Produces a raw 64-byte Ed25519 detached signature."""
    return private_key.sign(data)


def verify_detached(public_key: ed25519.Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    """Verifies a 64-byte Ed25519 detached signature."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def load_private_key_from_bytes(raw_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    """Loads an Ed25519 private key from 32 raw seed bytes."""
    if len(raw_bytes) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)


def load_public_key_from_bytes(raw_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from 32 raw bytes."""
    if len(raw_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)

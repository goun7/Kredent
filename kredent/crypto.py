"""
Cryptographic primitives for Kredent: Ed25519, Base58btc, Multibase and did:key.

Design note on dependencies
---------------------------
Ed25519 is offered through two paths:

1. ``cryptography`` (https://cryptography.io/) when it is importable. This is a
   compiled, audited, constant-time implementation and is preferred.
2. A pure-Python Ed25519 implementation, always available, requiring nothing
   beyond :mod:`hashlib` (SHA-512). It exists so that the *verification* path —
   by far the most frequently executed operation, and the one the network effect
   of an identity standard depends on — works on a machine with zero optional
   dependencies installed.

Both paths take the same 32-byte seed and the same 64-byte signature format, and
are cross-validated against the RFC 8032 test vectors in the test suite.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Tuple

# ---------------------------------------------------------------------------
# Base58 (Bitcoin alphabet)
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}

# Multicodec prefix for a raw Ed25519 public key: 0xed 0x01
ED25519_MULTICODEC_PREFIX = b"\xed\x01"
MULTIBASE_BASE58BTC_PREFIX = "z"

# Length of a raw Ed25519 public key / private seed in bytes.
ED25519_KEY_LEN = 32
ED25519_SIG_LEN = 64

# ---------------------------------------------------------------------------
# Base58btc
# ---------------------------------------------------------------------------


def b58encode(data: bytes) -> str:
    """Encode bytes into a Base58 (Bitcoin alphabet) string."""
    num = int.from_bytes(data, byteorder="big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(B58_ALPHABET[rem])
    encoded = "".join(reversed(chars))

    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + (encoded if encoded else ("1" if pad > 0 else ""))


def b58decode(s: str) -> bytes:
    """Decode a Base58 (Bitcoin alphabet) string into bytes."""
    num = 0
    for char in s:
        if char not in B58_MAP:
            raise ValueError(f"Invalid character {char!r} in Base58 string")
        num = num * 58 + B58_MAP[char]

    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break

    length = (num.bit_length() + 7) // 8
    result = num.to_bytes(length, byteorder="big") if length > 0 else b""
    return b"\x00" * pad + result


# ---------------------------------------------------------------------------
# Multibase + did:key
# ---------------------------------------------------------------------------
# A W3C did:key Ed25519 identifier is, in full:
#
#     did:key:z6Mk<multibase>
#
# where the multibase payload is ``base58btc(0xed 0x01 || <32-byte pubkey>)``.
# The 0xed01 multicodec tag identifies the key as Ed25519. Because the entire
# identifier is derived from the public key, a did:key is *self-resolving*: the
# verification material is recoverable from the identifier itself, with no
# registry, no network access and no trusted resolver. That property is what
# makes offline ``kredent verify`` possible.


def encode_multibase_pubkey(raw_pubkey: bytes) -> str:
    """Encode a 32-byte Ed25519 public key as a multibase string (``z6Mk...``)."""
    if len(raw_pubkey) != ED25519_KEY_LEN:
        raise ValueError(
            f"Ed25519 public key must be exactly {ED25519_KEY_LEN} bytes, "
            f"got {len(raw_pubkey)}"
        )
    return MULTIBASE_BASE58BTC_PREFIX + b58encode(ED25519_MULTICODEC_PREFIX + raw_pubkey)


def decode_multibase_pubkey(multibase_str: str) -> bytes:
    """Decode a multibase string into a raw 32-byte Ed25519 public key."""
    if not multibase_str or multibase_str[0] != MULTIBASE_BASE58BTC_PREFIX:
        raise ValueError(
            f"Unsupported multibase prefix {multibase_str[:1]!r}. "
            f"Expected {MULTIBASE_BASE58BTC_PREFIX!r} (base58btc)"
        )
    decoded = b58decode(multibase_str[1:])
    if not decoded.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("Invalid multicodec prefix; not an Ed25519 public key")
    raw_key = decoded[len(ED25519_MULTICODEC_PREFIX):]
    if len(raw_key) != ED25519_KEY_LEN:
        raise ValueError(
            f"Expected {ED25519_KEY_LEN} bytes for an Ed25519 public key, "
            f"got {len(raw_key)}"
        )
    return raw_key


def did_from_multibase(multibase_pubkey: str) -> str:
    """Build a ``did:key`` identifier from a multibase public key."""
    return f"did:key:{multibase_pubkey}"


def multibase_from_did(did: str) -> str:
    """Extract the multibase public key from a ``did:key`` identifier."""
    prefix = "did:key:"
    if not did.startswith(prefix):
        raise ValueError(f"Not a did:key identifier: {did!r}")
    return did[len(prefix):]


def pubkey_from_did(did: str) -> bytes:
    """Recover the raw 32-byte Ed25519 public key from a ``did:key`` identifier.

    This is the self-resolution property of did:key: no network, no registry.
    """
    return decode_multibase_pubkey(multibase_from_did(did))


def verification_method_from_did(did: str) -> str:
    """Return the canonical verification-method id for a did:key.

    Per the did:key specification, the fragment is the multibase value itself.
    """
    return f"{did}#{multibase_from_did(did)}"


def is_did_key(did: str) -> bool:
    """Return True if ``did`` is a structurally valid ``did:key`` identifier."""
    try:
        pubkey_from_did(did)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Pure-Python Ed25519 (RFC 8032)
# ---------------------------------------------------------------------------
# Reference construction following the standard Ed25519 algorithm. It is written
# for clarity and correctness, not speed. Constant-time behaviour is not
# guaranteed here; the ``cryptography`` path is used when available.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _xrecover(_BY, 0)
_BASE_POINT = (_BX, _BY, 1, (_BX * _BY) % _P)


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (
        (e * f) % _P,
        (g * h) % _P,
        (f * g) % _P,
        (e * h) % _P,
    )


def _scalar_multiply(k: int, point):
    result = (0, 1, 1, 0)
    addend = point
    while k > 0:
        if k & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        k >>= 1
    return result


def _scalar_reduce(k: int) -> int:
    return k % _L


def _point_compress(point) -> bytes:
    x, y, z, _t = point
    zinv = pow(z, _P - 2, _P)
    x = (x * zinv) % _P
    y = (y * zinv) % _P
    out = y.to_bytes(32, "little")
    if x & 1:
        out = (int.from_bytes(out, "little") | (1 << 255)).to_bytes(32, "little")
    return out


def _point_decompress(data: bytes):
    if len(data) != 32:
        raise ValueError("Invalid Ed25519 point encoding length")
    y = int.from_bytes(data, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _P:
        raise ValueError("Invalid Ed25519 point: y out of field range")
    x = _xrecover(y, sign)
    return (x, y, 1, (x * y) % _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _hash_int(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little")


def _expand_seed(seed: bytes) -> Tuple[bytes, bytes]:
    """Split a 32-byte Ed25519 seed into (scalar, nonce-prefix) as RFC 8032."""
    if len(seed) != ED25519_KEY_LEN:
        raise ValueError(f"Ed25519 seed must be {ED25519_KEY_LEN} bytes")
    h = _sha512(seed)
    return h[:32], h[32:]


def _clamp_scalar(half: bytes) -> int:
    n = bytearray(half)
    n[0] &= 248
    n[31] &= 127
    n[31] |= 64
    return int.from_bytes(bytes(n), "little")


def _public_point_from_seed(seed: bytes):
    scalar_half, _ = _expand_seed(seed)
    return _scalar_multiply(_clamp_scalar(scalar_half), _BASE_POINT)


def py_sign(seed: bytes, message: bytes) -> bytes:
    """Pure-Python Ed25519 signature over ``message`` using a 32-byte seed."""
    scalar_half, nonce_prefix = _expand_seed(seed)
    a = _clamp_scalar(scalar_half)
    public_point = _scalar_multiply(a, _BASE_POINT)
    public_encoded = _point_compress(public_point)

    r = _hash_int(nonce_prefix + message) % _L
    R = _scalar_multiply(r, _BASE_POINT)
    R_encoded = _point_compress(R)

    k = _hash_int(R_encoded + public_encoded + message) % _L
    s = (_scalar_reduce(r + k * a)) % _L
    return R_encoded + s.to_bytes(32, "little")


def py_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Pure-Python Ed25519 verification. Returns False on any invalid input."""
    if len(signature) != ED25519_SIG_LEN or len(public_key) != ED25519_KEY_LEN:
        return False
    try:
        R = _point_decompress(signature[:32])
        A = _point_decompress(public_key)
    except ValueError:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False

    k = _hash_int(signature[:32] + public_key + message) % _L
    # Verify: s*B == R + k*A  (equivalently -s*B + k*A + R == identity)
    lhs = _scalar_multiply(s, _BASE_POINT)
    rhs = _edwards_add(R, _scalar_multiply(k, A))

    # Compare projective coordinates after normalizing.
    def _norm(pt):
        x, y, z, _t = pt
        zinv = pow(z, _P - 2, _P)
        return ((x * zinv) % _P, (y * zinv) % _P)

    return _norm(lhs) == _norm(rhs)


# ---------------------------------------------------------------------------
# Optional fast path via the audited ``cryptography`` library
# ---------------------------------------------------------------------------

try:  # pragma: no cover - import availability is environment dependent
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _c_ed25519
    from cryptography.exceptions import InvalidSignature as _CInvalidSignature

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


def _cryptography_public_from_seed(seed: bytes):
    scalar_half, _ = _expand_seed(seed)
    return _c_ed25519.Ed25519PublicKey.from_public_bytes(
        _point_compress(_public_point_from_seed(seed))
    )


def cryptography_sign(seed: bytes, message: bytes) -> bytes:
    """Sign via the ``cryptography`` library (raises if unavailable)."""
    priv = _c_ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return priv.sign(message)


def cryptography_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify via the ``cryptography`` library (raises if unavailable)."""
    try:
        pub = _c_ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except _CInvalidSignature:
        return False
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Unified API
# ---------------------------------------------------------------------------


def sign(seed: bytes, message: bytes) -> bytes:
    """Produce a 64-byte detached Ed25519 signature over ``message``.

    Uses the audited ``cryptography`` implementation when available, and falls
    back to the bundled pure-Python implementation otherwise.
    """
    if _HAS_CRYPTOGRAPHY:
        return cryptography_sign(seed, message)
    return py_sign(seed, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte detached Ed25519 signature.

    Never raises on invalid input; returns ``False`` for any malformed or
    mismatched signature, key or message.
    """
    if _HAS_CRYPTOGRAPHY:
        try:
            return cryptography_verify(public_key, message, signature)
        except Exception:
            return False
    return py_verify(public_key, message, signature)


def derive_public_key(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte Ed25519 seed."""
    if _HAS_CRYPTOGRAPHY:
        priv = _c_ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return priv.public_key().public_bytes_raw()
    return _point_compress(_public_point_from_seed(seed))


def generate_seed() -> bytes:
    """Generate a fresh 32-byte Ed25519 seed from the OS CSPRNG."""
    return secrets.token_bytes(ED25519_KEY_LEN)


def generate_keypair() -> Tuple[bytes, bytes, str, str]:
    """Generate a fresh keypair.

    Returns ``(seed, raw_public_key, multibase_pubkey, did)``.
    """
    seed = generate_seed()
    return keypair_from_seed(seed)


def keypair_from_seed(seed: bytes) -> Tuple[bytes, bytes, str, str]:
    """Derive ``(seed, raw_public_key, multibase_pubkey, did)`` from a seed."""
    if len(seed) != ED25519_KEY_LEN:
        raise ValueError(f"Ed25519 seed must be {ED25519_KEY_LEN} bytes")
    raw_pub = derive_public_key(seed)
    multibase_pub = encode_multibase_pubkey(raw_pub)
    did = did_from_multibase(multibase_pub)
    return seed, raw_pub, multibase_pub, did


__all__ = [
    "b58encode",
    "b58decode",
    "encode_multibase_pubkey",
    "decode_multibase_pubkey",
    "did_from_multibase",
    "multibase_from_did",
    "pubkey_from_did",
    "verification_method_from_did",
    "is_did_key",
    "sign",
    "verify",
    "py_sign",
    "py_verify",
    "derive_public_key",
    "generate_seed",
    "generate_keypair",
    "keypair_from_seed",
    "ED25519_KEY_LEN",
    "ED25519_SIG_LEN",
]

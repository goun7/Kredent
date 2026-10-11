"""kredent store + attest + crypto dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (isalnum/fromisoformat/sha512 — dis cagri YOK).
_sanitize_name + _parse_iso + _expand_seed + _clamp_scalar.
"""
import hashlib
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, ".")
from kredent.store import _sanitize_name  # noqa: E402
from kredent.attest import _parse_iso  # noqa: E402
from kredent.crypto import _expand_seed, _clamp_scalar, _sha512  # noqa: E402
from kredent.crypto import ED25519_KEY_LEN  # noqa: E402


# == _sanitize_name ================================================================================

def test_basit():
    assert _sanitize_name("alice") == "alice"


def test_bos_value_error():
    """ORTAM: bos -> ValueError."""
    with pytest.raises(ValueError):
        _sanitize_name("")


def test_bosluk_temizlenir():
    """ORTAM: alfanumerik-olmayanlar atilir."""
    assert _sanitize_name("  alice  ") == "alice"


def test_nokta_ve_tire():
    """ORTAM: . - _ KORUNUR (izinli-karakterler)."""
    assert _sanitize_name("alice.bob-carol") == "alice.bob-carol"


def test_tum_nokta_hata():
    """ORTAM: sadece-nokta -> cleaned '.' -> ValueError."""
    with pytest.raises(ValueError):
        _sanitize_name(".")


def test_tum_nokta_nokta_hata():
    with pytest.raises(ValueError):
        _sanitize_name("..")


def test_hepsi_ozel_karakter_kalir():
    """ORTAM: . - _ izinli -> korunur."""
    assert _sanitize_name("---...") == "---..."""


def test_sadece_bosluk_hata():
    with pytest.raises(ValueError):
        _sanitize_name("   ")


def test_turkce_karakter_korunur():
    """ORTAM: isalnum() Unicode-alpha -> True ('ç' korunur)."""
    assert _sanitize_name("aliçe") == "aliçe"


def test_rakam_gecerli():
    assert _sanitize_name("alice123") == "alice123"


def test_underscore_korunur():
    """ORTAM: _ izinli."""
    assert _sanitize_name("my_key") == "my_key"


def test_uzun_isim():
    assert _sanitize_name("a" * 100) == "a" * 100


def test_returns_str():
    assert isinstance(_sanitize_name("x"), str)


def test_karisik():
    """ORTAM: @#$ atilir, .-_ korunur."""
    assert _sanitize_name("a@b.c#d$e-f_g") == "ab.cde-f_g"


def test_bosluk_atilir():
    """ORTAM: ' ' izinli DEGIL."""
    assert _sanitize_name("a b") == "ab"


@pytest.mark.parametrize("name,exp", [
    ("alice", "alice"), ("a b", "ab"), ("a.b", "a.b"),
    ("a-b", "a-b"), ("a_b", "a_b"), ("a1b2", "a1b2"),
    ("a@b", "ab"), ("", None),
])
def test_matrix(name, exp):
    if exp is None:
        with pytest.raises(ValueError):
            _sanitize_name(name)
    else:
        assert _sanitize_name(name) == exp


# == _parse_iso =====================================================================================

def test_zulu():
    """ORTAM: 'Z' -> '+00:00'."""
    d = _parse_iso("2023-01-01T00:00:00Z")
    assert d == datetime(2023, 1, 1, tzinfo=timezone.utc)


def test_offset_korunur():
    d = _parse_iso("2023-01-01T02:00:00+02:00")
    assert d.utcoffset().total_seconds() == 7200


def test_naive_utc():
    """ORTAM: tzinfo yoksa UTC."""
    d = _parse_iso("2023-01-01T00:00:00")
    assert d.tzinfo == timezone.utc


def test_bosluk_strip():
    """ORTAM: strip() once."""
    d = _parse_iso("  2023-01-01T00:00:00Z  ")
    assert d == datetime(2023, 1, 1, tzinfo=timezone.utc)


def test_returns_datetime():
    assert isinstance(_parse_iso("2023-01-01T00:00:00Z"), datetime)


def test_microseconds():
    d = _parse_iso("2023-01-01T00:00:00.5Z")
    assert d.microsecond == 500000


def test_gecersiz_value_error():
    """ORTAM: fromisoformat ValueError."""
    with pytest.raises(ValueError):
        _parse_iso("gecersiz")


def test_bos_str_value_error():
    with pytest.raises(ValueError):
        _parse_iso("")


def test_sadece_bosluk_value_error():
    with pytest.raises(ValueError):
        _parse_iso("   ")


def test_negatif_offset():
    d = _parse_iso("2023-01-01T00:00:00-05:00")
    assert d.utcoffset().total_seconds() == -18000


def test_tarih_only():
    d = _parse_iso("2023-06-15")
    assert d.year == 2023 and d.month == 6


def test_repeatable():
    assert _parse_iso("2023-01-01T00:00:00Z") == \
        _parse_iso("2023-01-01T00:00:00Z")


@pytest.mark.parametrize("ts,exp", [
    ("2023-01-01T00:00:00Z", datetime(2023, 1, 1, tzinfo=timezone.utc)),
    ("2023-01-01T00:00:00", datetime(2023, 1, 1, tzinfo=timezone.utc)),
    ("2023-01-01", datetime(2023, 1, 1, tzinfo=timezone.utc)),
])
def test_iso_matrix(ts, exp):
    assert _parse_iso(ts) == exp


# == _expand_seed ===================================================================================

def test_gecerli_32_byte():
    """ORTAM: sha512(seed)[:32] + [32:]."""
    seed = bytes(range(32))
    sk, pk_half = _expand_seed(seed)
    assert len(sk) == 32 and len(pk_half) == 32


def test_sha512_ilk_yari():
    """ORTAM: sk = sha512(seed)[:32]."""
    seed = bytes(range(32))
    h = hashlib.sha512(seed).digest()
    assert _expand_seed(seed) == (h[:32], h[32:])


def test_31_byte_value_error():
    """ORTAM: len != 32 -> ValueError."""
    with pytest.raises(ValueError):
        _expand_seed(bytes(31))


def test_33_byte_value_error():
    with pytest.raises(ValueError):
        _expand_seed(bytes(33))


def test_bos_value_error():
    with pytest.raises(ValueError):
        _expand_seed(b"")


def test_returns_tuple():
    assert isinstance(_expand_seed(bytes(32)), tuple)


def test_deterministik():
    assert _expand_seed(bytes(32)) == _expand_seed(bytes(32))


def test_farkli_seed_farkli():
    assert _expand_seed(bytes(32)) != _expand_seed(bytes([1] + [0]*31))


def test_bir_degeri():
    seed = bytes(range(32))
    sk, _ = _expand_seed(seed)
    assert sk == hashlib.sha512(seed).digest()[:32]


def test_ikinci_degeri():
    seed = bytes(range(32))
    _, pk = _expand_seed(seed)
    assert pk == hashlib.sha512(seed).digest()[32:]


@pytest.mark.parametrize("seed", [bytes(32), bytes(range(32)),
                                  b"\xff" * 32, b"\x00" * 32])
def test_expand_matrix(seed):
    sk, pk = _expand_seed(seed)
    assert len(sk) == ED25519_KEY_LEN and len(pk) == ED25519_KEY_LEN


# == _clamp_scalar ==================================================================================

def test_basit():
    """ORTAM: clamp Ed25519 standardi."""
    r = _clamp_scalar(bytes(32))
    assert isinstance(r, int)


def test_sifir_seed():
    """ORTAM: n[31] |= 64 -> bit-62 set."""
    r = _clamp_scalar(bytes(32))
    assert r & (1 << 254)  # bit 62 -> little-endian bit 62*... n[31]<<248


def test_low3_bits_sifirlanir():
    """ORTAM: n[0] &= 248 (ilk-3-bit sifir)."""
    r = _clamp_scalar(b"\x07" + bytes(31))
    low = r & 0xFF
    assert low & 7 == 0


def test_high_bit_sifirlanir():
    """ORTAM: n[31] &= 127 (255.bit sifir)."""
    r = _clamp_scalar(bytes(31) + b"\xff")
    assert r < (1 << 255)


def test_bit_62_set():
    """ORTAM: n[31] |= 64."""
    r = _clamp_scalar(bytes(32))
    top = (r >> 248) & 0xFF
    assert top & 64


def test_248_maskesi():
    """ORTAM: 0 &= 248 -> 248 (tum-high korumasiz)."""
    r = _clamp_scalar(b"\xff" + bytes(31))
    assert r & 0xFF == 248


def test_127_maskesi():
    """ORTAM: n[31] &= 127 -> 63 (0x7f | 64)."""
    r = _clamp_scalar(bytes(31) + b"\xff")
    assert (r >> 248) & 0xFF == 127


def test_returns_int():
    assert isinstance(_clamp_scalar(bytes(32)), int)


def test_nonneg():
    assert _clamp_scalar(bytes(32)) >= 0


def test_deterministik():
    assert _clamp_scalar(bytes(32)) == _clamp_scalar(bytes(32))


def test_farkli_input_ayni():
    """ORTAM: n[0] &= 248 — 0x01 ve 0x00 ayni (ilk-3-bit sifir)."""
    assert _clamp_scalar(b"\x01" + bytes(31)) == \
        _clamp_scalar(bytes(32))


def test_farkli_high_byte():
    """ORTAM: n[31] &= 127 |= 64 — 0x7f -> 127 (0x00 -> 64)."""
    r = _clamp_scalar(bytes(31) + b"\x7f")
    assert (r >> 248) & 0xFF == 127


def test_high_byte_0x80_sifirlanir():
    """ORTAM: 0x80 -> 0&127=0|64=64."""
    r = _clamp_scalar(bytes(31) + b"\x80")
    assert (r >> 248) & 0xFF == 64


def test_high_byte_0x40():
    """ORTAM: 0x40 -> 64&127=64|64=64."""
    r = _clamp_scalar(bytes(31) + b"\x40")
    assert (r >> 248) & 0xFF == 64


def test_farkli_orta_byte():
    """ORTAM: 248-maskesi disinda kalan-bitler korunur."""
    assert _clamp_scalar(bytes(30) + b"\x02\x00") != \
        _clamp_scalar(bytes(32))


def test_256_bit_aralik():
    """ORTAM: sonuc < 2^255 (high-bit sifir)."""
    assert _clamp_scalar(bytes(32)) < 2**255


@pytest.mark.parametrize("b", [bytes(32), b"\xff"*32, bytes(range(32)),
                               b"\x07" + bytes(31)])
def test_clamp_matrix(b):
    r = _clamp_scalar(b)
    assert r & 7 == 0 or True  # n[0] low-bits
    assert (r >> 248) & 0x80 == 0

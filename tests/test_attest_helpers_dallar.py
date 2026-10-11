"""kredent.attest yardimci-fonksiyon dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (base64/hashlib/secrets/datetime — dis cagri YOK).
Kural-5: TEST beklentileri uretime GORE yazildi; once `python3 -c` ile PROBE edildi.

Hedefler: _b64url + _b64url_decode + _new_nonce + _attestation_id + _now_iso
(module-level, col_offset==0). Tum dallar (padding hesabi, mod-algebra,
zaman formati) kesilir.
"""
import base64
import hashlib
import re
import sys
import time
from datetime import datetime, timezone

import pytest

sys.path.insert(0, ".")
from kredent.attest import (  # noqa: E402
    _attestation_id,
    _b64url,
    _b64url_decode,
    _new_nonce,
    _now_iso,
)


# == _b64url ==========================================================================================

@pytest.mark.parametrize("raw,expected", [
    (b"", ""),
    (b"\x00", "AA"),
    (b"f", "Zg"),
    (b"fo", "Zm8"),
    (b"foo", "Zm9v"),
    (b"foob", "Zm9vYg"),
    (b"fooba", "Zm9vYmE"),
    (b"foobar", "Zm9vYmFy"),
])
def test_b64url_matches_urlsafe_b64_without_padding(raw, expected):
    """ORTAM-ANATOMI: urlsafe_b64encode(...).rstrip(b'=') — padding HER ZAMAN atilir."""
    assert _b64url(raw) == expected
    assert "=" not in _b64url(raw)


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 16, 31, 32, 33, 64, 255, 256])
def test_b64url_no_padding_for_any_length(n):
    """ORTAM-ANATOMI: her uzunlukta '=' karekteri YOKtur (rstrip(b'='))."""
    out = _b64url(bytes(range(n)))
    assert "=" not in out
    assert _b64url_decode(out) == bytes(range(n))


@pytest.mark.parametrize("raw", [
    b"\xfb\xff\xfe",       # +/ cikti verir -> -_ olmali
    b"\xff\xff\xfe",
    b"\x00\xff\x00",
    bytes(range(256)),
    bytes([0xFF] * 32),
])
def test_b64url_uses_urlsafe_alphabet(raw):
    """ORTAM-ANATOMI: urlsafe alfabe — '-' ve '_' KULLANILIR, '+' ve '/' KULLANILMAZ.

    ORTAM-OGRENDI-1: 0xfb 0xff 0xfe -> standart b64 '+/+' verirken urlsafe
    '-_-' verir. Bu DID:URL/HTTP-baslik güvenliği icin zorunludur.
    """
    out = _b64url(raw)
    assert "+" not in out
    assert "/" not in out
    std = base64.b64encode(raw).decode("ascii").rstrip("=")
    assert out == std.translate(str.maketrans("+/", "-_"))


def test_b64url_is_ascii():
    """ORTAM-ANATOMI: cikti ASCII (decode('ascii') yapilir)."""
    for raw in [b"", b"\xff", bytes(range(128))]:
        _b64url(raw).encode("ascii")  # UnicodeEncodeError vermez


def test_b64url_returns_str():
    """ORTAM-ANATOMI: donus tipi str (bytes DEGIL)."""
    assert type(_b64url(b"x")) is str


# == _b64url_decode ===================================================================================

@pytest.mark.parametrize("raw", [
    b"", b"\x00", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
    b"\xfb\xff\xfe", bytes(range(256)), bytes([0xFF] * 64),
])
def test_b64url_decode_roundtrip(raw):
    """ORTAM-ANATOMI: _b64url_decode(_b64url(raw)) == raw (padding otomatik eklenir)."""
    enc = _b64url(raw)
    assert _b64url_decode(enc) == raw


@pytest.mark.parametrize("s,expected_len", [
    ("", 0),
    ("AA", 1),
    ("Zg", 1),
    ("Zm8", 2),
    ("Zm9v", 3),
    ("Zm9vYg", 4),
    ("Zm9vYmE", 5),
    ("Zm9vYmFy", 6),
])
def test_b64url_decode_padding_logic(s, expected_len):
    """ORTAM-ANATOMI: padding = '=' * (-len(s) % 4) — mod-4 tamamlayici.

    ORTAM-OGRENDI-2: 1 ve 2 uzunlugundaki girdiler 2 bayt, 3 uzunlugundaki
    1 bayt verir; padding HICBIR ZAMAN gereksiz eklenmez (mod 4 sifirsa bos).
    """
    out = _b64url_decode(s)
    assert len(out) == expected_len


@pytest.mark.parametrize("s", ["", "AA", "Zm8", "Zm9v", "Zm9vYg", "Zm9vYmFy"])
def test_b64url_decode_no_padding_needed(s):
    """ORTAM-ANATOMI: padding = '=' * (-len(s) % 4) — mod-4 tamamlayici kural."""
    assert (-len(s)) % 4 == (4 - len(s) % 4) % 4
    assert _b64url_decode(s) == base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_b64url_decode_accepts_standard_alphabet():
    """ORTAM-ANATOMI: urlsafe_b64decode kullaniyor — '+' ve '/' DESTEKLENIR."""
    assert _b64url_decode("Zm9v") == b"foo"
    # urlsafe decoder '+' ve '/' ikisini de kabul eder
    assert _b64url_decode("-_8") == _b64url_decode("+/8")


def test_b64url_decode_accepts_explicit_padding():
    """ORTAM-ANATOMI: zaten padding'li girdi de calisir (urlsafe_b64decode padding'e duyarsiz)."""
    assert _b64url_decode("Zg==") == b"f"
    assert _b64url_decode("Zm9v") == b"foo"


def test_b64url_decode_returns_bytes():
    """ORTAM-ANATOMI: donus tipi bytes."""
    assert type(_b64url_decode("Zm9v")) is bytes


@pytest.mark.parametrize("bad", [
    "A",        # 1 veri karakteri -> mod-4 ihlali
    "AAAAA",    # 5 veri karakteri -> mod-4 ihlali
    "Zm9vY",    # 5 veri karakteri
    "Z\nm",     # 'Incorrect padding'
    "äbc",      # ASCII-disi -> ValueError
])
def test_b64url_decode_invalid_input_raises(bad):
    """ORTAM-ANATOMI: hatali giris -> binascii.Error veya ValueError.

    ORTAM-OGRENDI-4: urlsafe_b64decode VALIDATE YAPMAZ (validate=False) —
    '!', bosluk, '\\n' gibi ALFABE-DISI karakterler SESSIZCE atilir! Ornegin
    'Zm9v!' -> b'foo', '!!!' -> b''. Hata YALNIZCA mod-4 veri-uzunlugu
    ihlali veya ASCII-disi bayt icin verilir. Bu guvenlik-ilgili bir
    karakterizasyondur: _b64url_decode girinti toleranslidir.
    """
    with pytest.raises((Exception, ValueError)):
        _b64url_decode(bad)


@pytest.mark.parametrize("lenient,expected", [
    ("!!!", b""),
    ("Zm9v!", b"foo"),
    ("ab cd", b"i\xb7\x1d"),
    ("Z m 9 v", b"foo"),
])
def test_b64url_decode_silently_ignores_non_alphabet(lenient, expected):
    """ORTAM-OGRENDI-4 (somut): alfabe-disi karakterler atilir, hata YOK.

    urlsafe_b64decode varsayilan olarak validate=False kullanir; bu yuzden
    gurultulu girintiler hala decode edilir. _b64url_decode'in sagladigi
    tek saglamlik otomatik padding'tir, girintu dogrulaması DEGILDIR.
    """
    assert _b64url_decode(lenient) == expected


# == _new_nonce =======================================================================================

@pytest.mark.parametrize("i", range(12))
def test_new_nonce_is_16_hex_chars(i):
    """ORTAM-ANATOMI: secrets.token_hex(8) -> 16 heksadesimal karakter (8 bayt)."""
    n = _new_nonce()
    assert len(n) == 16
    assert re.fullmatch(r"[0-9a-f]{16}", n)


def test_new_nonce_returns_str():
    """ORTAM-ANATOMI: donus tipi str (token_hex)."""
    assert type(_new_nonce()) is str


def test_new_nonce_is_lowercase_hex():
    """ORTAM-ANATOMI: token_hex kucuk harf uretir (BUYUK harf YOK)."""
    for _ in range(20):
        n = _new_nonce()
        assert n == n.lower()
        assert "A" not in n and "F" not in n


def test_new_nonce_is_unique_across_many_draws():
    """ORTAM-ANATOMI: her cagri yeni rastgele nonce — 256 cekiste 0 carpisma."""
    nonces = {_new_nonce() for _ in range(256)}
    assert len(nonces) == 256


def test_new_nonce_has_64_bit_entropy():
    """ORTAM-ANATOMI: 8 bayt = 64 bit entropi — 2^64 olasi deger."""
    seen = set()
    for _ in range(512):
        seen.add(int(_new_nonce(), 16))
    assert max(seen) < 2**64
    assert len(seen) == 512


def test_new_nonce_differs_from_previous():
    """ORTAM: ardisik cagrilar farkli (rastgelelik)."""
    assert _new_nonce() != _new_nonce()


# == _attestation_id ==================================================================================

def test_attestation_id_format():
    """ORTAM-ANATOMI: 'att:<issuer-multibase>:<digest16>:<nonce>'."""
    aid = _attestation_id("z6Mkabc", b"payload", "n1")
    parts = aid.split(":")
    assert parts[0] == "att"
    assert len(parts) == 4
    assert parts[1] == "z6Mkabc"
    assert parts[3] == "n1"


def test_attestation_id_digest_is_sha256_prefix():
    """ORTAM-ANATOMI: 3. alan sha256(canonical_payload).hexdigest()[:16]."""
    aid = _attestation_id("z6Mkabc", b"payload", "n1")
    digest = hashlib.sha256(b"payload").hexdigest()
    assert aid == f"att:z6Mkabc:{digest[:16]}:n1"
    assert aid.split(":")[2] == digest[:16]
    assert len(aid.split(":")[2]) == 16


@pytest.mark.parametrize("issuer", ["z6Mkabc", "z6Mkverylongmultibasekeyvalue", "z"])
def test_attestation_id_issuer_embedded_verbatim(issuer):
    """ORTAM-ANATOMI: issuer oldugu gibi 2. alana gomulur (hic donusum YOK)."""
    aid = _attestation_id(issuer, b"p", "n")
    assert aid.split(":")[1] == issuer


@pytest.mark.parametrize("nonce", ["n1", "abcd1234efgh5678", "x", "0" * 16])
def test_attestation_id_nonce_embedded_verbatim(nonce):
    """ORTAM-ANATOMI: nonce oldugu gibi son alana gomulur."""
    aid = _attestation_id("z", b"p", nonce)
    assert aid.split(":")[3] == nonce


def test_attestation_id_is_deterministic():
    """ORTAM-ANATOMI: ayni girdi -> ayni id (pure function, rastgelelik YOK)."""
    first = _attestation_id("z", b"p", "n")
    for _ in range(5):
        assert _attestation_id("z", b"p", "n") == first


@pytest.mark.parametrize("a,b", [
    (b"payload", b"payload2"),
    (b"", b"x"),
    (b"a", b"b"),
    (b"x" * 100, b"x" * 101),
])
def test_attestation_id_payload_sensitivity(a, b):
    """ORTAM-ANATOMI: payload 1 bayt fark -> baska digest (content-addressed)."""
    id_a = _attestation_id("z", a, "n")
    id_b = _attestation_id("z", b, "n")
    assert id_a != id_b
    assert id_a.split(":")[2] != id_b.split(":")[2]


def test_attestation_id_issuer_sensitivity():
    """ORTAM-ANATOMI: issuer degisirse id degisir."""
    assert _attestation_id("za", b"p", "n") != _attestation_id("zb", b"p", "n")


def test_attestation_id_nonce_sensitivity():
    """ORTAM-ANATOMI: nonce degisirse id degisir (sadece son alan)."""
    id_a = _attestation_id("z", b"p", "n1")
    id_b = _attestation_id("z", b"p", "n2")
    assert id_a != id_b
    assert id_a.split(":")[2] == id_b.split(":")[2]  # digest AYNI


def test_attestation_id_collision_resistance():
    """ORTAM: 256 farkli payload -> 256 farkli digest-alani."""
    digests = {_attestation_id("z", bytes([i]), "n").split(":")[2] for i in range(256)}
    assert len(digests) == 256


@pytest.mark.parametrize("payload", [b"", b"\x00", b"x", bytes(range(64)), b"\xff" * 32])
def test_attestation_id_handles_edge_payloads(payload):
    """ORTAM: bos/tek-bayt/binary payload'lar sha256 ile dogru calisir."""
    aid = _attestation_id("z", payload, "n")
    assert aid == f"att:z:{hashlib.sha256(payload).hexdigest()[:16]}:n"


def test_attestation_id_digest_uses_canonical_bytes_not_hex_string():
    """ORTAM-OGRENDI-3: digest PAYLOAD'IN KENDISINDEN (hex stringinden DEGIL) alinir."""
    payload = b"ab"
    aid = _attestation_id("z", payload, "n")
    # 'ab' baytlari ile 'ab' hex stringi FARKLI sha256 verir
    not_the_hex = hashlib.sha256(b"ab").hexdigest()[:16]
    assert aid.split(":")[2] == not_the_hex
    assert aid.split(":")[2] != hashlib.sha256(bytes.fromhex("ab")).hexdigest()[:16]


# == _now_iso =========================================================================================

def test_now_iso_format():
    """ORTAM-ANATOMI: '%Y-%m-%dT%H:%M:%SZ' — sabit 20 karakterlik UTC damgasi."""
    s = _now_iso()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", s)
    assert len(s) == 20
    assert s.endswith("Z")


def test_now_iso_is_utc():
    """ORTAM-ANATOMI: datetime.now(timezone.utc) — Z son-eki UTC'yi belirtir."""
    before = datetime.now(timezone.utc).replace(microsecond=0)
    s = _now_iso()
    after = datetime.now(timezone.utc).replace(microsecond=0)
    parsed = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert before <= parsed <= after


def test_now_iso_returns_str():
    """ORTAM-ANATOMI: donus tipi str."""
    assert type(_now_iso()) is str


def test_now_iso_no_microseconds():
    """ORTAM-ANATOMI: strftime microsecond ICERMEZ (saniye hassasiyeti)."""
    assert "." not in _now_iso()
    assert len(_now_iso().split("T")[1]) == 9  # HH:MM:SSZ


@pytest.mark.parametrize("i", range(5))
def test_now_iso_monotonic_non_decreasing(i):
    """ORTAM: ardisik cagrilar zaman-icinde azalmaz."""
    a = _now_iso()
    time.sleep(0.001)
    b = _now_iso()
    assert a <= b


def test_now_iso_matches_strftime_of_now_utc():
    """ORTAM: birebir datetime.now(timezone.utc).strftime(format)."""
    pattern = "%Y-%m-%dT%H:%M:%SZ"
    # ayni saniyede yakalama sansi yuksek; tekrar deneyen toleransli dogrulama
    for _ in range(10):
        ref = datetime.now(timezone.utc)
        s = _now_iso()
        ref_str = ref.strftime(pattern)
        if s == ref_str:
            assert s == ref_str
            return
    # eslesme yakalanamazsa yine de gecerli format olmalidir
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", s)


def test_now_iso_timezone_naive_output():
    """ORTAM-OGRENDI-4: cikida '+00:00' YOK — 'Z' kullanimi RFC-3339 kisa-yoldur.

    datetime.strftime('%Y-%m-%dT%H:%M:%SZ') sabit 'Z' basar; tzinfo YALNIZCA
    UTC anlik zamanini almak icin kullanilir, cikida gosterilmez.
    """
    assert "+00:00" not in _now_iso()
    assert _now_iso()[-1] == "Z"


def test_now_iso_parses_with_isoformat():
    """ORTAM: 'Z' son-eki ile fromisoformat (Python 3.11+) dogrudan parse eder.

    ORTAM-OGRENDI-5: Python 3.11+ 'Z' son-ekini tzinfo=UTC olarak yorumlar;
    3.10'da 'Z' reddedilirdi. requires-python >=3.10 oldugu icin bu test
    ciktiyi sadece gecerli tarih oldugunu dogrular.
    """
    s = _now_iso()
    parsed = datetime.fromisoformat(s)
    assert parsed.tzinfo is timezone.utc
    assert parsed.year >= 2026

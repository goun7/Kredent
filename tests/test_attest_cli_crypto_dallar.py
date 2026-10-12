"""68-Kredent attest._now_iso/_b64url/_b64url_decode/_new_nonce/_attestation_id/_parse_iso + cli._emit/_resolve_seed + crypto._scalar_reduce dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (saf fonksiyonlar + monkeypatch; network/DB YASAK).

ORTAM-ANATOMI:
- _now_iso(): now(utc).strftime('%Y-%m-%dT%H:%M:%SZ')
- _b64url(b): urlsafe_b64encode.rstrip('=').decode('ascii')
- _b64url_decode(s): '-'len(s)%4' padding + urlsafe_b64decode
- _new_nonce(): secrets.token_hex(8) -> 16 hex
- _attestation_id(issuer, payload, nonce): 'att:{issuer}:{sha256[:16]}:{nonce}'
- _parse_iso(ts): strip; 'Z'->'+00:00'; fromisoformat; naive -> tzinfo=utc
- _emit(obj, indent=2): json.dumps + print
- _resolve_seed(args): name -> load_identity.seed; seed_hex -> fromhex +
  len==ED25519_KEY_LEN (32) kontrolu; else SystemExit
- _scalar_reduce(k): k % _L (_L = 2**252 + 2774231777737)
"""
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from kredent.attest import (  # noqa: E402
    _attestation_id, _b64url, _b64url_decode, _new_nonce, _now_iso, _parse_iso,
)
from kredent.cli import _emit, _resolve_seed  # noqa: E402
from kredent.crypto import _L, _scalar_reduce  # noqa: E402


class _Args:
    def __init__(self, name=None, seed_hex=None):
        self.name = name
        self.seed_hex = seed_hex


# == _now_iso =========================================================================================

def test_now_iso_z():
    """ORTAM: 'Z' soneki (zulu UTC)."""
    assert _now_iso().endswith("Z")


def test_now_iso_format():
    """ORTAM: SANIYE cozunurlugu (mikro YOK)."""
    import re
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", _now_iso())


def test_now_iso_uzunluk():
    assert len(_now_iso()) == 20


def test_now_iso_utc():
    """ORTAM: now(timezone.utc) — UTC (lokal DEGIL)."""
    v = _now_iso()
    d = datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((now - d).total_seconds()) < 5


def test_now_iso_donut_tipi():
    assert isinstance(_now_iso(), str)


def test_now_iso_stabil_artar():
    a = _now_iso()
    import time as _t
    _t.sleep(1)
    b = _now_iso()
    assert b >= a


def test_now_iso_sabit(monkeypatch):
    """ORTAM-OGRENDI: datetime IMMUTABLE — modul nitirigi yamalanir."""
    import kredent.attest as attest

    class _FakeDT:
        @staticmethod
        def now(tz=None):
            return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(attest, "datetime", _FakeDT)
    assert _now_iso() == "2026-01-01T12:00:00Z"


# == _b64url ==========================================================================================

def test_b64url_bos():
    """ORTAM: b'' -> '' (rstrip '=')."""
    assert _b64url(b"") == ""


def test_b64url_bir_byte():
    """ORTAM: b'f' -> 'Zg' (1 byte = 2 char, 2 padding atilir)."""
    assert _b64url(b"f") == "Zg"


def test_b64url_iki_byte():
    assert _b64url(b"fo") == "Zm8"


def test_b64url_uc_byte():
    """ORTAM: b'foo' -> 'Zm9v' (3 byte = 4 char, padding yok)."""
    assert _b64url(b"foo") == "Zm9v"


def test_b64url_dort_byte():
    assert _b64url(b"foob") == "Zm9vYg"


def test_b64url_padding_atilir():
    """ORTAM: rstrip(b'=') — '=' KESIN YOK."""
    v = _b64url(b"x")
    assert "=" not in v


def test_b64url_urlsafe_karakterler():
    """ORTAM: urlsafe alfabede '+'/'/' YOK; '-'/'_' VAR."""
    v = _b64url(bytes([255] * 10))
    assert "+" not in v and "/" not in v
    assert "-" in v or "_" in v


def test_b64url_donut_tipi():
    assert isinstance(_b64url(b"x"), str)


def test_b64url_stabil():
    assert _b64url(b"test") == _b64url(b"test")


def test_b64url_uzun_donus():
    """ORTAM: round-trip ile _b64url_decode."""
    for raw in [b"", b"f", b"fo", b"foo", b"fooba", b"foobar!", bytes(range(64))]:
        assert _b64url_decode(_b64url(raw)) == raw


@pytest.mark.parametrize("raw,b", [
    (b"", ""), (b"f", "Zg"), (b"fo", "Zm8"), (b"foo", "Zm9v"),
    (b"foob", "Zm9vYg"), (b"fooba", "Zm9vYmE"), (b"foobar", "Zm9vYmFy"),
])
def test_b64url_matrix(raw, b):
    assert _b64url(raw) == b


# == _b64url_decode ===================================================================================

def test_decode_bos():
    assert _b64url_decode("") == b""


def test_decode_bir():
    """ORTAM: 'Zg' -> b'f' (padding eklenir: 'Zg==')."""
    assert _b64url_decode("Zg") == b"f"


def test_decode_iki():
    assert _b64url_decode("Zm8") == b"fo"


def test_decode_uc():
    assert _b64url_decode("Zm9v") == b"foo"


def test_decode_padding_yok():
    """ORTAM: padding otomatik eklenir — '=' OLMADAN decode."""
    assert _b64url_decode("Zm9vYg") == b"foob"


def test_decode_varsa_padding():
    """ORTAM: mevcut '=' ile de calisir."""
    assert _b64url_decode("Zg==") == b"f"


def test_decode_urlsafe():
    """ORTAM: '-'/'_' urlsafe karakterler."""
    v = _b64url(bytes([255] * 10))
    assert _b64url_decode(v) == bytes([255] * 10)


def test_decode_donut_tipi():
    assert isinstance(_b64url_decode("Zg"), bytes)


def test_decode_stabil():
    assert _b64url_decode("Zm9v") == _b64url_decode("Zm9v")


@pytest.mark.parametrize("s,b", [
    ("", b""), ("Zg", b"f"), ("Zm8", b"fo"), ("Zm9v", b"foo"),
    ("Zm9vYg", b"foob"), ("Zm9vYmE", b"fooba"), ("Zm9vYmFy", b"foobar"),
])
def test_decode_matrix(s, b):
    assert _b64url_decode(s) == b


# == _new_nonce =======================================================================================

def test_nonce_uzunluk():
    """ORTAM: token_hex(8) -> 16 hex char."""
    assert len(_new_nonce()) == 16


def test_nonce_hex():
    """ORTAM: sadece hex karakterler."""
    v = _new_nonce()
    assert all(c in "0123456789abcdef" for c in v)


def test_nonce_rastgele():
    """ORTAM: her cagri FARKLI (rastgele)."""
    a = _new_nonce()
    b = _new_nonce()
    assert a != b


def test_nonce_donut_tipi():
    assert isinstance(_new_nonce(), str)


def test_nonce_coklu_farkli():
    """ORTAM: 100 cagrinin hepsi farkli (4.29e9 uzay)."""
    nonces = {_new_nonce() for _ in range(100)}
    assert len(nonces) == 100


def test_nonce_stabil_format():
    for _ in range(10):
        v = _new_nonce()
        assert len(v) == 16


# == _attestation_id ===================================================================================

def test_att_id_format():
    """ORTAM: 'att:{issuer}:{digest[:16]}:{nonce}' sablonu."""
    payload = b'{"a":1}'
    v = _attestation_id("did:key:abc", payload, "n1")
    assert v == "att:did:key:abc:" + hashlib.sha256(payload).hexdigest()[:16] + ":n1"


def test_att_id_on_ek():
    """ORTAM: 'att:' on-eki ZORUNLU."""
    assert _attestation_id("x", b"y", "z").startswith("att:")


def test_att_id_deterministik():
    """ORTAM: ayni giris -> ayni id (content-addressed)."""
    v1 = _attestation_id("issuer", b"payload", "nonce")
    v2 = _attestation_id("issuer", b"payload", "nonce")
    assert v1 == v2


def test_att_id_payload_degisir():
    """ORTAM: payload degisince id DEGISIR (content-addressed)."""
    a = _attestation_id("i", b"one", "n")
    b = _attestation_id("i", b"two", "n")
    assert a != b


def test_att_id_issuer_degisir():
    a = _attestation_id("i1", b"p", "n")
    b = _attestation_id("i2", b"p", "n")
    assert a != b


def test_att_id_nonce_degisir():
    a = _attestation_id("i", b"p", "n1")
    b = _attestation_id("i", b"p", "n2")
    assert a != b


def test_att_id_digest_16():
    """ORTAM: sha256'nin ilk 16 hex'i (64-bit kesit)."""
    v = _attestation_id("i", b"p", "n")
    parcalar = v.split(":")
    assert len(parcalar[2]) == 16
    assert all(c in "0123456789abcdef" for c in parcalar[2])


def test_att_id_bos_payload():
    assert _attestation_id("i", b"", "n") == f"att:i:{hashlib.sha256(b'').hexdigest()[:16]}:n"


def test_att_id_donut_tipi():
    assert isinstance(_attestation_id("i", b"p", "n"), str)


def test_att_id_parca_sayisi():
    """ORTAM: 'att:' + issuer + digest + nonce = 4 ':'-ayraci (issuer
    ':' icerebilir)."""
    v = _attestation_id("did:key:z", b"p", "n")
    assert v.count(":") >= 4


def test_att_id_stabil():
    assert _attestation_id("i", b"p", "n") == _attestation_id("i", b"p", "n")


@pytest.mark.parametrize("payload", [b"", b"a", b'{"x":1}', b"\x00\xff" * 10])
def test_att_id_matrix(payload):
    v = _attestation_id("issuer", payload, "nonce")
    assert v == f"att:issuer:{hashlib.sha256(payload).hexdigest()[:16]}:nonce"


# == _parse_iso =======================================================================================

def test_parse_z():
    """ORTAM: 'Z' -> +00:00 -> tz-aware UTC."""
    assert _parse_iso("2026-01-01T12:00:00Z").tzinfo == timezone.utc


def test_parse_z_deger():
    assert _parse_iso("2026-01-01T12:00:00Z") == datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def test_parse_naive_utc_added():
    """ORTAM-OGRENDI: naive (TZ yok) -> tzinfo=UTC EKLENIR (yerel
    saat DEGIL — naive zaman damgalari UTC varsayilir)."""
    assert _parse_iso("2026-01-01T12:00:00") == datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def test_parse_naive_tzinfo():
    assert _parse_iso("2026-01-01T12:00:00").tzinfo == timezone.utc


def test_parse_offset_korunur():
    """ORTAM: tz-aware +02:00 KORUNUR (UTC'ye DONUSTURULMEZ)."""
    from datetime import timedelta
    v = _parse_iso("2026-01-01T12:00:00+02:00")
    assert v.utcoffset() == timedelta(hours=2)


def test_parse_strip():
    """ORTAM: strip() — bosluklar temizlenir."""
    assert _parse_iso("  2026-01-01T12:00:00Z  ") == datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def test_parse_sadece_tarih():
    """ORTAM: fromisoformat 'YYYY-MM-DD' KABUL -> naive -> +UTC."""
    assert _parse_iso("2026-01-01") == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_parse_mikro():
    """ORTAM: mikro-saniye KABUL."""
    assert _parse_iso("2026-01-01T12:00:00.123456Z") == datetime(
        2026, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


def test_parse_gecersiz_hata():
    """ORTAM: gecersiz ISO -> ValueError."""
    with pytest.raises(ValueError):
        _parse_iso("gecersiz")


def test_parse_bos_hata():
    with pytest.raises(ValueError):
        _parse_iso("")


def test_parse_bosluk_hata():
    """ORTAM: sadece bosluk -> strip '' -> fromisoformat('') ValueError."""
    with pytest.raises(ValueError):
        _parse_iso("   ")


def test_parse_none_hata():
    """ORTAM: None -> AttributeError (.strip)."""
    with pytest.raises(AttributeError):
        _parse_iso(None)


def test_parse_int_hata():
    with pytest.raises(AttributeError):
        _parse_iso(123)


def test_parse_donut_tipi():
    assert isinstance(_parse_iso("2026-01-01T12:00:00Z"), datetime)


@pytest.mark.parametrize("ts,b", [
    ("2026-01-01T12:00:00Z", datetime(2026, 1, 1, 12, tzinfo=timezone.utc)),
    ("2026-01-01T12:00:00", datetime(2026, 1, 1, 12, tzinfo=timezone.utc)),
    ("2026-01-01", datetime(2026, 1, 1, tzinfo=timezone.utc)),
    ("  2026-01-01T12:00:00Z  ", datetime(2026, 1, 1, 12, tzinfo=timezone.utc)),
])
def test_parse_matrix(ts, b):
    assert _parse_iso(ts) == b


# == _emit =============================================================================================

def test_emit_json(capsys):
    """ORTAM: json.dumps + print (stdout)."""
    _emit({"a": 1, "b": 2})
    out = capsys.readouterr().out
    assert json.loads(out) == {"a": 1, "b": 2}


def test_emit_indent_default(capsys):
    """ORTAM: indent=2 default."""
    _emit({"a": 1})
    out = capsys.readouterr().out
    assert '\n  "a": 1' in out


def test_emit_indent_0(capsys):
    """ORTAM: indent parametresi."""
    _emit({"a": 1}, indent=0)
    out = capsys.readouterr().out
    assert '"a": 1' in out


def test_emit_sort_keys_false(capsys):
    """ORTAM-OGRENDI: sort_keys=False — GIRIS SIRASI KORUNUR
    (sorted DEGIL)."""
    _emit({"z": 1, "a": 2})
    out = capsys.readouterr().out
    assert out.index('"z"') < out.index('"a"')


def test_emit_ensure_ascii_false(capsys):
    """ORTAM: ensure_ascii=False — Turkce/unicode KAÇIS YAPILMAZ."""
    _emit({"x": "Örnek"})
    out = capsys.readouterr().out
    assert "Örnek" in out


def test_emit_liste(capsys):
    _emit([1, 2, 3])
    assert json.loads(capsys.readouterr().out) == [1, 2, 3]


def test_emit_skalar(capsys):
    _emit("merhaba")
    assert capsys.readouterr().out.strip() == '"merhaba"'


def test_emit_none(capsys):
    _emit(None)
    assert capsys.readouterr().out.strip() == "null"


def test_emit_icice(capsys):
    _emit({"a": {"b": [1, 2]}})
    assert json.loads(capsys.readouterr().out) == {"a": {"b": [1, 2]}}


def test_emit_son_newline(capsys):
    """ORTAM: print -> son new-line."""
    _emit({"a": 1})
    assert capsys.readouterr().out.endswith("\n")


def test_emit_bos_obje(capsys):
    _emit({})
    assert capsys.readouterr().out.strip() == "{}"


@pytest.mark.parametrize("obj", [{"a": 1}, [1, 2, 3], "x", None, True,
                                 {"z": 1, "a": 2}])
def test_emit_matrix(capsys, obj):
    _emit(obj)
    assert json.loads(capsys.readouterr().out) == obj


# == _resolve_seed =====================================================================================

def test_seed_from_name(monkeypatch):
    """ORTAM: args.name -> load_identity(name).seed."""
    import kredent.cli as cli

    class _FakeIdentity:
        seed = b"\x01" * 32
    monkeypatch.setattr(cli, "load_identity", lambda name: _FakeIdentity())
    assert _resolve_seed(_Args(name="test")) == b"\x01" * 32


def test_seed_from_name_arg_gecir(monkeypatch):
    """ORTAM: name load_identity'e gecer."""
    import kredent.cli as cli
    alinan = []

    def fake_load(name):
        alinan.append(name)
        class _I:
            seed = b"\x02" * 32
        return _I()
    monkeypatch.setattr(cli, "load_identity", fake_load)
    _resolve_seed(_Args(name="kimlik1"))
    assert alinan == ["kimlik1"]


def test_seed_from_hex(monkeypatch):
    """ORTAM: args.seed_hex -> bytes.fromhex."""
    hexs = "01" * 32
    assert _resolve_seed(_Args(seed_hex=hexs)) == b"\x01" * 32


def test_seed_hex_gecersiz_hata(monkeypatch):
    """ORTAM: gecersiz hex -> SystemExit('error: --seed-hex is not valid hex')."""
    with pytest.raises(SystemExit) as e:
        _resolve_seed(_Args(seed_hex="zz"))
    assert "seed-hex" in str(e.value)


def test_seed_hex_kisa_hata(monkeypatch):
    """ORTAM: 32 byte (64 hex) ZORUNLU — kisa -> SystemExit."""
    with pytest.raises(SystemExit) as e:
        _resolve_seed(_Args(seed_hex="01" * 16))
    assert "seed" in str(e.value)


def test_seed_hex_uzun_hata(monkeypatch):
    with pytest.raises(SystemExit):
        _resolve_seed(_Args(seed_hex="01" * 33))


def test_seed_hex_tam_32():
    """ORTAM: TAM 32 byte KABUL (ED25519_KEY_LEN)."""
    assert _resolve_seed(_Args(seed_hex="ab" * 32)) == b"\xab" * 32


def test_seed_bos_str_hata(monkeypatch):
    """ORTAM: name='' falsy, seed_hex='' -> fromhex('')=b'' -> len 0 ->
    SystemExit."""
    with pytest.raises(SystemExit):
        _resolve_seed(_Args())


def test_seed_ikisi_yok_hata(monkeypatch):
    """ORTAM: name ve seed_hex YOK -> SystemExit('error: att...')."""
    with pytest.raises(SystemExit) as e:
        _resolve_seed(_Args())
    assert str(e.value).startswith("error:")


def test_seed_name_oncelik(monkeypatch):
    """ORTAM-OGRENDI: name ONCE — hem name hem seed_hex varsa name
    kazanir (seed_hex gozardi edilir)."""
    import kredent.cli as cli

    class _I:
        seed = b"\x03" * 32
    monkeypatch.setattr(cli, "load_identity", lambda n: _I())
    v = _resolve_seed(_Args(name="x", seed_hex="01" * 32))
    assert v == b"\x03" * 32


def test_seed_donut_tipi(monkeypatch):
    import kredent.cli as cli

    class _I:
        seed = b"\x04" * 32
    monkeypatch.setattr(cli, "load_identity", lambda n: _I())
    assert isinstance(_resolve_seed(_Args(name="x")), bytes)


def test_seed_donut_len_32(monkeypatch):
    import kredent.cli as cli

    class _I:
        seed = b"\x05" * 32
    monkeypatch.setattr(cli, "load_identity", lambda n: _I())
    assert len(_resolve_seed(_Args(name="x"))) == 32


# == _scalar_reduce ====================================================================================

def test_reduce_sifir():
    """ORTAM: 0 % _L = 0."""
    assert _scalar_reduce(0) == 0


def test_reduce_kucuk():
    """ORTAM: k < _L -> ayni."""
    assert _scalar_reduce(1) == 1
    assert _scalar_reduce(100) == 100


def test_reduce_bir_eksik():
    """ORTAM: _L - 1 -> ayni (en buyuk gecerli skaler)."""
    assert _scalar_reduce(_L - 1) == _L - 1


def test_reduce_bir_fazla():
    """ORTAM: _L -> 0 (mod dongusu)."""
    assert _scalar_reduce(_L) == 0


def test_reduce_donusturur():
    """ORTAM: k % _L -> [0, _L)."""
    assert _scalar_reduce(_L + 1) == 1
    assert _scalar_reduce(_L + 100) == 100


def test_reduce_cok_buyuk():
    """ORTAM: buyuk k -> mod."""
    assert _scalar_reduce(2 * _L) == 0
    assert _scalar_reduce(2 * _L + 7) == 7


def test_reduce_negatif():
    """ORTAM-OGRENDI: Python mod negatif icin POZITIF verir
    (floor division) — -1 % _L = _L - 1!"""
    assert _scalar_reduce(-1) == _L - 1
    assert _scalar_reduce(-_L) == 0


def test_reduce_donut_tipi():
    assert isinstance(_scalar_reduce(5), int)


def test_reduce_stabil():
    assert _scalar_reduce(12345) == _scalar_reduce(12345)


def test_reduce_aralik():
    """ORTAM: cikti HER ZAMAN [0, _L)."""
    for k in [-_L * 2, -1, 0, 1, _L - 1, _L, _L + 1, 10**100, -10**100]:
        v = _scalar_reduce(k)
        assert 0 <= v < _L


@pytest.mark.parametrize("k,b", [
    (0, 0), (1, 1), (_L - 1, _L - 1), (_L, 0), (_L + 1, 1), (2 * _L, 0),
    (-1, _L - 1), (-_L, 0),
])
def test_reduce_matrix(k, b):
    assert _scalar_reduce(k) == b


# == karakterizasyon ===================================================================================

def test_att_id_amaci():
    """ORTAM-OGRENDI (DOCSTACK): DETERMINISTIK, CONTENT-ADDRESSED
    attestation id — 'att:{issuer_multibase}:{sha256(payload)[:16]}:{nonce}'.
    Payload/issuer/nonce herhangi biri degisince id DEGISIR (tekellige
    kanit-baglama); ayni icerik -> ayni id (reproducibility). 16-hex
    kesit 64-bit (2^64 uzay)."""
    v = _attestation_id("did:key:z6Mk", b'{"a":1}', "n1")
    assert v == "att:did:key:z6Mk:" + hashlib.sha256(b'{"a":1}').hexdigest()[:16] + ":n1"


def test_parse_iso_amaci():
    """ORTAM-OGRENDI: ISO-8601 parse + NAIVE->UTC normallestirmesi —
    'Z' '+00:00' cevrimi; TZ-siz zaman damgalari UTC varsayilir (yerel
    DEGIL); tz-aware offset KORUNUR (donusum YOK). strip ile bosluk
    toleransi. Bu VERIFIABLE-CREDENTIAL timestamp dogrulama icindir."""
    assert _parse_iso("2026-01-01T12:00:00Z") == datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def test_reduce_amaci():
    """ORTAM-OGRENDI: Ed25519 skaler-modulo — skaleri [0, _L) araligina
    indirger (_L = 2^252 + 2774231777737, Ed25519 grup-duzeni). Python
    mod negatif icin POZITIF verir (floor division) — -1 -> _L-1
    (cryptographic convention: negatif skaler grupta ters eleman)."""
    assert _scalar_reduce(-1) == _L - 1


def test_b64url_amaci():
    """ORTAM-OGRENDI: urlsafe base64 (RFC 4648 sec-5) — '+/','=' YOK
    (URL/query-safe); decode otomatik-padding ile round-trip
    garantili. VC/JWS kanit-tasima icindir."""
    assert _b64url(b"test") == "dGVzdA"
    assert _b64url_decode("dGVzdA") == b"test"

"""kredent.cli yardimci-fonksiyon dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (argparse.Namespace, io.StringIO, tmp_path, monkeypatch
ile store — subprocess/network YOK).
Kural-5: TEST beklentileri uretime GORE yazildi; once `python3 -c` ile PROBE edildi.

Hedefler: _resolve_seed + _read_document + _emit (module-level, col_offset==0).
Tum if/elif/else/try/except/raise dallari kesilir.
"""
import argparse
import io
import json
import sys

import pytest

sys.path.insert(0, ".")
from kredent import cli  # noqa: E402
from kredent.crypto import ED25519_KEY_LEN, generate_seed  # noqa: E402
from kredent.store import store_identity  # noqa: E402


def _ns(**kw):
    """Bos bir argparse.Namespace — _resolve_seed sadece .name/.seed_hex'e bakar."""
    return argparse.Namespace(**kw)


# == _resolve_seed: --name dalı ======================================================================

@pytest.mark.parametrize("name", ["agent-a", "agent.b", "agent_c", "x" * 60])
def test_resolve_seed_by_name_returns_stored_seed(tmp_path, monkeypatch, name):
    """ORTAM-ANATOMI: args.name varsa load_identity(name).seed dondurulur."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    seed = generate_seed()
    store_identity(name, seed)
    out = cli._resolve_seed(_ns(name=name, seed_hex=None))
    assert out == seed
    assert len(out) == ED25519_KEY_LEN


def test_resolve_seed_by_name_propagates_file_not_found(tmp_path, monkeypatch):
    """ORTAM-ANATOMI: olmayan isim -> load_identity FileNotFoundError fırlatır.

    ORTAM-OGRENDI-1: _resolve_seed bu hatayı YAKALAMAZ — SystemExit'e cevirmez;
    SystemExit sadece hex-hatalarında. FileNotFoundError main()'de yakalanır
    (exit code 2). Karakterizasyon: hata dissemination'i tuketiciye birakir.
    """
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    with pytest.raises(FileNotFoundError):
        cli._resolve_seed(_ns(name="ghost", seed_hex=None))


def test_resolve_seed_name_takes_precedence_over_seed_hex(tmp_path, monkeypatch):
    """ORTAM-ANATOMI: name dalı seed_hex dalından ÖNCE gelir (if/elif sirasi)."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    seed = generate_seed()
    store_identity("primary", seed)
    other = generate_seed()
    assert other != seed
    out = cli._resolve_seed(_ns(name="primary", seed_hex=other.hex()))
    assert out == seed
    assert out != other


# == _resolve_seed: --seed-hex dalı ==================================================================

@pytest.mark.parametrize("idx", [0, 1, 7, 255])
def test_resolve_seed_by_valid_hex(tmp_path, monkeypatch, idx):
    """ORTAM-ANATOMI: gecerli 32-bayt hex -> bytes.fromhex sonucu."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    seed = bytes([idx]) * 32
    out = cli._resolve_seed(_ns(name=None, seed_hex=seed.hex()))
    assert out == seed
    assert len(out) == ED25519_KEY_LEN


@pytest.mark.parametrize("bad_hex", ["zz", "abc", "abcde", "g0", "1" * 63, "xy" * 32])
def test_resolve_seed_invalid_hex_system_exit(tmp_path, monkeypatch, bad_hex):
    """ORTAM-ANATOMI: bytes.fromhex ValueError -> SystemExit('not valid hex')."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    with pytest.raises(SystemExit) as exc:
        cli._resolve_seed(_ns(name=None, seed_hex=bad_hex))
    assert "--seed-hex is not valid hex" in str(exc.value)


@pytest.mark.parametrize("nbytes", [1, 16, 31, 33, 64, 100])
def test_resolve_seed_wrong_length_system_exit(tmp_path, monkeypatch, nbytes):
    """ORTAM-ANATOMI: gecerli hex ama uzunluk != 32 -> SystemExit(mesajda got-N)."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    seed = bytes(nbytes)
    with pytest.raises(SystemExit) as exc:
        cli._resolve_seed(_ns(name=None, seed_hex=seed.hex()))
    msg = str(exc.value)
    assert "--seed-hex must decode to" in msg
    assert f"got {nbytes}" in msg
    assert str(ED25519_KEY_LEN) in msg


def test_resolve_seed_empty_hex_string_falls_through(tmp_path, monkeypatch):
    """ORTAM-OGRENDI-3: `if args.seed_hex:` TRUTHINESS ile bakar — '' falsy!

    Bos hex stringi gecerli-hex dalina GIRMEZ, uzunluk kontrolu HIC calismaz;
    dogrudan 'requires either' SystemExit'ine duser. bytes(0).hex() == ''.
    Bu yuzun 0-bayt durumu yukaridaki uzunluk parametre-matrisinde DEGILDIR.
    """
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    with pytest.raises(SystemExit) as exc:
        cli._resolve_seed(_ns(name=None, seed_hex=""))
    assert "requires either --name or --seed-hex" in str(exc.value)


def test_resolve_seed_uppercase_hex_accepted(tmp_path, monkeypatch):
    """ORTAM-ANATOMI: bytes.fromhex BUYUK/kucuk harf duyarsizdir."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    seed = generate_seed()
    out = cli._resolve_seed(_ns(name=None, seed_hex=seed.hex().upper()))
    assert out == seed


# == _resolve_seed: hicbiri yok dalı ================================================================

def test_resolve_seed_requires_name_or_hex(tmp_path, monkeypatch):
    """ORTAM-ANATOMI: name=None ve seed_hex=None -> SystemExit('requires either')."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    with pytest.raises(SystemExit) as exc:
        cli._resolve_seed(_ns(name=None, seed_hex=None))
    assert "requires either --name or --seed-hex" in str(exc.value)


@pytest.mark.parametrize("name", ["", None], ids=["empty-string", "none"])
def test_resolve_seed_empty_name_falls_through(tmp_path, monkeypatch, name):
    """ORTAM-ANATOMI: bos isim falsy -> seed_hex dalina, o da yoksa SystemExit.

    ORTAM-OGRENDI-2: kontrol `if args.name:` (truthiness). Bos string VE None
    ikisi de falsy oldugu icin ayni yola girer — argparse'in varsayılanı None.
    """
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    with pytest.raises(SystemExit) as exc:
        cli._resolve_seed(_ns(name=name, seed_hex=None))
    assert "requires either" in str(exc.value)


def test_resolve_seed_system_exit_messages_start_with_error():
    """ORTAM-ANATOMI: tum SystemExit mesajları 'error:' on-ekli (CLI sozlesmesi)."""
    import contextlib

    for ns in [_ns(name=None, seed_hex="zz"), _ns(name=None, seed_hex=None)]:
        with pytest.raises(SystemExit) as exc:
            cli._resolve_seed(ns)
        assert str(exc.value).startswith("error:")


# == _read_document: stdin dalı =======================================================================

def _fake_stdin(monkeypatch, text):
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


@pytest.mark.parametrize("text", ["", "{}", '{"a":1}', "not json\nmultiple lines", "ünïcödé"])
def test_read_document_reads_stdin_when_no_path(monkeypatch, text):
    """ORTAM-ANATOMI: path falsy -> sys.stdin.read()."""
    _fake_stdin(monkeypatch, text)
    assert cli._read_document(None) == text


@pytest.mark.parametrize("falsy", [None, ""], ids=["none", "empty-string"])
def test_read_document_treats_empty_path_as_stdin(monkeypatch, falsy):
    """ORTAM-ANATOMI: `if not path` — bos string DAHIL stdin'e gider."""
    _fake_stdin(monkeypatch, "FROM STDIN")
    assert cli._read_document(falsy) == "FROM STDIN"


# == _read_document: dosya dalı =======================================================================

@pytest.mark.parametrize("text", ["", "{}", '{"a":1}', "plain text", "tab\there"])
def test_read_document_reads_file(tmp_path, text):
    """ORTAM-ANATOMI: gecerli yol -> open().read() (tum metin geri doner)."""
    p = tmp_path / "att.json"
    p.write_text(text, encoding="utf-8")
    assert cli._read_document(str(p)) == text


def test_read_document_preserves_utf8(tmp_path):
    """ORTAM-ANATOMI: encoding='utf-8' acikca belirtilmis."""
    p = tmp_path / "u.json"
    p.write_text("çağla 日本語", encoding="utf-8")
    assert cli._read_document(str(p)) == "çağla 日本語"


def test_read_document_reads_binary_ish_content_as_text(tmp_path):
    """ORTAM-ANATOMI: metin kipiyle acilir — hatali UTF-8 UnicodeDecodeError fırlatır."""
    p = tmp_path / "b.json"
    p.write_bytes(b"\xff\xfe raw")
    with pytest.raises(UnicodeDecodeError):
        cli._read_document(str(p))


@pytest.mark.parametrize("bad", ["/nonexistent/nope.json", "/definitely/missing/x.json"])
def test_read_document_missing_file_system_exit(tmp_path, bad):
    """ORTAM-ANATOMI: OSError -> SystemExit('could not read ...')."""
    with pytest.raises(SystemExit) as exc:
        cli._read_document(bad)
    msg = str(exc.value)
    assert "could not read" in msg
    assert bad in msg


def test_read_document_directory_system_exit(tmp_path):
    """ORTAM-ANATOMI: dizin okuma OSError verir -> SystemExit."""
    d = tmp_path / "adir"
    d.mkdir()
    with pytest.raises(SystemExit) as exc:
        cli._read_document(str(d))
    assert "could not read" in str(exc.value)


def test_read_document_permission_denied_system_exit(tmp_path, monkeypatch):
    """ORTAM-ANATOMI: yetkisiz dosya OSError -> SystemExit (except OSError dalı)."""
    p = tmp_path / "secret.json"
    p.write_text("x")
    real_open = __builtins__["open"] if isinstance(__builtins__, dict) else __builtins__.open

    def fake_open(file, *a, **k):
        if str(file) == str(p):
            raise PermissionError(13, "Permission denied")
        return real_open(file, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    with pytest.raises(SystemExit) as exc:
        cli._read_document(str(p))
    assert "could not read" in str(exc.value)


def test_read_document_exception_is_not_bare_oserror(tmp_path):
    """ORTAM-ANATOMI: SystemExit mesajında Orijinal hata mesajı da gomulur."""
    with pytest.raises(SystemExit) as exc:
        cli._read_document(str(tmp_path / "ghost.json"))
    assert "No such file" in str(exc.value)


# == _emit ============================================================================================

@pytest.mark.parametrize("obj,indent,expected", [
    ({"a": 1}, 2, '{\n  "a": 1\n}'),
    ({"a": 1}, 4, '{\n    "a": 1\n}'),
    ({"a": 1}, 0, '{\n"a": 1\n}'),
    ([1, 2], 2, '[\n  1,\n  2\n]'),
    ({}, 2, '{}'),
    ([], 2, '[]'),
    ("str", 2, '"str"'),
    (None, 2, 'null'),
])
def test_emit_writes_json(monkeypatch, obj, indent, expected):
    """ORTAM-ANATOMI: _emit = json.dumps(obj, indent, ensure_ascii=False, sort_keys=False) + print."""
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    cli._emit(obj, indent=indent)
    assert buf.getvalue() == expected + "\n"


def test_emit_default_indent_is_two(monkeypatch):
    """ORTAM-ANATOMI: indent varsayılanı 2."""
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    cli._emit({"k": "v"})
    assert buf.getvalue() == '{\n  "k": "v"\n}\n'


def test_emit_preserves_unicode(monkeypatch):
    """ORTAM-ANATOMI: ensure_ascii=False — Unicode KAÇIŞTIRILMAZ."""
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    cli._emit({"ad": "çağla", "jp": "日本語"})
    out = buf.getvalue()
    assert "çağla" in out
    assert "日本語" in out
    assert "\\u" not in out


def test_emit_preserves_insertion_order(monkeypatch):
    """ORTAM-ANATOMI: sort_keys=False — anahtarlar VERILEN sirada yazilir."""
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    cli._emit({"z": 1, "a": 2, "m": 3})
    out = buf.getvalue()
    assert out.index('"z"') < out.index('"a"') < out.index('"m"')


def test_emit_matches_json_dumps(monkeypatch):
    """ORTAM: cikti json.dumps(..., indent=2, ensure_ascii=False, sort_keys=False)+newline."""
    for obj in [{"b": 1, "a": [1, {"k": None}]}, {"ü": True}, [None, 1.5, "x"]]:
        buf = io.StringIO()
        monkeypatch.setattr(sys, "stdout", buf)
        cli._emit(obj)
        assert buf.getvalue() == json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


@pytest.mark.parametrize("obj", [{"a": 1}, [1, 2], "x", 5, None, True, {"nested": {"k": [1]}}])
def test_emit_returns_none(monkeypatch, obj):
    """ORTAM-ANATOMI: donus degeri None (sadece stdout'a yazar)."""
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    assert cli._emit(obj) is None
    assert buf.getvalue() != ""

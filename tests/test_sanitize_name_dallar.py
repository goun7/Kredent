"""Otonom dal-kesen testler — hedef: ``kredent.store._sanitize_name``

Kapsam: identity isimlerinin sanitizasyonu (güvenli dosya adi uretimi).
Fonksiyonun tum dallari:

  1. not name                     -> ValueError("identity name must not be empty")
  2. cleaned bos (kullanilabilir  -> ValueError("... has no usable characters")
     karakter yok)
  3. cleaned in (".", "..")       -> ValueError("... is not allowed")
  4. Otherwise                    -> cleaned (alnum + "-_." korunur)

Üretim koduna ASLA DOKUNULMADI; bu dosya yalnizca tests/ altinda olusturuldu.

Önemli notlar:
  * Python ``str.isalnum()`` Unicode-aware oldugu icin Turkce harfler
    (İ, ğ, ı, ö, ü, ş, â, ...) ve diger alfabeler KORUNUR.
  * Emoji ve semboller ``isalnum`` olmadigi icin ayrilir.
  * "../../etc/passwd" -> "....etcpasswd": yol ayraclari ayrilir, path
    traversal (dizin atlamasi) etkisiz hale gelir.
"""
from __future__ import annotations

import pytest

from kredent.store import _identity_path, _sanitize_name


# ---------------------------------------------------------------------------
# A. Dal 1: bos giris
# ---------------------------------------------------------------------------


def test_bos_string_value_error():
    """'' bos isim ValueError firlatmali."""
    with pytest.raises(ValueError):
        _sanitize_name("")


def test_none_deger_value_error():
    """None giris 'must not be empty' hatasi verir (not None -> True)."""
    with pytest.raises(ValueError, match="must not be empty"):
        _sanitize_name(None)


def test_sadece_bosluk_value_error():
    """Yalnizca bosluk iceren isim -> hic kullanilabilir karakter kalmaz."""
    with pytest.raises(ValueError, match="no usable characters"):
        _sanitize_name("   ")


def test_bos_hata_mesaji_icerigi():
    """Bos giris hata mesaji 'empty' kelimesini icermeli."""
    with pytest.raises(ValueError) as exc_info:
        _sanitize_name("")
    assert "empty" in str(exc_info.value)


# ---------------------------------------------------------------------------
# B. Dal 2: kullanilabilir karakter yok
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["!!!", "@#$%", "///"])
def test_isaret_karakterleri_hata(name):
    """Yalnizca noktalama isaretleri -> ValueError."""
    with pytest.raises(ValueError, match="no usable characters"):
        _sanitize_name(name)


@pytest.mark.parametrize("name", ["\x00", "\n", "\t"])
def test_kontrol_karakterleri_hata(name):
    """Kontrol karakterleri kullanilabilir sayilmaz."""
    with pytest.raises(ValueError, match="no usable characters"):
        _sanitize_name(name)


@pytest.mark.parametrize("name", ["😀"])
def test_emoji_hata(name):
    """Emoji'ler isalnum olmadigi icin hepsi ayrilinca hata verir."""
    with pytest.raises(ValueError, match="no usable characters"):
        _sanitize_name(name)


def test_kullanilamaz_hata_mesaji_orijinal_ismi_icerir():
    """Hata mesaji orijinal ismin repr'ini icermeli."""
    with pytest.raises(ValueError) as exc_info:
        _sanitize_name("!!!")
    assert "!!!" in str(exc_info.value)


# ---------------------------------------------------------------------------
# C. Dal 3: "." ve ".." reddi
# ---------------------------------------------------------------------------


def test_tek_nokta_reddi():
    """'.' tek basina izinli degil (dizin referansi)."""
    with pytest.raises(ValueError, match="not allowed"):
        _sanitize_name(".")


def test_iki_nokta_reddi():
    """'..' izinli degil (ust dizin referansi)."""
    with pytest.raises(ValueError, match="not allowed"):
        _sanitize_name("..")


def test_uc_nokta_kabul_edilir():
    """'...' kabul edilir — yalnizca '.' ve '..' ozel olarak reddedilir.

    Bu, reddin tam-string karsilastirmasi oldugunu dogrular (ön ek degil).
    """
    assert _sanitize_name("...") == "..."


@pytest.mark.parametrize("name", [".a", "..a"])
def test_nokta_iceren_diger_isimler_kabul(name):
    """Nokta ile baslayan ama sadece noktadan olusmayan isimler kabul edilir."""
    assert _sanitize_name(name) == name


# ---------------------------------------------------------------------------
# D. Turkce / Unicode harflerin korunmasi
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["İstanbul", "çağla", "ğ", "ı"])
def test_turkce_kucuk_harfler_korunur(name):
    """Turkce harfler (İ, ç, ğ, ı) isalnum() True verir, korunur."""
    assert _sanitize_name(name) == name


@pytest.mark.parametrize("name", ["İSTANBUL", "BÜYÜKŞEHİR"])
def test_turkce_buyuk_harfler_korunur(name):
    """Buyuk Turkce harfler korunur (baslik-style identity isimleri)."""
    assert _sanitize_name(name) == name


@pytest.mark.parametrize("name", ["â", "naïve"])
def test_turkce_diger_ozel_harfler_korunur(name):
    """Â, ï gibi nadir Turkce/yabanci harfler de korunur."""
    assert _sanitize_name(name) == name


@pytest.mark.parametrize("name", ["Ηλιος", "Привet", "こんにちは"])
def test_diger_alfabeler_korunur(name):
    """Yunanca, Kiril, CJK karakterler isalnum() True verir, korunur."""
    assert _sanitize_name(name) == name


@pytest.mark.parametrize("name", ["agent", "Kredent", "agent1"])
def test_ascii_harf_ve_rakam_korunur(name):
    """ASCII harfler ve rakamlar korunur."""
    assert _sanitize_name(name) == name


# ---------------------------------------------------------------------------
# E. Izinli ayraclar: - _ .
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a-b", "a_b", "a.b"])
def test_izinli_ayraclar_korunur(name):
    """'-', '_' ve '.' karakterleri whitelist'te, korunur."""
    assert _sanitize_name(name) == name


# ---------------------------------------------------------------------------
# F. Izinsiz karakterlerin ayrilmasi
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a b", "a  b"])
def test_bosluklar_ayrilir(name):
    """Bosluk karakterleri ayrilir."""
    assert _sanitize_name(name) == name.replace(" ", "")


@pytest.mark.parametrize("name", ["a/b", "a\\b", "../../etc/passwd"])
def test_yol_ayraclari_ayrilir(name):
    """'/' ve '\\' ayrilir — path traversal (dizin atlamasi) engellenir."""
    result = _sanitize_name(name)
    assert "/" not in result
    assert "\\" not in result


@pytest.mark.parametrize("name", ["a\x00b", "a\nb", "a😀b"])
def test_kontrol_ve_emoji_ayrilir(name):
    """NULL, yeni satir ve emoji ayrilir; harfler korunur."""
    assert _sanitize_name(name) == "ab"


@pytest.mark.parametrize("name,expected", [("İstanbul!", "İstanbul"), ("agent?", "agent")])
def test_noktalama_ayrilir(name, expected):
    """Noktalama isaretleri ayrilir."""
    assert _sanitize_name(name) == expected


# ---------------------------------------------------------------------------
# G. Karmaşik Turkce/unicode girisler
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["Türkiye_2026", "agent-İstanbul-1"],
)
def test_karisik_turkce_isimler_korunur(name):
    """Turkce + ayraç + rakam karisimi isimler oldugu gibi korunur."""
    assert _sanitize_name(name) == name


@pytest.mark.parametrize("name,expected", [("!!!agent!!!", "agent"), ("..İstanbul..", "..İstanbul..")])
def test_bas_sondaki_isaretler_ayrilir(name, expected):
    """Bas/sondaki isaretler ayrilir, icerideki noktalar korunur."""
    assert _sanitize_name(name) == expected


# ---------------------------------------------------------------------------
# H. Invariantlar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a/b", "../../etc/passwd"])
def test_cikti_hicbir_zaman_yol_ayraci_icermiyor(name):
    """Sonuc asla yol ayiraci icermemeli (guvenli dosya adi invarianti)."""
    result = _sanitize_name(name)
    assert "/" not in result
    assert "\\" not in result
    assert "\x00" not in result


@pytest.mark.parametrize("name", ["Türkiye_2026", "İstanbul"])
def test_idempotans(name):
    """Sanitizasyon idempotent olmali: f(f(x)) == f(x)."""
    once = _sanitize_name(name)
    assert _sanitize_name(once) == once


def test_cikti_str_tipinde_ve_bos_degil():
    """Cikti bir str olmali ve bos olmamali."""
    result = _sanitize_name("İstanbul-2026")
    assert isinstance(result, str)
    assert result != ""


def test_int_giris_type_error():
    """int giris yinelendigi icin TypeError verir (str beklenir)."""
    with pytest.raises(TypeError):
        _sanitize_name(5)


# ---------------------------------------------------------------------------
# I. Uzunluk sinirlari
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a", "İ", "1"])
def test_tek_karakter_kabul(name):
    """Tek karakterli gecerli isimler kabul edilir."""
    assert _sanitize_name(name) == name


def test_uzun_isim_korunur():
    """200 karakterlik uzun isim oldugu gibi korunur (kesme yok)."""
    long_name = "İstanbul" * 25  # 8 * 25 = 200 karakter
    assert _sanitize_name(long_name) == long_name


# ---------------------------------------------------------------------------
# J. Entegrasyon: _identity_path ile guvenli dosya yolu
# ---------------------------------------------------------------------------


def test_identity_path_sanitize_uygular():
    """_identity_path, path traversal girisini sanitizasyon ile etkisizlestirir."""
    p = _identity_path("../../etc/passwd")
    assert p.name == "....etcpasswd.json"
    # Cikti identities dizini disina cikamaz
    parts = p.parts
    assert ".." not in parts


def test_identity_path_tr_isim_guvenli():
    """Turkce isimle uretilen yol identities dizini altinda olur."""
    p = _identity_path("İstanbul-ajan")
    assert p.name == "İstanbul-ajan.json"
    assert p.parent == _identity_path("x").parent

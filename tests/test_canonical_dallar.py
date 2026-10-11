"""kredent.canonical dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (str/repr/json.dumps — dis cagri YOK).
Kural-5: TEST beklentileri uretime GORE yazildi; once `python3 -c` ile PROBE edildi.

Hedefler: _serialize_number + _jcs_serialize + _jcs_sort_key (module-level,
col_offset==0). Tum if/elif/else/raise dallari kesilir.
"""
import json
import sys
from decimal import Decimal
from fractions import Fraction

import pytest

sys.path.insert(0, ".")
from kredent.canonical import _jcs_serialize, _jcs_sort_key, _serialize_number  # noqa: E402


# == _serialize_number: int dalı ====================================================================

@pytest.mark.parametrize("value,expected", [
    (0, "0"),
    (1, "1"),
    (-1, "-1"),
    (42, "42"),
    (-42, "-42"),
    (255, "255"),
    (2**255 - 19, str(2**255 - 19)),
    (-(2**255), str(-(2**255))),
    (10**40, "10000000000000000000000000000000000000000"),
    (2**252 + 27742317777372353535851937790883648493, str(2**252 + 27742317777372353535851937790883648493)),
])
def test_serialize_number_int(value, expected):
    """ORTAM-ANATOMI: int -> str(value) — herhangi bir biçimlendirme YOK."""
    assert _serialize_number(value) == expected


@pytest.mark.parametrize("value", [True, False])
def test_serialize_number_bool_rejected_before_int(value):
    """ORTAM-ANATOMI: bool int'in alt-sınıfıdır ama İLK if bloğu onu yakalar.

    ORTAM-OGRENDI-1: bool dalı _serialize_number içinden AsLA int dalına
    düşmez; _jcs_serialize bool'u kendisi işler (true/false), bu yüzden
    _serialize_number(True) sadece doğrudan çağrıda patlar.
    """
    with pytest.raises(TypeError, match="bool is not a JCS number"):
        _serialize_number(value)


# == _serialize_number: float integral & abs < 1e21 dalı ============================================

@pytest.mark.parametrize("value,expected", [
    (0.0, "0"),
    (-0.0, "0"),
    (1.0, "1"),
    (-1.0, "-1"),
    (10.0, "10"),
    (100.0, "100"),
    (255.0, "255"),
    (1e20, "100000000000000000000"),
    (12345678901234567168.0, "12345678901234567168"),
])
def test_serialize_number_float_integral(value, expected):
    """ORTAM-ANATOMI: value == int(value) and abs(value) < 1e21 -> str(int(value)).

    ORTAM-OGRENDI-2: -0.0 == 0 oldugu icin '-0.0' DEGIL '0' uretilir
    (RFC 8785 negatif-sifiri korumaz, bu uygulama da korumaz).
    ORTAM-OGRENDI-3: 1.23456790e19 gibi tam-sayi gorunumlu floatlar
    IEEE-754 yuvarlamasiyla ZATEN kaybolmus degeri dondurur
    (12345678901234567168, niyet edilen 12345678901234567890 DEGIL) —
    bu uretim davranışıdır, düzeltilmez.
    """
    assert _serialize_number(value) == expected


# == _serialize_number: float repr dalı (kesirli veya abs >= 1e21) ==================================

@pytest.mark.parametrize("value,expected", [
    (0.5, "0.5"),
    (-0.5, "-0.5"),
    (0.1, "0.1"),
    (2.5, "2.5"),
    (3.14, "3.14"),
    (1e21, "1e+21"),
    (-1e21, "-1e+21"),
    (1e22, "1e+22"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
])
def test_serialize_number_float_repr(value, expected):
    """ORTAM-ANATOMI: kesirli veya abs>=1e21 -> repr(value) (en kısa round-trip)."""
    assert _serialize_number(value) == expected


@pytest.mark.parametrize("value", [
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="inf"),
    pytest.param(float("-inf"), id="-inf"),
])
def test_serialize_number_nan_inf_rejected(value):
    """ORTAM-ANATOMI: NaN/Infinity -> ValueError (RFC 8785 bunları JSON'a sokmaz).

    ORTAM-OGRENDI-4: kontrol `value != value` (NaN kendi kendine esit degil)
    VE `value in (inf, -inf)` ile BIRLIKTE yapilir; tek bir ValueError fırlatılır.
    """
    with pytest.raises(ValueError, match="JCS cannot serialize NaN or Infinity"):
        _serialize_number(value)


@pytest.mark.parametrize("value,type_name", [
    ("5", "str"),
    ("", "str"),
    (None, "NoneType"),
    (1 + 2j, "complex"),
    (Decimal("1.5"), "Decimal"),
    (Fraction(1, 2), "Fraction"),
    ([1], "list"),
    ({1: 2}, "dict"),
    (object(), "object"),
])
def test_serialize_number_unsupported_type(value, type_name):
    """ORTAM-ANATOMI: desteklenmeyen tip -> TypeError(mesajda tip adı)."""
    with pytest.raises(TypeError, match=f"Unsupported JCS number type: {type_name}"):
        _serialize_number(value)


# == _jcs_serialize: skaler dallar ==================================================================

@pytest.mark.parametrize("value,expected", [
    (None, "null"),
    (True, "true"),
    (False, "false"),
    (0, "0"),
    (7, "7"),
    (-7, "-7"),
    (3.0, "3"),
    (1.5, "1.5"),
    ("", '""'),
    ("hi", '"hi"'),
    ('a"b', '"a\\"b"'),
    ("a\\b", '"a\\\\b"'),
    ("tab\there", '"tab\\there"'),
    ("çağla", '"çağla"'),
    ("日本語", '"日本語"'),
    ("𝄞music", '"𝄞music"'),
    ("emoji😀", '"emoji😀"'),
])
def test_jcs_serialize_scalars(value, expected):
    """ORTAM-ANATOMI: None/bool/int/float/str sırasıyla işlenir.

    ORTAM-OGRENDI-5: str dalı `json.dumps(..., ensure_ascii=False)` kullanır —
    Unicode KAÇIŞTIRILMAZ (Türkçe/CJK/emoji ham UTF-8 olarak kalır).
    ORTAM-OGRENDI-6: bool dalı int dalından ÖNCE gelir, bu yüzden True -> '1' DEGIL 'true'.
    """
    assert _jcs_serialize(value) == expected


def test_jcs_serialize_str_matches_json_dumps():
    """ORTAM: str dalı birebir json.dumps(ensure_ascii=False) ile aynı."""
    for s in ["", "plain", "quote\"back\\slash", "ünïcödé", "new\nline"]:
        assert _jcs_serialize(s) == json.dumps(s, ensure_ascii=False)


# == _jcs_serialize: list/tuple dalları ==============================================================

@pytest.mark.parametrize("value,expected", [
    ([], "[]"),
    ((), "[]"),
    ([1], "[1]"),
    ((1,), "[1]"),
    ([1, "a", None], '[1,"a",null]'),
    ((1, "a", None), '[1,"a",null]'),
    ([[1, 2], [3]], "[[1,2],[3]]"),
    ([{"a": 1}], '[{"a":1}]'),
    ([True, False, None, 1.5], "[true,false,null,1.5]"),
    ((1, (2, 3)), "[1,[2,3]]"),
])
def test_jcs_serialize_sequences(value, expected):
    """ORTAM-ANATOMI: list VE tuple AYNI çıktıyı verir (ikisi de '[]' içine alınır)."""
    assert _jcs_serialize(value) == expected


def test_jcs_serialize_list_is_ordered():
    """ORTAM: dizi elemanları sıralanmaz, verilen sırada kalır."""
    assert _jcs_serialize([3, 2, 1]) == "[3,2,1]"
    assert _jcs_serialize(["c", "b", "a"]) == '["c","b","a"]'


# == _jcs_serialize: dict dalı =======================================================================

@pytest.mark.parametrize("value,expected", [
    ({}, "{}"),
    ({"a": 1}, '{"a":1}'),
    ({"b": 1, "a": 2}, '{"a":2,"b":1}'),
    ({"Z": 1, "a": 2, "_": 3, "0": 4}, '{"0":4,"Z":1,"_":3,"a":2}'),
    ({"nested": {"deep": [1, {"x": 2}]}}, '{"nested":{"deep":[1,{"x":2}]}}'),
    ({"k": None, "j": True, "i": False}, '{"i":false,"j":true,"k":null}'),
    ({"ü": 1, "a": 2}, '{"a":2,"ü":1}'),
])
def test_jcs_serialize_dict_sorted(value, expected):
    """ORTAM-ANATOMI: anahtarlar _jcs_sort_key'e göre (Unicode kod-sırası) sıralanır.

    ORTAM-OGRENDI-7: sıralama Python kod-noktası sırasıdır: rakamlar < büyük
    harf < '_' (0x5F) < küçük harf < UTF-8 devamı.
    """
    assert _jcs_serialize(value) == expected


@pytest.mark.parametrize("key", [1, 1.5, True, None, (1, 2), object()])
def test_jcs_serialize_dict_non_string_key(key):
    """ORTAM-ANATOMI: str-olmayan anahtar -> TypeError('JCS requires string keys')."""
    with pytest.raises(TypeError, match="JCS requires string keys"):
        _jcs_serialize({key: "v"})


@pytest.mark.parametrize("value,type_name", [
    ({1, 2}, "set"),
    (frozenset({1}), "frozenset"),
    (object(), "object"),
    (b"bytes", "bytes"),
    (bytearray(b"x"), "bytearray"),
])
def test_jcs_serialize_unsupported_type(value, type_name):
    """ORTAM-ANATOMI: desteklenmeyen kök tip -> TypeError(mesajda tip adı)."""
    with pytest.raises(TypeError, match=f"Unsupported JCS type: {type_name}"):
        _jcs_serialize(value)


def test_jcs_serialize_dict_value_error_propagates():
    """ORTAM: icteki değerin hatası dısarı sızar.

    ORTAM-OGRENDI-8: _jcs_serialize str değerleri KENDİSİ işler (str dalı),
    bu yüzden {"a": "5"} ASLA _serialize_number'a ulaşmaz ve TypeError
    VERMEZ — "Unsupported JCS number type: str" yalnızca _serialize_number
    doğrudan çağrılınca çıkar (bkz. test_serialize_number_unsupported_type).
    """
    with pytest.raises(ValueError, match="JCS cannot serialize NaN or Infinity"):
        _jcs_serialize({"a": float("nan")})
    with pytest.raises(TypeError, match="Unsupported JCS type: set"):
        _jcs_serialize({"a": "x", "b": {1, 2}})
    # Hata iç-icteki yapılardan da sızar.
    with pytest.raises(TypeError, match="JCS requires string keys"):
        _jcs_serialize({"a": {"b": [1, {2: "c"}]}})
    with pytest.raises(ValueError, match="JCS cannot serialize NaN or Infinity"):
        _jcs_serialize([{"a": [float("inf")]}])


# == _jcs_sort_key ===================================================================================

@pytest.mark.parametrize("key", ["", "a", "Z", "0", "_", "ü", "日本語", "𝄞"])
def test_jcs_sort_key_identity(key):
    """ORTAM-ANATOMI: _jcs_sort_key anahtarı OLDUĞU GİBİ döndürür (identity)."""
    assert _jcs_sort_key(key) == key


@pytest.mark.parametrize("a,b", [
    ("0", "Z"), ("Z", "_"), ("_", "a"), ("a", "z"), ("z", "ü"), ("A", "a"), ("ü", "日本語"),
])
def test_jcs_sort_key_ordering(a, b):
    """ORTAM: sıralama kod-noktası sırası verir (a < b)."""
    assert _jcs_sort_key(a) < _jcs_sort_key(b)


def test_jcs_sort_key_is_used_by_jcs_serialize():
    """ORTAM: _jcs_serialize sıralama için _jcs_sort_key'i çağırır."""
    calls = []
    orig = _jcs_sort_key

    def spy(k):
        calls.append(k)
        return orig(k)

    import kredent.canonical as mod
    mod._jcs_sort_key = spy
    try:
        _jcs_serialize({"b": 1, "a": 2})
    finally:
        mod._jcs_sort_key = orig
    assert sorted(calls) == ["a", "b"]


# == RFC 8785 tutarlılık / round-trip ================================================================

@pytest.mark.parametrize("value", [
    {},
    [],
    [1, [2, 3], {"a": 4}],
    {"z": {"y": {"x": [1, 2, 3]}}, "a": None},
    {"str": "é\t\"\\", "n": -0.0, "t": True},
    [{"k": [{"j": 1}]}],
])
def test_jcs_serialize_is_deterministic(value):
    """ORTAM: aynı girdi her zaman aynı baytları verir (imza taşınabilirliği)."""
    first = _jcs_serialize(value)
    for _ in range(5):
        assert _jcs_serialize(value) == first


@pytest.mark.parametrize("value", [
    {"b": 1, "a": 2},
    ["a", "b"],
    {"x": [1, 2]},
])
def test_jcs_serialize_key_order_independent(value):
    """ORTAM: anahtar sırası değişse de çıktı aynı (JCS canonicalization)."""
    if isinstance(value, dict):
        items = list(value.items())
        reordered = dict(items[::-1])
        assert _jcs_serialize(reordered) == _jcs_serialize(value)


def test_jcs_serialize_no_whitespace():
    """ORTAM: çıktıda boşluk/sonsuz-newline YOK ( kompakt )."""
    out = _jcs_serialize({"a": [1, 2], "b": {"c": None}})
    assert " " not in out
    assert "\n" not in out
    assert "\t" not in out

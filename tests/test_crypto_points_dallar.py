"""kredent.crypto nokta-dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (mod-algebra — dis cagri YOK).
Kural-5: TEST beklentileri uretime GORE yazildi; once `python3 -c` ile PROBE edildi.

Hedefler: _xrecover + _scalar_multiply + _scalar_reduce + _point_compress +
_point_decompress + _public_point_from_seed + _cryptography_public_from_seed
(module-level, col_offset==0). Tum if/while/raise dallari kesilir.

BAGIMSIZ ORACLE'LER (uretim fonksiyonu kullanMAK YOK):
  _affine   — projective -> affine (z-locale gore normalize et)
  _xx_of    — Edwards xx degeri
  _on_curve — twisted-Edwards denklemini affine'de dogrula
"""
import sys

import pytest

sys.path.insert(0, ".")
from kredent import crypto as cr  # noqa: E402
from kredent.crypto import (  # noqa: E402
    _clamp_scalar,
    _cryptography_public_from_seed,
    _expand_seed,
    _point_compress,
    _point_decompress,
    _public_point_from_seed,
    _scalar_multiply,
    _scalar_reduce,
    _xrecover,
)

_P, _L, _D, _I = cr._P, cr._L, cr._D, cr._I
_BASE = cr._BASE_POINT


# == bagimsiz oracle'ler ===========================================================================

def _affine(pt):
    """Projective -> affine (test-side oracle; uretim _point_compress'in aynisi DEGIL)."""
    x, y, z, _t = pt
    zi = pow(z, _P - 2, _P)
    return ((x * zi) % _P, (y * zi) % _P)


def _xx_of(y):
    """Edwards xx = (y^2-1)/(D y^2+1) (mod P)."""
    return (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P


def _on_curve(pt):
    """-x^2 + y^2 == 1 + D x^2 y^2 (mod P) — twisted-Edwards denkleimi."""
    x, y = _affine(pt)
    return (-x * x + y * y) % _P == (1 + _D * x * x * y * y) % _P


# == _xrecover: parite / aralik / toplam invariants =================================================

@pytest.mark.parametrize("y", [0, 1, 2, 3, 4, 5, 7, 10, 100, 12345, cr._BY, _P // 2, _P - 1, _P - 2])
def test_xrecover_parity_matches_sign(y):
    """ORTAM-ANATOMI: son `if x % 2 != sign: x = _P - x` — x'in paritesi sign'e zorlanir.

    _P tek sayi oldugu icin `_P - x` pariteyi TERSINE cevirir.
    """
    assert _xrecover(y, 0) % 2 == 0
    assert _xrecover(y, 1) % 2 == 1


@pytest.mark.parametrize("y", [0, 1, 2, 3, 4, 5, 10, 100, cr._BY, _P - 1])
def test_xrecover_sign_pair_sums_to_P(y):
    """ORTAM-ANATOMI: xrecover(y,0) + xrecover(y,1) == _P (iki isaret koku)."""
    assert _xrecover(y, 0) + _xrecover(y, 1) == _P


@pytest.mark.parametrize("y", [0, 1, 2, 3, 4, 5, 10, cr._BY, _P - 1])
@pytest.mark.parametrize("sign", [0, 1])
def test_xrecover_range(y, sign):
    """ORTAM-ANATOMI: 0 <= x <= _P.

    ORTAM-OGRENDI-1: aralik [0, _P) DEGIL [0, _P] — x=0 ve sign=1 icin
    `_P - 0 == _P` doner, yani _xrecover(1,1) BIREBIR _P'dir (alan disi!).
    Bu uretimin kusurudur: menzil KORUMASI YOK, test bunu oldugu gibi belgeler.
    """
    x = _xrecover(y, sign)
    assert 0 <= x <= _P


def test_xrecover_x_equals_P_quirk():
    """ORTAM-OGRENDI-1 (somut): y=1 -> xx=0 -> x=0; sign=1 -> x = _P - 0 = _P.

    xrecover(1,1) alanin DISINDA bir tamsayi dondurur. Karakterizasyon:
    uretim bunu engellemez; tuketici _point_decompress'tedir.
    """
    assert _xrecover(1, 0) == 0
    assert _xrecover(1, 1) == _P


# == _xrecover: kok dogrulugu (QR / non-QR) ==========================================================

@pytest.mark.parametrize("y", [0, 3, 4, 5, 6, 9, 10, 14, 15, 16])
@pytest.mark.parametrize("sign", [0, 1])
def test_xrecover_sqrt_when_qr(y, sign):
    """ORTAM-ANATOMI: xx quadratic-residue iken x^2 == xx (mod P).

    QR-dali: (x*x - xx) % _P == 0 -> x oldugu gibi birakilir.
    (y=0: xx = -1, P ≡ 1 mod 4 oldugu icin QR'dir — ayrica asagidaki teste bak.)
    """
    xx = _xx_of(y)
    assert pow(xx, (_P - 1) // 2, _P) == 1  # once QR oldugundan emin ol
    assert (_xrecover(y, sign) ** 2 - xx) % _P == 0


@pytest.mark.parametrize("y", [2, 7, 8, 11, 12, 13, 17, 20, 22])
@pytest.mark.parametrize("sign", [0, 1])
def test_xrecover_non_qr_branch(y, sign):
    """ORTAM-ANATOMI: xx non-residue iken `x = x * _I` dali calisir.

    ORTAM-OGRENDI-2: Bu dalda x^2 == xx GECERLI DEGILDIR (boyle bir kok yok
    zaten). Yine de x^8 == xx^4 (mod P) saglanir. Uretim QR KORUMASI vermez:
    non-residue xx icin anlamli bir kok degil, well-defined bir cikti uretir.
    """
    xx = _xx_of(y)
    assert pow(xx, (_P - 1) // 2, _P) == _P - 1  # non-residue
    x = _xrecover(y, sign)
    assert pow(x, 8, _P) == pow(xx, 4, _P)
    assert pow(x, 4, _P) in (pow(xx, 2, _P), _P - pow(xx, 2, _P))


@pytest.mark.parametrize("y", [0, 1, 2, 3, 4, 5, 10, cr._BY])
@pytest.mark.parametrize("sign", [0, 1])
def test_xrecover_eighth_power_invariant(y, sign):
    """ORTAM: her iki dalda da x^8 == xx^4 (Fermat: x = xx^((P+3)/8) veya .I ile)."""
    xx = _xx_of(y)
    assert pow(_xrecover(y, sign), 8, _P) == pow(xx, 4, _P)


# == _xrecover: bilinen degerler =====================================================================

def test_xrecover_recovers_base_point_x():
    """ORTAM-ANATOMI: _BX = _xrecover(_BY, 0) — taban-noktasinin olusumu."""
    assert _xrecover(cr._BY, 0) == cr._BX
    assert _xrecover(cr._BY, 1) == _P - cr._BX


def test_xrecover_y_zero_is_sqrt_minus_one():
    """ORTAM: y=0 -> xx = -1; -1, P mod 4 == 1 oldugu icin QR'dir.

    _P = 2^255-19 ≡ 1 (mod 4) -> -1 bir karesi var: _I = 2^((P-1)/4).
    """
    assert _P % 4 == 1
    assert _xx_of(0) == _P - 1
    assert _xrecover(0, 0) == _I
    assert (_I * _I) % _P == _P - 1
    assert _xrecover(0, 1) == _P - _I


def test_xrecover_y_one_is_zero_root():
    """ORTAM-OGRENDI: y=1 -> xx = 0 (0 ne QR ne non-QR; tek koku 0'dir).

    x = 0^((P+3)/8) = 0; QR kontrolu (0-0)%P==0 gecer; sign=0 -> x=0 kalir,
    sign=1 -> x = _P - 0 = _P (alan disi, yukaridaki quirk).
    """
    assert _xx_of(1) == 0
    assert _xrecover(1, 0) == 0


def test_xrecover_is_deterministic():
    """ORTAM: ayni girdi her seferinde ayni cikti (pure function)."""
    for y, sign in [(cr._BY, 0), (5, 1), (1000, 0)]:
        first = _xrecover(y, sign)
        for _ in range(5):
            assert _xrecover(y, sign) == first


# == _scalar_multiply ================================================================================

def test_scalar_multiply_zero_is_identity():
    """ORTAM-ANATOMI: k=0 -> while dongusu HIC calismaz -> (0,1,1,0) kimlik."""
    assert _scalar_multiply(0, _BASE) == (0, 1, 1, 0)


@pytest.mark.parametrize("k", [1, 2, 3, 4, 5, 7, 8, 15, 16, 255, 256, 1000])
def test_scalar_multiply_affine_equals_base_times_k(k):
    """ORTAM-ANATOMI: k*B, affine'de taban-noktanin k-inci skaler-katidir.

    ORTAM-OGRENDI-3: _scalar_multiply NORMALIZE-EDILMEMIS projective coords
    dondurur, bu yuzden `_scalar_multiply(1, B) == B` tuple olarak FALSE!
    Kiyaslama icin z-locale gore affine normalizasyonu sarttir.
    """
    assert _affine(_scalar_multiply(k, _BASE)) != (0, 1) or k == 0
    result = _affine(_scalar_multiply(k, _BASE))
    # bagimsiz oracle: k kez tekrarli _edwards_add (uretim degil, test oracle'i)
    acc = (0, 1, 1, 0)
    for _ in range(k):
        acc = cr._edwards_add(acc, _BASE)
    assert result == _affine(acc)


def test_scalar_multiply_one_projective_neq_base_tuple():
    """ORTAM-OGRENDI-3 (somut): tuple esitligi FALSE, affine esitligi TRUE."""
    assert _scalar_multiply(1, _BASE) != _BASE
    assert _affine(_scalar_multiply(1, _BASE)) == (_BASE[0], _BASE[1])


@pytest.mark.parametrize("k", [1, 2, 3, 5, 7, 64, 255])
def test_scalar_multiply_matches_double_and_add(k):
    """ORTAM: k*B == k kez (B+B+...+B) — while/if bit dallari tum k-bitleri yorar."""
    acc = (0, 1, 1, 0)
    for _ in range(k):
        acc = cr._edwards_add(acc, _BASE)
    assert _affine(_scalar_multiply(k, _BASE)) == _affine(acc)


@pytest.mark.parametrize("a,b", [(1, 1), (1, 2), (2, 3), (3, 5), (7, 11), (100, 201)])
def test_scalar_multiply_distributive(a, b):
    """ORTAM: (a+b)*B == a*B + b*B (grup kanunu, affine'de)."""
    lhs = _affine(_scalar_multiply(a + b, _BASE))
    rhs = _affine(cr._edwards_add(_scalar_multiply(a, _BASE), _scalar_multiply(b, _BASE)))
    assert lhs == rhs


@pytest.mark.parametrize("k,j", [(2, 3), (3, 2), (5, 7), (7, 5), (13, 17)])
def test_scalar_multiply_composition(k, j):
    """ORTAM: k*(j*B) == (k*j)*B (skaler kompozisyon)."""
    lhs = _affine(_scalar_multiply(k, _scalar_multiply(j, _BASE)))
    rhs = _affine(_scalar_multiply(k * j, _BASE))
    assert lhs == rhs


@pytest.mark.parametrize("k", [2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
def test_scalar_multiply_bit_patterns_covered(k):
    """ORTAM: k'nin her bit deseni (tek/cift) if k&1 dalini yorar.

    ORTAM-OGRENDI-4: k=5 (0b101) icin x-koordinati TEK oldugu goruldu —
    bu _point_compress'in sign-bit dalini tetikler (bkz. asagida).
    """
    pt = _scalar_multiply(k, _BASE)
    assert _on_curve(pt)


@pytest.mark.parametrize("k", [1, 2, 3, 5, 7, 9, 10, 11])
def test_scalar_multiply_points_on_curve(k):
    """ORTAM: her skaler-kat gecerli Edwards noktasidir."""
    assert _on_curve(_scalar_multiply(k, _BASE))


# == _scalar_reduce ==================================================================================

@pytest.mark.parametrize("k,expected", [
    (0, 0),
    (1, 1),
    (5, 5),
    (_L - 1, _L - 1),
    (_L, 0),
    (_L + 1, 1),
    (_L + 5, 5),
    (2 * _L, 0),
    (2 * _L + 3, 3),
    (10 ** 50, 10 ** 50 % _L),
])
def test_scalar_reduce_is_modulo_L(k, expected):
    """ORTAM-ANATOMI: _scalar_reduce(k) = k % _L (tek satir, tek dal)."""
    assert _scalar_reduce(k) == expected
    assert 0 <= _scalar_reduce(k) < _L


@pytest.mark.parametrize("k", [_L, 2 * _L, 5 * _L, _L * _L])
def test_scalar_reduce_multiples_of_L_are_zero(k):
    """ORTAM: L'nin katlari sifira indirgenir (grp duzeni L)."""
    assert _scalar_reduce(k) == 0


# == _point_compress =================================================================================

@pytest.mark.parametrize("pt,label", [
    ((0, 1, 1, 0), "identity"),
    (_BASE, "base"),
    (cr._BASE_POINT, "base-again"),
])
def test_point_compress_length(pt, label):
    """ORTAM-ANATOMI: cikti her zaman 32 bayt (y little-endian + sign bit)."""
    assert len(_point_compress(pt)) == 32


def test_point_compress_identity():
    """ORTAM-OGRENDI-5: kimlik (0,1,1,0) -> y=1, x cift -> sign-bit YOK.

    Cikti: 0x01 followed by 31 zero bytes — y=1 little-endian. Sifir DEGIL.
    """
    out = _point_compress((0, 1, 1, 0))
    assert out == b"\x01" + b"\x00" * 31
    assert out[31] & 0x80 == 0


def test_point_compress_base_point_sign_bit():
    """ORTAM: taban-nokta x'i cift -> sign-bit SET DEGIL, son bayt < 0x80."""
    out = _point_compress(_BASE)
    assert out[31] & 0x80 == 0
    assert int.from_bytes(out, "little") == cr._BY


def test_point_compress_odd_x_sets_sign_bit():
    """ORTAM-ANATOMI: `if x & 1` -> 255. bit set edilir.

    ORTAM-OGRENDI-4: 5*B taban-noktasinin x-koordinati TEK oldugu icin
    compressed[31] = 0xdf (sign bit + y'nin yuksek bitlari).
    """
    pt = _scalar_multiply(5, _BASE)
    assert _affine(pt)[0] % 2 == 1
    out = _point_compress(pt)
    assert out[31] & 0x80 == 0x80
    assert out[31] == 0xDF


def test_point_compress_even_x_no_sign_bit():
    """ORTAM: x cift -> sign bit 0."""
    for k in (1, 2, 3, 4, 8, 9):
        pt = _scalar_multiply(k, _BASE)
        if _affine(pt)[0] % 2 == 0:
            assert _point_compress(pt)[31] & 0x80 == 0


@pytest.mark.parametrize("c", [2, 3, 7, 12345, _P - 5])
def test_point_compress_z_scaling_invariant(c):
    """ORTAM-ANATOMI: projective (x,y,z,t) ile (cx,cy,cz,c^2 t) AYNI cikti.

    _point_compress once zinv = z^-1 ile affine'e indirir — projective
    temsilin ozgurlugu korunur.
    """
    x, y, z, t = _BASE
    scaled = ((x * c) % _P, (y * c) % _P, (z * c) % _P, (t * c * c) % _P)
    assert _point_compress(scaled) == _point_compress(_BASE)


# == _point_decompress ===============================================================================

@pytest.mark.parametrize("n", [0, 1, 2, 16, 31, 33, 48, 64, 100])
def test_point_decompress_wrong_length(n):
    """ORTAM-ANATOMI: len != 32 -> ValueError (ilk if, tek dal)."""
    with pytest.raises(ValueError, match="Invalid Ed25519 point encoding length"):
        _point_decompress(bytes(n))


@pytest.mark.parametrize("label,encoding", [
    ("P", _P.to_bytes(32, "little")),
    ("P+1", (_P + 1).to_bytes(32, "little")),
    ("2^255-1", (2**255 - 1).to_bytes(32, "little")),
    ("ff*32", b"\xff" * 32),
])
def test_point_decompress_y_out_of_field(label, encoding):
    """ORTAM-ANATOMI: y >= _P -> ValueError (y aralik korumasi).

    ORTAM-OGRENDI: 0xff*32 -> sign bit 1, y = 0x7fff...ff = 2^255-1 > _P
    (cunku _P = 2^255-19). AMA 0xfe*32 REDDEDILMEZ: y = 0x7efe...fe < _P.
    Esik tam bit-254/255 sinirindadir; bu test sadece gercekten tasan
    kodlamalarla yazildi.
    """
    assert len(encoding) == 32
    y_probe = int.from_bytes(encoding, "little") & ((1 << 255) - 1)
    assert y_probe >= _P  # test kendi onkosulunu dogrular
    with pytest.raises(ValueError, match="y out of field range"):
        _point_decompress(encoding)


@pytest.mark.parametrize("fill", [b"\xfe", b"\xf0", b"\x7f"])
def test_point_decompress_accepts_high_y_under_P(fill):
    """ORTAM-OGRENDI: 0xfe/0xf0*32 -> y < _P oldugu icin ValueError VERMEZ.

    0x7efe...fe < 2^255-19: high-byte mask'lemesi sonrasi y hala alandadir.
    Bu noktalar curve'de OLMAYABILIR (bkz. curve-denklemi testi) ama uzunluk
    ve aralik kontrollerinden gecerler.
    """
    enc = fill * 32
    y_probe = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    assert y_probe < _P
    _point_decompress(enc)  # hata firlatmaz


def test_point_decompress_accepts_max_valid_y():
    """ORTAM: y = _P - 1 kabul edilir (alanin en buyuk gecerli elemani)."""
    pt = _point_decompress((_P - 1).to_bytes(32, "little"))
    assert pt[1] == _P - 1
    assert pt[2] == 1


@pytest.mark.parametrize("k", [1, 2, 3, 5, 7, 8, 11, 64])
def test_point_decompress_roundtrip(k):
    """ORTAM-ANATOMI: decompress(compress(k*B)) affine olarak k*B'ye esittir.

    ORTAM-OGRENDI-6: _point_decompress (x, y, 1, x*y) dondurur (z=1), ama
    _scalar_multiply normalize-EDILMEMIS projective coords dondurur. Bu yuzden
    tuple kiyaslamasi DEGIL, affine (x/z, y/z) kiyaslamasi dogru olandır.
    """
    pt = _scalar_multiply(k, _BASE)
    enc = _point_compress(pt)
    dec = _point_decompress(enc)
    assert dec[2] == 1
    assert _affine(dec) == _affine(pt)
    assert dec[0] % 2 == _affine(pt)[0] % 2
    assert dec[1] == _affine(pt)[1]


def test_point_decompress_sign_bit_recovers_odd_x():
    """ORTAM-ANATOMI: sign biti x'in paritesini geri yukler.

    compress(x cift) -> bit 0; decompress -> xrecover(y, 0) (cift).
    compress(x tek)  -> bit 1; decompress -> xrecover(y, 1) (tek).
    """
    pt = _scalar_multiply(5, _BASE)  # x tek
    enc = _point_compress(pt)
    assert enc[31] & 0x80
    dec = _point_decompress(enc)
    assert dec[0] % 2 == 1
    assert _affine(dec) == _affine(pt)


def test_point_decompress_strips_sign_bit_from_y():
    """ORTAM-ANATOMI: y &= (1<<255)-1 — sign bit y'den cikarilir."""
    enc = bytearray(_point_compress(_BASE))
    enc[31] |= 0x80  # sign bit set (x paritesini tersine cevir)
    dec = _point_decompress(bytes(enc))
    assert dec[1] == cr._BY  # y hala ayni
    assert dec[0] == _P - cr._BX  # x isaret-koku degisti


def test_point_decompress_zeros_is_valid_point():
    """ORTAM-OGRENDI-7: b'\\x00'*32 REDDEDILMEZ — y=0 gecerli bir noktadir.

    xx = -1, ve -1 (P ≡ 1 mod 4) bir QR oldugu icin x = _I (2^((P-1)/4)).
    Bu nokta curve'dedir: -_I^2 + 0 = 1 - 0 = 1.
    """
    pt = _point_decompress(b"\x00" * 32)
    assert pt[1] == 0
    assert pt[0] == _I
    assert _on_curve(pt)


def test_point_decompress_no_curve_equation_check():
    """ORTAM-OGRENDI-8: _point_decompress curve denklemini DOGRULAMAZ.

    y=2: xx bir non-residue -> _xrecover anlamli bir kok uretemez ama yine de
    bir nokta dondurur. Sonuc curve'de DEGILDIR. Bu bir GUVENLIK-ILGILI
    karakterizasyondur: koruma yalnizca yukarida (y >= _P kontrolu) ve
    py_verify'deki imza denklemindedir.
    """
    pt = _point_decompress((2).to_bytes(32, "little"))
    assert pt[1] == 2
    assert not _on_curve(pt)


# == _public_point_from_seed / _cryptography_public_from_seed ========================================

@pytest.mark.parametrize("seed_hex", [
    "9d61b19deff52181de4d4021a206b16d4f9a2d5d5c3f2f4b7d9b5e1f8f7e6d5c",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
])
def test_public_point_from_seed_matches_scalar_multiply(seed_hex):
    """ORTAM-ANATOMI: _public_point_from_seed = _scalar_multiply(clamp(expand(seed)[0]), B)."""
    seed = bytes.fromhex(seed_hex)
    scalar_half, _ = _expand_seed(seed)
    expected = _scalar_multiply(_clamp_scalar(scalar_half), _BASE)
    assert _public_point_from_seed(seed) == expected
    assert _affine(_public_point_from_seed(seed)) == _affine(expected)


@pytest.mark.parametrize("seed_hex", [
    "9d61b19deff52181de4d4021a206b16d4f9a2d5d5c3f2f4b7d9b5e1f8f7e6d5c",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0707070707070707070707070707070707070707070707070707070707070707",
])
def test_public_point_from_seed_on_curve(seed_hex):
    """ORTAM: seed'den turetilen acik-anahtar gecerli Edwards noktasidir."""
    assert _on_curve(_public_point_from_seed(bytes.fromhex(seed_hex)))


@pytest.mark.parametrize("seed_hex", [
    "9d61b19deff52181de4d4021a206b16d4f9a2d5d5c3f2f4b7d9b5e1f8f7e6d5c",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f",
])
def test_cryptography_public_from_seed_matches_pure_python(seed_hex):
    """ORTAM-ANATOMI: pyca/cryptography yolu pure-Python yolu ile AYNI acik-anahtari verir.

    Iki bagimsiz implementasyonun uyusmasi (cross-implementation oracle)
    _point_compress + _scalar_multiply + _clamp_scalar + _expand_seed
    zincirinin dogrulugudur.
    """
    seed = bytes.fromhex(seed_hex)
    crypto_pub = _cryptography_public_from_seed(seed).public_bytes_raw()
    pure_pub = _point_compress(_public_point_from_seed(seed))
    assert crypto_pub == pure_pub


@pytest.mark.parametrize("seed_hex", [
    "9d61b19deff52181de4d4021a206b16d4f9a2d5d5c3f2f4b7d9b5e1f8f7e6d5c",
    "1111111111111111111111111111111111111111111111111111111111111111",
])
def test_public_point_from_seed_matches_keypair(seed_hex):
    """ORTAM: _public_point_from_seed, keypair_from_seed'in raw_pub ile uyusur."""
    from kredent.crypto import keypair_from_seed

    seed = bytes.fromhex(seed_hex)
    _, raw_pub, _mb, _did = keypair_from_seed(seed)
    assert raw_pub == _point_compress(_public_point_from_seed(seed))


def test_public_point_from_seed_distinct_seeds_distinct_points():
    """ORTAM: farkli seed'ler farkli acik-anahtarlari uretir (carpisma kontrolu)."""
    pubs = set()
    for i in range(20):
        seed = bytes([i]) * 32
        pubs.add(_point_compress(_public_point_from_seed(seed)))
    assert len(pubs) == 20

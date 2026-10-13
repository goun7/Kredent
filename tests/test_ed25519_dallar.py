r"""68-Kredent crypto.py saf-Python Ed25519 ( RFC 8032) dal-kesen testleri.

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf matematik ( DIS-AG YOK; nacl ile capraz-dogrulama SADECE
   yerel-kutuphane; RFC 8032 test-vektorleri).

ORTAM-ANATOMI: _xrecover/ _edwards_add/ _scalar_multiply/ _scalar_reduce/
   _point_compress/ _point_decompress/ _sha512/ _hash_int/ _expand_seed/
   _clamp_scalar/ _public_point_from_seed/ py_sign/ py_verify
"""
import hashlib
import sys

import pytest

sys.path.insert(0, ".")

import kredent.crypto as C  # noqa: E402

_P = C._P
_L = C._L
_B = C._BASE_POINT
_NEUTRAL = (0, 1, 1, 0)

# RFC 8032 / bilinen-sifir-seed public-key
_PUB_SIFIR = ("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63"
              "ac048a18b59da29")

_HAS_NACL = True
try:
    import nacl.signing
except ImportError:  # pragma: no cover
    _HAS_NACL = False


def _esit(p, q):
    """ORTAM-OGRENDI: extended-Edwards koordinatlarinda GORUNTU-ESITLIK
    YOKTUR — ( x,y) = ( X/Z, Y/Z) oldugu-icin carprazi-karsilastir (
    x1*z2 == x2*z1 ve y1*z2 == y2*z1)."""
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return ((x1 * z2) % _P == (x2 * z1) % _P
            and (y1 * z2) % _P == (y2 * z1) % _P)


def _seed(i):
    return hashlib.sha256(("seed-%d" % i).encode()).digest()


# == alan-sabitleri ===================================================================================

def test_P_degeri():
    """ORTAM-GERCEK: p = 2^255 - 19 ( RFC 8032 asal-cismi)."""
    assert _P == 2**255 - 19


def test_L_degeri():
    """ORTAM-GERCEK: L = 2^252 + 27742317777372353535851937790883648493
    ( taban-nokta-duzeni)."""
    assert _L == 2**252 + 27742317777372353535851937790883648493


def test_L_asalligi_uzunlugu():
    """ORTAM: L ~ 2^252 ( 253-bit)."""
    assert _L.bit_length() == 253


def test_P_bit_uzunlugu():
    assert _P.bit_length() == 255


def test_D_degeri():
    """ORTAM-GERCEK: d = -121665/ 121666 mod p ( twisted-Edwards egrisi)."""
    bek = (-121665 * pow(121666, _P - 2, _P)) % _P
    assert C._D == bek
    assert C._D == int(
        "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
        16)


def test_I_degeri():
    """ORTAM: I = 2^(( p-1)/ 4) mod p ( quadratic-nonresidue sqrt)."""
    assert C._I == pow(2, (_P - 1) // 4, _P)


def test_BY_degeri():
    """ORTAM-GERCEK: B_y = 4/5 mod p ( RFC 8032 taban-noktasi)."""
    assert C._BY == (4 * pow(5, _P - 2, _P)) % _P
    assert C._BY == int("6" * 62 + "58", 16)  # 64 hex hane


def test_BX_degeri():
    """ORTAM-GERCEK: B_x = xrecover( B_y, 0)."""
    assert C._BX == int("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c"
                        "9562d608f25d51a", 16)


def test_base_point_yapi():
    """ORTAM-OGRENDI: _BASE_POINT = ( B_x, B_y, 1, ( B_x* B_y) % p) (
    extended-koordinatlar; z=1)."""
    x, y, z, t = _B
    assert (x, y, z) == (C._BX, C._BY, 1)
    assert t == (C._BX * C._BY) % _P


# == _xrecover ========================================================================================

def test_xrecover_bx():
    """ORTAM-GERCEK: xrecover( B_y, 0) == B_x."""
    assert C._xrecover(C._BY, 0) == C._BX


def test_xrecover_isaret_parity():
    """ORTAM-OGRENDI: sign-bit x'in paritesini-secer — xrecover( y,1) ==
    p - xrecover( y,0) ( diger-isaret-koku)."""
    a = C._xrecover(C._BY, 0)
    b = C._xrecover(C._BY, 1)
    assert b == (_P - a) % _P


@pytest.mark.parametrize("sign", [0, 1])
def test_xrecover_uzeri_egri(sign):
    """ORTAM: her-iki-isaret-koku de egri-uzere ( -x^2 + y^2 = 1 + d*x^2*
    y^2)."""
    x = C._xrecover(C._BY, sign)
    lhs = (-x * x + C._BY * C._BY) % _P
    rhs = (1 + C._D * x * x * C._BY * C._BY) % _P
    assert lhs == rhs


def test_xrecover_donut_int():
    assert isinstance(C._xrecover(C._BY, 0), int)


def test_xrecover_pozitif_aralik():
    """ORTAM: sonuc [ 0, p)."""
    for sign in (0, 1):
        v = C._xrecover(C._BY, sign)
        assert 0 <= v < _P


# == _edwards_add =====================================================================================

def test_edwards_add_neutral():
    """ORTAM-OGRENDI (GUVENLIK-ONEMLI): ( 0,1,1,0) birim-oge — toplamayi
    etkilemez ( ANCAK extended-koordinatlarda GORUNTU-ESITLIK YOKTUR:
    ( 4X,4Y,4,4XY) ayni-nokta; _esit ile-karsilastir)."""
    s1 = C._edwards_add(_NEUTRAL, _B)
    assert _esit(s1, _B)
    assert s1 != _B  # goruntu-farkli; anlamlari-ayni


def test_edwards_add_neutral_sira():
    """ORTAM: toplama DEGISMELI ( commutative)."""
    assert _esit(C._edwards_add(_B, _NEUTRAL), _B)


def test_edwards_add_degismeli():
    """ORTAM: P + Q == Q + P ( projective)."""
    p2 = C._scalar_multiply(2, _B)
    p3 = C._scalar_multiply(3, _B)
    assert _esit(C._edwards_add(_B, p2), C._edwards_add(p2, _B))


def test_edwards_add_iliskisel():
    """ORTAM: ( B + 2B) + 3B == B + ( 2B + 3B) ( associativity)."""
    p2 = C._scalar_multiply(2, _B)
    p3 = C._scalar_multiply(3, _B)
    lhs = C._edwards_add(C._edwards_add(_B, p2), p3)
    rhs = C._edwards_add(_B, C._edwards_add(p2, p3))
    assert _esit(lhs, rhs)


def test_edwards_add_doubling():
    """ORTAM: B + B == 2* B ( unified-formula doubling)."""
    assert _esit(C._edwards_add(_B, _B), C._scalar_multiply(2, _B))


def test_edwards_add_donut_oge_sayisi():
    """ORTAM: 4-ogeli-tuple doner ( x,y,z,t)."""
    out = C._edwards_add(_B, _B)
    assert isinstance(out, tuple) and len(out) == 4


def test_edwards_add_neutral_neutral():
    """ORTAM: N + N == N."""
    assert _esit(C._edwards_add(_NEUTRAL, _NEUTRAL), _NEUTRAL)


# == _scalar_multiply =================================================================================

def test_smul_sifir_neutral():
    """ORTAM-GERCEK: k=0 -> ( 0,1,1,0) birim-oge."""
    assert C._scalar_multiply(0, _B) == _NEUTRAL


def test_smul_bir_taban():
    """ORTAM-GERCEK: k=1 -> taban-nokta ( projective)."""
    assert _esit(C._scalar_multiply(1, _B), _B)


@pytest.mark.parametrize("k", [1, 2, 3, 5, 7, 100, 12345, 2**128])
def test_smul_artis(k):
    """ORTAM: k*B = ( k-1)*B + B ( recursive-tanim)."""
    onceki = C._scalar_multiply(k - 1, _B)
    bek = C._edwards_add(onceki, _B)
    assert _esit(C._scalar_multiply(k, _B), bek)


def test_smul_duzen_basamagi():
    """ORTAM-OGRENDI: L* B = birim-oge — taban-nokta-duzeni L (
    GUVENLIK-ONEMLI: signature-verification bu-duzene-dayanir)."""
    assert _esit(C._scalar_multiply(_L, _B), _NEUTRAL)


@pytest.mark.parametrize("ek", [1, 2, 3, 7, 1234])
def test_smul_duzen_mod(ek):
    """ORTAM: ( L + k)* B == k* B ( duzere-gore-indirgenir)."""
    tam = C._scalar_multiply(_L + ek, _B)
    kisa = C._scalar_multiply(ek, _B)
    assert _esit(tam, kisa)


@pytest.mark.parametrize("k", [1, 2, 3, 5, 17])
def test_smul_doubling_cift(k):
    """ORTAM: 2k* B == k* B + k* B."""
    kb = C._scalar_multiply(k, _B)
    assert _esit(C._scalar_multiply(2 * k, _B), C._edwards_add(kb, kb))


def test_smul_donut_oge_sayisi():
    assert len(C._scalar_multiply(7, _B)) == 4


def test_smul_buyuk_skalar():
    """ORTAM: 2^256 ( L'den-buyuk) calisir; L'ye-gore-indirgenmis-
    sonuc-verir."""
    k = 2**256
    bek = C._scalar_multiply(C._scalar_reduce(k), _B)
    assert _esit(C._scalar_multiply(k, _B), bek)


def test_smul_kucuk_256bit_hiz():
    """ORTAM: 256-bit skalar (< 2^255) L'yi-asar-ve-indirgenir."""
    k = 2**255
    assert k > _L
    assert _esit(C._scalar_multiply(k, _B),
                 C._scalar_multiply(C._scalar_reduce(k), _B))


# == _scalar_reduce ====================================================================================

@pytest.mark.parametrize("k,bek", [(0, 0), (1, 1), (5, 5), (_L, 0),
                                   (_L + 1, 1), (_L + 5, 5),
                                   (2 * _L, 0), (2 * _L + 7, 7)])
def test_reduce_mod_L(k, bek):
    """ORTAM-GERCEK: k mod L."""
    assert C._scalar_reduce(k) == bek


def test_reduce_donut_int():
    assert isinstance(C._scalar_reduce(2**512), int)


def test_reduce_aralik():
    """ORTAM: sonuc [ 0, L)."""
    for k in [0, 1, _L - 1, _L, 2**512]:
        assert 0 <= C._scalar_reduce(k) < _L


# == _point_compress/ _point_decompress ===============================================================

def test_compress_taban():
    """ORTAM-GERCEK: B'nin sikistirilmis-hali 32-byte."""
    out = C._point_compress(_B)
    assert len(out) == 32


def test_compress_sifir_seed_pub():
    """ORTAM-GERCEK: sifir-seed public-key RFC 8032 bilinen-degeri ( 3b6a27
    bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29)."""
    assert C._point_compress(
        C._public_point_from_seed(bytes(32))).hex() == _PUB_SIFIR


@pytest.mark.parametrize("pt", [_B, C._scalar_multiply(2, _B),
                                C._scalar_multiply(7, _B),
                                C._scalar_multiply(12345, _B),
                                C._scalar_multiply(_L - 1, _B)])
def test_compress_decompress_donusturme(pt):
    """ORTAM-GERCEK: compress( decompress( compress( pt))) == compress( pt)
    ( 32-byte little-endian y + isaret-bit)."""
    c = C._point_compress(pt)
    assert C._point_compress(C._point_decompress(c)) == c


def test_compress_neutral():
    """ORTAM-OGRENDI: birim-ogeyi sikistirir ( y=1, x=0 -> 32-byte)."""
    out = C._point_compress(_NEUTRAL)
    assert len(out) == 32
    assert int.from_bytes(out, "little") < (1 << 255)


@pytest.mark.parametrize("len_", [0, 1, 31, 33, 64])
def test_decompress_uzunluk_hatasi(len_):
    """ORTAM-OGRENDI: len != 32 -> ValueError 'Invalid Ed25519 point
    encoding length'."""
    with pytest.raises(ValueError, match="encoding length"):
        C._point_decompress(bytes(len_))


def test_decompress_aralik_hatasi():
    """ORTAM-OGRENDI: y >= p -> ValueError 'y out of field range' (
    GUVENLIK-ONEMLI: sahte-nokta-reddi)."""
    with pytest.raises(ValueError, match="field range"):
        C._point_decompress(b"\xff" * 32)


def test_decompress_aralik_sapma():
    """ORTAM: y = p ( tam-sinir) -> ValueError."""
    veri = _P.to_bytes(32, "little")
    with pytest.raises(ValueError):
        C._point_decompress(veri)


def test_decompress_y_p_eksi_bir():
    """ORTAM: y = p-1 gecerli ( max-y)."""
    veri = (_P - 1).to_bytes(32, "little")
    pt = C._point_decompress(veri)
    assert pt[1] == _P - 1


def test_decompress_isaret_bit():
    """ORTAM-OGRENDI: 255. bit x'in paritesini-tasir — ayni-y'de 2-farkli
    nokta ( x ve p-x)."""
    base = (12345).to_bytes(32, "little")
    isaretli = (12345 | (1 << 255)).to_bytes(32, "little")
    p1 = C._point_decompress(base)
    p2 = C._point_decompress(isaretli)
    assert p1[1] == p2[1] == 12345
    assert p1[0] == (_P - p2[0]) % _P


def test_decompress_donut_yapi():
    """ORTAM: ( x, y, 1, x*y mod p) tuple."""
    pt = C._point_decompress(C._point_compress(_B))
    assert len(pt) == 4 and pt[2] == 1
    assert pt[3] == (pt[0] * pt[1]) % _P


# == _sha512/ _hash_int ================================================================================

@pytest.mark.parametrize("veri,bek", [(b"", "cf83e1357eefb8bd"),
                                      (b"abc", "ddaf35a193617aba")])
def test_sha512(veri, bek):
    """ORTAM-GERCEK: SHA-512 ( hashlib ile ayni)."""
    assert C._sha512(veri).hex().startswith(bek)
    assert C._sha512(veri) == hashlib.sha512(veri).digest()


def test_sha512_uzunluk():
    assert len(C._sha512(b"")) == 64


def test_hash_int():
    """ORTAM-GERCEK: little-endian int.from_bytes( sha512( data))."""
    assert C._hash_int(b"abc") == int.from_bytes(
        C._sha512(b"abc"), "little")


def test_hash_int_aralik():
    """ORTAM: sonuc [ 0, 2^512)."""
    v = C._hash_int(b"x")
    assert 0 <= v < 2**512


def test_hash_int_deterministik():
    assert C._hash_int(b"abc") == C._hash_int(b"abc")


def test_hash_int_farkli_girdi():
    assert C._hash_int(b"abc") != C._hash_int(b"abd")


# == _expand_seed ======================================================================================

def test_expand_seed_bolme():
    """ORTAM-GERCEK: sha512( seed) -> ( [:32], [32:]) ( RFC 8032)."""
    h = C._sha512(bytes(32))
    skel, nonce = C._expand_seed(bytes(32))
    assert skel == h[:32]
    assert nonce == h[32:]


@pytest.mark.parametrize("len_", [0, 1, 16, 31, 33, 48, 64])
def test_expand_seed_uzunluk_hatasi(len_):
    """ORTAM-OGRENDI: seed 32-byte ZORUNLU -> ValueError."""
    with pytest.raises(ValueError, match="32 bytes"):
        C._expand_seed(bytes(len_))


def test_expand_seed_deterministik():
    a = C._expand_seed(bytes(32))
    b = C._expand_seed(bytes(32))
    assert a == b


def test_expand_seed_farkli():
    a = C._expand_seed(bytes(32))
    b = C._expand_seed(b"\x01" + bytes(31))
    assert a != b


# == _clamp_scalar =====================================================================================

def test_clamp_sifir_seed():
    """ORTAM-GERCEK: 32-sifir-byte -> n[31] |= 64 -> 0x4000...0000 (
    little-endian)."""
    assert C._clamp_scalar(bytes(32)) == 0x40 * (1 << 248)


@pytest.mark.parametrize("b0", [0, 1, 3, 7, 248, 255])
def test_clamp_b0_mask(b0):
    """ORTAM-OGRENDI: n[0] &= 248 — alt-3-bit-temizlenir ( group-order
    korunmasi; 2^252 alt-katlar-onlenir)."""
    out = C._clamp_scalar(bytes([b0]) + bytes(31))
    assert (out & 0xFF) % 8 == 0


@pytest.mark.parametrize("b31", [0, 1, 64, 127, 128, 200, 255])
def test_clamp_b31_mask(b31):
    """ORTAM-OGRENDI: n[31] &= 127 ( 255.bit-temizlenir) VE n[31] |= 64 (
    254.bit-set-edilir)."""
    n = bytearray(C._clamp_scalar(bytes(31) + bytes([b31])).to_bytes(
        32, "little"))
    assert n[31] == (b31 & 127) | 64


def test_clamp_donut_int():
    assert isinstance(C._clamp_scalar(bytes(32)), int)


def test_clamp_aralik():
    """ORTAM-OGRENDI: clamped-scalar her-zaman [ 2^254, 2^255) (
    GUVENLIK-ONEMLI: duzen-alt-grup saldirisini-onler)."""
    for i in range(4):
        skel = C._expand_seed(_seed(i))[0]
        v = C._clamp_scalar(skel)
        assert 2**254 <= v < 2**255


# == _public_point_from_seed ===========================================================================

def test_pub_sifir_seed():
    """ORTAM-GERCEK: bytes(32) seed -> 3b6a27bc... ( RFC 8032)."""
    assert C._point_compress(
        C._public_point_from_seed(bytes(32))).hex() == _PUB_SIFIR


@pytest.mark.parametrize("i", range(6))
def test_pub_deterministik(i):
    """ORTAM: ayni-seed ayni-public-key."""
    a = C._point_compress(C._public_point_from_seed(_seed(i)))
    b = C._point_compress(C._public_point_from_seed(_seed(i)))
    assert a == b


@pytest.mark.parametrize("i", range(5))
def test_pub_farkli_seed(i):
    """ORTAM: farkli-seedler farkli-public-key ( collision yok)."""
    a = C._point_compress(C._public_point_from_seed(_seed(i)))
    b = C._point_compress(C._public_point_from_seed(_seed(i + 1)))
    assert a != b


def test_pub_32_byte():
    assert len(C._point_compress(C._public_point_from_seed(_seed(0)))) == 32


def test_pub_clamp_uygulanir():
    """ORTAM: public = clamp( sha512( seed)[:32]) * B."""
    skel, _ = C._expand_seed(_seed(0))
    bek = C._scalar_multiply(C._clamp_scalar(skel), _B)
    assert _esit(C._public_point_from_seed(_seed(0)), bek)


# == py_sign: RFC 8032 + nacl capraz ===================================================================

def test_sign_sifir_seed_uzunluk():
    """ORTAM: imza 64-byte ( R 32 + s 32)."""
    assert len(C.py_sign(bytes(32), b"")) == 64


def test_sign_sifir_seed_deterministik():
    """ORTAM: Ed25519 DETERMINISTIK ( ayni-seed+mesaj ayni-imza)."""
    a = C.py_sign(bytes(32), b"")
    b = C.py_sign(bytes(32), b"")
    assert a == b


def test_sign_mesaj_farkli():
    """ORTAM: farkli-mesaj farkli-imza."""
    assert C.py_sign(_seed(0), b"a") != C.py_sign(_seed(0), b"b")


def test_sign_seed_farkli():
    assert C.py_sign(_seed(0), b"m") != C.py_sign(_seed(1), b"m")


def test_sign_bos_mesaj():
    """ORTAM: bos-mesaj gecerli-imza."""
    sig = C.py_sign(bytes(32), b"")
    assert len(sig) == 64


@pytest.mark.parametrize("i", range(5))
def test_sign_buyuk_mesaj(i):
    """ORTAM: 1KB-mesaj calisir ( streaming-hash)."""
    msg = bytes(range(256)) * 4
    sig = C.py_sign(_seed(i), msg)
    assert len(sig) == 64
    pub = C._point_compress(C._public_point_from_seed(_seed(i)))
    assert C.py_verify(pub, msg, sig)


def test_sign_yapi():
    """ORTAM-OGRENDI: imza = R ( 32-byte) || s ( 32-byte little-endian)."""
    sig = C.py_sign(bytes(32), b"")
    r_kismi = sig[:32]
    s_kismi = int.from_bytes(sig[32:], "little")
    assert 0 <= s_kismi < _L
    assert len(r_kismi) == 32


# == py_verify ========================================================================================

def test_verify_dogrulama():
    """ORTAM-GERCEK: py_sign + py_verify round-trip."""
    seed = _seed(0)
    pub = C._point_compress(C._public_point_from_seed(seed))
    sig = C.py_sign(seed, b"mesaj")
    assert C.py_verify(pub, b"mesaj", sig) is True


@pytest.mark.parametrize("i", range(6))
def test_verify_dogrulama_tablo(i):
    """ORTAM: 6-seed x 3-mesaj round-trip."""
    seed = _seed(i)
    pub = C._point_compress(C._public_point_from_seed(seed))
    for msg in [b"", b"abc", b"uzun-mesaj-" * 10]:
        assert C.py_verify(pub, msg, C.py_sign(seed, msg)) is True


def test_verify_yanlis_mesaj():
    """ORTAM-OGRENDI (GUVENLIK-ONEMLI): mesaj-degistirilince imza
    GECERSIZ ( forgery-reddi)."""
    seed = _seed(0)
    pub = C._point_compress(C._public_point_from_seed(seed))
    sig = C.py_sign(seed, b"mesaj")
    assert C.py_verify(pub, b"baska", sig) is not True


def test_verify_yanlis_anahtar():
    """ORTAM-OGRENDI (GUVENLIK-ONEMLI): baska-public-key ile dogrulama
    GECERSIZ ( anahtar-ikame saldirisi-reddi)."""
    seed = _seed(0)
    pub0 = C._point_compress(C._public_point_from_seed(seed))
    pub1 = C._point_compress(C._public_point_from_seed(_seed(1)))
    sig = C.py_sign(seed, b"mesaj")
    assert C.py_verify(pub1, b"mesaj", sig) is not True
    assert C.py_verify(pub0, b"mesaj", sig) is True


def test_verify_yanlis_imza():
    """ORTAM: cur-cont imza gecersiz."""
    seed = _seed(0)
    pub = C._point_compress(C._public_point_from_seed(seed))
    assert C.py_verify(pub, b"m", bytes(64)) is not True


# == nacl capraz-dogrulama ( yerel-kutuphane) =========================================================

@pytest.mark.skipif(not _HAS_NACL, reason="pynacl-yok")
@pytest.mark.parametrize("i", range(6))
def test_nacl_capraz_pub(i):
    """ORTAM-GERCEK (GUVENLIK-ONEMLI): saf-Python public-key, nacl ile
    BIREBIR-AYNI ( iki-bagimsiz-uygulama; RFC 8032-uyumlu)."""
    seed = _seed(i)
    nacl_pub = bytes(nacl.signing.SigningKey(seed).verify_key)
    py_pub = C._point_compress(C._public_point_from_seed(seed))
    assert py_pub == nacl_pub


@pytest.mark.skipif(not _HAS_NACL, reason="pynacl-yok")
@pytest.mark.parametrize("i", range(5))
@pytest.mark.parametrize("msg", [b"", b"a", b"hello world",
                                 bytes(range(64)), b"x" * 1000])
def test_nacl_capraz_isimza(i, msg):
    """ORTAM-GERCEK (GUVENLIK-ONEMLI): saf-Python imza, nacl ile BIREBIR-
    AYNI ( 25 capraz-imza; deterministik RFC 8032)."""
    seed = _seed(i)
    nacl_sig = nacl.signing.SigningKey(seed).sign(msg).signature
    assert C.py_sign(seed, msg) == nacl_sig


@pytest.mark.skipif(not _HAS_NACL, reason="pynacl-yok")
@pytest.mark.parametrize("i", range(5))
def test_nacl_verify_py_isimza(i):
    """ORTAM: py_sign imzasini nacl verify-kabul-eder."""
    seed = _seed(i)
    sig = C.py_sign(seed, b"cross")
    vk = nacl.signing.SigningKey(seed).verify_key
    assert vk.verify(b"cross", sig) is not None


@pytest.mark.skipif(not _HAS_NACL, reason="pynacl-yok")
@pytest.mark.parametrize("i", range(5))
def test_py_verify_nacl_isimza(i):
    """ORTAM: nacl imzasini py_verify kabul-eder ( geri-uyumlu)."""
    seed = _seed(i)
    vk = nacl.signing.SigningKey(seed)
    sig = vk.sign(b"cross").signature
    pub = C._point_compress(C._public_point_from_seed(seed))
    assert C.py_verify(pub, b"cross", sig) is True


# == karakterizasyon ===================================================================================

def test_ed25519_amaci():
    r"""ORTAM-OGRENDI (DOCSTACK, GUVENLIK-ONEMLI): saf-Python Ed25519 (
    RFC 8032) — did:key kimlik-protokolu-icin. _BASE_POINT = ( B_x, B_y, 1,
    B_x* B_y mod p) extended-koordinatlar; B_y = 4/5 mod p. _edwards_add
    unified-formula ( toplama+iki-kat ayni); BIRIM-OGE ( 0,1,1,0). ORTAM-
    ALTYAPI-1: extended-koordinatlarda GORUNTU-ESITLIK YOKTUR — ( x,y) =
    ( X/Z, Y/Z); ( 4X,4Y,4,4XY) ayni-nokta ( N + B == B projective-ama-
    tuple-farkli). _scalar_multiply double-and-add; L* B = birim-oge (
    taban-duzeni L = 2^252 + 27742...48493). _point_compress 32-byte
    little-endian y + 255.bit-x-paritesi; _point_decompress len != 32 VEYA
    y >= p -> ValueError. _expand_seed 32-byte-ZORUNLU; _clamp_scalar
    n[0] &= 248 ( alt-3-bit) + n[31] &= 127 | 64 ( 2^254-alt-grupsaldiri-
    onu). py_sign = R||s 64-byte DETERMINISTIK; nacl ile 25-imza BIREBIR-
    AYNI ( iki-bagimsiz-uygulama capraz-dogrulandi). sifir-seed public-key
    3b6a27bc... ( RFC 8032)."""
    assert C._P == 2**255 - 19
    assert _esit(C._scalar_multiply(_L, _B), _NEUTRAL)
    assert C._point_compress(
        C._public_point_from_seed(bytes(32))).hex() == _PUB_SIFIR

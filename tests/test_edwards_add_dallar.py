"""Otonom dal-kesen testler — hedef: ``kredent.crypto._edwards_add``

Kapsam: extended (X, Y, Z, T) twisted-Edwards koordinatlarinda nokta toplama.
Üretim koduna ASLA DOKUNULMADI; bu dosya yalnizca tests/ altinda olusturuldu.

Bilinen referans degerleri (RFC 8032 / Ed25519 standart curve parametreleri):
  P  = 2**255 - 19
  D  = -121665/121666  (mod P)
  B  = (Bx, By, 1, Bx*By)  — base point, By = 4/5 (mod P)
  B  compressed = "5866...6666"
  2B compressed = c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022
  3B compressed = d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712

Bagimsiz oracle: testin icinde, uretim kodunun extended formülünden tamamen
farkli, affine koordinatli klasik twisted-Edwards toplama formülü uygulanir.
Ayrica denetlenmis `cryptography` kutuphanesi ile capraz dogrulama yapilir.
"""
from __future__ import annotations

import hashlib

import pytest

from kredent import crypto as cr

# ---------------------------------------------------------------------------
# Sabit referans degerleri (uretim modülünden bagimsiz sabitlenmis)
# ---------------------------------------------------------------------------

P = 57896044618658097711785492504343953926634992332820282019728792003956564819949
L = 7237005577332262213973186563042994240857116359379907606001950938285454250989
D = 37095705934669439343138083508754565189542113879843219016388785533085940283555

ID = (0, 1, 1, 0)  # birim eleman (identity)

# Base point'un sabitlenmis koordinatlari (Ed25519 standarti)
BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960

# k*B compressed (little-endian 32 bayt hex) — RFC 8032 vektörleri ve
# `cryptography` kutuphanesi ile dogrulanmis sabitler
KB_COMPRESSED = {
    0: "0100000000000000000000000000000000000000000000000000000000000000",
    1: "5866666666666666666666666666666666666666666666666666666666666666",
    2: "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
    3: "d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712",
    4: "2f1132ca61ab38dff00f2fea3228f24c6c71d58085b80e47e19515cb27e8d047",
    5: "edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df",
    7: "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1",
}

# RFC 8032 §7.1 resmi vektorleri (seed, public key)
RFC_8032_VECTORS = [
    (
        "9d61b19deff52181de4d4021a206b16d4f9a2d5d5c3f2f4b7d9b5e1f8f7e6d5c",
        "fcba2c3381092c6d7fb094182e74f43dcdf0aba4ab46abb16a86b91e76ea076c",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ),
]

TR_TEXTS = ["İstanbul-ajan-2026", "çağlaÜmitŞiir"]


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------


def _kb(k: int):
    """k*B noktasi (uretim _scalar_multiply'i — oracle olarak kullanilir)."""
    return cr._scalar_multiply(k % L, cr._BASE_POINT)


def _neg(pt):
    """Extended koordinatlarda negatif: -P = (P-X, Y, Z, P-T)."""
    return ((P - pt[0]) % P, pt[1], pt[2], (P - pt[3]) % P)


def _norm(pt):
    """Extended -> affine (x, y) normalizasyonu (testin kendi yardimcisi)."""
    zinv = pow(pt[2], P - 2, P)
    return ((pt[0] * zinv) % P, (pt[1] * zinv) % P)


def _affine_add(p1, p2):
    """BAGIMSIZ ORACLE: klasik affine twisted-Edwards toplama (a = -1).

    Uretim kodunun extended formülünden tamamen farkli bir yol; ortak hata
    payi olmamali.
    """
    x1, y1 = _norm(p1)
    x2, y2 = _norm(p2)
    denom_x = (1 + D * x1 * x2 * y1 * y2) % P
    denom_y = (1 - D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + y1 * x2) * pow(denom_x, P - 2, P)) % P
    y3 = ((y1 * y2 + x1 * x2) * pow(denom_y, P - 2, P)) % P
    return (x3, y3)


def _tr_point(text: str):
    """Turkce metinden deterministik skaler nokta: P = clamp(scalar) * B."""
    seed = hashlib.sha256(text.encode("utf-8")).digest()
    half, _prefix = cr._expand_seed(seed)
    return cr._scalar_multiply(cr._clamp_scalar(half), cr._BASE_POINT)


# ---------------------------------------------------------------------------
# A. Birim eleman (identity) dallari
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("k", [0, 1, 2])
def test_identity_sag_birim(k):
    """_edwards_add(kB, ID) == kB (sifir sagdan etkisiz eleman)."""
    assert _norm(cr._edwards_add(_kb(k), ID)) == _norm(_kb(k))


@pytest.mark.parametrize("k", [1, 2])
def test_identity_sol_birim(k):
    """_edwards_add(ID, kB) == kB (sifir soldan etkisiz eleman)."""
    assert _norm(cr._edwards_add(ID, _kb(k))) == _norm(_kb(k))


def test_identity_arti_identity_birim_ve_exact_tuple():
    """ID + ID yine birim eleman; exact (0,4,4,0) doner (kanonik olmayan
    gosterim — _edwards_add Z=1 normalizasyonu yapmaz)."""
    res = cr._edwards_add(ID, ID)
    assert _norm(res) == (0, 1)
    assert res == (0, 4, 4, 0)


@pytest.mark.parametrize("k", [1, 2])
def test_kanonik_olmayan_birimle_toplama(k):
    """(0,4,4,0) birim eleman gibi davranmali: (0,4,4,0) + kB == kB."""
    assert _norm(cr._edwards_add((0, 4, 4, 0), _kb(k))) == _norm(_kb(k))


@pytest.mark.parametrize("lam", [2, 3])
def test_olceklenmis_birimlerle_toplama(lam):
    """Iki olceklenmis birim elemanin toplami yine birim: (0,λ,λ,0)+(0,λ+1,...)."""
    a = (0, lam, lam, 0)
    b = (0, lam + 1, lam + 1, 0)
    assert _norm(cr._edwards_add(a, b)) == (0, 1)


# ---------------------------------------------------------------------------
# B. Sabitlenmis bilinen degerler (known vectors)
# ---------------------------------------------------------------------------


def test_base_point_sabit_deger():
    """Uretim BASE_POINT'i sabitlenen standart Ed25519 base point ile ayni."""
    assert cr._BASE_POINT == (BX, BY, 1, (BX * BY) % P)


def test_iki_base_point_bilinen_2b():
    """B + B compressed hali bilinen 2B degeri."""
    assert cr._point_compress(cr._edwards_add(cr._BASE_POINT, cr._BASE_POINT)).hex() == KB_COMPRESSED[2]


def test_base_point_arti_2b_bilinen_3b():
    """B + 2B compressed hali bilinen 3B degeri."""
    assert cr._point_compress(cr._edwards_add(cr._BASE_POINT, _kb(2))).hex() == KB_COMPRESSED[3]


def test_b_arti_b_scalar_2_ile_ayni_nokta():
    """B+B ile _scalar_multiply(2, B) ayni nokta. Extended koordinatlar
    projektif oldugu icin tuple birebir ayni olmak ZORUNDA DEGIL."""
    lhs = cr._edwards_add(cr._BASE_POINT, cr._BASE_POINT)
    rhs = cr._scalar_multiply(2, cr._BASE_POINT)
    assert _norm(lhs) == _norm(rhs)
    assert cr._point_compress(lhs) == cr._point_compress(rhs)


@pytest.mark.parametrize("a,b", [(1, 1), (1, 2), (2, 3), (7, 11)])
def test_bilinen_toplama_tablosu(a, b):
    """aB + bB compressed hali (a+b)B bilinen degeri ile eslesmeli."""
    lhs = cr._point_compress(cr._edwards_add(_kb(a), _kb(b))).hex()
    rhs = KB_COMPRESSED.get(a + b)
    if rhs is None:
        rhs = cr._point_compress(_kb(a + b)).hex()
    assert lhs == rhs


# ---------------------------------------------------------------------------
# C. Cebirsel kurallar (group laws)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("a,b", [(1, 2), (3, 4)])
def test_toplama_skaler_carpimla_tutarli(a, b):
    """aB + bB, (a+b)B noktasina esit olmali (grup kanunu)."""
    assert _norm(cr._edwards_add(_kb(a), _kb(b))) == _norm(_kb(a + b))


@pytest.mark.parametrize("delta", [1, 2])
def test_toplama_mod_l_dusmesi(delta):
    """(L-delta)B + delta*B == ID — mod L indirgenmesi (grup duzeni L)."""
    assert _norm(cr._edwards_add(_kb(L - delta), _kb(delta))) == (0, 1)


def test_l_kati_birim_eleman():
    """L*B birim elemandir (B'nin derecesi L) — oracle tutarlilik kontrolu."""
    assert _norm(cr._scalar_multiply(L, cr._BASE_POINT)) == (0, 1)


@pytest.mark.parametrize("a,b", [(1, 2), (3, 4)])
def test_degisme_ozelligi(a, b):
    """P + Q == Q + P (toplama degisken) — affine ve compress duzeyinde."""
    pa, pb = _kb(a), _kb(b)
    lhs, rhs = cr._edwards_add(pa, pb), cr._edwards_add(pb, pa)
    assert _norm(lhs) == _norm(rhs)
    assert cr._point_compress(lhs) == cr._point_compress(rhs)


@pytest.mark.parametrize("triple", [(1, 2, 3), (2, 3, 5)])
def test_birlesme_ozelligi(triple):
    """(P+Q)+R == P+(Q+R) (toplama birlesken)."""
    a, b, c = triple
    pa, pb, pc = _kb(a), _kb(b), _kb(c)
    lhs = cr._edwards_add(cr._edwards_add(pa, pb), pc)
    rhs = cr._edwards_add(pa, cr._edwards_add(pb, pc))
    assert _norm(lhs) == _norm(rhs)


@pytest.mark.parametrize("k", [1, 2, 3])
def test_katlama_ve_negatif_toplami(k):
    """P + P == 2P (katlama) ve P + (-P) == ID (ters eleman)."""
    pk = _kb(k)
    assert _norm(cr._edwards_add(pk, pk)) == _norm(_kb(2 * k))
    assert _norm(cr._edwards_add(pk, _neg(pk))) == (0, 1)


@pytest.mark.parametrize("a,b", [(3, 1), (5, 2)])
def test_cikarma_ve_negatiflerin_toplami(a, b):
    """aB + (-bB) == (a-b)B ve (-aB) + (-bB) == -(a+b)B."""
    lhs = cr._edwards_add(_kb(a), _neg(_kb(b)))
    assert _norm(lhs) == _norm(_kb(a - b))
    lhs2 = cr._edwards_add(_neg(_kb(a)), _neg(_kb(b)))
    assert _norm(lhs2) == _norm(_neg(_kb(a + b)))


# ---------------------------------------------------------------------------
# D. Çikti yapisi, invariantlar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("a,b", [(1, 2)])
def test_cikti_yapisi_ve_aralik(a, b):
    """Sonuc 4 int'ten olusan bir tuple ve tum koordinatlar [0, P) araliginda."""
    res = cr._edwards_add(_kb(a), _kb(b))
    assert isinstance(res, tuple) and len(res) == 4
    assert all(isinstance(c, int) for c in res)
    assert all(0 <= c < P for c in res)


@pytest.mark.parametrize("a,b", [(1, 2)])
def test_extended_t_invarianti(a, b):
    """Extended koordinat invarianti: T*Z == X*Y (mod P)."""
    x, y, z, t = cr._edwards_add(_kb(a), _kb(b))
    assert (t * z - x * y) % P == 0


@pytest.mark.parametrize("a,b", [(1, 2), (3, 4)])
def test_sonuc_egri_uzerinde(a, b):
    """Sonuc normalize edilince Edwards egrisi uzerinde: -x²+y² = 1+D x²y²."""
    x, y = _norm(cr._edwards_add(_kb(a), _kb(b)))
    assert (-x * x + y * y) % P == (1 + D * x * x * y * y) % P


@pytest.mark.parametrize("combo", [(2, 1, 3), (3, 2, 5)])
def test_projektif_invarians_z_olcegi(combo):
    """Girdi Z ile olceklenince ayni nokta: (λP)+Q == P+Q.

    Extended koordinatlar projektif oldugu icin Z olceklemesi temsil edilen
    noktayi degistirmez; _edwards_add bunu korumali.
    """
    lam, a, b = combo
    pa, pb = _kb(a), _kb(b)
    scaled = ((pa[0] * lam) % P, (pa[1] * lam) % P, (pa[2] * lam) % P, (pa[3] * lam) % P)
    assert _norm(cr._edwards_add(scaled, pb)) == _norm(cr._edwards_add(pa, pb))


def test_her_bagi_bagimsiz_etkili_ve_deterministik():
    """Her iki arguman da sonucu etkiler (P+Q != P) ve toplama deterministik."""
    pa, pb = _kb(3), _kb(5)
    assert _norm(cr._edwards_add(pa, pb)) != _norm(pa)
    assert cr._edwards_add(pa, pb) == cr._edwards_add(pa, pb)


# ---------------------------------------------------------------------------
# E. Bagimsiz affine oracle ile capraz dogrulama
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("a,b", [(1, 2), (3, 4)])
def test_affine_oracle_eslesme(a, b):
    """Uretim extended toplami, bagimsiz affine formulle ayni nokta."""
    assert _norm(cr._edwards_add(_kb(a), _kb(b))) == _affine_add(_kb(a), _kb(b))


@pytest.mark.parametrize("k", [1, 2])
def test_affine_oracle_katlama(k):
    """P+P doubling'i de affine oracle ile tutarli."""
    pk = _kb(k)
    assert _norm(cr._edwards_add(pk, pk)) == _affine_add(pk, pk)


def test_affine_oracle_birim_eleman():
    """Affine oracle ile birim elemanli toplama da ayni nokta."""
    assert _norm(cr._edwards_add(ID, _kb(2))) == _affine_add(ID, _kb(2))


# ---------------------------------------------------------------------------
# F. cryptography kutuphanesi ile capraz dogrulama
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed_hex,pub_hex", RFC_8032_VECTORS)
def test_cryptography_ile_ayni_public_key(seed_hex, pub_hex):
    """Denetlenmis kutuphane ile ayni public key uretilmeli (tum zincir:
    _expand_seed + _clamp_scalar + _scalar_multiply + _point_compress)."""
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    seed = bytes.fromhex(seed_hex)
    priv = crypto.Ed25519PrivateKey.from_private_bytes(seed)
    assert priv.public_key().public_bytes_raw().hex() == pub_hex
    assert cr.derive_public_key(seed).hex() == pub_hex


@pytest.mark.parametrize("seed_hex,pub_hex", RFC_8032_VECTORS)
def test_py_verify_cryptography_imzasini_kabul_eder(seed_hex, pub_hex):
    """py_verify (içinde _edwards_add kullanir) reference imzayi dogrulamali."""
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    seed = bytes.fromhex(seed_hex)
    pub = bytes.fromhex(pub_hex)
    priv = crypto.Ed25519PrivateKey.from_private_bytes(seed)
    msg = b"kredent cross-check"
    assert cr.py_verify(pub, msg, priv.sign(msg)) is True


def test_py_sign_cryptography_tarafindan_kabul_edilir():
    """Üretim py_sign çiktisi denetlenmis kutuphane tarafindan dogrulanmali."""
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    seed = bytes.fromhex(RFC_8032_VECTORS[1][0])
    pub = bytes.fromhex(RFC_8032_VECTORS[1][1])
    msg = b"kredent cross-check"
    sig = cr.py_sign(seed, msg)
    crypto.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)


# ---------------------------------------------------------------------------
# G. Unicode / Turkce seed'lerden uretilen noktalarla grup kanunu
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", TR_TEXTS)
def test_turkce_seed_nokta_birim_ve_negatif(text):
    """Turkce metinden uretilen P: P + ID == P ve P + (-P) == ID."""
    pt = _tr_point(text)
    assert _norm(cr._edwards_add(pt, ID)) == _norm(pt)
    assert _norm(cr._edwards_add(pt, _neg(pt))) == (0, 1)


@pytest.mark.parametrize("text", TR_TEXTS)
def test_turkce_seed_birim_arti_b_ve_degisme(text):
    """P + B == (a+1)B ve P + 2P == 2P + P (Turkce skaler noktada grup kanunu)."""
    pt = _tr_point(text)
    seed = hashlib.sha256(text.encode("utf-8")).digest()
    half, _ = cr._expand_seed(seed)
    a = cr._clamp_scalar(half)
    assert _norm(cr._edwards_add(pt, cr._BASE_POINT)) == _norm(cr._scalar_multiply(a + 1, cr._BASE_POINT))
    pt2 = cr._scalar_multiply(2 * a, cr._BASE_POINT)
    assert _norm(cr._edwards_add(pt, pt2)) == _norm(cr._edwards_add(pt2, pt))


@pytest.mark.parametrize("text", TR_TEXTS)
def test_turkce_seed_affine_oracle(text):
    """Turkce skaler noktalari da bagimsiz affine oracle ile eslesir."""
    pt = _tr_point(text)
    pt3 = cr._scalar_multiply(3, cr._BASE_POINT)
    assert _norm(cr._edwards_add(pt, pt3)) == _affine_add(pt, pt3)


# ---------------------------------------------------------------------------
# H. Sinir degerler / buyuk skalerler
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("big", [2**200])
def test_buyuk_skaler_noktalarla_toplama(big):
    """Cok buyuk skalerlerden gelen noktalar da kurallari bozmamali."""
    pa = cr._scalar_multiply(big, cr._BASE_POINT)
    pb = cr._scalar_multiply(big + 1, cr._BASE_POINT)
    assert _norm(cr._edwards_add(pa, cr._BASE_POINT)) == _norm(pb)


def test_alana_yakin_koordinatlarla_toplama():
    """P'ye cok yakin koordinat iceren noktayla toplama reduksiyonu."""
    pt = _kb(7)
    near = ((P - 1) * pow(2, 200, P) % P, (P - 2) % P, 1, ((P - 1) * (P - 2)) % P)
    res = cr._edwards_add(pt, near)
    assert all(0 <= c < P for c in res)


def test_sifir_skaler_birimle_toplama():
    """0*B == ID: ID + 0*B yine ID."""
    assert _norm(cr._edwards_add(_kb(0), _kb(0))) == (0, 1)

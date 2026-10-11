"""kredent.mcp_server ozel-tool-handler dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (dict argumanlar, tmp_path uzerinde store — transport/
stdio/network YOK). mcp.type'lar sadece ic-aktarim icin import edilir.
Kural-5: TEST beklentileri uretime GORE yazildi; once `python3 -c` ile PROBE edildi.

Hedefler: _tool_attest + _tool_verify + _make_result (module-level,
col_offset==0). test_mcp.py call_tool() genel-erisim entegrasyonudur; BU dosya
OZEL handler'lari dogrudan cagirip tum if/elif/else/raise dallarini keser.
"""
import json
import sys

import pytest

sys.path.insert(0, ".")
from kredent import mcp_server as m  # noqa: E402
from kredent.attest import create_attestation  # noqa: E402
from kredent.crypto import generate_seed  # noqa: E402
from kredent.store import store_identity  # noqa: E402


# == _tool_attest: claim dogrulama dalı ===============================================================

@pytest.mark.parametrize("claim", [None, "not-a-dict", 5, 3.14, [], ["a"], (), {}])
def test_tool_attest_rejects_bad_or_empty_claim(tmp_path, claim):
    """ORTAM-ANATOMI: `not isinstance(claim, dict) or not claim` -> ValueError.

    Bos dict DAHIL: `or not claim` kosisi {}'yi yakalar. Tuple/list de
    isinstance(dict) kontrolundan dolayi reddedilir.
    """
    with pytest.raises(ValueError, match="attest requires a non-empty 'claim' object"):
        m._tool_attest({"claim": claim, "seed_hex": "00" * 32})


@pytest.mark.parametrize("claim", [{"": None}, {"a": 1}, {"a": 1, "b": [1, 2]}, {"x": None, "y": True}])
def test_tool_attest_nonempty_claim_passes_tool_gate(tmp_path, claim):
    """ORTAM-OGRENDI: tool KATMANI sadece dict+non-empty kontrolu yapar.

    `{"": None}` non-empty dict oldugu icin tool'dan GECER ve
    create_attestation DAHI kabul eder (bos ANAHTAR reddedilmez, yalnizca
    bos OBJECT reddedilir). Sonuc gecerli bir attestation'dir.
    """
    out = m._tool_attest({"claim": claim, "seed_hex": generate_seed().hex()})
    assert out["claim"] == claim
    assert m._tool_verify({"attestation": out})["valid"] is True


def test_tool_attest_empty_claim_rejected_by_both_layers(tmp_path):
    """ORTAM: bos dict HER IKI katman tarafindan reddedilir.

    ORTAM-OGRENDI: tool 'attest requires a non-empty claim object' verir;
    create_attestation ise 'attestation claim must be a non-empty JSON object'
    verir — ayni kural, farkli mesaj, farkli katman.
    """
    with pytest.raises(ValueError, match="attest requires a non-empty 'claim' object"):
        m._tool_attest({"claim": {}, "seed_hex": generate_seed().hex()})


def test_tool_attest_missing_claim_key(tmp_path):
    """ORTAM-ANATOMI: args.get('claim') -> None -> ValueError (dict ERISIMI YOK)."""
    with pytest.raises(ValueError, match="attest requires a non-empty 'claim' object"):
        m._tool_attest({"seed_hex": "00" * 32})


def test_tool_attest_empty_args(tmp_path):
    """ORTAM-ANATOMI: bos args -> claim None -> ValueError."""
    with pytest.raises(ValueError, match="attest requires a non-empty 'claim' object"):
        m._tool_attest({})


# == _tool_attest: name dalı ===========================================================================

@pytest.mark.parametrize("name", ["agent-a", "agent.b", "x" * 50])
def test_tool_attest_by_name_signs_with_stored_seed(tmp_path, name):
    """ORTAM-ANATOMI: name varsa identity_exists kontrolu, sonra load_identity(name).seed."""
    seed = generate_seed()
    store_identity(name, seed)
    out = m._tool_attest({"claim": {"a": 1}, "name": name})
    assert out["issuer"]  # did:key dolar
    assert out["claim"] == {"a": 1}
    assert out["type"] == "KredentAttestation"


@pytest.mark.parametrize("name", ["ghost", "missing", "nobody"])
def test_tool_attest_by_missing_name_raises(tmp_path, name):
    """ORTAM-ANATOMI: identity_exists(name) False -> ValueError('No stored identity named ...')."""
    with pytest.raises(ValueError) as exc:
        m._tool_attest({"claim": {"a": 1}, "name": name})
    assert f"No stored identity named {name!r}" in str(exc.value)


def test_tool_attest_name_takes_precedence_over_seed_hex(tmp_path):
    """ORTAM-ANATOMI: `if name:` dalı `elif seed_hex:` dalindan ÖNCE gelir."""
    seed = generate_seed()
    other = generate_seed()
    assert seed != other
    store_identity("primary", seed)
    out = m._tool_attest({"claim": {"a": 1}, "name": "primary", "seed_hex": other.hex()})
    _, _, _, did = __import__(
        "kredent.crypto", fromlist=["keypair_from_seed"]
    ).keypair_from_seed(seed)
    assert out["issuer"] == did


def test_tool_attest_name_triggers_no_disk_lookup_for_seed_hex(tmp_path):
    """ORTAM: name dalinda seed_hex hic okunmaz (elif kisa-devre)."""
    store_identity("real", generate_seed())
    # gecersiz seed_hex olsa da name dalı kazanar
    out = m._tool_attest({"claim": {"a": 1}, "name": "real", "seed_hex": "zz"})
    assert out["claim"] == {"a": 1}


# == _tool_attest: seed_hex dalı =======================================================================

@pytest.mark.parametrize("idx", [0, 1, 17, 255])
def test_tool_attest_by_valid_seed_hex(tmp_path, idx):
    """ORTAM-ANATOMI: gecerli 64-karakter hex -> 32 bayt seed ile imzalar."""
    seed = bytes([idx]) * 32
    out = m._tool_attest({"claim": {"a": 1}, "seed_hex": seed.hex()})
    _, _, _, did = __import__(
        "kredent.crypto", fromlist=["keypair_from_seed"]
    ).keypair_from_seed(seed)
    assert out["issuer"] == did


@pytest.mark.parametrize("bad", ["zz", "abc", "g", "xyz123"])
def test_tool_attest_invalid_hex_raises(tmp_path, bad):
    """ORTAM-ANATOMI: bytes.fromhex ValueError -> ValueError('not valid hexadecimal').

    ORTAM-OGRENDI-1: mesaj 'seed_hex is not valid hexadecimal' — burada
    SystemExit DEGIL ValueError (CLI'dan farkli: MCP transport hatayi
    tool-error olarak yuzeyler).
    """
    with pytest.raises(ValueError, match="seed_hex is not valid hexadecimal"):
        m._tool_attest({"claim": {"a": 1}, "seed_hex": bad})


@pytest.mark.parametrize("nbytes", [1, 16, 31, 33, 64])
def test_tool_attest_wrong_seed_length_raises(tmp_path, nbytes):
    """ORTAM-ANATOMI: gecerli hex ama != 32 bayt -> ValueError('exactly 32 bytes')."""
    with pytest.raises(ValueError, match="seed_hex must decode to exactly 32 bytes"):
        m._tool_attest({"claim": {"a": 1}, "seed_hex": bytes(nbytes).hex()})


def test_tool_attest_empty_seed_hex_falls_through(tmp_path):
    """ORTAM-OGRENDI-2: `elif seed_hex:` truthiness — '' falsy -> else dalı.

    Bos string gecerli-hex kontrolune GIRMEZ; 'requires either' hatasi verir.
    """
    with pytest.raises(ValueError, match="attest requires either 'name' or 'seed_hex'"):
        m._tool_attest({"claim": {"a": 1}, "seed_hex": ""})


# == _tool_attest: hicbiri yok dalı ====================================================================

def test_tool_attest_requires_name_or_seed_hex(tmp_path):
    """ORTAM-ANATOMI: name ve seed_hex ikisi de yok -> ValueError."""
    with pytest.raises(ValueError, match="attest requires either 'name' or 'seed_hex'"):
        m._tool_attest({"claim": {"a": 1}})


@pytest.mark.parametrize("name", [None, ""])
def test_tool_attest_falsy_name_falls_through(tmp_path, name):
    """ORTAM-OGRENDI-3: `if name:` truthiness — bos string None gibi davranir."""
    with pytest.raises(ValueError, match="attest requires either 'name' or 'seed_hex'"):
        m._tool_attest({"claim": {"a": 1}, "name": name})


# == _tool_attest: cikti anatomisi =====================================================================

@pytest.mark.parametrize("key", [
    "claim", "id", "issued_at", "issuer", "kid", "nonce", "proof", "type",
])
def test_tool_attest_output_keys(tmp_path, key):
    """ORTAM-ANATOMI: cikti create_attestation(...).to_dict() ile birebir ayni."""
    seed = generate_seed()
    out = m._tool_attest({"claim": {"a": 1}, "seed_hex": seed.hex()})
    assert key in out


def test_tool_attest_id_is_content_addressed(tmp_path):
    """ORTAM-ANATOMI: id 'att:<issuer-multibase>:<digest16>:<nonce>' formatinda.

    ORTAM-OGRENDI: id'nin 2. alani TAM did DEGIL, multibase kisimidir
    (did:key:z6Mk... -> z6Mk...), bu yuzden split(':') tam olarak 4 parca
    verir ve parts[1] out['issuer'] icinde GOMULUDUR.
    """
    seed = generate_seed()
    out = m._tool_attest({"claim": {"a": 1}, "seed_hex": seed.hex()})
    parts = out["id"].split(":")
    assert parts[0] == "att"
    assert len(parts) == 4
    assert len(parts[2]) == 16
    assert out["issuer"].endswith(parts[1])
    assert parts[3] == out["nonce"]


def test_tool_attest_is_verifiable(tmp_path):
    """ORTAM: tool tarafindan uretilen attestation gercekten dogrulanir."""
    from kredent.attest import verify_attestation

    out = m._tool_attest({"claim": {"action": "deployed"}, "seed_hex": generate_seed().hex()})
    result = verify_attestation(out)
    assert result.valid


def test_tool_attest_expires_at_passthrough(tmp_path):
    """ORTAM-ANATOMI: args.get('expires_at') create_attestation'a aktarilir."""
    out = m._tool_attest({
        "claim": {"a": 1},
        "seed_hex": generate_seed().hex(),
        "expires_at": "2099-01-01T00:00:00Z",
    })
    assert out["expires_at"] == "2099-01-01T00:00:00Z"


def test_tool_attest_without_expires_at(tmp_path):
    """ORTAM: expires_at verilmezse None kalir (create_attestation varsayilan)."""
    out = m._tool_attest({"claim": {"a": 1}, "seed_hex": generate_seed().hex()})
    assert out.get("expires_at") is None


def test_tool_attest_deterministic_for_same_claim_and_seed(tmp_path):
    """ORTAM: ayni seed+claim -> ayni issuer; id nonce yuzunden FARKLI.

    ORTAM-OGRENDI-4: id icerisinde rastgele nonce oldugu icin ayni girdi
    BILE her cagirida farkli id uretir (id deterministic DEGIL, ama
    issuer/claim deterministic).
    """
    seed = generate_seed()
    a = m._tool_attest({"claim": {"a": 1}, "seed_hex": seed.hex()})
    b = m._tool_attest({"claim": {"a": 1}, "seed_hex": seed.hex()})
    assert a["issuer"] == b["issuer"]
    assert a["claim"] == b["claim"]
    assert a["id"] != b["id"]
    assert a["nonce"] != b["nonce"]


# == _tool_verify: giris dogrulama dalı =================================================================

@pytest.mark.parametrize("doc", [None, "string", 5, 3.14, [], ["a"], b"bytes"])
def test_tool_verify_requires_dict(tmp_path, doc):
    """ORTAM-ANATOMI: `not isinstance(doc, dict)` -> ValueError."""
    with pytest.raises(ValueError, match="verify requires an 'attestation' object"):
        m._tool_verify({"attestation": doc})


def test_tool_verify_missing_key(tmp_path):
    """ORTAM-ANATOMI: args.get('attestation') -> None -> ValueError."""
    with pytest.raises(ValueError, match="verify requires an 'attestation' object"):
        m._tool_verify({})


def test_tool_verify_empty_dict_is_accepted(tmp_path):
    """ORTAM-OGRENDI-5: {} isinstance(dict) GECER, ValueError VERMEZ.

    Bos dict verify_attestation'a gider ve orada MISSING_ISSUER (400) olur —
    ValueError dogrulama KATMANINDA degil, is mantiginda verilir.
    """
    out = m._tool_verify({"attestation": {}})
    assert out["valid"] is False
    assert out["status_code"] == 400


# == _tool_verify: gecerli attestation ===================================================================

@pytest.mark.parametrize("claim", [{"a": 1}, {"action": "deployed", "v": "1.2"}, {"z": 1, "a": 2}])
def test_tool_verify_valid_attestation(tmp_path, claim):
    """ORTAM-ANATOMI: gecerli imza -> valid True, status 200.

    NOT: bos claim create_attestation'da reddedildigi icin burada YOKTUR
    (bkz. test_tool_attest_nonempty_claim_passes_tool_gate).
    """
    seed = generate_seed()
    doc = create_attestation(seed, claim).to_dict()
    out = m._tool_verify({"attestation": doc})
    assert out["valid"] is True
    assert out["status_code"] == 200
    assert out["agent_id"] == doc["issuer"]
    assert "verified" in out["message"]


def test_tool_verify_output_has_no_error_code_when_valid(tmp_path):
    """ORTAM-ANATOMI: `if result.error_code` False -> 'error_code' ANAHTARI YOK."""
    doc = create_attestation(generate_seed(), {"a": 1}).to_dict()
    out = m._tool_verify({"attestation": doc})
    assert "error_code" not in out
    assert set(out.keys()) == {"valid", "status_code", "agent_id", "message"}


# == _tool_verify: gecersiz attestation (error_code dallari) =============================================

def test_tool_verify_tampered_claim(tmp_path):
    """ORTAM-ANATOMI: claim degistirildi -> INVALID_SIGNATURE + error_code."""
    doc = create_attestation(generate_seed(), {"a": 1}).to_dict()
    doc["claim"] = {"a": 999}
    out = m._tool_verify({"attestation": doc})
    assert out["valid"] is False
    assert out["error_code"] == "INVALID_SIGNATURE"
    assert out["status_code"] == 401


def test_tool_verify_forged_signature(tmp_path):
    """ORTAM: imza baska bir anahtarla yapildi -> INVALID_SIGNATURE.

    ORTAM-OGRENDI: proof anahtari 'proofValue' DEGIL 'proof_value'
    (W3C Data Integrity snake-case sozlesmesi).
    """
    doc = create_attestation(generate_seed(), {"a": 1}).to_dict()
    other = create_attestation(generate_seed(), {"a": 1}).to_dict()
    doc["proof"]["proof_value"] = other["proof"]["proof_value"]
    out = m._tool_verify({"attestation": doc})
    assert out["valid"] is False
    assert out["error_code"] == "INVALID_SIGNATURE"


def test_tool_verify_missing_issuer(tmp_path):
    """ORTAM-ANATOMI: issuer yok -> MISSING_ISSUER (400)."""
    out = m._tool_verify({"attestation": {"foo": "bar"}})
    assert out["valid"] is False
    assert out["error_code"] == "MISSING_ISSUER"
    assert out["agent_id"] is None


def test_tool_verify_expired(tmp_path):
    """ORTAM-ANATOMI: expires_at gecmiste -> ATTESTATION_EXPIRED (check_expiry True)."""
    doc = create_attestation(generate_seed(), {"a": 1}, expires_at="2020-01-01T00:00:00Z").to_dict()
    out = m._tool_verify({"attestation": doc})
    assert out["valid"] is False
    assert out["error_code"] == "ATTESTATION_EXPIRED"


def test_tool_verify_ignore_expiry_true_rescues_expired(tmp_path):
    """ORTAM-ANATOMI: ignore_expiry True -> check_expiry=False -> imza gecerli."""
    doc = create_attestation(generate_seed(), {"a": 1}, expires_at="2020-01-01T00:00:00Z").to_dict()
    out = m._tool_verify({"attestation": doc, "ignore_expiry": True})
    assert out["valid"] is True
    assert out["status_code"] == 200
    assert "error_code" not in out


def test_tool_verify_ignore_expiry_false_checks_expiry(tmp_path):
    """ORTAM: ignore_expiry explicit False -> süre kontrolu YAPILIR."""
    doc = create_attestation(generate_seed(), {"a": 1}, expires_at="2020-01-01T00:00:00Z").to_dict()
    out = m._tool_verify({"attestation": doc, "ignore_expiry": False})
    assert out["valid"] is False
    assert out["error_code"] == "ATTESTATION_EXPIRED"


@pytest.mark.parametrize("truthy", [True, 1, "yes", 1.0])
def test_tool_verify_ignore_expiry_truthy_values(tmp_path, truthy):
    """ORTAM-OGRENDI-6: `not args.get('ignore_expiry', False)` truthiness —
    her truthy deger sure kontrolunu kapatir (sadece True DEGIL)."""
    doc = create_attestation(generate_seed(), {"a": 1}, expires_at="2020-01-01T00:00:00Z").to_dict()
    out = m._tool_verify({"attestation": doc, "ignore_expiry": truthy})
    assert out["valid"] is True


@pytest.mark.parametrize("falsy", [False, 0, "", None])
def test_tool_verify_ignore_expiry_falsy_values(tmp_path, falsy):
    """ORTAM: falsy degerler sure kontrolunu ACIK birakir."""
    doc = create_attestation(generate_seed(), {"a": 1}, expires_at="2020-01-01T00:00:00Z").to_dict()
    out = m._tool_verify({"attestation": doc, "ignore_expiry": falsy})
    assert out["valid"] is False


def test_tool_verify_uses_tool_attest_output_directly(tmp_path):
    """ORTAM: _tool_attest ciktisi _tool_verify girdisi olarak birebir uyusur."""
    doc = m._tool_attest({"claim": {"a": 1}, "seed_hex": generate_seed().hex()})
    out = m._tool_verify({"attestation": doc})
    assert out["valid"] is True
    assert out["agent_id"] == doc["issuer"]


# == _make_result =======================================================================================

def test_make_result_text_content():
    """ORTAM-ANATOMI: payload json.dumps(indent=2, ensure_ascii=False, default=str)."""
    res = m._make_result({"a": 1})
    assert len(res.content) == 1
    assert res.content[0].type == "text"
    assert json.loads(res.content[0].text) == {"a": 1}


@pytest.mark.parametrize("payload,expected", [
    ({"a": 1}, '{\n  "a": 1\n}'),
    ([1, 2], '[\n  1,\n  2\n]'),
    ({}, '{}'),
    (None, "null"),
    ("plain", '"plain"'),
])
def test_make_result_json_indentation(payload, expected):
    """ORTAM-ANATOMI: cikti 2-bosluk girintili JSON."""
    res = m._make_result(payload)
    assert res.content[0].text == expected


def test_make_result_default_is_not_error():
    """ORTAM-ANATOMI: is_error varsayilani False."""
    res = m._make_result({"a": 1})
    assert res.is_error is False


def test_make_result_error_flag():
    """ORTAM-ANATOMI: is_error=True -> CallToolResult.is_error True."""
    res = m._make_result({"error": "boom"}, is_error=True)
    assert res.is_error is True


@pytest.mark.parametrize("is_error", [True, False])
def test_make_result_error_flag_passthrough(is_error):
    """ORTAM: bayrak dogrudan CallToolResult'a gecer."""
    assert m._make_result({"x": 1}, is_error=is_error).is_error is is_error


def test_make_result_default_str_for_non_json_types():
    """ORTAM-ANATOMI: default=str — datetime gibi tipler str()'e duser (crash YOK)."""
    import datetime

    res = m._make_result({"d": datetime.datetime(2026, 1, 2, 3, 4, 5)})
    assert res.content[0].text == '{\n  "d": "2026-01-02 03:04:05"\n}'


def test_make_result_preserves_unicode():
    """ORTAM-ANATOMI: ensure_ascii=False — Unicode ham kalir."""
    res = m._make_result({"ad": "çağla", "jp": "日本語"})
    text = res.content[0].text
    assert "çağla" in text
    assert "日本語" in text
    assert "\\u" not in text


def test_make_result_returns_call_tool_result():
    """ORTAM-ANATOMI: donus tipi mcp.types.CallToolResult (transport tarafindan kullanilir)."""
    from mcp.types import CallToolResult

    assert isinstance(m._make_result({"a": 1}), CallToolResult)


def test_make_result_error_payload_roundtrip():
    """ORTAM: handler hatasi _make_result ile tool-error'a cevrilir (build_server ile ayni)."""
    res = m._make_result({"error": "seed_hex is not valid hexadecimal"}, is_error=True)
    assert json.loads(res.content[0].text) == {"error": "seed_hex is not valid hexadecimal"}
    assert res.is_error is True

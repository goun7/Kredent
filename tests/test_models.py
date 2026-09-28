"""
Tests for Kredent data models and serialization.
"""

import json

import pytest

from kredent.models import (
    AgentID,
    Attestation,
    AttestationProof,
    CalibrationEvent,
    ReputationScore,
    VerificationKey,
)


def test_agent_id_valid(sample_agent):
    assert sample_agent.agent_id.startswith("did:key:z6Mk")
    key = sample_agent.get_key("sig-ed25519-primary")
    assert key is not None
    assert key.key_type == "Ed25519VerificationKey2020"
    assert not key.revoked


def test_agent_id_invalid_format():
    vkey = VerificationKey(
        kid="k1",
        key_type="Ed25519VerificationKey2020",
        public_key_multibase="z6Mk1234",
        purposes=["attestation"],
    )
    with pytest.raises(ValueError, match="Invalid Kredent agent identifier"):
        AgentID(
            agent_id="invalid:agent:id",
            version="1.0.0",
            created_at="2026-09-13T00:00:00Z",
            controller="did:legal:test",
            keys=[vkey],
            capabilities=["test"],
        )


def test_agent_id_requires_a_key():
    with pytest.raises(ValueError, match="at least one verification key"):
        AgentID(agent_id="did:key:z6Mk1234", keys=[], capabilities=[])


def test_agent_id_accepts_legacy_form_on_read():
    """The Roboseal-era identifier is tolerated so old documents still load."""
    vkey = VerificationKey(kid="k1", public_key_multibase="z6Mk1234")
    agent = AgentID(agent_id="did:agent:68:key:z6Mk1234", keys=[vkey], capabilities=[])
    assert agent.is_legacy is True


def test_agent_id_json_serialization(sample_agent):
    json_str = sample_agent.to_json()
    parsed = json.loads(json_str)
    assert parsed["agent_id"] == sample_agent.agent_id
    assert parsed["controller"] == "did:legal:tr:vkn:1234567890"

    reconstructed = AgentID.from_json(json_str)
    assert reconstructed.agent_id == sample_agent.agent_id
    assert reconstructed.controller == sample_agent.controller
    assert len(reconstructed.keys) == 1
    assert reconstructed.keys[0].public_key_multibase == sample_agent.keys[0].public_key_multibase


def test_get_key_skips_revoked():
    vkey = VerificationKey(kid="k1", public_key_multibase="z6Mk1234", revoked=True)
    agent = AgentID(agent_id="did:key:z6Mk1234", keys=[vkey], capabilities=[])
    assert agent.get_key() is None


def test_calibration_event_roundtrip():
    evt = CalibrationEvent(
        event_id="evt_01",
        agent_id="did:key:z6Mku7X",
        event_type="contradiction",
        claim_ref="claim_1",
        evidence_hash="sha256:abcd",
        timestamp="2026-09-13T01:00:00Z",
        score_impact=-0.25,
    )
    d = evt.to_dict()
    assert d["event_id"] == "evt_01"
    assert d["event_type"] == "contradiction"
    assert d["score_impact"] == -0.25
    assert CalibrationEvent.from_dict(d).event_id == "evt_01"


def test_reputation_score_rounds_on_serialization():
    score = ReputationScore(
        score=0.123456789,
        base_score=0.5,
        reliability=0.9,
        accuracy=0.9,
        stability=0.9,
        contradiction_rate=0.1,
        volume_damping=0.4,
        tier="TIER_B",
        total_transactions=10,
        total_claims=8,
        refuted_claims=1,
    )
    d = score.to_dict()
    assert d["score"] == 0.1235
    assert d["tier"] == "TIER_B"


def test_attestation_model_roundtrip():
    proof = AttestationProof(verification_method="did:key:z6Mkabc#z6Mkabc", proof_value="v")
    att = Attestation(
        id="att:x",
        issuer="did:key:z6Mkabc",
        claim={"action": "deployed"},
        proof=proof,
    )
    parsed = Attestation.from_dict(att.to_dict())
    assert parsed.issuer == "did:key:z6Mkabc"
    assert parsed.claim == {"action": "deployed"}
    assert parsed.proof is not None
    assert parsed.proof.proof_value == "v"


def test_attestation_from_json_string():
    text = '{"id":"att:x","issuer":"did:key:z6Mkabc","claim":{"a":1},"proof":null}'
    att = Attestation.from_json(text)
    assert att.proof is None
    assert att.claim == {"a": 1}

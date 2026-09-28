"""
Tests for the CalibrationLedger: event storage, sliding windows and the
asymmetric penalty that keeps the cost of a contradiction above the value of a
confirmation.
"""

from datetime import datetime, timedelta, timezone

import pytest

from kredent import create_attestation, generate_seed
from kredent.ledger import CalibrationLedger
from kredent.models import CalibrationEvent


def test_calibration_ledger_events():
    ledger = CalibrationLedger()
    agent_id = "did:key:z6MkTestAgent"

    now_iso = datetime.now(timezone.utc).isoformat()
    for i, etype in enumerate(("claim", "confirmation", "contradiction")):
        ledger.record_event(
            CalibrationEvent(
                event_id=f"e{i}",
                agent_id=agent_id,
                event_type=etype,
                claim_ref="claim_lat",
                evidence_hash=f"sha256:{i}",
                timestamp=now_iso,
            )
        )

    assert len(ledger) == 3
    assert len(ledger.get_agent_events(agent_id)) == 3

    stats = ledger.get_agent_stats(agent_id, window_days=90)
    assert stats["total_claims"] == 1
    assert stats["confirmations"] == 1
    assert stats["contradictions"] == 1
    # Asymmetric weighting: (1*2.0) / (1 + 1*2.0) = 2/3 ~ 0.6667
    assert 0.66 <= stats["effective_contradiction_rate"] <= 0.67


def test_calibration_ledger_window_filtering():
    ledger = CalibrationLedger()
    agent_id = "did:key:z6MkTestAgentOld"
    now = datetime.now(timezone.utc)

    ledger.record_event(
        CalibrationEvent(
            event_id="e_old",
            agent_id=agent_id,
            event_type="contradiction",
            claim_ref="claim_old",
            evidence_hash="sha256:old",
            timestamp=(now - timedelta(days=120)).isoformat(),
        )
    )
    ledger.record_event(
        CalibrationEvent(
            event_id="e_rec",
            agent_id=agent_id,
            event_type="confirmation",
            claim_ref="claim_rec",
            evidence_hash="sha256:rec",
            timestamp=(now - timedelta(days=10)).isoformat(),
        )
    )

    stats = ledger.get_agent_stats(agent_id, window_days=90, now=now)
    assert stats["contradictions"] == 0
    assert stats["confirmations"] == 1
    assert stats["effective_contradiction_rate"] == 0.0


def test_ledger_export_import_roundtrip():
    ledger = CalibrationLedger()
    ledger.record_event(
        CalibrationEvent(
            event_id="e1",
            agent_id="did:key:z6MkA",
            event_type="claim",
            claim_ref="c1",
            evidence_hash="h1",
            timestamp="2026-09-13T00:00:00Z",
        )
    )
    exported = ledger.export_events()
    assert len(exported) == 1

    other = CalibrationLedger()
    other.import_events(exported)
    assert len(other) == 1
    assert other.export_events() == exported


def test_record_attestation_produces_events():
    ledger = CalibrationLedger()
    seed = generate_seed()
    att = create_attestation(seed, {"action": "deployed"})

    claim_evt = ledger.record_attestation(att, event_type="claim")
    confirm_evt = ledger.record_attestation(att, event_type="confirmation")

    assert claim_evt.event_type == "claim"
    assert claim_evt.agent_id == att.issuer
    assert claim_evt.score_impact == 0.0
    assert confirm_evt.event_type == "confirmation"
    assert confirm_evt.score_impact == 1.0
    assert confirm_evt.claim_ref == att.id


def test_unparseable_timestamp_is_not_silently_dropped():
    """An auditor must be able to see malformed records, not have them hidden."""
    ledger = CalibrationLedger()
    agent_id = "did:key:z6MkB"
    ledger.record_event(
        CalibrationEvent(
            event_id="e_bad",
            agent_id=agent_id,
            event_type="claim",
            claim_ref="c1",
            evidence_hash="h1",
            timestamp="not-a-timestamp",
        )
    )
    # No window filter is applied because the timestamp cannot be parsed.
    assert len(ledger.get_agent_events(agent_id)) == 1


def test_agent_events_are_scoped_by_agent():
    ledger = CalibrationLedger()
    for agent in ("did:key:z6MkA", "did:key:z6MkB"):
        ledger.record_event(
            CalibrationEvent(
                event_id=f"e_{agent[-1]}",
                agent_id=agent,
                event_type="claim",
                claim_ref="c",
                evidence_hash="h",
                timestamp="2026-09-13T00:00:00Z",
            )
        )
    assert len(ledger.get_agent_events("did:key:z6MkA")) == 1
    assert len(ledger.get_agent_events("did:key:z6MkB")) == 1

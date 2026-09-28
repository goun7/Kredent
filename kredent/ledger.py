"""
The calibration ledger: an append-only record of claims, confirmations and
contradictions.

Reputation has to be grounded in something observable, otherwise it is opinion.
The ledger is that ground: it records what an agent claimed, and what later
happened to that claim. Reputation is then a pure function of the ledger, which
means any auditor can recompute it and check that a reported score is not
invented.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .models import CalibrationEvent


class CalibrationLedger:
    """Append-only ledger of agent calibration events.

    Penality dynamics are deliberately asymmetric: a contradiction carries twice
    the weight of a confirmation. A history is therefore harder to farm than to
    lose, which is the correct direction for a trust signal.
    """

    CONTRADICTION_WEIGHT = 2.0
    CONFIRMATION_WEIGHT = 1.0

    def __init__(self) -> None:
        self._events: List[CalibrationEvent] = []

    def __len__(self) -> int:
        return len(self._events)

    def record_event(self, event: CalibrationEvent) -> None:
        """Append a new event. The ledger is append-only; events are immutable."""
        self._events.append(event)

    def record_attestation(
        self,
        attestation,
        event_type: str = "claim",
        timestamp: Optional[str] = None,
    ) -> CalibrationEvent:
        """Record a ledger event for an attestation object.

        ``event_type`` is ``claim`` when an attestation is first made,
        ``confirmation`` when it is independently verified, and
        ``contradiction`` when it is refuted.
        """
        from .canonical import sha256_hex

        claim_ref = getattr(attestation, "id", None) or ""
        agent_id = getattr(attestation, "issuer", None) or ""
        evidence = sha256_hex(
            (getattr(attestation, "nonce", "") + claim_ref + agent_id).encode("utf-8")
        )
        event = CalibrationEvent(
            event_id=f"evt:{sha256_hex((claim_ref + event_type).encode('utf-8'))[:24]}",
            agent_id=agent_id,
            event_type=event_type,
            claim_ref=claim_ref,
            evidence_hash=evidence,
            timestamp=timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            score_impact={
                "claim": 0.0,
                "confirmation": 1.0,
                "contradiction": -2.0,
            }.get(event_type, 0.0),
        )
        self.record_event(event)
        return event

    def get_agent_events(
        self,
        agent_id: str,
        since: Optional[datetime] = None,
    ) -> List[CalibrationEvent]:
        """Events for ``agent_id``, optionally only those after ``since``."""
        results = []
        for e in self._events:
            if e.agent_id != agent_id:
                continue
            if since is not None:
                try:
                    event_dt = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
                    if event_dt < since:
                        continue
                except Exception:
                    # An unparseable timestamp should not silently drop an event;
                    # it should be visible to an auditor. Keep it.
                    pass
            results.append(e)
        return results

    def get_agent_stats(
        self,
        agent_id: str,
        window_days: int = 90,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Aggregate claim/confirmation/contradiction counts over a window."""
        current_dt = now if now is not None else datetime.now(timezone.utc)
        if current_dt.tzinfo is None:
            current_dt = current_dt.replace(tzinfo=timezone.utc)
        since_dt = current_dt - timedelta(days=window_days)

        events = self.get_agent_events(agent_id, since=since_dt)

        claims = 0
        confirmations = 0
        contradictions = 0

        for e in events:
            if e.event_type == "claim":
                claims += 1
            elif e.event_type == "confirmation":
                confirmations += 1
            elif e.event_type == "contradiction":
                contradictions += 1

        total_evaluations = confirmations + contradictions
        if total_evaluations > 0:
            effective_contradiction_rate = min(
                1.0,
                (contradictions * self.CONTRADICTION_WEIGHT)
                / (confirmations + (contradictions * self.CONTRADICTION_WEIGHT)),
            )
        else:
            effective_contradiction_rate = 0.0

        return {
            "agent_id": agent_id,
            "window_days": window_days,
            "total_claims": claims,
            "confirmations": confirmations,
            "contradictions": contradictions,
            "effective_contradiction_rate": round(effective_contradiction_rate, 4),
            "total_events": len(events),
        }

    def export_events(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]

    def import_events(self, data: List[Dict[str, Any]]) -> None:
        for item in data:
            self._events.append(CalibrationEvent.from_dict(item))


__all__ = ["CalibrationLedger"]

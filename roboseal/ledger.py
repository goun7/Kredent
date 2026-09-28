"""
CalibrationLedger implementation for managing claims, confirmations, and contradictions.
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timezone, timedelta
from roboseal.models import CalibrationEvent


class CalibrationLedger:
    """
    Append-only ledger tracking agent capability claims and empirical validations.
    Enforces asymmetric penalty dynamics (2:1 penalization vs restoration).
    """

    def __init__(self) -> None:
        self._events: List[CalibrationEvent] = []

    def record_event(self, event: CalibrationEvent) -> None:
        """Appends a new event to the ledger."""
        self._events.append(event)

    def get_agent_events(
        self,
        agent_id: str,
        since: Optional[datetime] = None,
    ) -> List[CalibrationEvent]:
        """Returns events for a specific agent filtered by timestamp."""
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
                    pass
            results.append(e)
        return results

    def get_agent_stats(
        self,
        agent_id: str,
        window_days: int = 90,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Computes total claims, confirmations, contradictions, and effective contradiction rate
        over a sliding window (default 90 days).
        """
        current_dt = now if now is not None else datetime.now(timezone.utc)
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

        # Asymmetric effective contradiction count:
        # Each contradiction has a weight of 2.0; each confirmation only redeems 1.0 of credit.
        total_evaluations = confirmations + contradictions
        if total_evaluations > 0:
            effective_contradiction_rate = min(1.0, (contradictions * 2.0) / (confirmations + (contradictions * 2.0)))
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
            self._events.append(
                CalibrationEvent(
                    event_id=item["event_id"],
                    agent_id=item["agent_id"],
                    event_type=item["event_type"],
                    claim_ref=item["claim_ref"],
                    evidence_hash=item["evidence_hash"],
                    timestamp=item["timestamp"],
                    challenger=item.get("challenger"),
                    arbitration_receipt=item.get("arbitration_receipt"),
                    score_impact=float(item.get("score_impact", 0.0)),
                )
            )

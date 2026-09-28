"""
Reputation scoring for Kredent agents.

Reputation here is not a secret score handed down by a platform. It is a
deterministic, published function of observable events, so that any party can
recompute it from the same ledger and arrive at the same number. That property
— reproducibility — is what makes a reputation trustworthy enough to act on.

The model combines three behaviour signals, penalises contradicted claims, and
applies cold-start damping so a freshly minted identity cannot buy credibility
with a handful of cherry-picked events.
"""

from __future__ import annotations

import math
from typing import Dict, List, Tuple

from .models import ReputationScore

# Model weights (v1.0). They sum to 0.85; the base score is renormalised by the
# sum so that a perfect agent scores exactly 1.0.
W_REL = 0.40  # reliability: did the agent do what it said it would
W_ACC = 0.30  # accuracy: were its assertions correct
W_STAB = 0.15  # stability: how consistent over time
W_TOTAL = W_REL + W_ACC + W_STAB  # 0.85

# A contradicted claim costs more than a confirmed one gains. Asymmetric
# penalisation keeps the cost of lying above the benefit of a fabricated history.
LAMBDA_PENALTY = 0.50

# Cold-start damping: an agent needs roughly N0 events before its score
# approaches its true level.
N0_DAMPING = 30.0

# Above this share of an agent's volume flowing to a single counterparty, the
# pattern is consistent with a collusion ring rather than genuine activity.
COLLUSION_RATIO_THRESHOLD = 0.35

TIER_A_THRESHOLD = 0.85
TIER_B_THRESHOLD = 0.60
QUARANTINE_THRESHOLD = 0.30


def compute_volume_damping(n: int, n0: float = N0_DAMPING) -> float:
    """Cold-start damping factor ``1 - exp(-n / n0)``.

    With one event an agent reaches ~3% of its nominal score; with N0 events
    ~63%. This is the mechanism that makes a brand-new identity cheap to create
    but expensive to make look established.
    """
    if n <= 0:
        return 0.0
    return 1.0 - math.exp(-float(n) / n0)


def compute_reputation_score(
    reliability: float,
    accuracy: float,
    stability: float,
    total_claims: int,
    refuted_claims: int,
    total_transactions: int,
    is_quarantined: bool = False,
    attestations_verified: int = 0,
) -> ReputationScore:
    """Compute the canonical Kredent reputation score, normalized to [0, 1]."""
    rel = max(0.0, min(1.0, float(reliability)))
    acc = max(0.0, min(1.0, float(accuracy)))
    stab = max(0.0, min(1.0, float(stability)))

    if total_claims <= 0:
        contra_rate = 0.0
    else:
        contra_rate = max(0.0, min(1.0, float(refuted_claims) / float(total_claims)))

    raw_base = (W_REL * rel) + (W_ACC * acc) + (W_STAB * stab)
    base_score = raw_base / W_TOTAL

    integrity_multiplier = max(0.0, 1.0 - (LAMBDA_PENALTY * contra_rate))
    damping = compute_volume_damping(total_transactions, N0_DAMPING)
    raw_score = base_score * integrity_multiplier * damping

    tier = evaluate_agent_tier(
        score=raw_score,
        refuted_claims=refuted_claims,
        is_quarantined=is_quarantined,
    )

    return ReputationScore(
        score=raw_score,
        base_score=base_score,
        reliability=rel,
        accuracy=acc,
        stability=stab,
        contradiction_rate=contra_rate,
        volume_damping=damping,
        tier=tier,
        total_transactions=total_transactions,
        total_claims=total_claims,
        refuted_claims=refuted_claims,
        attestations_verified=attestations_verified,
    )


def evaluate_agent_tier(
    score: float,
    refuted_claims: int,
    is_quarantined: bool = False,
) -> str:
    """Map a score and penalty state to an authorization tier."""
    if is_quarantined or score < QUARANTINE_THRESHOLD:
        return "QUARANTINED"
    if score >= TIER_A_THRESHOLD and refuted_claims == 0:
        return "TIER_A"
    if score >= TIER_B_THRESHOLD:
        return "TIER_B"
    return "TIER_C"


def detect_collusion_cycle(
    transaction_records: List[Tuple[str, str, float]],
    target_agent: str,
    counterparty_agent: str,
    threshold: float = COLLUSION_RATIO_THRESHOLD,
) -> Tuple[bool, float]:
    """Flag volume skew between two agents that suggests a collusion ring.

    Returns ``(detected, ratio)`` where ``ratio`` is the share of the target's
    total volume that flows to/from the single counterparty. Reputation farming
    needs a partner to trade with; concentrating volume in one place is its
    tell.
    """
    target_total = 0.0
    pair_volume = 0.0

    for sender, receiver, amount in transaction_records:
        if sender == target_agent or receiver == target_agent:
            target_total += amount
            if (sender == target_agent and receiver == counterparty_agent) or (
                sender == counterparty_agent and receiver == target_agent
            ):
                pair_volume += amount

    if target_total <= 0.0:
        return False, 0.0

    ratio = pair_volume / target_total
    return ratio > threshold, ratio


def apply_eigentrust_weights(
    counterparty_reputations: List[float],
    success_flags: List[bool],
) -> float:
    """Weight each interaction by the counterparty's own reputation.

    A swarm of zero-reputation identities confirming each other is the other
    classic farming pattern. Weighting by counterparty reputation means praise
    from unproven agents counts for almost nothing.
    """
    if not counterparty_reputations or len(counterparty_reputations) != len(success_flags):
        return 0.0

    total_weight = 0.0
    weighted_success = 0.0

    for rep, succ in zip(counterparty_reputations, success_flags):
        w = max(0.01, min(1.0, rep))
        total_weight += w
        if succ:
            weighted_success += w

    if total_weight <= 0.0:
        return 0.0
    return weighted_success / total_weight


def reputation_from_events(
    agent_id: str,
    events: List,
    *,
    reliability: float = 0.9,
    accuracy: float = 0.9,
    stability: float = 0.9,
) -> ReputationScore:
    """Compute a reputation score from ledger events for an agent.

    ``events`` are :class:`~kredent.models.CalibrationEvent` objects (or dicts
    shaped like them). Confirmations raise the score; contradictions cost doubly.
    """
    total_claims = 0
    confirmations = 0
    contradictions = 0
    verified = 0

    for event in events:
        etype = getattr(event, "event_type", None) or (
            event.get("event_type") if isinstance(event, dict) else None
        )
        if etype == "claim":
            total_claims += 1
        elif etype == "confirmation":
            confirmations += 1
            verified += 1
        elif etype == "contradiction":
            contradictions += 1

    total_evaluations = confirmations + contradictions
    if total_evaluations > 0:
        effective_contradiction_rate = min(
            1.0, (contradictions * 2.0) / (confirmations + (contradictions * 2.0))
        )
    else:
        effective_contradiction_rate = 0.0

    refuted = int(round(effective_contradiction_rate * max(total_claims, total_evaluations)))

    return compute_reputation_score(
        reliability=reliability,
        accuracy=accuracy,
        stability=stability,
        total_claims=max(total_claims, total_evaluations),
        refuted_claims=refuted,
        total_transactions=total_evaluations,
        attestations_verified=verified,
    )


__all__ = [
    "compute_volume_damping",
    "compute_reputation_score",
    "evaluate_agent_tier",
    "detect_collusion_cycle",
    "apply_eigentrust_weights",
    "reputation_from_events",
]

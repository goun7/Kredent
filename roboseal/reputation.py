"""
Roboseal mathematical reputation scoring engine and anti-gaming filters.
"""

from typing import List, Tuple, Dict
import math
from roboseal.models import ReputationScore

# Mathematical Model Weights (v1.0 Standard)
W_REL = 0.40
W_ACC = 0.30
W_STAB = 0.15
W_TOTAL = W_REL + W_ACC + W_STAB  # 0.85
LAMBDA_PENALTY = 0.50
N0_DAMPING = 30.0

# Collusion detection threshold
COLLUSION_RATIO_THRESHOLD = 0.35


def compute_volume_damping(n: int, n0: float = N0_DAMPING) -> float:
    """
    Computes cold-start damping factor: 1 - exp(-n / n0).
    Ensures that newly spun-up agents cannot claim a high reputation score
    with only 1 or 2 cherry-picked transactions.
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
) -> ReputationScore:
    """
    Computes the canonical Roboseal multi-factor reputation score.
    Normalized to [0.0, 1.0].
    """
    # Bound inputs [0.0, 1.0]
    rel = max(0.0, min(1.0, float(reliability)))
    acc = max(0.0, min(1.0, float(accuracy)))
    stab = max(0.0, min(1.0, float(stability)))

    # Contradiction rate calculation
    if total_claims <= 0:
        contra_rate = 0.0
    else:
        contra_rate = max(0.0, min(1.0, float(refuted_claims) / float(total_claims)))

    # Base Score calculation normalized by W_TOTAL
    raw_base = (W_REL * rel) + (W_ACC * acc) + (W_STAB * stab)
    base_score = raw_base / W_TOTAL

    # Integrity multiplier: (1 - lambda * contra_rate)
    integrity_multiplier = max(0.0, 1.0 - (LAMBDA_PENALTY * contra_rate))

    # Volume damping
    damping = compute_volume_damping(total_transactions, N0_DAMPING)

    # Final Score
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
    )


def evaluate_agent_tier(
    score: float,
    refuted_claims: int,
    is_quarantined: bool = False,
) -> str:
    """
    Maps numerical score and penalty status to authorization tier.
    """
    if is_quarantined or score < 0.30:
        return "QUARANTINED"
    if score >= 0.85 and refuted_claims == 0:
        return "TIER_A"
    if score >= 0.60:
        return "TIER_B"
    return "TIER_C"


def detect_collusion_cycle(
    transaction_records: List[Tuple[str, str, float]],
    target_agent: str,
    counterparty_agent: str,
    threshold: float = COLLUSION_RATIO_THRESHOLD,
) -> Tuple[bool, float]:
    """
    Detects mutual transaction skew (collusion rings/farming).
    If the volume between target_agent and counterparty_agent exceeds
    'threshold' of target_agent's total volume, returns (True, ratio).
    """
    target_total = 0.0
    pair_volume = 0.0

    for sender, receiver, amount in transaction_records:
        if sender == target_agent or receiver == target_agent:
            target_total += amount
            if (sender == target_agent and receiver == counterparty_agent) or \
               (sender == counterparty_agent and receiver == target_agent):
                pair_volume += amount

    if target_total <= 0.0:
        return False, 0.0

    ratio = pair_volume / target_total
    is_collusion = ratio > threshold
    return is_collusion, ratio


def apply_eigentrust_weights(
    counterparty_reputations: List[float],
    success_flags: List[bool],
) -> float:
    """
    Weights transaction reliability using the counterparty's own reputation score.
    Prevents Sybil swarms from inflating reliability with fake zero-reputation agents.
    """
    if not counterparty_reputations or len(counterparty_reputations) != len(success_flags):
        return 0.0

    total_weight = 0.0
    weighted_success = 0.0

    for rep, succ in zip(counterparty_reputations, success_flags):
        # Bound rep
        w = max(0.01, min(1.0, rep))
        total_weight += w
        if succ:
            weighted_success += w

    if total_weight <= 0.0:
        return 0.0
    return weighted_success / total_weight

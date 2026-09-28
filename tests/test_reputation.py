"""
Tests for mathematical reputation scoring, cold-start volume damping, and collusion filtering.
"""

import pytest
from kredent.reputation import (
    compute_reputation_score,
    compute_volume_damping,
    detect_collusion_cycle,
    apply_eigentrust_weights,
    evaluate_agent_tier,
)


def test_volume_damping():
    # 0 transactions -> 0.0
    assert compute_volume_damping(0) == 0.0

    # 30 transactions (N0) -> 1 - 1/e ≈ 0.6321
    d30 = compute_volume_damping(30)
    assert 0.63 <= d30 <= 0.64

    # 150 transactions -> > 0.99
    assert compute_volume_damping(150) > 0.99


def test_compute_reputation_score_mature_agent():
    # High reliability, high accuracy, high stability, zero contradictions, 100 transactions
    score = compute_reputation_score(
        reliability=1.0,
        accuracy=1.0,
        stability=1.0,
        total_claims=10,
        refuted_claims=0,
        total_transactions=150,
    )
    # normalized base_score = (0.4*1 + 0.3*1 + 0.15*1) / 0.85 = 1.00
    assert round(score.base_score, 2) == 1.00
    assert score.contradiction_rate == 0.0
    assert score.score > 0.85
    assert score.tier == "TIER_A"


def test_compute_reputation_score_penalized_contradiction():
    # 5 out of 10 claims refuted -> contradiction_rate = 0.50
    # multiplier = 1 - 0.5 * 0.5 = 0.75
    score = compute_reputation_score(
        reliability=0.90,
        accuracy=0.85,
        stability=0.80,
        total_claims=10,
        refuted_claims=5,
        total_transactions=100,
    )
    assert score.contradiction_rate == 0.50
    # Because refuted_claims > 0, cannot be TIER_A even if score is moderate
    assert score.tier in ["TIER_B", "TIER_C"]


def test_collusion_detection():
    agent_a = "did:agent:68:key:zAlice"
    agent_b = "did:agent:68:key:zBob"
    agent_c = "did:agent:68:key:zCharlie"

    # Transactions list: (sender, receiver, amount)
    # Total volume involving Alice = 100 + 10 = 110. Volume with Bob = 100 / 110 ≈ 90.9% (> 35%)
    txs = [
        (agent_a, agent_b, 50.0),
        (agent_b, agent_a, 50.0),
        (agent_a, agent_c, 10.0),
    ]

    is_collusion, ratio = detect_collusion_cycle(txs, agent_a, agent_b, threshold=0.35)
    assert is_collusion is True
    assert ratio > 0.90

    # Normal dispersed trade: Alice with Charlie = 10 / 110 ≈ 9.1% (< 35%)
    is_collusion_c, ratio_c = detect_collusion_cycle(txs, agent_a, agent_c, threshold=0.35)
    assert is_collusion_c is False


def test_eigentrust_counterparty_weighting():
    # 3 counterparties:
    # 1. Reputable agent (score 0.90), success True
    # 2. Sybil bot (score 0.01), success True
    # 3. Mid agent (score 0.50), success False
    scores = [0.90, 0.01, 0.50]
    successes = [True, True, False]

    weighted_rel = apply_eigentrust_weights(scores, successes)
    # Total weight = 0.90 + 0.01 + 0.50 = 1.41
    # Successful weight = 0.90 + 0.01 = 0.91
    # Rel = 0.91 / 1.41 ≈ 0.645
    assert 0.64 <= weighted_rel <= 0.65

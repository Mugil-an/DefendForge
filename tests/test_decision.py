"""
Tests for blue_agent.decision — action space, PPO policy,
confidence routing, and decision engine.
"""

from __future__ import annotations

import numpy as np
import pytest

from blue_agent.schemas import AttackEvent, DecisionPath, PPODecision, Severity


# =========================================================================
# Action Space
# =========================================================================
class TestActionSpace:
    def test_default_has_10_actions(self):
        from blue_agent.decision.action_space import ActionSpace
        space = ActionSpace()
        assert space.n_actions == 10
        assert len(space) == 10

    def test_get_by_id(self):
        from blue_agent.decision.action_space import ActionSpace
        space = ActionSpace()
        a = space.get(6)
        assert a.name == "apply_known_patch"
        assert a.requires_validation is True

    def test_get_by_name(self):
        from blue_agent.decision.action_space import ActionSpace
        space = ActionSpace()
        a = space.get_by_name("block_source_ip")
        assert a.action_id == 1

    def test_invalid_id_raises(self):
        from blue_agent.decision.action_space import ActionSpace
        space = ActionSpace()
        with pytest.raises(ValueError):
            space.get(99)

    def test_invalid_name_raises(self):
        from blue_agent.decision.action_space import ActionSpace
        space = ActionSpace()
        with pytest.raises(ValueError):
            space.get_by_name("launch_nukes")

    def test_is_escalation(self):
        from blue_agent.decision.action_space import ActionSpace, DefensiveAction
        space = ActionSpace()
        assert space.is_escalation(DefensiveAction.ESCALATE_TO_LLM) is True
        assert space.is_escalation(DefensiveAction.BLOCK_SOURCE_IP) is False

    def test_action_names(self):
        from blue_agent.decision.action_space import ActionSpace
        space = ActionSpace()
        names = space.action_names()
        assert "no_action" in names
        assert "escalate_to_llm" in names
        assert len(names) == 10


# =========================================================================
# Confidence Tracker
# =========================================================================
class TestConfidenceTracker:
    def test_below_threshold_escalates(self):
        from blue_agent.decision.confidence import ConfidenceTracker
        tracker = ConfidenceTracker(threshold=0.80)
        assert tracker.should_escalate(0.79) is True
        assert tracker.should_escalate(0.80) is False
        assert tracker.should_escalate(0.95) is False

    def test_record_and_stats(self):
        from blue_agent.decision.confidence import ConfidenceTracker, ConfidenceRecord
        tracker = ConfidenceTracker(threshold=0.80)
        tracker.record(ConfidenceRecord(ppo_confidence=0.90, action=1, escalated=False, decision_latency_ms=5.0))
        tracker.record(ConfidenceRecord(ppo_confidence=0.60, action=8, escalated=True, decision_latency_ms=3.0))

        assert tracker.total_decisions == 2
        assert tracker.escalation_count == 1
        assert abs(tracker.escalation_rate - 0.5) < 1e-6
        assert abs(tracker.mean_confidence - 0.75) < 1e-6

    def test_stats_dict(self):
        from blue_agent.decision.confidence import ConfidenceTracker
        tracker = ConfidenceTracker(threshold=0.80)
        s = tracker.stats()
        assert "threshold" in s
        assert s["total_decisions"] == 0

    def test_reset(self):
        from blue_agent.decision.confidence import ConfidenceTracker, ConfidenceRecord
        tracker = ConfidenceTracker(threshold=0.80)
        tracker.record(ConfidenceRecord(ppo_confidence=0.90, action=1, escalated=False, decision_latency_ms=5.0))
        tracker.reset()
        assert tracker.total_decisions == 0


# =========================================================================
# PPO Policy (rule-based fallback, no trained model)
# =========================================================================
class TestPPOPolicy:
    def test_decide_sql_injection(self):
        from blue_agent.decision.ppo_policy import PPOPolicy
        from blue_agent.decision.action_space import DefensiveAction
        policy = PPOPolicy()
        event = AttackEvent(
            attack_type="SQL Injection",
            anomaly_score=0.85,
            detection_confidence=0.9,
            endpoint="/login",
            severity=Severity.HIGH,
        )
        decision = policy.decide(event)
        assert isinstance(decision, PPODecision)
        assert decision.action == DefensiveAction.APPLY_KNOWN_PATCH
        assert decision.confidence > 0.7

    def test_decide_unknown_high_anomaly(self):
        from blue_agent.decision.ppo_policy import PPOPolicy
        from blue_agent.decision.action_space import DefensiveAction
        policy = PPOPolicy()
        event = AttackEvent(
            attack_type="",
            anomaly_score=0.85,
            detection_confidence=0.5,
            endpoint="/api/something",
            severity=Severity.HIGH,
        )
        decision = policy.decide(event)
        # Unknown high anomaly → should escalate
        assert decision.action == DefensiveAction.ESCALATE_TO_LLM

    def test_decide_low_anomaly(self):
        from blue_agent.decision.ppo_policy import PPOPolicy
        from blue_agent.decision.action_space import DefensiveAction
        policy = PPOPolicy()
        event = AttackEvent(
            attack_type="",
            anomaly_score=0.3,
            detection_confidence=0.5,
            endpoint="/health",
        )
        decision = policy.decide(event)
        assert decision.action == DefensiveAction.NO_ACTION

    def test_decide_xss(self):
        from blue_agent.decision.ppo_policy import PPOPolicy
        from blue_agent.decision.action_space import DefensiveAction
        policy = PPOPolicy()
        event = AttackEvent(
            attack_type="Cross-Site Scripting",
            anomaly_score=0.75,
            detection_confidence=0.8,
            endpoint="/greet",
            severity=Severity.MEDIUM,
        )
        decision = policy.decide(event)
        assert decision.action == DefensiveAction.APPLY_KNOWN_PATCH

    def test_observation_shape(self):
        from blue_agent.decision.ppo_policy import PPOPolicy, OBS_DIM
        policy = PPOPolicy()
        event = AttackEvent(anomaly_score=0.5, endpoint="/test")
        obs = policy._build_observation(event, {})
        assert obs.shape == (OBS_DIM,)
        assert all(0.0 <= v <= 1.0 for v in obs)


# =========================================================================
# Decision Engine (integration)
# =========================================================================
class TestDecisionEngine:
    def test_fast_path(self):
        from blue_agent.decision.decision_engine import DecisionEngine
        from blue_agent.decision.confidence import ConfidenceTracker
        engine = DecisionEngine(confidence_tracker=ConfidenceTracker(threshold=0.50))
        event = AttackEvent(
            attack_type="SQL Injection",
            anomaly_score=0.9,
            detection_confidence=0.9,
            endpoint="/login",
            severity=Severity.HIGH,
        )
        result = engine.decide(event)
        # SQL Injection with high confidence → fast path
        assert result.path == DecisionPath.FAST
        assert result.escalated is False
        assert result.confidence > 0.5

    def test_slow_path_low_confidence(self):
        from blue_agent.decision.decision_engine import DecisionEngine
        from blue_agent.decision.confidence import ConfidenceTracker
        engine = DecisionEngine(confidence_tracker=ConfidenceTracker(threshold=0.99))
        event = AttackEvent(
            attack_type="SQL Injection",
            anomaly_score=0.9,
            endpoint="/login",
            severity=Severity.HIGH,
        )
        result = engine.decide(event)
        # threshold=0.99, so almost everything escalates
        assert result.path == DecisionPath.SLOW
        assert result.escalated is True

    def test_slow_path_unknown_attack(self):
        from blue_agent.decision.decision_engine import DecisionEngine
        from blue_agent.decision.confidence import ConfidenceTracker
        engine = DecisionEngine(confidence_tracker=ConfidenceTracker(threshold=0.50))
        event = AttackEvent(
            attack_type="",
            anomaly_score=0.85,
            detection_confidence=0.5,
            endpoint="/api/weird",
            severity=Severity.HIGH,
        )
        result = engine.decide(event)
        # Unknown attack → PPO picks escalation → slow path
        assert result.path == DecisionPath.SLOW
        assert result.escalated is True

    def test_tracker_records_decisions(self):
        from blue_agent.decision.decision_engine import DecisionEngine
        engine = DecisionEngine()
        event = AttackEvent(
            attack_type="SQL Injection",
            anomaly_score=0.9,
            endpoint="/login",
            severity=Severity.HIGH,
        )
        engine.decide(event)
        engine.decide(event)
        assert engine.tracker.total_decisions == 2

    def test_decision_latency_recorded(self):
        from blue_agent.decision.decision_engine import DecisionEngine
        engine = DecisionEngine()
        event = AttackEvent(anomaly_score=0.5, endpoint="/test")
        result = engine.decide(event)
        assert result.decision_latency_ms >= 0

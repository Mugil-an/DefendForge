import json

import pytest

from red_agent.campaign import AdaptiveEvaluator
from red_agent.guardrails import SafetyViolation, TargetGuard
from red_agent.knowledge import AttackKnowledge
from red_agent.models import AttackPlan, CampaignState
from red_agent.traffic_generator import TrafficGenerator
from red_agent.campaign import SimulatedCampaign
from red_agent.planner import TargetAwarePlanner
from red_agent.provenance import signed_provenance_headers, verify_provenance
from target_platform.registry import Endpoint, RegisteredTarget


def test_attack_plan_validation():
    assert AttackPlan.from_dict({"attack_type": "xss", "endpoint": "/greet"}).attack_type == "xss"
    with pytest.raises(ValueError):
        AttackPlan.from_dict({"attack_type": "not-a-payload"})
    with pytest.raises(ValueError):
        AttackPlan("xss", endpoint="https://example.com")


def test_target_guard_rejects_external_targets():
    guard = TargetGuard()
    guard.validate("sim://target-app")
    guard.validate("http://127.0.0.1:5000")
    with pytest.raises(SafetyViolation):
        guard.validate("https://example.com")


def test_campaign_limits_and_simulation():
    campaign = SimulatedCampaign(TrafficGenerator(seed=1), max_rounds=2, max_events=2)
    traffic, _ = campaign.run()
    assert len(traffic) == 2
    assert campaign.state.rounds == 2


def test_adaptive_history_changes_next_plan():
    evaluator = AdaptiveEvaluator()
    knowledge = AttackKnowledge()
    state = CampaignState()
    first = evaluator.choose(state.history, knowledge)
    evaluator.record(state, first, detected=True)
    second = evaluator.choose(state.history, knowledge)
    assert first.attack_type == "reconnaissance"
    assert second.attack_type == "sql_injection"


def test_knowledge_retrieval_from_local_json(tmp_path):
    path = tmp_path / "knowledge.json"
    path.write_text(json.dumps([{
        "attack_type": "xss", "technique": "T1189",
        "description": "output encoding", "tags": ["web"]
    }]), encoding="utf-8")
    knowledge = AttackKnowledge.from_json(path)
    assert knowledge.get("xss").technique == "T1189"
    assert knowledge.retrieve("encoding")[0].attack_type == "xss"


def test_target_aware_planner_uses_discovery_and_audit_with_bound():
    target = RegisteredTarget(
        "payments",
        "http://127.0.0.1:8000",
        endpoints=(Endpoint("GET", "/lookup", ("q",)),),
    )
    plans = TargetAwarePlanner(target, max_events=1).plan(
        target.endpoints, {"semgrep": {"result": [{"check_id": "CWE-89"}]}}
    )
    assert len(plans) == 1
    assert plans[0]["type"] == "sql_injection"
    assert plans[0]["endpoint"] == "/lookup"


def test_red_provenance_is_signed_and_tamper_evident():
    headers = signed_provenance_headers("campaign-1", "request-1", secret="test")
    assert verify_provenance(
        "campaign-1", "request-1", headers["X-DefendForge-Signature"], secret="test"
    )
    assert not verify_provenance(
        "campaign-1", "request-2", headers["X-DefendForge-Signature"], secret="test"
    )

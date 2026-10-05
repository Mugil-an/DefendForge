import pytest
from red_agent.payloads import get_payloads, get_all_categories, AttackPayload
from red_agent.traffic_generator import TrafficGenerator
from red_agent.scenarios import list_scenarios, get_scenario, ScenarioResult
from red_agent.orchestrator import RedAgent


class TestPayloads:
    def test_get_all_categories(self):
        cats = get_all_categories()
        assert "sql_injection" in cats
        assert "xss" in cats
        assert "path_traversal" in cats
        assert len(cats) >= 7
    
    def test_get_payloads_returns_list(self):
        payloads = get_payloads("sql_injection")
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        assert all(isinstance(p, AttackPayload) for p in payloads)
    
    def test_payload_has_required_fields(self):
        payloads = get_payloads("xss")
        for p in payloads:
            assert p.payload  # not empty
            assert p.category == "xss"
            assert p.severity in ("low", "medium", "high", "critical")
            assert p.cwe_id
            assert p.target_endpoint
    
    def test_unknown_category_returns_empty(self):
        payloads = get_payloads("nonexistent")
        assert payloads == []


class TestTrafficGenerator:
    def test_generate_benign(self):
        gen = TrafficGenerator(seed=42)
        events = gen.generate_benign(5)
        assert len(events) == 5
        for e in events:
            assert "source" in e
            assert "endpoint" in e
            assert "method" in e
    
    def test_generate_attack(self):
        gen = TrafficGenerator(seed=42)
        events = gen.generate_attack("sql_injection", 3)
        assert len(events) == 3
        for e in events:
            assert "source" in e
            assert "endpoint" in e
    
    def test_generate_mixed_stream(self):
        gen = TrafficGenerator(seed=42)
        events = gen.generate_mixed_stream(total=10, benign_ratio=0.3)
        assert len(events) == 10
    
    def test_reproducibility(self):
        gen1 = TrafficGenerator(seed=123)
        gen2 = TrafficGenerator(seed=123)
        e1 = gen1.generate_benign(5)
        e2 = gen2.generate_benign(5)
        for e in e1:
            if "timestamp" in e: del e["timestamp"]
        for e in e2:
            if "timestamp" in e: del e["timestamp"]
        assert e1 == e2


class TestScenarios:
    def test_list_scenarios(self):
        names = list_scenarios()
        assert len(names) >= 6
        assert "ReconThenExploit" in names
    
    def test_get_scenario(self):
        gen = TrafficGenerator(seed=42)
        scenario = get_scenario("ReconThenExploit", gen)
        result = scenario.generate()
        assert isinstance(result, ScenarioResult)
        assert len(result.traffic) > 0
        assert len(result.ground_truth) == len(result.traffic)
    
    def test_ground_truth_format(self):
        gen = TrafficGenerator(seed=42)
        scenario = get_scenario("MultiVectorAttack", gen)
        result = scenario.generate()
        for gt in result.ground_truth:
            assert "is_attack" in gt
            assert "attack_type" in gt
            assert isinstance(gt["is_attack"], bool)


class TestRedAgent:
    def test_run_scenario(self):
        agent = RedAgent(seed=42)
        result = agent.run_scenario("BruteForceLogin")
        assert len(result.traffic) > 0
        assert len(agent.get_attack_log()) > 0
    
    def test_reset(self):
        agent = RedAgent(seed=42)
        agent.run_scenario("ReconThenExploit")
        assert len(agent.get_attack_log()) > 0
        agent.reset()
        assert len(agent.get_attack_log()) == 0
    
    def test_run_continuous(self):
        agent = RedAgent(seed=42)
        result = agent.run_continuous(total_events=15, benign_ratio=0.4)
        assert len(result.traffic) == 15

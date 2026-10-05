import json
import pytest
from blue_agent.hardening.rule_manager import RuleManager
from blue_agent.schemas import AttackEvent, Severity


class TestRuleManager:
    def setup_method(self, tmp_path_factory=None):
        pass  # Will use tmp_path fixture
    
    def test_block_ip(self, tmp_path):
        rm = RuleManager(rules_dir=str(tmp_path))
        rm.block_ip("10.0.0.99", reason="SQLi detected")
        data = json.loads((tmp_path / "ip_blocklist.json").read_text())
        assert len(data["blocked_ips"]) == 1
        assert data["blocked_ips"][0]["ip"] == "10.0.0.99"
    
    def test_block_ip_dedup(self, tmp_path):
        rm = RuleManager(rules_dir=str(tmp_path))
        rm.block_ip("10.0.0.99")
        rm.block_ip("10.0.0.99")  # duplicate
        data = json.loads((tmp_path / "ip_blocklist.json").read_text())
        assert len(data["blocked_ips"]) == 1
    
    def test_add_waf_rule(self, tmp_path):
        rm = RuleManager(rules_dir=str(tmp_path))
        rm.add_waf_rule(r"(?i)(UNION\s+SELECT)", "SQL Injection")
        data = json.loads((tmp_path / "waf_rules.json").read_text())
        assert len(data["rules"]) == 1
    
    def test_derive_rules_from_event(self, tmp_path):
        rm = RuleManager(rules_dir=str(tmp_path))
        event = AttackEvent(
            source="10.0.0.99",
            attack_type="SQL Injection",
            severity=Severity.HIGH,
            anomaly_score=0.9,
        )
        actions = rm.derive_rules_from_event(event)
        assert len(actions) > 0
        assert any("Blocked IP" in a for a in actions)
    
    def test_empty_ip_not_blocked(self, tmp_path):
        rm = RuleManager(rules_dir=str(tmp_path))
        rm.block_ip("")  # should be no-op
        data = json.loads((tmp_path / "ip_blocklist.json").read_text())
        assert len(data["blocked_ips"]) == 0
    
    def test_initialize_creates_files(self, tmp_path):
        rm = RuleManager(rules_dir=str(tmp_path))
        assert (tmp_path / "ip_blocklist.json").exists()
        assert (tmp_path / "waf_rules.json").exists()

import pytest
from unittest.mock import patch, MagicMock
from blue_agent.remediation.patch_generator import PatchGenerator
from blue_agent.schemas import AttackEvent, LLMAnalysis, Patch, PatchOrigin, Severity


class TestPatchGenerator:
    def setup_method(self):
        self.gen = PatchGenerator()
    
    def test_sqli_login_patch(self):
        event = AttackEvent(
            attack_type="SQL Injection",
            endpoint="/login",
            anomaly_score=0.9,
            severity=Severity.HIGH,
        )
        result = self.gen.generate_patch(event)
        assert result is not None
        assert isinstance(result, Patch)
        assert "target_app/app.py" in result.files_changed
        assert result.generated_by == PatchOrigin.TEMPLATE
        assert "parameterized" in result.strategy.lower() or "param" in result.strategy.lower()
    
    def test_xss_greet_patch(self):
        event = AttackEvent(
            attack_type="Cross-Site Scripting",
            endpoint="/greet",
            anomaly_score=0.85,
        )
        result = self.gen.generate_patch(event)
        assert result is not None
        assert "escape" in result.diff.lower() or "markupsafe" in result.diff.lower()
    
    def test_path_traversal_patch(self):
        event = AttackEvent(
            attack_type="Path Traversal",
            endpoint="/file",
            anomaly_score=0.8,
        )
        result = self.gen.generate_patch(event)
        assert result is not None
        assert "secure_filename" in result.diff.lower() or "werkzeug" in result.diff.lower()
    
    def test_unknown_attack_returns_none_without_analysis(self):
        event = AttackEvent(
            attack_type="Unknown",
            endpoint="/unknown",
            anomaly_score=0.7,
        )
        result = self.gen.generate_patch(event)
        assert result is None
    
    def test_patch_has_valid_diff_format(self):
        event = AttackEvent(
            attack_type="SQL Injection",
            endpoint="/login",
            anomaly_score=0.9,
        )
        result = self.gen.generate_patch(event)
        assert result is not None
        assert "---" in result.diff
        assert "+++" in result.diff
        assert "@@" in result.diff

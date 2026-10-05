"""
Tests for blue_agent.schemas — verify all Pydantic models
validate and serialize correctly.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from blue_agent.schemas import (
    AnomalyResult,
    AttackEvent,
    AuditReport,
    BlueMemoryRecord,
    DecisionPath,
    LLMAnalysis,
    MetricsSnapshot,
    Patch,
    PatchOrigin,
    PPODecision,
    Severity,
    ToolCall,
    ToolCallResult,
    ValidationDecision,
    ValidationResult,
    VulnerabilityFinding,
)


class TestVulnerabilityFinding:
    def test_defaults(self):
        f = VulnerabilityFinding(source="semgrep")
        assert f.source == "semgrep"
        assert f.severity == Severity.UNKNOWN
        assert f.vulnerability_id  # uuid generated

    def test_full_fields(self):
        f = VulnerabilityFinding(
            source="bandit",
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            file="app.py",
            line=42,
            component="B608",
            description="SQL injection",
            evidence="query = f'SELECT ...'",
        )
        assert f.cwe == "CWE-89"
        assert f.line == 42
        data = f.model_dump()
        assert data["severity"] == "critical"

    def test_json_round_trip(self):
        f = VulnerabilityFinding(source="dependency-check", cwe="CWE-502")
        j = f.model_dump_json()
        rebuilt = VulnerabilityFinding.model_validate_json(j)
        assert rebuilt.cwe == f.cwe


class TestAnomalyResult:
    def test_creation(self):
        r = AnomalyResult(is_anomaly=True, anomaly_score=0.91, confidence=0.87)
        assert r.is_anomaly is True
        assert r.anomaly_score == 0.91


class TestAttackEvent:
    def test_defaults(self):
        e = AttackEvent()
        assert e.attack_type == ""
        assert e.severity == Severity.UNKNOWN

    def test_with_features(self):
        e = AttackEvent(
            source="10.0.0.1",
            destination="10.0.0.2",
            endpoint="/login",
            attack_type="sql_injection",
            features={"request_size": 1024, "failed_logins": 5},
            anomaly_score=0.95,
        )
        assert e.features["failed_logins"] == 5


class TestPPODecision:
    def test_creation(self):
        d = PPODecision(action=6, action_name="apply_known_patch", confidence=0.92)
        assert d.action == 6
        assert d.confidence == 0.92


class TestLLMAnalysis:
    def test_schema_validation(self):
        a = LLMAnalysis(
            attack_classification="SQL Injection",
            severity=Severity.HIGH,
            root_cause="Unsanitized user input in query",
            recommended_action="parameterize_query",
            patch_required=True,
            patch_strategy="Replace f-string with parameterized query",
            hardening_actions=["input_validation", "waf_rule"],
            confidence=0.88,
        )
        assert a.patch_required is True
        assert len(a.hardening_actions) == 2


class TestPatch:
    def test_defaults(self):
        p = Patch()
        assert p.generated_by == PatchOrigin.TEMPLATE
        assert p.patch_id  # uuid

    def test_llm_origin(self):
        p = Patch(generated_by=PatchOrigin.LLM, diff="--- a/app.py\n+++ b/app.py")
        assert p.generated_by == PatchOrigin.LLM


class TestValidationResult:
    def test_accept(self):
        v = ValidationResult(
            patch_id="abc",
            tests_passed=True,
            security_checks_passed=True,
            decision=ValidationDecision.ACCEPT,
        )
        assert v.decision == ValidationDecision.ACCEPT

    def test_rollback(self):
        v = ValidationResult(
            patch_id="abc",
            decision=ValidationDecision.ROLLBACK,
            failure_reason="Unit test regression",
            failed_tests=["test_login"],
        )
        assert v.decision == ValidationDecision.ROLLBACK
        assert "test_login" in v.failed_tests


class TestBlueMemoryRecord:
    def test_full_record(self):
        r = BlueMemoryRecord(
            round=3,
            attack_type="SQL Injection",
            detected=True,
            detection_time_ms=420.0,
            decision_path=DecisionPath.FAST,
            ppo_confidence=0.92,
            remediation="parameterized_queries",
            patch_validation=ValidationDecision.ACCEPT,
            hardening=["input_validation"],
            outcome="SUCCESS",
        )
        assert r.round == 3
        data = r.model_dump()
        assert data["decision_path"] == "fast"


class TestToolCall:
    def test_creation(self):
        tc = ToolCall(
            tool_name="block_ip",
            parameters={"ip": "10.0.0.1"},
            caller="ppo_policy",
        )
        assert tc.tool_name == "block_ip"


class TestMetricsSnapshot:
    def test_defaults(self):
        m = MetricsSnapshot()
        assert m.round == 0
        assert m.detection_rate == 0.0


class TestAuditReport:
    def test_empty_report(self):
        r = AuditReport(target_path="/app")
        assert r.target_path == "/app"
        assert len(r.findings) == 0

    def test_with_findings(self):
        f = VulnerabilityFinding(source="semgrep", severity=Severity.HIGH)
        r = AuditReport(target_path="/app", findings=[f])
        assert len(r.findings) == 1

"""
Canonical data schemas shared across every Blue Agent module.

These Pydantic models are the *single source of truth* for data
flowing through the pipeline.  Every module must import from here
rather than inventing ad-hoc dicts.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DecisionPath(str, Enum):
    FAST = "fast"          # PPO handled it
    SLOW = "slow"          # LLM escalation
    MANUAL = "manual"      # operator override


class PatchOrigin(str, Enum):
    TEMPLATE = "template"
    LLM = "llm"


class ValidationDecision(str, Enum):
    ACCEPT = "ACCEPT"
    ROLLBACK = "ROLLBACK"


class RoundPhase(str, Enum):
    AUDIT = "AUDIT"
    DETECT = "DETECT"
    ANALYZE = "ANALYZE"
    REMEDIATE = "REMEDIATE"
    VALIDATE = "VALIDATE"
    HARDEN = "HARDEN"
    MEMORY = "MEMORY"
    COMPLETE = "COMPLETE"


# ---------------------------------------------------------------------------
# Vulnerability (audit output)
# ---------------------------------------------------------------------------
class VulnerabilityFinding(BaseModel):
    vulnerability_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str                        # semgrep / bandit / dependency-check
    cwe: str = ""
    severity: Severity = Severity.UNKNOWN
    file: str = ""
    line: Optional[int] = None
    component: str = ""
    description: str = ""
    evidence: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Anomaly detection output
# ---------------------------------------------------------------------------
class AnomalyResult(BaseModel):
    is_anomaly: bool
    anomaly_score: float = 0.0
    confidence: float = 0.0
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Normalized attack event
# ---------------------------------------------------------------------------
class AttackEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    destination: str = ""
    endpoint: str = ""
    attack_type: str = ""                       # may be empty
    cwe: str = ""
    mitre_technique: str = ""
    features: Dict[str, Any] = Field(default_factory=dict)
    anomaly_score: float = 0.0
    detection_confidence: float = 0.0
    evidence: List[str] = Field(default_factory=list)
    severity: Severity = Severity.UNKNOWN
    raw_logs: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# PPO action output
# ---------------------------------------------------------------------------
class PPODecision(BaseModel):
    action: int
    action_name: str = ""
    confidence: float = 0.0
    reason: str = ""
    state: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# LLM reasoning output
# ---------------------------------------------------------------------------
class LLMAnalysis(BaseModel):
    attack_classification: str = ""
    severity: Severity = Severity.UNKNOWN
    root_cause: str = ""
    affected_component: str = ""
    recommended_action: str = ""
    patch_required: bool = False
    patch_strategy: str = ""
    hardening_actions: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    reasoning_summary: str = ""


# ---------------------------------------------------------------------------
# Patch
# ---------------------------------------------------------------------------
class Patch(BaseModel):
    patch_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_id: str = ""
    files_changed: List[str] = Field(default_factory=list)
    diff: str = ""
    strategy: str = ""
    generated_by: PatchOrigin = PatchOrigin.TEMPLATE


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------
class ValidationResult(BaseModel):
    patch_id: str
    tests_passed: bool = False
    security_checks_passed: bool = False
    regression_detected: bool = False
    validation_time_ms: float = 0.0
    decision: ValidationDecision = ValidationDecision.ROLLBACK
    failure_reason: str = ""
    failed_tests: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Blue Memory record
# ---------------------------------------------------------------------------
class BlueMemoryRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    round: int = 0
    attack_type: str = ""
    detected: bool = False
    detection_time_ms: float = 0.0
    decision_path: DecisionPath = DecisionPath.FAST
    ppo_confidence: float = 0.0
    llm_escalation: bool = False
    retrieved_documents: List[str] = Field(default_factory=list)
    remediation: str = ""
    patch_id: str = ""
    patch_validation: ValidationDecision = ValidationDecision.ROLLBACK
    remediation_time_ms: float = 0.0
    hardening: List[str] = Field(default_factory=list)
    outcome: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    extra: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Audit report (aggregate)
# ---------------------------------------------------------------------------
class AuditReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_path: str = ""
    target_url: str = ""
    assets: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tool call (for safety broker)
# ---------------------------------------------------------------------------
class ToolCall(BaseModel):
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    caller: str = ""   # which component requested
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ToolCallResult(BaseModel):
    tool_name: str
    success: bool
    output: Any = None
    error: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Metrics snapshot
# ---------------------------------------------------------------------------
class MetricsSnapshot(BaseModel):
    round: int = 0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    time_to_detect_ms: float = 0.0
    time_to_remediate_ms: float = 0.0
    patch_success_rate: float = 0.0
    rollback_rate: float = 0.0
    ppo_decision_latency_ms: float = 0.0
    llm_latency_ms: float = 0.0
    llm_escalation_count: int = 0
    successful_remediations: int = 0
    failed_remediations: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

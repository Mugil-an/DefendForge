"""
Blue Agent Orchestrator — The core execution loop connecting all modules.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

from blue_agent.audit import orchestrator as audit_orchestrator
from blue_agent.config import settings
from blue_agent.decision.decision_engine import DecisionEngine
from blue_agent.decision.action_space import DefensiveAction
from blue_agent.detection.alert_manager import AlertManager
from blue_agent.detection.random_forest import RandomForestDetector
from blue_agent.hardening.rule_manager import RuleManager
from blue_agent.llm.reasoning_engine import ReasoningEngine
from blue_agent.logging_cfg import get_logger
from blue_agent.memory.repository import MemoryRepository
from blue_agent.metrics.tracker import MetricsTracker
from blue_agent.remediation.patch_generator import PatchGenerator
from blue_agent.remediation.validator import PatchValidator
from blue_agent.schemas import (
    AttackEvent,
    BlueMemoryRecord,
    DecisionPath,
    MetricsSnapshot,
    Severity,
    ToolCall,
    ValidationDecision,
    ValidationResult,
)
from blue_agent.safety.broker import register_tool, execute_tool

log = get_logger("orchestrator")


class BlueAgent:
    """
    The top-level orchestrator for the Collaborative Multi-Agent
    Cybersecurity Hardening system (Blue Agent).
    """

    def __init__(self):
        log.info("blue_agent_initializing")
        
        # Core modules
        self.audit = audit_orchestrator
        
        # Detection
        detector = RandomForestDetector()
        try:
            detector.load(str(settings.detection.model_path))
        except (FileNotFoundError, Exception):
            try:
                detector.load(str(Path(__file__).resolve().parent.parent / "models" / "random_forest_24.joblib"))
            except Exception as e:
                log.warning("detector_model_not_found_skipping_load")
        self.alert_manager = AlertManager(detector=detector)
        
        # Decision
        self.decision_engine = DecisionEngine()
        self.reasoning_engine = ReasoningEngine()
        
        # Remediation
        self.patch_gen = PatchGenerator()
        self.validator = PatchValidator()
        
        # Hardening & Memory
        self.hardening = RuleManager()
        self.memory = MemoryRepository()
        self.metrics = MetricsTracker()
        self.last_round_details: List[Dict[str, Any]] = []
        
        # Register tools with safety broker
        self._register_tools()

    def _register_tools(self):
        """Register defensive action handlers with the safety broker."""
        register_tool("block_ip", self.hardening.block_ip, {"ip_address": str, "reason": str})
        register_tool("apply_patch", self._apply_patch_handler, {"patch_id": str})
        register_tool("rate_limit", self._rate_limit_handler, {"source": str, "attack_type": str})
        register_tool("update_security_rule", self._update_rule_handler, {"attack_type": str, "source": str})
        register_tool("run_tests", self._run_tests_handler, {})
        register_tool("rollback_patch", self._rollback_handler, {"patch_id": str})

    def _apply_patch_handler(self, patch_id: str) -> str:
        """Handler for apply_patch tool."""
        return f"Patch {patch_id} application delegated to PatchValidator"

    def _rate_limit_handler(self, source: str, attack_type: str) -> str:
        """Handler for rate_limit tool."""
        pattern = f"(?i)rate_limit:{source}"
        self.hardening.add_waf_rule(pattern, f"Rate limit for {attack_type}")
        return f"Rate limit applied for {source}"

    def _update_rule_handler(self, attack_type: str, source: str) -> str:
        """Handler for update_security_rule tool."""
        from blue_agent.schemas import AttackEvent, Severity
        event = AttackEvent(source=source, attack_type=attack_type, severity=Severity.HIGH)
        actions = self.hardening.derive_rules_from_event(event)
        return f"Rules updated: {actions}"

    def _run_tests_handler(self) -> str:
        """Handler for run_tests tool."""
        return "Test execution delegated to PatchValidator"

    def _rollback_handler(self, patch_id: str) -> str:
        """Handler for rollback_patch tool."""
        return f"Rollback of {patch_id} delegated to PatchValidator"

    def ingest_knowledge(self) -> None:
        """Ingest initial RAG knowledge base."""
        from blue_agent.rag.knowledge_ingestion import ingest_initial_knowledge
        ingest_initial_knowledge(self.reasoning_engine._retriever)
        log.info("knowledge_base_ingested")

    def run_audit(self) -> None:
        """Run a full SAST/SCA audit and store the report."""
        report = self.audit.run_full_audit()
        log.info("initial_audit_complete", findings=len(report.findings))

    def process_traffic(self, raw_events: List[Dict[str, Any]]) -> List[MetricsSnapshot]:
        """
        Process a batch of traffic. Each detected attack triggers a full round.
        """
        self.metrics.increment_round()
        self.last_round_details = []
        snapshots = []
        
        # 1. Detection Phase
        t0_detect = time.perf_counter()
        try:
            alerts = self.alert_manager.process_batch(raw_events)
        except (RuntimeError, ValueError) as exc:
            log.warning("detector_schema_mismatch_failing_closed", error=str(exc))
            alerts = []
            attack_events = raw_events # Evaluate all events as suspicious when detector is down
            for event in raw_events:
                # Don't peek at ground truth 'is_attack' flag. Assume true to fail closed.
                self.metrics.record_detection(is_attack=True, detected=True, time_ms=0.0)
                
            for event in attack_events:
                self._run_llm_fallback(event, str(exc))
                
        detect_time = (time.perf_counter() - t0_detect) * 1000
        
        if not alerts and not self.last_round_details:
            log.info("no_attacks_detected")
            
        # Accurately record detection metrics
        alert_event_ids = {a.event_id for a in alerts if a.event_id}
        for event in raw_events:
            is_attack = bool(event.get("is_attack", event.get("attack_type")))
            event_id = event.get("event_id")
            detected = event_id in alert_event_ids
            self.metrics.record_detection(is_attack=is_attack, detected=detected)
            
        for event in alerts:
            # We already recorded the detection metric above, so we pass time_ms=0.0 here
            # to avoid double-counting in _run_defense_round, OR we can remove the record_detection 
            # from _run_defense_round. 
            snapshot = self._run_defense_round(event, detect_time / len(alerts) if alerts else 0.0)
            snapshots.append(snapshot)
            
        if not snapshots:
            return [self.metrics.get_snapshot()]
            
        return snapshots

    def _run_llm_fallback(self, raw_event: Dict[str, Any], detector_error: str) -> None:
        """Use the LLM when the anomaly model cannot consume the current schema."""
        attack_type = raw_event.get("attack_type") or raw_event.get("_attack_meta", {}).get(
            "attack_type", "unknown"
        )
        severity_value = str(raw_event.get("severity", "high")).lower()
        try:
            severity = Severity(severity_value)
        except ValueError:
            severity = Severity.UNKNOWN
        event = AttackEvent(
            source=str(raw_event.get("source", "unknown")),
            destination=str(raw_event.get("destination", "target")),
            endpoint=str(raw_event.get("endpoint", "/")),
            attack_type=str(attack_type),
            severity=severity,
            features=dict(raw_event.get("features") or {}),
            evidence=[f"anomaly detector unavailable: {detector_error}"],
            raw_logs=[str(raw_event)],
        )
        started = time.perf_counter()
        try:
            analysis = self.reasoning_engine.analyze_event(event)
            llm_time = (time.perf_counter() - started) * 1000
            action = analysis.recommended_action or "no_action"
            self.metrics.record_decision(
                ppo_latency_ms=0,
                escalated=True,
                llm_latency_ms=llm_time,
            )
            self.last_round_details.append({
                "event_id": event.event_id,
                "decision_path": "slow",
                "confidence": round(analysis.confidence, 4),
                "llm_escalation": True,
                "action": action,
                "defense_action": action,
                "remediation": "llm_recommended",
                "validation": "NOT_REQUIRED",
                "outcome": "OBSERVED",
                "decision_reason": "detector_schema_mismatch",
                "reasoning": analysis.reasoning_summary,
                "hardening": analysis.hardening_actions,
                "phase": "COMPLETE",
            })
            log.info(
                "llm_fallback_complete",
                attack_type=attack_type,
                action=action,
                confidence=analysis.confidence,
                time_ms=round(llm_time, 2),
            )
        except (RuntimeError, ValueError, OSError) as exc:
            log.error("llm_fallback_failed", error=str(exc), attack_type=attack_type)
            self.last_round_details.append({
                "event_id": event.event_id,
                "decision_path": "fallback",
                "confidence": None,
                "llm_escalation": False,
                "action": "block_source_ip",
                "defense_action": "block_source_ip",
                "remediation": "blocked_after_llm_failure",
                "validation": "NOT_REQUIRED",
                "outcome": "OBSERVED",
                "decision_reason": "llm_unavailable",
                "hardening": [],
                "phase": "COMPLETE",
            })

    def _run_defense_round(self, event: AttackEvent, detect_time_ms: float) -> MetricsSnapshot:
        """Run the full defense pipeline for a single attack event."""
        log.info("defense_round_started", event_id=event.event_id, type=event.attack_type)
        
        record = BlueMemoryRecord(
            round=self.metrics._rounds,
            attack_type=event.attack_type,
            detected=True,
            detection_time_ms=detect_time_ms,
        )
        # Removed record_detection here to prevent double-counting, 
        # since it is now accurately tracked in process_traffic per raw_event.
        if detect_time_ms > 0:
            self.metrics._detection_times.append(detect_time_ms)
        
        # 2. Decision Phase (Fast/Slow Routing)
        decision_result = self.decision_engine.decide(event)
        record.decision_path = decision_result.path
        record.ppo_confidence = decision_result.confidence
        record.llm_escalation = decision_result.escalated
        
        self.metrics.record_decision(
            ppo_latency_ms=decision_result.decision_latency_ms,
            escalated=decision_result.escalated
        )
        
        analysis = None
        if decision_result.path == DecisionPath.SLOW:
            # Execute LLM Reasoning
            t0_llm = time.perf_counter()
            analysis = self.reasoning_engine.analyze_event(event)
            llm_time = (time.perf_counter() - t0_llm) * 1000
            
            self.metrics.record_decision(
                ppo_latency_ms=0,
                escalated=True,
                llm_latency_ms=llm_time
            )
            action_name = analysis.recommended_action
            log.info("llm_reasoning_complete", action=action_name, time_ms=round(llm_time, 2))
        else:
            action_name = decision_result.action_name
            
        # 3. Action Execution (Remediation & Validation)
        patch = None
        val_result = None
        t0_remediate = time.perf_counter()
        
        if action_name == "apply_known_patch" or (analysis and analysis.patch_required):
            patch = self.patch_gen.generate_patch(event, analysis)
            if patch:
                val_result = self.validator.validate_and_apply(patch)
                record.patch_id = patch.patch_id
                record.patch_validation = val_result.decision
        else:
            if action_name in ("block_source_ip", "block_ip"):
                self.hardening.block_ip(event.source, f"{event.attack_type} detected")
                record.remediation = f"Blocked IP: {event.source}"
            elif action_name in ("rate_limit_source", "rate_limit"):
                self._rate_limit_handler(event.source, event.attack_type)
                record.remediation = f"Rate limited: {event.source}"
            elif action_name == "update_security_rule":
                self._update_rule_handler(event.attack_type, event.source)
                record.remediation = f"Security rule updated for {event.attack_type}"
            else:
                record.remediation = action_name
                
        # Calculate time taken for remediation/action
        remediate_time = (time.perf_counter() - t0_remediate) * 1000
        record.remediation_time_ms = remediate_time
        
        # Determine success
        success = True
        if patch:
            success = val_result.decision == ValidationDecision.ACCEPT
            
        self.metrics.record_remediation(success, remediate_time)
            
        # 4. Hardening
        hardening_actions = self.hardening.derive_rules_from_event(event)
        record.hardening = hardening_actions
        
        # 5. Store Memory
        record.outcome = "SUCCESS" if (val_result and val_result.decision == ValidationDecision.ACCEPT) or (not patch) else "ROLLED_BACK"
        try:
            self.memory.store(record)
        except Exception as e:
            log.error("memory_store_failed", error=str(e), record_id=record.record_id)
        
        log.info("defense_round_completed", event_id=event.event_id, outcome=record.outcome)
        self.last_round_details.append({
            "event_id": event.event_id,
            "finding_id": event.features.get("finding_id"),
            "patch_id": record.patch_id or None,
            "validation_id": val_result.validation_id if val_result else None,
            "decision_path": record.decision_path.value,
            "confidence": round(record.ppo_confidence, 4),
            "llm_escalation": record.llm_escalation,
            "action": action_name,
            "remediation": record.remediation or ("validated_patch" if patch else action_name),
            "validation": record.patch_validation.value if patch else "NOT_REQUIRED",
            "outcome": record.outcome,
            "hardening": list(record.hardening),
            "phase": "COMPLETE",
        })
        return self.metrics.get_snapshot()

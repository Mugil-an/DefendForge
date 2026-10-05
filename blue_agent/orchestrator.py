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
from blue_agent.detection.isolation_forest import IsolationForestDetector
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
        detector = IsolationForestDetector()
        try:
            detector.load(str(settings.detection.model_path))
        except FileNotFoundError:
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
        snapshots = []
        
        # 1. Detection Phase
        t0_detect = time.perf_counter()
        alerts = self.alert_manager.process_batch(raw_events)
        detect_time = (time.perf_counter() - t0_detect) * 1000
        
        if not alerts:
            log.info("no_attacks_detected")
            # Log true negative (assuming these were benign)
            self.metrics.record_detection(is_attack=False, detected=False)
            return [self.metrics.get_snapshot()]
            
        for event in alerts:
            snapshot = self._run_defense_round(event, detect_time / len(alerts))
            snapshots.append(snapshot)
            
        return snapshots

    def _run_defense_round(self, event: AttackEvent, detect_time_ms: float) -> MetricsSnapshot:
        """Run the full defense pipeline for a single attack event."""
        log.info("defense_round_started", event_id=event.event_id, type=event.attack_type)
        
        record = BlueMemoryRecord(
            round=self.metrics._rounds,
            attack_type=event.attack_type,
            detected=True,
            detection_time_ms=detect_time_ms,
        )
        self.metrics.record_detection(is_attack=True, detected=True, time_ms=detect_time_ms)
        
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
                
                success = val_result.decision == ValidationDecision.ACCEPT
                remediate_time = (time.perf_counter() - t0_remediate) * 1000
                record.remediation_time_ms = remediate_time
                self.metrics.record_remediation(success, remediate_time)
        else:
            # For non-patch actions, execute through safety broker
            if action_name in ("block_source_ip", "block_ip"):
                tool_call = ToolCall(tool_name="block_ip", parameters={"ip_address": event.source, "reason": f"{event.attack_type} detected"}, caller="orchestrator")
                asyncio.get_event_loop().run_until_complete(execute_tool(tool_call))
                record.remediation = f"Blocked IP: {event.source}"
            elif action_name in ("rate_limit_source", "rate_limit"):
                tool_call = ToolCall(tool_name="rate_limit", parameters={"source": event.source, "attack_type": event.attack_type}, caller="orchestrator")
                asyncio.get_event_loop().run_until_complete(execute_tool(tool_call))
                record.remediation = f"Rate limited: {event.source}"
            elif action_name == "update_security_rule":
                tool_call = ToolCall(tool_name="update_security_rule", parameters={"attack_type": event.attack_type, "source": event.source}, caller="orchestrator")
                asyncio.get_event_loop().run_until_complete(execute_tool(tool_call))
                record.remediation = f"Security rule updated for {event.attack_type}"
            else:
                record.remediation = action_name
            
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
        return self.metrics.get_snapshot()

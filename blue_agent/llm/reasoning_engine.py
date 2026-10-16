"""
LLM Reasoning Engine — The "Slow Path" of the decision architecture.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from blue_agent.decision.action_space import ActionSpace
from blue_agent.llm.llm_client import LLMClient
from blue_agent.llm.prompt_templates import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from blue_agent.logging_cfg import get_logger
from blue_agent.rag.retriever import Retriever
from blue_agent.schemas import AttackEvent, LLMAnalysis, Severity

log = get_logger("llm.reasoning")


class ReasoningEngine:
    """
    Coordinates RAG context retrieval and LLM structured generation
    to reason about complex, ambiguous, or novel attacks.
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        retriever: Optional[Retriever] = None,
        action_space: Optional[ActionSpace] = None,
    ):
        self._llm = llm_client or LLMClient()
        self._retriever = retriever or Retriever()
        self._action_space = action_space or ActionSpace()

    def analyze_event(
        self, 
        event: AttackEvent, 
        context: Optional[Dict[str, Any]] = None
    ) -> LLMAnalysis:
        """
        Analyze an escalated attack event using RAG + LLM.
        """
        log.info("llm_reasoning_started", event_id=event.event_id)
        
        # 1. Build search query from event
        query = f"{event.attack_type} on {event.endpoint} with severity {event.severity.value}"
        
        # 2. Retrieve RAG context
        rag_context = self._retriever.get_context_string(query, top_k=3)
        
        # 3. Format available actions
        actions_list = []
        for action in self._action_space.all_actions():
            # Don't let the LLM choose to escalate to itself
            if action.name != "escalate_to_llm":
                actions_list.append(f"- {action.name}: {action.label}")
        available_actions = "\n".join(actions_list)
        
        # 4. Format prompt
        user_prompt = USER_PROMPT_TEMPLATE.format(
            attack_type=event.attack_type or "Unknown",
            severity=event.severity.value,
            endpoint=event.endpoint,
            anomaly_score=round(event.anomaly_score, 4),
            detection_confidence=round(event.detection_confidence, 4),
            features=json.dumps(event.features, indent=2),
            raw_logs=json.dumps(event.raw_logs, indent=2),
            rag_context=rag_context,
            available_actions=available_actions,
        )
        
        # 5. Execute LLM call with robust cybersecurity heuristic fallback
        try:
            analysis = self._llm.generate_structured(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                response_model=LLMAnalysis,
            )
        except Exception as exc:
            log.warning("llm_reasoning_failed_falling_back_to_heuristic", error=str(exc))
            analysis = self._heuristic_analysis(event, rag_context)

        log.info(
            "llm_reasoning_completed",
            event_id=event.event_id,
            recommended_action=analysis.recommended_action,
            confidence=analysis.confidence,
        )

        # Validate action
        try:
            self._action_space.get_by_name(analysis.recommended_action)
        except ValueError:
            log.warning("llm_returned_invalid_action", action=analysis.recommended_action)
            # Fallback
            analysis.recommended_action = "no_action"

        return analysis

    def _heuristic_analysis(self, event: AttackEvent, rag_context: str = "") -> LLMAnalysis:
        """
        Deterministic, expert cybersecurity heuristic analysis when external LLM providers
        are offline, unreachable, or unauthenticated.
        """
        attack_type = (event.attack_type or "unknown").lower()

        if "sql" in attack_type:
            return LLMAnalysis(
                attack_classification="SQL Injection (CWE-89)",
                severity=Severity.HIGH,
                root_cause="Unsanitized user input concatenated directly into SQL queries.",
                affected_component="Database Query Layer",
                recommended_action="apply_known_patch",
                patch_required=True,
                patch_strategy="Use parameterized queries (e.g. cursor.execute('... WHERE username=%s', (val,))).",
                hardening_actions=[
                    "Deploy regex WAF rule blocking SQL syntax keywords (UNION SELECT, OR 1=1, DROP TABLE)",
                    "Block attacking source IP",
                    "Enforce least-privilege DB role permissions",
                ],
                confidence=0.88,
                reasoning_summary="SQL injection payload detected. Parameterized query patch proposed and WAF rule queued.",
            )
        elif "command" in attack_type:
            return LLMAnalysis(
                attack_classification="Command Injection (CWE-78)",
                severity=Severity.CRITICAL,
                root_cause="User input passed directly to shell execution (subprocess shell=True or os.system).",
                affected_component="System Process Execution",
                recommended_action="block_source_ip",
                patch_required=True,
                patch_strategy="Refactor to avoid shell invocation; validate argument against strict allowlist.",
                hardening_actions=[
                    "Block source IP immediately",
                    "Add WAF pattern matching shell metacharacters (; | ` $)",
                ],
                confidence=0.92,
                reasoning_summary="OS command injection attempt detected. Source IP blocked and process execution restricted.",
            )
        elif "xss" in attack_type or "script" in attack_type:
            return LLMAnalysis(
                attack_classification="Cross-Site Scripting (CWE-79)",
                severity=Severity.HIGH,
                root_cause="User input reflected in HTML response without contextual entity escaping.",
                affected_component="Template Rendering Engine",
                recommended_action="apply_known_patch",
                patch_required=True,
                patch_strategy="Escape dynamic variables using markupsafe.escape() or HTML entity encoding.",
                hardening_actions=[
                    "Configure Content-Security-Policy (CSP) headers",
                    "Add WAF script tag filter",
                ],
                confidence=0.85,
                reasoning_summary="XSS payload detected. Output encoding patch proposed and CSP header defense advised.",
            )
        elif "traversal" in attack_type or "file" in attack_type:
            return LLMAnalysis(
                attack_classification="Path Traversal (CWE-22)",
                severity=Severity.HIGH,
                root_cause="File path parameter contains directory traversal sequences (../).",
                affected_component="Static / Media File Handler",
                recommended_action="apply_known_patch",
                patch_required=True,
                patch_strategy="Use werkzeug.utils.secure_filename and enforce absolute base directory prefix check.",
                hardening_actions=[
                    "Block source IP",
                    "Filter directory traversal dot-dot-slash patterns",
                ],
                confidence=0.89,
                reasoning_summary="Path traversal sequence identified. File access sanitization patch generated.",
            )
        elif "brute" in attack_type or "login" in attack_type:
            return LLMAnalysis(
                attack_classification="Brute Force Credential Guessing (CWE-307)",
                severity=Severity.MEDIUM,
                root_cause="Excessive repeated authentication attempts without rate limiting.",
                affected_component="Authentication Gateway",
                recommended_action="rate_limit_source",
                patch_required=False,
                patch_strategy="",
                hardening_actions=[
                    "Enforce exponential backoff and IP rate limiting on /login",
                    "Require CAPTCHA after 5 failed attempts",
                ],
                confidence=0.85,
                reasoning_summary="High-volume authentication failure burst. Rate limiting and IP threshold applied.",
            )
        elif "ssrf" in attack_type:
            return LLMAnalysis(
                attack_classification="Server-Side Request Forgery (CWE-918)",
                severity=Severity.HIGH,
                root_cause="Target application fetches arbitrary user-supplied URLs without IP range allowlisting.",
                affected_component="Outbound HTTP Fetch Client",
                recommended_action="update_security_rule",
                patch_required=True,
                patch_strategy="Validate target host against internal IP blocklist (169.254.169.254, 127.0.0.1, 10.0.0.0/8).",
                hardening_actions=[
                    "Disallow metadata endpoint (169.254.169.254)",
                    "Restrict fetch service to explicit allowlisted domains",
                ],
                confidence=0.87,
                reasoning_summary="SSRF probe towards internal metadata service. Outbound URL filter and WAF rule deployed.",
            )
        else:
            return LLMAnalysis(
                attack_classification=event.attack_type or "Suspicious Anomaly",
                severity=event.severity,
                root_cause="Anomalous network telemetry or automated scanning signature.",
                affected_component="Reverse Proxy / HTTP Gateway",
                recommended_action="rate_limit_source",
                patch_required=False,
                patch_strategy="",
                hardening_actions=[
                    "Apply rate limit to source IP",
                    "Log high-fidelity security event telemetry",
                ],
                confidence=0.75,
                reasoning_summary="Anomalous request detected by ML detector. Source rate limit enforced.",
            )

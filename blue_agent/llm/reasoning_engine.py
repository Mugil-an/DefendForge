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
from blue_agent.schemas import AttackEvent, LLMAnalysis

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
        
        # 5. Execute LLM call
        analysis = self._llm.generate_structured(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            response_model=LLMAnalysis,
        )
        
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

"""
Decision Engine — the central fast-or-slow router.

Pipeline:
  1. Receive ``AttackEvent`` from detection layer.
  2. Query PPO policy → get action + confidence.
  3. IF confidence >= threshold → execute FAST PATH (use PPO action).
  4. ELSE → SLOW PATH: escalate to LLM reasoning engine.
  5. Record decision metrics.

The Decision Engine does NOT execute the action — it returns a
``DecisionResult`` that the orchestrator uses to dispatch to
the remediation or hardening layer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from blue_agent.config import settings
from blue_agent.decision.action_space import ActionSpace, DefensiveAction
from blue_agent.decision.confidence import ConfidenceRecord, ConfidenceTracker
from blue_agent.decision.ppo_policy import PPOPolicy
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AttackEvent, DecisionPath, PPODecision

log = get_logger("decision.engine")


@dataclass
class DecisionResult:
    """Output of the decision engine."""
    event_id: str
    path: DecisionPath            # FAST or SLOW
    ppo_decision: PPODecision     # always populated
    action_id: int
    action_name: str
    confidence: float
    escalated: bool
    decision_latency_ms: float
    context: Dict[str, Any]       # passed to remediation


class DecisionEngine:
    """
    Two-tier decision architecture:
      - FAST PATH: PPO confidence ≥ threshold
      - SLOW PATH: PPO confidence < threshold → LLM escalation

    The engine always runs PPO first.  If the PPO itself selects
    ``ESCALATE_TO_LLM`` as the best action, that also triggers
    the slow path regardless of confidence.
    """

    def __init__(
        self,
        ppo_policy: Optional[PPOPolicy] = None,
        action_space: Optional[ActionSpace] = None,
        confidence_tracker: Optional[ConfidenceTracker] = None,
    ):
        self._action_space = action_space or ActionSpace()
        self._ppo = ppo_policy or PPOPolicy(self._action_space)
        self._tracker = confidence_tracker or ConfidenceTracker()

    def decide(
        self,
        event: AttackEvent,
        context: Optional[Dict[str, Any]] = None,
    ) -> DecisionResult:
        """
        Run the fast/slow routing for a single attack event.

        Parameters
        ----------
        event : AttackEvent
            The normalised attack event from the detection layer.
        context : dict, optional
            Additional context (app health, previous actions, memory
            similarity) forwarded to the PPO observation builder.

        Returns
        -------
        DecisionResult
            Contains the chosen action, path taken, confidence,
            and timing metrics.
        """
        ctx = context or {}
        t0 = time.perf_counter()

        # 1. Always run PPO
        ppo_decision = self._ppo.decide(event, ctx)
        decision_ms = (time.perf_counter() - t0) * 1000

        # 2. Determine path
        escalated = False
        if self._tracker.should_escalate(ppo_decision.confidence):
            escalated = True
            path = DecisionPath.SLOW
            # Override action to escalation
            action_id = DefensiveAction.ESCALATE_TO_LLM
            action_name = "escalate_to_llm"
            log.info(
                "decision_escalating",
                reason="low_confidence",
                ppo_confidence=ppo_decision.confidence,
                threshold=self._tracker.threshold,
                original_action=ppo_decision.action_name,
            )
        elif ppo_decision.action == DefensiveAction.ESCALATE_TO_LLM:
            # PPO explicitly chose escalation
            escalated = True
            path = DecisionPath.SLOW
            action_id = DefensiveAction.ESCALATE_TO_LLM
            action_name = "escalate_to_llm"
            log.info(
                "decision_escalating",
                reason="ppo_chose_escalation",
                ppo_confidence=ppo_decision.confidence,
            )
        else:
            path = DecisionPath.FAST
            action_id = ppo_decision.action
            action_name = ppo_decision.action_name

        # 3. Record metrics
        record = ConfidenceRecord(
            ppo_confidence=ppo_decision.confidence,
            action=action_id,
            escalated=escalated,
            decision_latency_ms=decision_ms,
        )
        self._tracker.record(record)

        result = DecisionResult(
            event_id=event.event_id,
            path=path,
            ppo_decision=ppo_decision,
            action_id=action_id,
            action_name=action_name,
            confidence=ppo_decision.confidence,
            escalated=escalated,
            decision_latency_ms=round(decision_ms, 2),
            context=ctx,
        )

        log.info(
            "decision_complete",
            event_id=event.event_id,
            path=path.value,
            action=action_name,
            confidence=round(ppo_decision.confidence, 4),
            latency_ms=round(decision_ms, 2),
        )
        return result

    @property
    def tracker(self) -> ConfidenceTracker:
        return self._tracker

    @property
    def ppo(self) -> PPOPolicy:
        return self._ppo

    @property
    def action_space(self) -> ActionSpace:
        return self._action_space

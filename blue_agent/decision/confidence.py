"""
Confidence module — computes and tracks PPO confidence metrics,
and provides the threshold check for fast/slow path routing.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("decision.confidence")


@dataclass
class ConfidenceRecord:
    """One decision's confidence data."""
    ppo_confidence: float
    action: int
    escalated: bool
    decision_latency_ms: float
    timestamp: float = field(default_factory=time.time)


class ConfidenceTracker:
    """
    Tracks PPO confidence statistics across decisions.

    Provides:
    - threshold-based fast/slow routing
    - running statistics (mean, escalation rate)
    - recent history for metrics reporting
    """

    def __init__(
        self,
        threshold: Optional[float] = None,
        history_size: int = 500,
    ):
        self.threshold = threshold or settings.ppo.confidence_threshold
        self._history: Deque[ConfidenceRecord] = deque(maxlen=history_size)

    def should_escalate(self, confidence: float) -> bool:
        """
        Core routing decision.

        Returns ``True`` if confidence is below threshold → use
        the LLM slow path.
        """
        return confidence < self.threshold

    def record(self, record: ConfidenceRecord) -> None:
        self._history.append(record)
        log.debug(
            "confidence_recorded",
            confidence=round(record.ppo_confidence, 4),
            escalated=record.escalated,
            action=record.action,
            latency_ms=round(record.decision_latency_ms, 2),
        )

    @property
    def total_decisions(self) -> int:
        return len(self._history)

    @property
    def escalation_count(self) -> int:
        return sum(1 for r in self._history if r.escalated)

    @property
    def escalation_rate(self) -> float:
        if not self._history:
            return 0.0
        return self.escalation_count / len(self._history)

    @property
    def mean_confidence(self) -> float:
        if not self._history:
            return 0.0
        return sum(r.ppo_confidence for r in self._history) / len(self._history)

    @property
    def mean_latency_ms(self) -> float:
        if not self._history:
            return 0.0
        return sum(r.decision_latency_ms for r in self._history) / len(self._history)

    def recent_records(self, n: int = 20) -> list[ConfidenceRecord]:
        return list(self._history)[-n:]

    def stats(self) -> dict:
        return {
            "threshold": self.threshold,
            "total_decisions": self.total_decisions,
            "escalation_count": self.escalation_count,
            "escalation_rate": round(self.escalation_rate, 4),
            "mean_confidence": round(self.mean_confidence, 4),
            "mean_latency_ms": round(self.mean_latency_ms, 2),
        }

    def reset(self) -> None:
        self._history.clear()

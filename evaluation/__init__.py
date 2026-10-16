"""
Evaluation & Shared Logging Harness for DefendForge.

Implements cross-agent phase transition logging and round-over-round evaluation metrics.
"""
from __future__ import annotations

from evaluation.harness import (
    EvaluationHarness,
    PhaseTransition,
    PhaseTransitionEvent,
    evaluation_harness,
)

__all__ = [
    "EvaluationHarness",
    "PhaseTransition",
    "PhaseTransitionEvent",
    "evaluation_harness",
]

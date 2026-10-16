"""
Phase 2 — Moving Target Defense (MTD) Package.

Provides self-evolving proactive surface reconfigurations and empirical paired
evaluation comparing MTD-enabled targets against static baselines on held-out techniques.
"""
from __future__ import annotations

from mtd.controller import MTDController
from mtd.evaluator import MTDEvaluator
from mtd.held_out_techniques import HeldOutTechnique, get_held_out_techniques

__all__ = [
    "MTDController",
    "MTDEvaluator",
    "HeldOutTechnique",
    "get_held_out_techniques",
]

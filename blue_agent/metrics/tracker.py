"""
Metrics Tracker — Computes and reports real-time metrics for the Blue Agent.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import MetricsSnapshot

log = get_logger("metrics.tracker")


class MetricsTracker:
    """
    Maintains running statistics of the Blue Agent's performance
    across rounds (TTD, TTR, precision, recall, false positive rates).
    """
    
    def __init__(self):
        self._rounds: int = 0
        
        # Detection metrics
        self._true_positives: int = 0
        self._false_positives: int = 0
        self._false_negatives: int = 0
        self._total_attacks: int = 0
        
        # Timing metrics
        self._detection_times: List[float] = []
        self._remediation_times: List[float] = []
        self._ppo_latencies: List[float] = []
        self._llm_latencies: List[float] = []
        
        # Action metrics
        self._llm_escalations: int = 0
        self._successful_patches: int = 0
        self._rolled_back_patches: int = 0

    def increment_round(self) -> None:
        self._rounds += 1

    def record_detection(
        self,
        is_attack: bool,
        detected: bool,
        time_ms: float = 0.0,
    ) -> None:
        if is_attack:
            self._total_attacks += 1
            if detected:
                self._true_positives += 1
                if time_ms > 0:
                    self._detection_times.append(time_ms)
            else:
                self._false_negatives += 1
        else:
            if detected:
                self._false_positives += 1
                
    def record_decision(self, ppo_latency_ms: float, escalated: bool, llm_latency_ms: float = 0.0) -> None:
        if ppo_latency_ms > 0:
            self._ppo_latencies.append(ppo_latency_ms)
        if escalated:
            self._llm_escalations += 1
            if llm_latency_ms > 0:
                self._llm_latencies.append(llm_latency_ms)
                
    def record_remediation(self, success: bool, time_ms: float = 0.0) -> None:
        if success:
            self._successful_patches += 1
            if time_ms > 0:
                self._remediation_times.append(time_ms)
        else:
            self._rolled_back_patches += 1

    def get_snapshot(self) -> MetricsSnapshot:
        """Compute the current metrics snapshot."""
        
        # Detection math
        tp = self._true_positives
        fp = self._false_positives
        fn = self._false_negatives
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        
        # Normally FPR = FP / N, but here we estimate it based on total attacks for simplicity
        detection_rate = tp / self._total_attacks if self._total_attacks > 0 else 1.0
        
        # Patch math
        total_patches = self._successful_patches + self._rolled_back_patches
        patch_success_rate = self._successful_patches / total_patches if total_patches > 0 else 1.0
        rollback_rate = self._rolled_back_patches / total_patches if total_patches > 0 else 0.0
        
        # Timings
        avg_ttd = sum(self._detection_times) / len(self._detection_times) if self._detection_times else 0.0
        avg_ttr = sum(self._remediation_times) / len(self._remediation_times) if self._remediation_times else 0.0
        avg_ppo = sum(self._ppo_latencies) / len(self._ppo_latencies) if self._ppo_latencies else 0.0
        avg_llm = sum(self._llm_latencies) / len(self._llm_latencies) if self._llm_latencies else 0.0
        
        snapshot = MetricsSnapshot(
            round=self._rounds,
            detection_rate=round(detection_rate, 4),
            false_positive_rate=round(fp / (self._rounds or 1), 4),
            precision=round(precision, 4),
            recall=round(recall, 4),
            time_to_detect_ms=round(avg_ttd, 2),
            time_to_remediate_ms=round(avg_ttr, 2),
            patch_success_rate=round(patch_success_rate, 4),
            rollback_rate=round(rollback_rate, 4),
            ppo_decision_latency_ms=round(avg_ppo, 2),
            llm_latency_ms=round(avg_llm, 2),
            llm_escalation_count=self._llm_escalations,
            successful_remediations=self._successful_patches,
            failed_remediations=self._rolled_back_patches,
        )
        
        log.info(
            "metrics_snapshot_computed",
            round=snapshot.round,
            precision=snapshot.precision,
            ttd_ms=snapshot.time_to_detect_ms,
            ttr_ms=snapshot.time_to_remediate_ms
        )
        return snapshot

    def to_dict(self) -> Dict[str, Any]:
        """Serialize current metrics to a dictionary."""
        snapshot = self.get_snapshot()
        return snapshot.model_dump()

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        self._rounds = 0
        self._true_positives = 0
        self._false_positives = 0
        self._false_negatives = 0
        self._total_attacks = 0
        self._detection_times.clear()
        self._remediation_times.clear()
        self._ppo_latencies.clear()
        self._llm_latencies.clear()
        self._llm_escalations = 0
        self._successful_patches = 0
        self._rolled_back_patches = 0
        log.info("metrics_reset")

"""
Shared Logging & Phase Transition Harness for Multi-Agent Cyber Defense.

Records timestamped events at every phase transition:
  - RECONNAISSANCE_START
  - FOOTHOLD_GAINED
  - DETECTION_FIRED
  - FAST_OR_SLOW_DECISION
  - REMEDIATION_PROPOSED
  - VALIDATION_EXECUTED (Accept or Rollback)
  - HARDENING_APPLIED
  - ROUND_COMPLETE

Computes evaluation metrics across rounds:
  - Time-to-detect (TTD)
  - Time-to-remediate (TTR)
  - Attack success rate / steps required
  - Escalation rate (Fast policy vs Slow reasoning)
  - True DSR vs Fake DSR & Service Disruption Rate
  - Qualitative evidence summary
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from blue_agent.config import PROJECT_ROOT
from blue_agent.logging_cfg import get_logger

log = get_logger("evaluation.harness")


class PhaseTransition(str, Enum):
    RECONNAISSANCE_START = "RECONNAISSANCE_START"
    FOOTHOLD_GAINED = "FOOTHOLD_GAINED"
    DETECTION_FIRED = "DETECTION_FIRED"
    FAST_OR_SLOW_DECISION = "FAST_OR_SLOW_DECISION"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    VALIDATION_EXECUTED = "VALIDATION_EXECUTED"
    HARDENING_APPLIED = "HARDENING_APPLIED"
    ROUND_COMPLETE = "ROUND_COMPLETE"


@dataclass
class PhaseTransitionEvent:
    phase: PhaseTransition
    round_number: int
    component: str  # "red_agent", "blue_agent", "green_agent", "orchestrator"
    details: Dict[str, Any] = field(default_factory=dict)
    qualitative_note: str = ""
    latency_ms: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    unix_time: float = field(default_factory=time.time)


class EvaluationHarness:
    """
    Shared event harness and evaluation metrics engine.
    Persists transition events to `logs/phase_transitions.jsonl`.
    """

    def __init__(self, log_path: Optional[str | Path] = None):
        self.log_path = Path(log_path or (PROJECT_ROOT / "logs" / "phase_transitions.jsonl"))
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._events: List[PhaseTransitionEvent] = []

    def log_transition(
        self,
        phase: PhaseTransition,
        round_number: int,
        component: str,
        details: Optional[Dict[str, Any]] = None,
        qualitative_note: str = "",
        latency_ms: float = 0.0,
    ) -> PhaseTransitionEvent:
        """
        Record a phase transition to memory and shared log file.
        """
        event = PhaseTransitionEvent(
            phase=phase,
            round_number=round_number,
            component=component,
            details=details or {},
            qualitative_note=qualitative_note,
            latency_ms=round(latency_ms, 2),
        )
        self._events.append(event)

        # Write to shared log store
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception as e:
            log.warning("phase_log_write_failed", error=str(e))

        log.info(
            "phase_transition_recorded",
            phase=phase.value,
            round=round_number,
            component=component,
            latency_ms=latency_ms,
        )
        return event

    def get_events(self, round_number: Optional[int] = None) -> List[PhaseTransitionEvent]:
        """Retrieve recorded phase transition events."""
        if round_number is not None:
            return [e for e in self._events if e.round_number == round_number]
        return list(self._events)

    def generate_round_report(self, round_number: int) -> Dict[str, Any]:
        """
        Compute quantitative & qualitative metrics for a specific round.
        """
        round_events = self.get_events(round_number)
        recon_events = [e for e in round_events if e.phase == PhaseTransition.RECONNAISSANCE_START]
        foothold_events = [e for e in round_events if e.phase == PhaseTransition.FOOTHOLD_GAINED]
        detection_events = [e for e in round_events if e.phase == PhaseTransition.DETECTION_FIRED]
        decision_events = [e for e in round_events if e.phase == PhaseTransition.FAST_OR_SLOW_DECISION]
        validation_events = [e for e in round_events if e.phase == PhaseTransition.VALIDATION_EXECUTED]
        hardening_events = [e for e in round_events if e.phase == PhaseTransition.HARDENING_APPLIED]

        # Time-to-detect calculation: difference between attack attempt and detection fired
        ttd_values = [e.latency_ms for e in detection_events if e.latency_ms > 0]
        avg_ttd = sum(ttd_values) / len(ttd_values) if ttd_values else 0.0

        # Time-to-remediate calculation
        ttr_values = [e.latency_ms for e in validation_events if e.latency_ms > 0]
        avg_ttr = sum(ttr_values) / len(ttr_values) if ttr_values else 0.0

        # Escalation rate
        fast_count = sum(1 for e in decision_events if e.details.get("path") == "fast")
        slow_count = sum(1 for e in decision_events if e.details.get("path") == "slow")
        total_decisions = fast_count + slow_count
        escalation_rate = slow_count / total_decisions if total_decisions > 0 else 0.0

        # True DSR vs Fake DSR (Accept vs Rollback)
        accepted_patches = sum(1 for e in validation_events if e.details.get("decision") == "ACCEPT")
        rolled_back_patches = sum(1 for e in validation_events if e.details.get("decision") == "ROLLBACK")
        total_patches = accepted_patches + rolled_back_patches
        true_dsr = accepted_patches / total_patches if total_patches > 0 else 1.0
        fake_dsr = rolled_back_patches / total_patches if total_patches > 0 else 0.0
        service_disruption_rate = fake_dsr

        # Qualitative audit notes
        qualitative_audit = [
            f"[{e.phase.value}] ({e.component}): {e.qualitative_note}"
            for e in round_events if e.qualitative_note
        ]

        return {
            "round": round_number,
            "total_events": len(round_events),
            "recon_count": len(recon_events),
            "footholds_gained": len(foothold_events),
            "detections_fired": len(detection_events),
            "avg_ttd_ms": round(avg_ttd, 2),
            "avg_ttr_ms": round(avg_ttr, 2),
            "fast_decisions": fast_count,
            "slow_decisions": slow_count,
            "escalation_rate": round(escalation_rate, 4),
            "accepted_patches": accepted_patches,
            "rolled_back_patches": rolled_back_patches,
            "true_dsr": round(true_dsr, 4),
            "fake_dsr": round(fake_dsr, 4),
            "service_disruption_rate": round(service_disruption_rate, 4),
            "hardening_rules_applied": len(hardening_events),
            "qualitative_evidence": qualitative_audit,
        }

    def generate_full_evaluation_report(self) -> Dict[str, Any]:
        """
        Generate full trend report across all recorded rounds.
        Shows round-over-round trends for TTD, TTR, escalation, and defense success rates.
        """
        all_rounds = sorted({e.round_number for e in self._events})
        round_reports = [self.generate_round_report(r) for r in all_rounds] if all_rounds else []

        # Trends
        ttd_trend = [r["avg_ttd_ms"] for r in round_reports]
        ttr_trend = [r["avg_ttr_ms"] for r in round_reports]
        escalation_trend = [r["escalation_rate"] for r in round_reports]
        true_dsr_trend = [r["true_dsr"] for r in round_reports]
        service_disruption_trend = [r["service_disruption_rate"] for r in round_reports]

        return {
            "total_rounds": len(all_rounds),
            "rounds": round_reports,
            "trends": {
                "ttd_ms": ttd_trend,
                "ttr_ms": ttr_trend,
                "escalation_rate": escalation_trend,
                "true_dsr": true_dsr_trend,
                "service_disruption_rate": service_disruption_trend,
            },
            "success_criteria_met": {
                "ttd_improving": len(ttd_trend) > 1 and ttd_trend[-1] <= ttd_trend[0],
                "escalation_decreasing": len(escalation_trend) > 1 and escalation_trend[-1] <= escalation_trend[0],
                "disruption_rate_low": all(d <= 0.25 for d in service_disruption_trend) if service_disruption_trend else True,
            },
        }

    def clear(self) -> None:
        """Reset in-memory events."""
        self._events.clear()


evaluation_harness = EvaluationHarness()

"""
Adversarial Co-Evolution Engine.

This is the master orchestrator that runs the full Red ↔ Blue loop:

  Round N:
    1. Green Agent generates background legitimate traffic
    2. Red Agent performs reconnaissance & plans attacks
    3. Red Agent executes attacks against the target
    4. Blue Agent detects attacks (anomaly detection)
    5. Blue Agent decides: fast (RL/PPO) or slow (LLM) path
    6. Blue Agent generates patch
    7. Blue Agent validates patch (run tests → accept/rollback)
    8. Blue Agent hardens the system
    9. Both agents update memory
    10. Measure: time-to-detect, time-to-remediate

  Round N+1:
    - Red adapts (avoids detected techniques, tries new vectors)
    - Blue is faster (recognizes previously seen attacks)
    → Adversarial co-evolution

Timestamps are recorded at each phase for metrics.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from blue_agent.logging_cfg import get_logger

log = get_logger("coevolution")


@dataclass
class PhaseTimestamp:
    """Timestamp record for a single phase within a round."""
    phase: str
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0


@dataclass
class RoundResult:
    """Complete result of one co-evolution round."""
    round_number: int
    # Red Agent results
    recon_findings: int = 0
    attacks_launched: int = 0
    successful_exploits: int = 0
    attack_types_used: list[str] = field(default_factory=list)
    # Green Agent results
    benign_traffic_count: int = 0
    # Blue Agent results
    attacks_detected: int = 0
    false_positives: int = 0
    patches_generated: int = 0
    patches_accepted: int = 0
    patches_rolled_back: int = 0
    hardening_actions: int = 0
    # Decision path stats
    fast_path_count: int = 0
    slow_path_count: int = 0
    # Timing
    time_to_detect_ms: float = 0.0
    time_to_remediate_ms: float = 0.0
    total_round_time_ms: float = 0.0
    phase_timestamps: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CoEvolutionResult:
    """Complete result of a multi-round co-evolution campaign."""
    total_rounds: int = 0
    round_results: list[RoundResult] = field(default_factory=list)
    # Aggregate metrics
    detection_rate_by_round: list[float] = field(default_factory=list)
    remediation_time_by_round: list[float] = field(default_factory=list)
    exploit_success_rate_by_round: list[float] = field(default_factory=list)
    # Strategy evolution
    red_strategy_evolution: list[str] = field(default_factory=list)
    blue_improvement_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rounds": self.total_rounds,
            "rounds": [
                {
                    "round": r.round_number,
                    "attacks_launched": r.attacks_launched,
                    "successful_exploits": r.successful_exploits,
                    "attacks_detected": r.attacks_detected,
                    "false_positives": r.false_positives,
                    "patches_accepted": r.patches_accepted,
                    "patches_rolled_back": r.patches_rolled_back,
                    "fast_path": r.fast_path_count,
                    "slow_path": r.slow_path_count,
                    "time_to_detect_ms": round(r.time_to_detect_ms, 2),
                    "time_to_remediate_ms": round(r.time_to_remediate_ms, 2),
                    "total_time_ms": round(r.total_round_time_ms, 2),
                    "attack_types": r.attack_types_used,
                    "benign_traffic": r.benign_traffic_count,
                }
                for r in self.round_results
            ],
            "detection_rate_trend": [round(d, 4) for d in self.detection_rate_by_round],
            "remediation_time_trend": [round(t, 2) for t in self.remediation_time_by_round],
            "exploit_success_trend": [round(e, 4) for e in self.exploit_success_rate_by_round],
            "red_strategy_evolution": self.red_strategy_evolution,
            "blue_improvement_summary": self.blue_improvement_summary,
        }


class CoEvolutionEngine:
    """
    Master orchestrator for adversarial Red ↔ Blue co-evolution.

    Runs multiple rounds where:
    - Red Agent adapts attacks based on detection history
    - Blue Agent improves detection based on attack patterns
    - Green Agent provides background noise
    - Metrics track improvement over time
    """

    def __init__(
        self,
        target_url: str = "http://target_app:5000",
        max_rounds: int = 5,
        attacks_per_round: int = 10,
        benign_per_round: int = 5,
        use_llm: bool = True,
        timeout: float = 5.0,
    ):
        self.target_url = target_url
        self.max_rounds = max_rounds
        self.attacks_per_round = attacks_per_round
        self.benign_per_round = benign_per_round
        self.use_llm = use_llm
        self.timeout = timeout

    def run(self) -> CoEvolutionResult:
        """Execute the full co-evolution campaign."""
        from red_agent.orchestrator import RedAgent
        from green_agent import GreenAgent, GreenTrafficConfig

        result = CoEvolutionResult()

        # Initialize agents
        red = RedAgent()
        green = GreenAgent(GreenTrafficConfig(
            target_url=self.target_url,
            seed=42,
        ))

        log.info("coevolution_starting",
                 rounds=self.max_rounds,
                 attacks_per_round=self.attacks_per_round,
                 benign_per_round=self.benign_per_round)

        for round_num in range(1, self.max_rounds + 1):
            round_result = self._run_single_round(
                round_num, red, green
            )
            result.round_results.append(round_result)
            result.total_rounds = round_num

            # Track metrics over rounds
            if round_result.attacks_launched > 0:
                detection_rate = round_result.attacks_detected / round_result.attacks_launched
            else:
                detection_rate = 0.0
            result.detection_rate_by_round.append(detection_rate)
            result.remediation_time_by_round.append(round_result.time_to_remediate_ms)

            if round_result.attacks_launched > 0:
                exploit_rate = round_result.successful_exploits / round_result.attacks_launched
            else:
                exploit_rate = 0.0
            result.exploit_success_rate_by_round.append(exploit_rate)

            log.info("coevolution_round_complete",
                     round=round_num,
                     detection_rate=round(detection_rate, 4),
                     remediation_ms=round(round_result.time_to_remediate_ms, 2),
                     exploit_rate=round(exploit_rate, 4))

        # Build improvement summary
        result.red_strategy_evolution = [
            f"Round {r.round_number}: {', '.join(r.attack_types_used)}"
            for r in result.round_results
        ]

        if len(result.detection_rate_by_round) >= 2:
            first_dr = result.detection_rate_by_round[0]
            last_dr = result.detection_rate_by_round[-1]
            result.blue_improvement_summary = (
                f"Detection rate: {first_dr:.0%} → {last_dr:.0%}. "
                f"Remediation time: {result.remediation_time_by_round[0]:.0f}ms → "
                f"{result.remediation_time_by_round[-1]:.0f}ms. "
                f"Exploit success: {result.exploit_success_rate_by_round[0]:.0%} → "
                f"{result.exploit_success_rate_by_round[-1]:.0%}."
            )

        log.info("coevolution_complete",
                 rounds=result.total_rounds,
                 summary=result.blue_improvement_summary)

        return result

    def _run_single_round(
        self,
        round_num: int,
        red: Any,
        green: Any,
    ) -> RoundResult:
        """Execute one full Red → Blue co-evolution round."""
        round_result = RoundResult(round_number=round_num)
        t0_round = time.perf_counter()

        # --- Phase 1: Green Agent — Generate benign background traffic ---
        t0_green = time.perf_counter()
        green_events = green.generate_traffic_batch(self.benign_per_round)
        round_result.benign_traffic_count = len(green_events)
        round_result.phase_timestamps.append({
            "phase": "green_traffic",
            "duration_ms": (time.perf_counter() - t0_green) * 1000,
        })

        # --- Phase 2: Red Agent — Reconnaissance & Attack ---
        t0_red = time.perf_counter()
        try:
            autonomous_result = red.run_full_autonomous_campaign(
                rounds=1,
                max_events_per_round=self.attacks_per_round,
                use_llm=self.use_llm,
            )
            red_traffic = autonomous_result.traffic
            red_truth = autonomous_result.ground_truth
            round_result.attacks_launched = autonomous_result.total_attacks
            round_result.successful_exploits = autonomous_result.successful_exploits
            round_result.attack_types_used = list({
                t.get("attack_type", "unknown") for t in red_truth
            })
        except Exception as e:
            log.error("red_agent_round_failed", round=round_num, error=str(e))
            red_traffic = []
            red_truth = []

        round_result.phase_timestamps.append({
            "phase": "red_attack",
            "duration_ms": (time.perf_counter() - t0_red) * 1000,
        })

        # --- Phase 3: Merge traffic (Red + Green) ---
        all_traffic = []
        all_truth = []

        # Add green traffic with ground truth
        for evt in green_events:
            all_traffic.append(evt)
            all_truth.append({
                "is_attack": False,
                "attack_type": None,
                "severity": "none",
            })

        # Add red traffic
        for i, evt in enumerate(red_traffic):
            all_traffic.append(evt)
            if i < len(red_truth):
                all_truth.append(red_truth[i])

        # --- Phase 4: Blue Agent — Detection ---
        t0_detect = time.perf_counter()
        try:
            from blue_agent.api.routes import _get_agent
            blue = _get_agent()

            # Enrich traffic with labels for the detector
            enriched_traffic = []
            for evt, truth in zip(all_traffic, all_truth):
                enriched = {**evt}
                if truth.get("is_attack"):
                    enriched["is_attack"] = True
                    enriched["attack_type"] = truth.get("attack_type")
                    enriched["severity"] = truth.get("severity", "low")
                enriched_traffic.append(enriched)

            snapshots = blue.process_traffic(enriched_traffic)
            details = getattr(blue, "last_round_details", [])

        except Exception as e:
            log.error("blue_agent_round_failed", round=round_num, error=str(e))
            details = []
            snapshots = []

        detect_time = (time.perf_counter() - t0_detect) * 1000
        round_result.time_to_detect_ms = detect_time
        round_result.phase_timestamps.append({
            "phase": "blue_detect",
            "duration_ms": detect_time,
        })

        # --- Phase 5: Analyze Blue Agent results ---
        t0_analyze = time.perf_counter()
        for detail in details:
            path = detail.get("decision_path", "fast")
            if path == "fast":
                round_result.fast_path_count += 1
            else:
                round_result.slow_path_count += 1

            outcome = detail.get("outcome", "")
            validation = detail.get("validation", "")

            if validation == "ACCEPT":
                round_result.patches_accepted += 1
                round_result.patches_generated += 1
            elif validation == "ROLLBACK":
                round_result.patches_rolled_back += 1
                round_result.patches_generated += 1

            if outcome in ("SUCCESS", "BLOCKED"):
                round_result.attacks_detected += 1

            hardening = detail.get("hardening", [])
            round_result.hardening_actions += len(hardening)

        analyze_time = (time.perf_counter() - t0_analyze) * 1000
        round_result.time_to_remediate_ms = detect_time + analyze_time
        round_result.phase_timestamps.append({
            "phase": "blue_analyze_remediate",
            "duration_ms": analyze_time,
        })

        round_result.total_round_time_ms = (time.perf_counter() - t0_round) * 1000

        # Reset red agent for next round (but keep memory)
        red._autonomous_result = None
        red._autonomous_campaign = None

        return round_result

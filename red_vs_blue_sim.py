"""
Red vs Blue Simulation — Multi-round adversarial evaluation.

Runs configurable attack scenarios and measures Blue Agent effectiveness.
"""
from __future__ import annotations

import csv
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from blue_agent.orchestrator import BlueAgent
from red_agent.orchestrator import RedAgent
from red_agent.scenarios import list_scenarios

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("red_vs_blue")


def run_simulation(rounds: int = 3, seed: int = 42) -> List[Dict[str, Any]]:
    """Run multi-round Red vs Blue simulation."""
    print("=" * 70)
    print(" DEFENDFORGE : RED vs BLUE SIMULATION")
    print(f" Rounds: {rounds} | Seed: {seed}")
    print("=" * 70)
    
    blue = BlueAgent()
    blue.ingest_knowledge()
    red = RedAgent(seed=seed)
    
    scenarios = list_scenarios()
    round_results = []
    
    for round_num in range(1, rounds + 1):
        scenario_name = scenarios[(round_num - 1) % len(scenarios)]
        
        print(f"\n{'─' * 70}")
        print(f" Round {round_num}/{rounds}: {scenario_name}")
        print(f"{'─' * 70}")
        
        blue.metrics.reset()
        result = red.run_scenario(scenario_name)
        
        t0 = time.perf_counter()
        attack_count = sum(1 for gt in result.ground_truth if gt["is_attack"])
        benign_count = len(result.traffic) - attack_count
        
        print(f"  Traffic: {len(result.traffic)} events ({attack_count} attacks, {benign_count} benign)")
        
        # Process all traffic
        all_snapshots = []
        for event in result.traffic:
            snapshots = blue.process_traffic([event])
            all_snapshots.extend(snapshots)
        
        elapsed = (time.perf_counter() - t0) * 1000
        
        # Get final metrics for this round
        final = blue.metrics.get_snapshot()
        
        round_data = {
            "round": round_num,
            "scenario": scenario_name,
            "total_events": len(result.traffic),
            "attacks": attack_count,
            "benign": benign_count,
            "detection_rate": final.detection_rate,
            "precision": final.precision,
            "recall": final.recall,
            "false_positive_rate": final.false_positive_rate,
            "avg_ttd_ms": final.time_to_detect_ms,
            "avg_ttr_ms": final.time_to_remediate_ms,
            "patch_success_rate": final.patch_success_rate,
            "llm_escalations": final.llm_escalation_count,
            "round_time_ms": round(elapsed, 2),
        }
        round_results.append(round_data)
        
        print(f"  Detection Rate: {final.detection_rate:.2%}")
        print(f"  Precision:      {final.precision:.2%}")
        print(f"  Recall:         {final.recall:.2%}")
        print(f"  Round Time:     {elapsed:.0f}ms")
    
    # Print summary table
    print(f"\n{'=' * 70}")
    print(" SIMULATION SUMMARY")
    print(f"{'=' * 70}")
    print(f"{'Round':<7} {'Scenario':<25} {'Det%':<8} {'Prec%':<8} {'Rec%':<8} {'TTD(ms)':<10}")
    print("-" * 70)
    for r in round_results:
        print(f"{r['round']:<7} {r['scenario']:<25} {r['detection_rate']:.2%}  {r['precision']:.2%}  {r['recall']:.2%}  {r['avg_ttd_ms']:<10.1f}")
    
    # Export CSV
    csv_path = Path("logs") / f"sim_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=round_results[0].keys())
        writer.writeheader()
        writer.writerows(round_results)
    print(f"\nResults exported to: {csv_path}")
    
    return round_results


if __name__ == "__main__":
    run_simulation(rounds=6, seed=42)

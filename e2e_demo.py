"""
End-to-End Demonstration — Red Agent vs Blue Agent.
"""
from __future__ import annotations

import logging
import time

from blue_agent.orchestrator import BlueAgent
from red_agent.orchestrator import RedAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("e2e_demo")


def run_demo():
    print("=" * 60)
    print(" DEFENDFORGE : RED vs BLUE DEMONSTRATION ")
    print("=" * 60)
    
    # Initialize agents
    print("\n[1] Initializing Blue Agent...")
    blue = BlueAgent()
    blue.ingest_knowledge()
    
    print("\n[2] Initializing Red Agent...")
    red = RedAgent(seed=42)
    
    # Run scenarios
    scenarios = ["recon_then_exploit", "multi_vector_attack"]
    
    for scenario_name in scenarios:
        print(f"\n{'=' * 60}")
        print(f" SCENARIO: {scenario_name.upper().replace('_', ' ')} ")
        print(f"{'=' * 60}")
        
        result = red.run_scenario(scenario_name)
        print(f"Description: {result.description}")
        print(f"Traffic events: {len(result.traffic)}")
        
        # Blue Agent processes each event
        for i, event in enumerate(result.traffic):
            gt = result.ground_truth[i]
            label = f"ATTACK ({gt['attack_type']})" if gt['is_attack'] else "BENIGN"
            print(f"\n  Event {i+1}/{len(result.traffic)}: {event['endpoint']} [{label}]")
            snapshots = blue.process_traffic([event])
            
            if snapshots:
                latest = snapshots[-1]
                print(f"  Metrics: TTD={latest.time_to_detect_ms:.1f}ms | Precision={latest.precision:.2f} | Recall={latest.recall:.2f}")
            time.sleep(0.5)
    
    # Summary
    print(f"\n{'=' * 60}")
    print(" FINAL METRICS SUMMARY ")
    print(f"{'=' * 60}")
    
    final = blue.metrics.get_snapshot()
    print(f"  Rounds:              {final.round}")
    print(f"  Detection Rate:      {final.detection_rate:.2%}")
    print(f"  Precision:           {final.precision:.2%}")
    print(f"  Recall:              {final.recall:.2%}")
    print(f"  Avg TTD:             {final.time_to_detect_ms:.2f}ms")
    print(f"  Avg TTR:             {final.time_to_remediate_ms:.2f}ms")
    print(f"  Patch Success Rate:  {final.patch_success_rate:.2%}")
    print(f"  LLM Escalations:     {final.llm_escalation_count}")
    
    # Display Blue Memory
    print(f"\n{'=' * 60}")
    print(" BLUE MEMORY DUMP ")
    print(f"{'=' * 60}")
    try:
        records = blue.memory.get_recent(limit=5)
        for r in records:
            print(f"  Round {r.round} | {r.attack_type or 'benign'} | Path: {r.decision_path.value} | Confidence: {r.ppo_confidence:.2f} | {r.outcome}")
    except Exception as e:
        print(f"  Memory unavailable: {e}")
    
    print("\nDemonstration Complete.")


if __name__ == "__main__":
    run_demo()

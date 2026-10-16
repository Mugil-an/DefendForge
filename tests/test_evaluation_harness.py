import pytest
from evaluation.harness import EvaluationHarness, PhaseTransition


class TestEvaluationHarness:
    def test_log_and_retrieve_transition(self, tmp_path):
        harness = EvaluationHarness(log_path=tmp_path / "test_transitions.jsonl")
        ev = harness.log_transition(
            phase=PhaseTransition.RECONNAISSANCE_START,
            round_number=1,
            component="red_agent",
            details={"target": "http://127.0.0.1:8080"},
            qualitative_note="Red agent initiated port discovery scan",
            latency_ms=12.5,
        )
        assert ev.phase == PhaseTransition.RECONNAISSANCE_START
        assert ev.round_number == 1
        assert len(harness.get_events()) == 1

        # Check file was written
        lines = (tmp_path / "test_transitions.jsonl").read_text().strip().split("\n")
        assert len(lines) == 1

    def test_round_report_computation(self, tmp_path):
        harness = EvaluationHarness(log_path=tmp_path / "test_transitions.jsonl")

        # Round 1 events
        harness.log_transition(PhaseTransition.RECONNAISSANCE_START, 1, "red_agent")
        harness.log_transition(PhaseTransition.DETECTION_FIRED, 1, "blue_agent", latency_ms=15.0)
        harness.log_transition(PhaseTransition.FAST_OR_SLOW_DECISION, 1, "blue_agent", details={"path": "fast"})
        harness.log_transition(PhaseTransition.VALIDATION_EXECUTED, 1, "blue_agent", details={"decision": "ACCEPT"}, latency_ms=45.0)

        # Round 2 events (slow escalation, rolled back patch)
        harness.log_transition(PhaseTransition.DETECTION_FIRED, 2, "blue_agent", latency_ms=8.0)
        harness.log_transition(PhaseTransition.FAST_OR_SLOW_DECISION, 2, "blue_agent", details={"path": "slow"})
        harness.log_transition(PhaseTransition.VALIDATION_EXECUTED, 2, "blue_agent", details={"decision": "ROLLBACK"}, latency_ms=30.0)

        r1 = harness.generate_round_report(1)
        assert r1["avg_ttd_ms"] == 15.0
        assert r1["avg_ttr_ms"] == 45.0
        assert r1["escalation_rate"] == 0.0
        assert r1["true_dsr"] == 1.0
        assert r1["fake_dsr"] == 0.0

        r2 = harness.generate_round_report(2)
        assert r2["avg_ttd_ms"] == 8.0
        assert r2["escalation_rate"] == 1.0
        assert r2["true_dsr"] == 0.0
        assert r2["fake_dsr"] == 1.0
        assert r2["service_disruption_rate"] == 1.0

        full = harness.generate_full_evaluation_report()
        assert full["total_rounds"] == 2
        assert len(full["rounds"]) == 2

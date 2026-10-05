import pytest
from blue_agent.metrics.tracker import MetricsTracker
from blue_agent.schemas import MetricsSnapshot


class TestMetricsTracker:
    def setup_method(self):
        self.tracker = MetricsTracker()
    
    def test_initial_snapshot(self):
        snapshot = self.tracker.get_snapshot()
        assert isinstance(snapshot, MetricsSnapshot)
        assert snapshot.round == 0
    
    def test_increment_round(self):
        self.tracker.increment_round()
        self.tracker.increment_round()
        snapshot = self.tracker.get_snapshot()
        assert snapshot.round == 2
    
    def test_record_detection_true_positive(self):
        self.tracker.increment_round()
        self.tracker.record_detection(is_attack=True, detected=True, time_ms=10.0)
        snapshot = self.tracker.get_snapshot()
        assert snapshot.detection_rate == 1.0
        assert snapshot.recall == 1.0
    
    def test_precision_calculation(self):
        self.tracker.increment_round()
        self.tracker.record_detection(is_attack=True, detected=True)
        self.tracker.record_detection(is_attack=False, detected=True)  # false positive
        snapshot = self.tracker.get_snapshot()
        assert snapshot.precision == 0.5
    
    def test_remediation_tracking(self):
        self.tracker.record_remediation(success=True, time_ms=50.0)
        self.tracker.record_remediation(success=False)
        snapshot = self.tracker.get_snapshot()
        assert snapshot.successful_remediations == 1
        assert snapshot.failed_remediations == 1
        assert snapshot.patch_success_rate == 0.5
        assert snapshot.rollback_rate == 0.5
    
    def test_reset(self):
        self.tracker.increment_round()
        self.tracker.record_detection(is_attack=True, detected=True)
        self.tracker.reset()
        snapshot = self.tracker.get_snapshot()
        assert snapshot.round == 0
        assert snapshot.detection_rate == 1.0  # 0/0 defaults to 1.0
    
    def test_to_dict(self):
        self.tracker.increment_round()
        result = self.tracker.to_dict()
        assert isinstance(result, dict)
        assert "round" in result
        assert "precision" in result
    
    def test_llm_escalation_tracking(self):
        self.tracker.record_decision(ppo_latency_ms=5.0, escalated=True, llm_latency_ms=200.0)
        snapshot = self.tracker.get_snapshot()
        assert snapshot.llm_escalation_count == 1

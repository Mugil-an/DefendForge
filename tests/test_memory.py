import pytest
from blue_agent.memory.repository import MemoryRepository
from blue_agent.schemas import BlueMemoryRecord, DecisionPath, SecurityEventRecord, ValidationDecision


class TestMemoryRepository:
    def setup_method(self):
        self.repo = MemoryRepository(db_url="sqlite:///:memory:")
    
    def test_store_and_retrieve(self):
        record = BlueMemoryRecord(
            round=1,
            attack_type="SQL Injection",
            detected=True,
            detection_time_ms=15.5,
            decision_path=DecisionPath.FAST,
            ppo_confidence=0.85,
            outcome="SUCCESS",
        )
        self.repo.store(record)
        records = self.repo.get_recent(limit=10)
        assert len(records) == 1
        assert records[0].attack_type == "SQL Injection"
        assert records[0].ppo_confidence == 0.85
    
    def test_get_recent_ordering(self):
        for i in range(5):
            record = BlueMemoryRecord(round=i, attack_type=f"attack_{i}", outcome="SUCCESS")
            self.repo.store(record)
        records = self.repo.get_recent(limit=3)
        assert len(records) == 3
    
    def test_store_with_json_fields(self):
        record = BlueMemoryRecord(
            round=1,
            attack_type="XSS",
            hardening=["Blocked IP: 10.0.0.1", "Added WAF rule"],
            retrieved_documents=["doc1", "doc2"],
            extra={"key": "value"},
            outcome="SUCCESS",
        )
        self.repo.store(record)
        records = self.repo.get_recent(limit=1)
        assert records[0].hardening == ["Blocked IP: 10.0.0.1", "Added WAF rule"]
        assert records[0].extra == {"key": "value"}
    
    def test_empty_retrieval(self):
        records = self.repo.get_recent(limit=10)
        assert records == []

    def test_security_event_preserves_provenance_and_prediction(self):
        event = SecurityEventRecord(
            event_id="evt-1",
            target_id="todo-app",
            method="POST",
            path="/todos",
            source_kind="red",
            source_provenance={"source_kind": "red", "campaign_id": "camp-1"},
            campaign_id="camp-1",
            request_id="req-1",
            prediction_is_attack=True,
            prediction_attack_type="sql_injection",
            prediction_confidence=0.91,
            raw_event={"status_code": 403},
        )
        self.repo.store_event(event)
        stored = self.repo.get_events()
        assert stored[0].event_id == "evt-1"
        assert stored[0].source_provenance["campaign_id"] == "camp-1"
        assert stored[0].prediction_attack_type == "sql_injection"

    def test_security_event_correlation_update(self):
        event = SecurityEventRecord(event_id="evt-2", source_kind="user")
        self.repo.store_event(event)
        event.patch_id = "patch-1"
        event.validation_id = "validation-1"
        event.finding_id = "finding-1"
        self.repo.update_event(event)
        stored = self.repo.get_events()[0]
        assert stored.finding_id == "finding-1"
        assert stored.patch_id == "patch-1"
        assert stored.validation_id == "validation-1"

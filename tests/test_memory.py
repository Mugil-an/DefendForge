import pytest
from blue_agent.memory.repository import MemoryRepository
from blue_agent.schemas import BlueMemoryRecord, DecisionPath, ValidationDecision


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

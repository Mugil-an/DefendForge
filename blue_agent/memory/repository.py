"""
Blue Memory Repository — Manages persistence of the agent's experiences.
"""

from __future__ import annotations

import json
from typing import List, Optional

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import BlueMemoryRecord, DecisionPath, ValidationDecision

log = get_logger("memory.repository")

Base = declarative_base()


class BlueMemoryModel(Base):
    """SQLAlchemy model for a Blue Memory record."""
    __tablename__ = "blue_memory"

    record_id = Column(String, primary_key=True)
    round = Column(Integer, default=0)
    attack_type = Column(String)
    detected = Column(Boolean, default=False)
    detection_time_ms = Column(Float, default=0.0)
    decision_path = Column(String)
    ppo_confidence = Column(Float, default=0.0)
    llm_escalation = Column(Boolean, default=False)
    retrieved_documents = Column(Text)  # JSON list
    remediation = Column(String)
    patch_id = Column(String)
    patch_validation = Column(String)
    remediation_time_ms = Column(Float, default=0.0)
    hardening = Column(Text)  # JSON list
    outcome = Column(String)
    timestamp = Column(DateTime)
    extra = Column(Text)  # JSON dict


class MemoryRepository:
    """
    Handles storing and retrieving the agent's experiences.
    Connects to Postgres (or SQLite for testing) via SQLAlchemy.
    """

    def __init__(self, db_url: Optional[str] = None):
        self._db_url = db_url or settings.db.sync_url
        self._engine = create_engine(self._db_url, echo=False)
        self._SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self._engine)
        
        # Initialize schema
        Base.metadata.create_all(bind=self._engine)
        log.info("memory_db_initialized", db_url=self._db_url)

    def store(self, record: BlueMemoryRecord) -> None:
        """Store a new memory record."""
        db_model = BlueMemoryModel(
            record_id=record.record_id,
            round=record.round,
            attack_type=record.attack_type,
            detected=record.detected,
            detection_time_ms=record.detection_time_ms,
            decision_path=record.decision_path.value,
            ppo_confidence=record.ppo_confidence,
            llm_escalation=record.llm_escalation,
            retrieved_documents=json.dumps(record.retrieved_documents),
            remediation=record.remediation,
            patch_id=record.patch_id,
            patch_validation=record.patch_validation.value,
            remediation_time_ms=record.remediation_time_ms,
            hardening=json.dumps(record.hardening),
            outcome=record.outcome,
            timestamp=record.timestamp,
            extra=json.dumps(record.extra),
        )
        
        with self._SessionLocal() as session:
            try:
                session.add(db_model)
                session.commit()
                log.info("memory_record_stored", record_id=record.record_id)
            except Exception as e:
                session.rollback()
                log.error("memory_store_failed", record_id=record.record_id, error=str(e))
                raise

    def get_recent(self, limit: int = 10) -> List[BlueMemoryRecord]:
        """Fetch the most recent memory records."""
        with self._SessionLocal() as session:
            db_models = session.query(BlueMemoryModel).order_by(BlueMemoryModel.timestamp.desc()).limit(limit).all()
            
            records = []
            for m in db_models:
                records.append(BlueMemoryRecord(
                    record_id=m.record_id,
                    round=m.round,
                    attack_type=m.attack_type,
                    detected=m.detected,
                    detection_time_ms=m.detection_time_ms,
                    decision_path=DecisionPath(m.decision_path),
                    ppo_confidence=m.ppo_confidence,
                    llm_escalation=m.llm_escalation,
                    retrieved_documents=json.loads(m.retrieved_documents),
                    remediation=m.remediation,
                    patch_id=m.patch_id,
                    patch_validation=ValidationDecision(m.patch_validation),
                    remediation_time_ms=m.remediation_time_ms,
                    hardening=json.loads(m.hardening),
                    outcome=m.outcome,
                    timestamp=m.timestamp,
                    extra=json.loads(m.extra),
                ))
            return records

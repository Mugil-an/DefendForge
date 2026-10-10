"""
Blue Memory Repository — Manages persistence of the agent's experiences.
"""

from __future__ import annotations

import json
from typing import List, Optional

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import BlueMemoryRecord, DecisionPath, SecurityEventRecord, ValidationDecision

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


class SecurityEventModel(Base):
    """Normalized gateway event, retained independently from Blue predictions."""

    __tablename__ = "security_events"

    event_id = Column(String, primary_key=True)
    occurred_at = Column(DateTime, nullable=False)
    target_id = Column(String, index=True)
    method = Column(String, nullable=False)
    path = Column(String, nullable=False)
    query = Column(Text)
    status_code = Column(Integer)
    duration_ms = Column(Float)
    request_size = Column(Integer)
    response_size = Column(Integer)
    source_kind = Column(String, nullable=False, index=True)
    source_provenance = Column(Text, nullable=False)
    campaign_id = Column(String, index=True)
    request_id = Column(String, index=True)
    finding_id = Column(String, index=True)
    patch_id = Column(String, index=True)
    validation_id = Column(String, index=True)
    prediction_is_attack = Column(Boolean)
    prediction_attack_type = Column(String)
    prediction_confidence = Column(Float)
    raw_event = Column(Text, nullable=False)


class MemoryRepository:
    """
    Handles storing and retrieving the agent's experiences.
    Connects to Postgres (or SQLite for testing) via SQLAlchemy.
    """

    def __init__(self, db_url: Optional[str] = None):
        self._db_url = db_url or settings.db.sync_url
        engine_options = {}
        if self._db_url == "sqlite:///:memory:":
            engine_options = {
                "connect_args": {"check_same_thread": False},
                "poolclass": StaticPool,
            }
        self._engine = create_engine(self._db_url, echo=False, **engine_options)
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

    def store_event(self, event: SecurityEventRecord) -> None:
        """Persist one normalized observation; duplicate event IDs are rejected."""
        model = SecurityEventModel(
            event_id=event.event_id,
            occurred_at=event.occurred_at,
            target_id=event.target_id,
            method=event.method,
            path=event.path,
            query=event.query,
            status_code=event.status_code,
            duration_ms=event.duration_ms,
            request_size=event.request_size,
            response_size=event.response_size,
            source_kind=event.source_kind,
            source_provenance=json.dumps(event.source_provenance),
            campaign_id=event.campaign_id,
            request_id=event.request_id,
            finding_id=event.finding_id,
            patch_id=event.patch_id,
            validation_id=event.validation_id,
            prediction_is_attack=event.prediction_is_attack,
            prediction_attack_type=event.prediction_attack_type,
            prediction_confidence=event.prediction_confidence,
            raw_event=json.dumps(event.raw_event),
        )
        with self._SessionLocal() as session:
            try:
                session.add(model)
                session.commit()
            except Exception:
                session.rollback()
                raise

    def update_event(self, event: SecurityEventRecord) -> None:
        """Update Blue's prediction/correlation fields without replacing provenance."""
        with self._SessionLocal() as session:
            model = session.get(SecurityEventModel, event.event_id)
            if model is None:
                self.store_event(event)
                return
            model.finding_id = event.finding_id
            model.patch_id = event.patch_id
            model.validation_id = event.validation_id
            model.prediction_is_attack = event.prediction_is_attack
            model.prediction_attack_type = event.prediction_attack_type
            model.prediction_confidence = event.prediction_confidence
            session.commit()

    def get_events(self, limit: int = 100) -> List[SecurityEventRecord]:
        """Return durable events newest first."""
        with self._SessionLocal() as session:
            models = (
                session.query(SecurityEventModel)
                .order_by(SecurityEventModel.occurred_at.desc())
                .limit(limit)
                .all()
            )
            return [
                SecurityEventRecord(
                    event_id=m.event_id,
                    occurred_at=m.occurred_at,
                    target_id=m.target_id or "",
                    method=m.method,
                    path=m.path,
                    query=m.query or "",
                    status_code=m.status_code,
                    duration_ms=m.duration_ms,
                    request_size=m.request_size,
                    response_size=m.response_size,
                    source_kind=m.source_kind,
                    source_provenance=json.loads(m.source_provenance),
                    campaign_id=m.campaign_id,
                    request_id=m.request_id,
                    finding_id=m.finding_id,
                    patch_id=m.patch_id,
                    validation_id=m.validation_id,
                    prediction_is_attack=m.prediction_is_attack,
                    prediction_attack_type=m.prediction_attack_type,
                    prediction_confidence=m.prediction_confidence,
                    raw_event=json.loads(m.raw_event),
                )
                for m in models
            ]

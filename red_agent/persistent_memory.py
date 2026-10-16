"""
Red Agent — Persistent Cross-Campaign Memory (PostgreSQL).

Stores attack history across multiple campaigns so the Red Agent can:
  - Know which MITRE techniques were blocked across past campaigns
  - Know which evasion variants were already tried
  - Avoid repeating exactly the same blocked approach
  - Pick novel techniques prioritized by past success
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from sqlalchemy import (
    Boolean, Column, Float, Integer, String, Text,
    create_engine, text,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("red.persistent_memory")

Base = declarative_base()


class RedAttackRecord(Base):
    """One attack attempt, persisted across campaigns."""

    __tablename__ = "red_attack_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(String, index=True, nullable=False)
    round_number = Column(Integer, default=0)
    technique_id = Column(String, index=True, nullable=False)
    technique_name = Column(String)
    tactic = Column(String)
    attack_type = Column(String, index=True, nullable=False)
    endpoint = Column(String, nullable=False)
    method = Column(String, default="GET")
    payload_hash = Column(String)   # SHA256 of the payload value
    evasion_variant = Column(String, default="none")
    response_code = Column(Integer, default=0)
    was_blocked = Column(Boolean, default=False)
    was_detected = Column(Boolean, default=False)
    exploit_success = Column(Boolean, default=False)
    timestamp = Column(Float, default=time.time)
    notes = Column(Text, default="")


class RedPersistentMemory:
    """
    Cross-campaign persistent memory backed by PostgreSQL.

    Key operations:
      - record_attack()      : Store a new attack attempt
      - get_blocked_techniques(): Return technique IDs that were blocked
      - get_tried_evasion_variants(): Return variants tried for a technique
      - get_campaign_summary(): Stats for the last N campaigns
      - get_best_attack_types(): Ranked by success/detection ratio
    """

    def __init__(self, db_url: str | None = None):
        resolved = db_url or settings.db.sync_url
        engine_opts: dict[str, Any] = {}
        if "sqlite:///:memory:" in resolved:
            engine_opts = {
                "connect_args": {"check_same_thread": False},
                "poolclass": StaticPool,
            }
        try:
            self._engine = create_engine(resolved, echo=False, **engine_opts)
            Base.metadata.create_all(bind=self._engine)
            self._Session = sessionmaker(bind=self._engine)
            log.info("red_persistent_memory_connected", db=resolved.split("@")[-1])
        except Exception as exc:
            log.warning("red_persistent_memory_db_unavailable",
                        error=str(exc), fallback="in-memory")
            # Fallback to in-memory SQLite
            mem_url = "sqlite:///:memory:"
            self._engine = create_engine(
                mem_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
            Base.metadata.create_all(bind=self._engine)
            self._Session = sessionmaker(bind=self._engine)

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def record_attack(
        self,
        campaign_id: str,
        round_number: int,
        technique_id: str,
        technique_name: str,
        tactic: str,
        attack_type: str,
        endpoint: str,
        method: str,
        payload_value: str,
        evasion_variant: str,
        response_code: int,
        was_blocked: bool,
        was_detected: bool,
        exploit_success: bool,
        notes: str = "",
    ) -> None:
        payload_hash = hashlib.sha256(payload_value.encode()).hexdigest()[:16]
        record = RedAttackRecord(
            campaign_id=campaign_id,
            round_number=round_number,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            attack_type=attack_type,
            endpoint=endpoint,
            method=method,
            payload_hash=payload_hash,
            evasion_variant=evasion_variant,
            response_code=response_code,
            was_blocked=was_blocked,
            was_detected=was_detected,
            exploit_success=exploit_success,
            timestamp=time.time(),
            notes=notes,
        )
        with self._Session() as session:
            try:
                session.add(record)
                session.commit()
            except Exception as exc:
                session.rollback()
                log.warning("red_memory_record_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_blocked_technique_ids(self, last_n_campaigns: int = 3) -> set[str]:
        """
        Return MITRE technique IDs that were blocked in the last N campaigns.
        If blocked in ANY of the last N campaigns, avoid it.
        """
        with self._Session() as session:
            try:
                # Get last N distinct campaign IDs (Postgres and SQLite compatible)
                from sqlalchemy import func
                campaigns = (
                    session.query(RedAttackRecord.campaign_id)
                    .group_by(RedAttackRecord.campaign_id)
                    .order_by(func.max(RedAttackRecord.timestamp).desc())
                    .limit(last_n_campaigns)
                    .all()
                )
                campaign_ids = [c[0] for c in campaigns]
                if not campaign_ids:
                    return set()
                records = (
                    session.query(RedAttackRecord.technique_id)
                    .filter(
                        RedAttackRecord.campaign_id.in_(campaign_ids),
                        RedAttackRecord.was_blocked == True,
                    )
                    .all()
                )
                return {r[0] for r in records}
            except Exception:
                return set()

    def get_tried_technique_ids(self, current_campaign_id: str) -> set[str]:
        """Return all technique IDs tried in the current campaign."""
        with self._Session() as session:
            try:
                records = (
                    session.query(RedAttackRecord.technique_id)
                    .filter(RedAttackRecord.campaign_id == current_campaign_id)
                    .all()
                )
                return {r[0] for r in records}
            except Exception:
                return set()

    def get_tried_evasion_variants(self, technique_id: str, last_n: int = 10) -> set[str]:
        """Return evasion variants already tried for a specific technique."""
        with self._Session() as session:
            try:
                records = (
                    session.query(RedAttackRecord.evasion_variant)
                    .filter(RedAttackRecord.technique_id == technique_id)
                    .order_by(RedAttackRecord.timestamp.desc())
                    .limit(last_n)
                    .all()
                )
                return {r[0] for r in records if r[0] and r[0] != "none"}
            except Exception:
                return set()

    def get_success_rates(self) -> dict[str, dict[str, float]]:
        """
        Return per attack_type success and detection rates over all history.
        """
        with self._Session() as session:
            try:
                from collections import defaultdict
                stats: dict[str, dict[str, int]] = defaultdict(lambda: {
                    "total": 0, "success": 0, "detected": 0, "blocked": 0
                })
                records = session.query(
                    RedAttackRecord.attack_type,
                    RedAttackRecord.exploit_success,
                    RedAttackRecord.was_detected,
                    RedAttackRecord.was_blocked,
                ).all()
                for row in records:
                    at = row[0]
                    stats[at]["total"] += 1
                    if row[1]:
                        stats[at]["success"] += 1
                    if row[2]:
                        stats[at]["detected"] += 1
                    if row[3]:
                        stats[at]["blocked"] += 1

                rates = {}
                for at, s in stats.items():
                    t = s["total"] or 1
                    rates[at] = {
                        "success_rate": s["success"] / t,
                        "detection_rate": s["detected"] / t,
                        "block_rate": s["blocked"] / t,
                        "total_attempts": s["total"],
                    }
                return rates
            except Exception:
                return {}

    def get_best_attack_types(self, top_k: int = 3) -> list[str]:
        """
        Return attack types sorted by composite score (high success, low block).
        """
        rates = self.get_success_rates()
        if not rates:
            return []
        scored = []
        for at, r in rates.items():
            # Score = success_rate * (1 - block_rate)
            score = r["success_rate"] * (1.0 - r["block_rate"])
            scored.append((at, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [at for at, _ in scored[:top_k]]

    def get_campaign_summary(self, campaign_id: str) -> dict[str, Any]:
        """Return a summary of a campaign's results."""
        with self._Session() as session:
            try:
                records = (
                    session.query(RedAttackRecord)
                    .filter(RedAttackRecord.campaign_id == campaign_id)
                    .all()
                )
                if not records:
                    return {"campaign_id": campaign_id, "total": 0}
                return {
                    "campaign_id": campaign_id,
                    "total": len(records),
                    "successes": sum(1 for r in records if r.exploit_success),
                    "blocked": sum(1 for r in records if r.was_blocked),
                    "detected": sum(1 for r in records if r.was_detected),
                    "techniques_used": list({r.technique_id for r in records}),
                    "evasion_variants_used": list({r.evasion_variant for r in records if r.evasion_variant != "none"}),
                }
            except Exception:
                return {"campaign_id": campaign_id, "error": "query_failed"}

    def context_for_llm(self, current_campaign_id: str) -> str:
        """Build a context string for LLM-guided attack planning."""
        rates = self.get_success_rates()
        blocked = self.get_blocked_technique_ids()
        tried = self.get_tried_technique_ids(current_campaign_id)

        lines = [
            "=== Red Agent Persistent Memory ===",
            f"Globally blocked techniques (last 3 campaigns): {', '.join(sorted(blocked)) or 'none'}",
            f"Tried in current campaign: {', '.join(sorted(tried)) or 'none'}",
            "",
            "Attack type performance (all time):",
        ]
        for at, r in sorted(rates.items()):
            lines.append(
                f"  {at}: success={r['success_rate']:.0%} "
                f"detect={r['detection_rate']:.0%} "
                f"block={r['block_rate']:.0%} "
                f"({r['total_attempts']} attempts)"
            )
        return "\n".join(lines)

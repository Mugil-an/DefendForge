"""
Red Agent — MITRE ATT&CK Knowledge Base.

Loads the embedded mitre_techniques.json and provides a structured
interface for the Red Agent to:
  - Pick novel techniques (not yet tried or previously blocked)
  - Find evasion variants for techniques that were detected/blocked
  - Map MITRE technique IDs to payload categories
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blue_agent.logging_cfg import get_logger

log = get_logger("red.mitre_knowledge")

_TECHNIQUES_FILE = Path(__file__).parent / "mitre_techniques.json"


@dataclass
class MitreTechnique:
    """One MITRE ATT&CK technique entry."""
    technique_id: str
    name: str
    tactic: str
    description: str
    payload_categories: tuple[str, ...]
    severity: str
    evasion_variants: tuple[str, ...]
    detection_signatures: tuple[str, ...]
    tags: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "payload_categories": list(self.payload_categories),
            "severity": self.severity,
            "evasion_variants": list(self.evasion_variants),
            "detection_signatures": list(self.detection_signatures),
            "tags": list(self.tags),
        }


class MitreKnowledge:
    """
    MITRE ATT&CK knowledge base for the Red Agent.

    Provides technique selection based on:
    - Novelty  : prefer untried techniques
    - Evasion  : pick variant if previously blocked
    - Coverage : ensure full tactic coverage across rounds
    """

    def __init__(self, path: str | Path | None = None):
        self._techniques: list[MitreTechnique] = []
        self._load(path or _TECHNIQUES_FILE)
        log.info("mitre_knowledge_loaded", count=len(self._techniques))

    def _load(self, path: str | Path) -> None:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        for item in raw:
            self._techniques.append(MitreTechnique(
                technique_id=item["technique_id"],
                name=item["name"],
                tactic=item["tactic"],
                description=item["description"],
                payload_categories=tuple(item.get("payload_categories", [])),
                severity=item.get("severity", "medium"),
                evasion_variants=tuple(item.get("evasion_variants", [])),
                detection_signatures=tuple(item.get("detection_signatures", [])),
                tags=tuple(item.get("tags", [])),
            ))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def all_techniques(self) -> list[MitreTechnique]:
        return list(self._techniques)

    def get_by_id(self, technique_id: str) -> MitreTechnique | None:
        return next((t for t in self._techniques if t.technique_id == technique_id), None)

    def get_by_payload_category(self, category: str) -> list[MitreTechnique]:
        """Return all techniques that can generate the given payload category."""
        return [t for t in self._techniques if category in t.payload_categories]

    def get_novel_technique(
        self,
        blocked_ids: set[str],
        tried_ids: set[str],
        preferred_tactic: str | None = None,
    ) -> MitreTechnique | None:
        """
        Pick a technique the Red Agent hasn't been blocked on.

        Priority order:
          1. Not blocked AND not yet tried
          2. Not blocked but already tried (retry with different variant)
          3. Blocked but highest severity (last resort)
        """
        candidates = [t for t in self._techniques if t.technique_id not in blocked_ids]

        if preferred_tactic:
            tactic_candidates = [t for t in candidates if t.tactic.lower() == preferred_tactic.lower()]
            if tactic_candidates:
                candidates = tactic_candidates

        # Tier 1: untried AND unblocked
        untried = [t for t in candidates if t.technique_id not in tried_ids]
        if untried:
            # Weight by severity
            return self._weighted_pick(untried)

        # Tier 2: tried but not blocked — pick with different evasion potential
        with_evasion = [t for t in candidates if t.evasion_variants]
        if with_evasion:
            return self._weighted_pick(with_evasion)

        # Tier 3: fallback to anything not blocked
        if candidates:
            return random.choice(candidates)

        # Everything blocked — pick the highest severity blocked one
        if self._techniques:
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            return max(self._techniques, key=lambda t: severity_order.get(t.severity, 0))

        return None

    def get_evasion_variant(self, technique_id: str, already_tried: set[str]) -> str | None:
        """
        Return a new evasion variant for this technique that hasn't been tried.
        """
        technique = self.get_by_id(technique_id)
        if not technique:
            return None
        available = [v for v in technique.evasion_variants if v not in already_tried]
        if not available:
            # All variants tried — return a random one anyway
            return random.choice(technique.evasion_variants) if technique.evasion_variants else None
        return random.choice(available)

    def get_tactics_coverage(self, tried_ids: set[str]) -> dict[str, int]:
        """Return count of tried techniques per tactic."""
        coverage: dict[str, int] = {}
        for t in self._techniques:
            if t.technique_id in tried_ids:
                coverage[t.tactic] = coverage.get(t.tactic, 0) + 1
        return coverage

    def get_least_covered_tactic(self, tried_ids: set[str]) -> str | None:
        """Return the tactic with the fewest tried techniques (encourages diversity)."""
        tactic_total: dict[str, int] = {}
        for t in self._techniques:
            tactic_total[t.tactic] = tactic_total.get(t.tactic, 0) + 1

        coverage = self.get_tactics_coverage(tried_ids)
        # Find tactic with lowest coverage ratio
        best_tactic = None
        best_ratio = 1.0
        for tactic, total in tactic_total.items():
            tried = coverage.get(tactic, 0)
            ratio = tried / total if total > 0 else 0.0
            if ratio < best_ratio:
                best_ratio = ratio
                best_tactic = tactic
        return best_tactic

    def summary(self, blocked_ids: set[str], tried_ids: set[str]) -> str:
        """Build a context string for LLM-guided attack planning."""
        lines = [
            f"=== MITRE ATT&CK Knowledge ({len(self._techniques)} techniques) ===",
            f"Tried: {len(tried_ids)} | Blocked: {len(blocked_ids)} | Available: {len(self._techniques) - len(blocked_ids)}",
            "",
        ]
        for t in self._techniques:
            status = "BLOCKED" if t.technique_id in blocked_ids else (
                "TRIED" if t.technique_id in tried_ids else "UNTRIED"
            )
            lines.append(f"  [{status}] {t.technique_id} {t.name} ({t.tactic}) — {t.severity}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _weighted_pick(self, candidates: list[MitreTechnique]) -> MitreTechnique:
        """Pick a technique weighted by severity."""
        severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        weights = [severity_weight.get(t.severity, 1) for t in candidates]
        return random.choices(candidates, weights=weights, k=1)[0]

"""
Alert Manager — consumes anomaly results, applies post-processing
(deduplication, windowed aggregation), and emits ``AttackEvent``
objects ready for the decision engine.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np

from blue_agent.config import settings
from blue_agent.detection.anomaly_detector import AnomalyDetectorBase
from blue_agent.detection.feature_extractor import (
    FEATURE_NAMES,
    extract_features,
    feature_vector_to_dict,
)
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AnomalyResult, AttackEvent, Severity

log = get_logger("detection.alert_manager")

# ---------------------------------------------------------------------------
# Heuristic attack-type classification from feature flags
# ---------------------------------------------------------------------------
_ATTACK_HEURISTICS = [
    ("has_sql_keywords",     "SQL Injection",         "CWE-89",  "T1190"),
    ("has_script_tags",      "Cross-Site Scripting",  "CWE-79",  "T1189"),
    ("has_path_traversal",   "Path Traversal",        "CWE-22",  "T1083"),
    ("has_command_chars",    "Command Injection",     "CWE-78",  "T1059"),
    ("is_known_scanner_ua",  "Reconnaissance Scan",   "",        "T1595"),
]


def _classify_attack(features: Dict[str, float]) -> Dict[str, str]:
    """
    Best-effort heuristic classification based on extracted
    feature flags.  Returns dict with ``attack_type``, ``cwe``,
    ``mitre_technique``.
    """
    for feature_name, attack_type, cwe, mitre in _ATTACK_HEURISTICS:
        if features.get(feature_name, 0.0) > 0.5:
            return {"attack_type": attack_type, "cwe": cwe, "mitre_technique": mitre}
    return {"attack_type": "", "cwe": "", "mitre_technique": ""}


def _estimate_severity(anomaly_score: float, features: Dict[str, float]) -> Severity:
    """Map anomaly score and certain features to a Severity level."""
    if anomaly_score >= 0.90:
        return Severity.CRITICAL
    if anomaly_score >= 0.75:
        return Severity.HIGH
    if anomaly_score >= 0.55:
        return Severity.MEDIUM
    if anomaly_score >= 0.40:
        return Severity.LOW
    return Severity.UNKNOWN


# ---------------------------------------------------------------------------
# Alert Manager
# ---------------------------------------------------------------------------
class AlertManager:
    """
    Stateful bridge between the anomaly detector and the decision
    engine.

    1. Receives raw events.
    2. Extracts features, runs detector.
    3. Filters noise (dedup window, minimum-events threshold).
    4. Classifies and emits ``AttackEvent`` objects.
    """

    def __init__(
        self,
        detector: AnomalyDetectorBase,
        dedup_window_seconds: int = 10,
        min_events_for_alert: Optional[int] = None,
    ):
        self._detector = detector
        self._dedup_window = dedup_window_seconds
        self._min_events = min_events_for_alert or settings.detection.min_events_for_alert
        # source → [timestamp of anomalous events]
        self._recent_anomalies: Dict[str, List[float]] = defaultdict(list)
        # event_id tracking to prevent duplicate alerts
        self._emitted: Dict[str, float] = {}

    def process_event(self, raw_event: Dict[str, Any]) -> Optional[AttackEvent]:
        """
        Process one raw traffic/log event.

        Returns an ``AttackEvent`` if the event is anomalous AND
        meets the minimum-events threshold, else ``None``.
        """
        features_vec = extract_features(raw_event)
        result: AnomalyResult = self._detector.predict_one(features_vec)

        if not result.is_anomaly:
            return None

        source = raw_event.get("source", "unknown")
        now = datetime.now(timezone.utc).timestamp()

        # Record anomaly timestamp for this source
        self._recent_anomalies[source].append(now)
        # Prune old entries
        cutoff = now - self._dedup_window
        self._recent_anomalies[source] = [
            ts for ts in self._recent_anomalies[source] if ts >= cutoff
        ]

        # Only emit an alert if we've seen enough anomalies from this source
        if len(self._recent_anomalies[source]) < self._min_events:
            log.debug(
                "anomaly_below_threshold",
                source=source,
                count=len(self._recent_anomalies[source]),
                required=self._min_events,
            )
            return None

        # Build the attack event
        features_dict = feature_vector_to_dict(features_vec)
        classification = _classify_attack(features_dict)
        severity = _estimate_severity(result.anomaly_score, features_dict)

        event = AttackEvent(
            event_id=raw_event.get("event_id") or str(uuid.uuid4()),
            source=source,
            destination=raw_event.get("destination", ""),
            endpoint=raw_event.get("endpoint", ""),
            attack_type=classification["attack_type"],
            cwe=classification["cwe"],
            mitre_technique=classification["mitre_technique"],
            features={**features_dict, "finding_id": raw_event.get("finding_id")},
            anomaly_score=result.anomaly_score,
            detection_confidence=result.confidence,
            evidence=[
                f"anomaly_score={result.anomaly_score}",
                f"confidence={result.confidence}",
            ],
            severity=severity,
            raw_logs=[str(raw_event)],
        )

        log.info(
            "attack_event_emitted",
            event_id=event.event_id,
            source=source,
            attack_type=event.attack_type or "unknown",
            severity=event.severity.value,
            anomaly_score=event.anomaly_score,
        )
        return event

    def process_batch(self, raw_events: List[Dict[str, Any]]) -> List[AttackEvent]:
        """Process multiple events, returning only those that trigger alerts."""
        alerts: List[AttackEvent] = []
        for evt in raw_events:
            alert = self.process_event(evt)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def reset(self) -> None:
        """Clear internal state (useful between rounds)."""
        self._recent_anomalies.clear()
        self._emitted.clear()

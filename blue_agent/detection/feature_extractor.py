"""
Feature Extractor — transforms raw HTTP traffic / log events
into numeric feature vectors suitable for anomaly detection models.

This is the single point where raw observability data becomes
a numeric representation.  Both Isolation Forest and Autoencoder
consume the same feature vector.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from blue_agent.logging_cfg import get_logger

log = get_logger("detection.feature_extractor")

# ---------------------------------------------------------------------------
# Canonical feature order — every model trained on this schema
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    "request_size",
    "response_size",
    "response_code",
    "latency_ms",
    "request_rate_1m",         # requests / minute from same source
    "failed_login_count_5m",
    "unique_endpoints_1m",     # distinct endpoints hit in 1 min
    "method_is_get",
    "method_is_post",
    "method_is_put",
    "method_is_delete",
    "method_is_other",
    "has_sql_keywords",
    "has_script_tags",
    "has_path_traversal",
    "has_command_chars",
    "param_count",
    "param_entropy",
    "url_length",
    "hour_of_day",
    "is_known_scanner_ua",
    "payload_entropy",
    "response_code_is_4xx",
    "response_code_is_5xx",
]

NUM_FEATURES = len(FEATURE_NAMES)

# ---------------------------------------------------------------------------
# Heuristic detectors for suspicious payloads
# ---------------------------------------------------------------------------
_SQL_KEYWORDS = {
    "select", "union", "insert", "update", "delete", "drop",
    "exec", "execute", "--", ";", "or 1=1", "' or", "1=1",
    "sleep(", "benchmark(", "waitfor",
}

_SCRIPT_PATTERNS = {
    "<script", "javascript:", "onerror=", "onload=",
    "alert(", "document.cookie", "eval(",
}

_PATH_TRAVERSAL_PATTERNS = {"../", "..\\", "%2e%2e", "%252e"}

_COMMAND_CHARS = {"|", ";", "`", "$(",  "&&", "||"}

_SCANNER_USER_AGENTS = {
    "nikto", "sqlmap", "nmap", "masscan", "gobuster", "dirbuster",
    "wfuzz", "ffuf", "hydra", "burpsuite", "zaproxy",
}


def _contains_any(text: str, patterns: set) -> bool:
    text_lower = text.lower()
    return any(p in text_lower for p in patterns)


def _shannon_entropy(data: str) -> float:
    """Shannon entropy in bits per character."""
    if not data:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# ---------------------------------------------------------------------------
# Rate-tracking state (per-source sliding window)
# ---------------------------------------------------------------------------
class RateTracker:
    """
    Lightweight in-memory counter for per-source request rates.

    Tracks request counts and distinct endpoints within a sliding
    window.  NOT thread-safe by design — use one per asyncio task
    or protect externally.
    """

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        # source → [(timestamp, endpoint), ...]
        self._events: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._failed_logins: Dict[str, List[float]] = defaultdict(list)

    def record(self, source: str, endpoint: str, timestamp: Optional[float] = None) -> None:
        ts = timestamp or datetime.now(timezone.utc).timestamp()
        self._events[source].append((ts, endpoint))

    def record_failed_login(self, source: str, timestamp: Optional[float] = None) -> None:
        ts = timestamp or datetime.now(timezone.utc).timestamp()
        self._failed_logins[source].append(ts)

    def _prune(self, source: str, now: float) -> None:
        cutoff = now - self.window
        self._events[source] = [
            (ts, ep) for ts, ep in self._events[source] if ts >= cutoff
        ]
        self._failed_logins[source] = [
            ts for ts in self._failed_logins[source] if ts >= cutoff
        ]

    def request_rate(self, source: str, now: Optional[float] = None) -> float:
        now = now or datetime.now(timezone.utc).timestamp()
        self._prune(source, now)
        count = len(self._events[source])
        return count / (self.window / 60.0)  # per minute

    def unique_endpoints(self, source: str, now: Optional[float] = None) -> int:
        now = now or datetime.now(timezone.utc).timestamp()
        self._prune(source, now)
        return len({ep for _, ep in self._events[source]})

    def failed_login_count(self, source: str, window_seconds: int = 300, now: Optional[float] = None) -> int:
        now = now or datetime.now(timezone.utc).timestamp()
        cutoff = now - window_seconds
        return sum(1 for ts in self._failed_logins.get(source, []) if ts >= cutoff)


# Global tracker — one per Blue Agent process
_rate_tracker = RateTracker(window_seconds=60)


def get_rate_tracker() -> RateTracker:
    return _rate_tracker


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------
def extract_features(event: Dict[str, Any]) -> np.ndarray:
    """
    Convert a raw traffic/log event dict into a fixed-size numeric
    feature vector.

    Expected event keys (all optional — missing values default to 0):

        source, destination, method, endpoint, response_code,
        request_size, response_size, latency_ms, user_agent,
        params (str or dict), body (str), timestamp (ISO or float),
        login_failed (bool)

    Returns
    -------
    np.ndarray of shape ``(NUM_FEATURES,)``
    """
    source = event.get("source", "unknown")
    endpoint = event.get("endpoint", "/")
    method = event.get("method", "GET").upper()
    params = event.get("params", "")
    body = event.get("body", "")
    user_agent = event.get("user_agent", "")
    now_ts = event.get("timestamp")

    if isinstance(now_ts, str):
        try:
            now_ts = datetime.fromisoformat(now_ts).timestamp()
        except (ValueError, TypeError):
            now_ts = datetime.now(timezone.utc).timestamp()
    elif now_ts is None:
        now_ts = datetime.now(timezone.utc).timestamp()

    # Track rate
    tracker = get_rate_tracker()
    tracker.record(source, endpoint, now_ts)
    if event.get("login_failed"):
        tracker.record_failed_login(source, now_ts)

    # Build combined payload for heuristic checks
    if isinstance(params, dict):
        params_str = "&".join(f"{k}={v}" for k, v in params.items())
    else:
        params_str = str(params)
    payload = f"{endpoint} {params_str} {body}"

    # Param count
    param_count = len(params) if isinstance(params, dict) else params_str.count("=")

    # Build feature vector
    features = np.zeros(NUM_FEATURES, dtype=np.float32)

    features[0] = float(event.get("request_size", 0))
    features[1] = float(event.get("response_size", 0))
    features[2] = float(event.get("response_code", 200))
    features[3] = float(event.get("latency_ms", 0))
    features[4] = tracker.request_rate(source, now_ts)
    features[5] = tracker.failed_login_count(source, 300, now_ts)
    features[6] = tracker.unique_endpoints(source, now_ts)
    features[7] = 1.0 if method == "GET" else 0.0
    features[8] = 1.0 if method == "POST" else 0.0
    features[9] = 1.0 if method == "PUT" else 0.0
    features[10] = 1.0 if method == "DELETE" else 0.0
    features[11] = 1.0 if method not in ("GET", "POST", "PUT", "DELETE") else 0.0
    features[12] = 1.0 if _contains_any(payload, _SQL_KEYWORDS) else 0.0
    features[13] = 1.0 if _contains_any(payload, _SCRIPT_PATTERNS) else 0.0
    features[14] = 1.0 if _contains_any(payload, _PATH_TRAVERSAL_PATTERNS) else 0.0
    features[15] = 1.0 if _contains_any(payload, _COMMAND_CHARS) else 0.0
    features[16] = float(param_count)
    features[17] = _shannon_entropy(params_str)
    features[18] = float(len(endpoint))
    features[19] = datetime.fromtimestamp(now_ts, tz=timezone.utc).hour
    features[20] = 1.0 if _contains_any(user_agent, _SCANNER_USER_AGENTS) else 0.0
    features[21] = _shannon_entropy(payload)
    features[22] = 1.0 if 400 <= int(event.get("response_code", 200)) < 500 else 0.0
    features[23] = 1.0 if int(event.get("response_code", 200)) >= 500 else 0.0

    return features


def extract_features_batch(events: List[Dict[str, Any]]) -> np.ndarray:
    """Extract features for multiple events. Returns (N, NUM_FEATURES)."""
    return np.array([extract_features(e) for e in events], dtype=np.float32)


def feature_vector_to_dict(vec: np.ndarray) -> Dict[str, float]:
    """Convert a feature vector back to a labelled dict (for logging)."""
    return {name: float(vec[i]) for i, name in enumerate(FEATURE_NAMES)}

"""
Anomaly Detection Bootstrap — trains and saves the RandomForest / IsolationForest
models when no pre-trained .joblib is found.

This solves the "detector_model_not_found_skipping_load" silent failure:
when the model file is absent, BlueAgent currently creates an UNFITTED
RandomForestDetector, which then crashes on the first predict_one() call
with RuntimeError("Model not fitted").

The orchestrator catches that with a schema-mismatch fallback to LLM,
but it means ZERO anomaly-model-based detection happens until someone
manually trains and deploys the model file.

This module:
  1. Generates synthetic normal + attack traffic (balanced)
  2. Trains a RandomForestClassifier on the 24 feature dimensions
  3. Also trains an IsolationForest on normal traffic only
  4. Saves both to models/ so the orchestrator can load them

Run standalone:
    python -m blue_agent.detection.bootstrap

Or imported programmatically:
    from blue_agent.detection.bootstrap import ensure_models_exist
    detector = ensure_models_exist()
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from blue_agent.config import settings
from blue_agent.detection.feature_extractor import (
    NUM_FEATURES,
    FEATURE_NAMES,
    extract_features,
)
from blue_agent.logging_cfg import get_logger

log = get_logger("detection.bootstrap")

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
RF_MODEL_PATH = MODELS_DIR / "random_forest_24.joblib"
IF_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic traffic generators
# ─────────────────────────────────────────────────────────────────────────────

_SQL_PAYLOADS = [
    "' OR 1=1--", "' UNION SELECT username,password FROM users--",
    "'; DROP TABLE users;--", "1' AND SLEEP(5)--", "' OR 'x'='x",
]
_XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)",
]
_CMD_PAYLOADS = ["; ls -la", "| cat /etc/passwd", "`whoami`", "$(id)", "& dir"]
_PATH_PAYLOADS = ["../../../etc/passwd", "%2e%2e%2fetc%2fpasswd", "....//etc/shadow"]
_SSRF_PAYLOADS = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22"]
_SCANNER_UAS = ["sqlmap/1.5", "Nikto/2.1.6", "Nmap Scripting Engine", "DirBuster-1.0"]
_NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/537",
    "python-httpx/0.26.0",
]
_ENDPOINTS = ["/", "/login", "/search", "/api/data", "/about", "/products"]
_ATTACK_ENDPOINTS = ["/login", "/search", "/file", "/ping", "/fetch", "/greet"]


def _normal_event() -> dict[str, Any]:
    """Simulate a benign HTTP request."""
    return {
        "source": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
        "endpoint": random.choice(_ENDPOINTS),
        "method": random.choice(["GET", "GET", "GET", "POST"]),
        "response_code": random.choice([200, 200, 200, 301, 404]),
        "request_size": random.randint(100, 800),
        "response_size": random.randint(500, 50_000),
        "latency_ms": random.uniform(5, 200),
        "user_agent": random.choice(_NORMAL_UAS),
        "params": {"q": random.choice(["hello", "world", "test", "search"])}
        if random.random() > 0.5 else "",
        "body": "",
    }


def _attack_event(attack_type: str | None = None) -> dict[str, Any]:
    """Simulate a malicious HTTP request."""
    types = ["sql_injection", "xss", "command_injection", "path_traversal", "ssrf", "scanner"]
    if attack_type is None:
        attack_type = random.choice(types)

    payload_map = {
        "sql_injection": _SQL_PAYLOADS,
        "xss": _XSS_PAYLOADS,
        "command_injection": _CMD_PAYLOADS,
        "path_traversal": _PATH_PAYLOADS,
        "ssrf": _SSRF_PAYLOADS,
        "scanner": [""],
    }
    payload = random.choice(payload_map.get(attack_type, [""]))
    ua = random.choice(_SCANNER_UAS) if attack_type == "scanner" else random.choice(_NORMAL_UAS)

    return {
        "source": f"192.168.{random.randint(1, 10)}.{random.randint(1, 10)}",
        "endpoint": random.choice(_ATTACK_ENDPOINTS),
        "method": random.choice(["GET", "POST"]),
        "response_code": random.choice([200, 400, 403, 500]),
        "request_size": random.randint(200, 2000),
        "response_size": random.randint(100, 5000),
        "latency_ms": random.uniform(1, 50),
        "user_agent": ua,
        "params": {"q": payload, "name": payload, "host": payload, "url": payload},
        "body": payload,
        "login_failed": attack_type == "brute_force",
    }


def generate_training_data(
    n_normal: int = 2000,
    n_attack: int = 2000,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate a balanced training dataset.
    Returns (X, y) where y=0 is normal, y=1 is attack.
    """
    log.info("generating_synthetic_training_data",
             n_normal=n_normal, n_attack=n_attack)

    X_normal = np.array([extract_features(_normal_event()) for _ in range(n_normal)],
                        dtype=np.float32)
    X_attack = np.array([extract_features(_attack_event()) for _ in range(n_attack)],
                        dtype=np.float32)

    X = np.vstack([X_normal, X_attack])
    y = np.array([0] * n_normal + [1] * n_attack, dtype=np.int32)

    # Shuffle
    idx = np.random.permutation(len(X))
    return X[idx], y[idx]


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def train_random_forest(X: np.ndarray, y: np.ndarray, path: Path) -> None:
    """Train and save a RandomForestClassifier."""
    log.info("training_random_forest", samples=len(X), path=str(path))
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X, y)
    accuracy = model.score(X, y)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "threshold": 0.5, "feature_names": FEATURE_NAMES}, path)
    log.info("random_forest_saved", path=str(path), train_accuracy=round(accuracy, 4))
    print(f"  RandomForest: train accuracy={accuracy:.1%}  → {path}")


def train_isolation_forest(X_normal: np.ndarray, path: Path) -> None:
    """Train and save an IsolationForest on normal traffic only."""
    log.info("training_isolation_forest", samples=len(X_normal))
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)
    model = IsolationForest(
        n_estimators=300,
        max_samples=512,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "threshold": 0.5}, path)
    log.info("isolation_forest_saved", path=str(path))
    print(f"  IsolationForest: trained on {len(X_normal)} normal samples → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def ensure_models_exist(force_retrain: bool = False) -> None:
    """
    Check if trained models exist; bootstrap-train if not.

    Called by the orchestrator before loading the detector — ensures
    there is always a fitted model available even in a fresh environment.
    """
    rf_exists = RF_MODEL_PATH.exists()
    if_exists = IF_MODEL_PATH.exists()

    if rf_exists and if_exists and not force_retrain:
        log.info("models_exist_skipping_bootstrap",
                 rf=str(RF_MODEL_PATH), iforest=str(IF_MODEL_PATH))
        return

    print("\n[Bootstrap] No trained detection models found — generating synthetic training data...")
    X, y = generate_training_data(n_normal=2000, n_attack=2000)
    X_normal = X[y == 0]

    if not rf_exists or force_retrain:
        print("[Bootstrap] Training RandomForest classifier...")
        train_random_forest(X, y, RF_MODEL_PATH)
    else:
        print(f"[Bootstrap] RandomForest already exists at {RF_MODEL_PATH}")

    if not if_exists or force_retrain:
        print("[Bootstrap] Training IsolationForest on normal traffic...")
        train_isolation_forest(X_normal, IF_MODEL_PATH)
    else:
        print(f"[Bootstrap] IsolationForest already exists at {IF_MODEL_PATH}")

    print("[Bootstrap] Detection models ready.\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Bootstrap DefendForge detection models")
    parser.add_argument("--force", action="store_true", help="Force retrain even if models exist")
    parser.add_argument("--n-normal", type=int, default=2000)
    parser.add_argument("--n-attack", type=int, default=2000)
    args = parser.parse_args()
    ensure_models_exist(force_retrain=args.force)

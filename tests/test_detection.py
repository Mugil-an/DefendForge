"""
Tests for blue_agent.detection — feature extraction, anomaly
detectors (IF, Autoencoder, CICIDS wrapper), and alert manager.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from pathlib import Path

import numpy as np
import pytest

from blue_agent.schemas import AnomalyResult, Severity


# =========================================================================
# Feature Extractor
# =========================================================================
class TestFeatureExtractor:
    def test_feature_count(self):
        from blue_agent.detection.feature_extractor import NUM_FEATURES, FEATURE_NAMES
        assert NUM_FEATURES == 24
        assert len(FEATURE_NAMES) == NUM_FEATURES

    def test_extract_benign_event(self):
        from blue_agent.detection.feature_extractor import extract_features, NUM_FEATURES
        event = {
            "source": "192.168.1.10",
            "endpoint": "/api/posts",
            "method": "GET",
            "response_code": 200,
            "request_size": 256,
            "response_size": 1024,
            "latency_ms": 45,
        }
        vec = extract_features(event)
        assert vec.shape == (NUM_FEATURES,)
        assert vec.dtype == np.float32
        assert vec[0] == 256.0    # request_size
        assert vec[7] == 1.0      # method_is_get
        assert vec[12] == 0.0     # no SQL keywords

    def test_extract_sqli_event(self):
        from blue_agent.detection.feature_extractor import extract_features
        event = {
            "source": "10.0.0.99",
            "endpoint": "/login",
            "method": "POST",
            "params": {"username": "admin' OR 1=1--", "password": "x"},
            "response_code": 200,
        }
        vec = extract_features(event)
        assert vec[8] == 1.0      # method_is_post
        assert vec[12] == 1.0     # has_sql_keywords

    def test_extract_xss_event(self):
        from blue_agent.detection.feature_extractor import extract_features
        event = {
            "source": "10.0.0.99",
            "endpoint": "/greet",
            "method": "GET",
            "params": "name=<script>alert(1)</script>",
            "response_code": 200,
        }
        vec = extract_features(event)
        assert vec[13] == 1.0     # has_script_tags

    def test_extract_path_traversal(self):
        from blue_agent.detection.feature_extractor import extract_features
        event = {
            "source": "10.0.0.99",
            "endpoint": "/file",
            "method": "GET",
            "params": "name=../../../etc/passwd",
        }
        vec = extract_features(event)
        assert vec[14] == 1.0     # has_path_traversal

    def test_extract_scanner_ua(self):
        from blue_agent.detection.feature_extractor import extract_features
        event = {
            "source": "10.0.0.99",
            "endpoint": "/",
            "user_agent": "sqlmap/1.7",
        }
        vec = extract_features(event)
        assert vec[20] == 1.0     # is_known_scanner_ua

    def test_batch_extraction(self):
        from blue_agent.detection.feature_extractor import extract_features_batch, NUM_FEATURES
        events = [
            {"source": "10.0.0.1", "endpoint": "/a"},
            {"source": "10.0.0.2", "endpoint": "/b"},
            {"source": "10.0.0.3", "endpoint": "/c"},
        ]
        batch = extract_features_batch(events)
        assert batch.shape == (3, NUM_FEATURES)

    def test_feature_vector_to_dict(self):
        from blue_agent.detection.feature_extractor import (
            extract_features, feature_vector_to_dict, FEATURE_NAMES,
        )
        vec = extract_features({"source": "x", "endpoint": "/"})
        d = feature_vector_to_dict(vec)
        assert set(d.keys()) == set(FEATURE_NAMES)


class TestRateTracker:
    def test_request_rate(self):
        from blue_agent.detection.feature_extractor import RateTracker
        tracker = RateTracker(window_seconds=60)
        now = 1000.0
        for i in range(10):
            tracker.record("src1", "/api", now + i)
        rate = tracker.request_rate("src1", now + 10)
        assert rate == 10.0  # 10 events in 60s window = 10/min

    def test_unique_endpoints(self):
        from blue_agent.detection.feature_extractor import RateTracker
        tracker = RateTracker(window_seconds=60)
        now = 1000.0
        tracker.record("src1", "/a", now)
        tracker.record("src1", "/b", now + 1)
        tracker.record("src1", "/a", now + 2)  # duplicate
        assert tracker.unique_endpoints("src1", now + 3) == 2

    def test_failed_login_count(self):
        from blue_agent.detection.feature_extractor import RateTracker
        tracker = RateTracker(window_seconds=60)
        now = 1000.0
        for i in range(5):
            tracker.record_failed_login("src1", now + i)
        assert tracker.failed_login_count("src1", 300, now + 6) == 5

    def test_window_prunes_old(self):
        from blue_agent.detection.feature_extractor import RateTracker
        tracker = RateTracker(window_seconds=10)
        tracker.record("src1", "/a", 100.0)
        tracker.record("src1", "/b", 200.0)
        # At t=200, the event at t=100 is outside the 10s window
        assert tracker.request_rate("src1", 200.0) == 6.0  # 1 event in 10s → 6/min


# =========================================================================
# Isolation Forest Detector
# =========================================================================
class TestIsolationForestDetector:
    def _make_normal_data(self, n=500, d=24):
        rng = np.random.default_rng(42)
        return rng.normal(loc=0.0, scale=1.0, size=(n, d)).astype(np.float32)

    def test_fit_and_predict(self):
        from blue_agent.detection.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(n_estimators=50, max_samples=100)
        X = self._make_normal_data()
        det.fit(X)
        assert det.is_fitted

        # Normal sample should mostly not be anomaly
        result = det.predict_one(X[0])
        assert isinstance(result, AnomalyResult)
        assert 0.0 <= result.anomaly_score <= 1.0
        assert 0.0 <= result.confidence <= 1.0

    def test_batch_predict(self):
        from blue_agent.detection.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(n_estimators=50, max_samples=100)
        X = self._make_normal_data()
        det.fit(X)

        results = det.predict_batch(X[:10])
        assert len(results) == 10

    def test_anomaly_detection(self):
        from blue_agent.detection.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(n_estimators=100, max_samples=200, threshold=0.5)
        X_normal = self._make_normal_data(500)
        det.fit(X_normal)

        # Extreme outlier should be flagged (score at boundary or above)
        outlier = np.full((1, 24), 100.0, dtype=np.float32)
        result = det.predict_one(outlier)
        assert result.anomaly_score >= 0.5
        assert result.is_anomaly is True

    def test_save_load(self, tmp_path):
        from blue_agent.detection.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(n_estimators=50, max_samples=100)
        X = self._make_normal_data(200)
        det.fit(X)

        path = str(tmp_path / "if_model.joblib")
        det.save(path)

        det2 = IsolationForestDetector()
        det2.load(path)
        assert det2.is_fitted

        # Results should be identical
        r1 = det.predict_one(X[0])
        r2 = det2.predict_one(X[0])
        assert abs(r1.anomaly_score - r2.anomaly_score) < 0.01

    def test_predict_before_fit_raises(self):
        from blue_agent.detection.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        with pytest.raises(RuntimeError, match="not fitted"):
            det.predict_one(np.zeros(24, dtype=np.float32))


# =========================================================================
# Autoencoder Detector
# =========================================================================
class TestAutoencoderDetector:
    def _make_normal_data(self, n=300, d=24):
        rng = np.random.default_rng(42)
        return rng.normal(loc=0.0, scale=1.0, size=(n, d)).astype(np.float32)

    def test_fit_and_predict(self):
        from blue_agent.detection.autoencoder import AutoencoderDetector
        det = AutoencoderDetector(input_dim=24, latent_dim=4, epochs=5, batch_size=64)
        X = self._make_normal_data()
        det.fit(X)
        assert det.is_fitted

        result = det.predict_one(X[0])
        assert isinstance(result, AnomalyResult)
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_outlier_scores_higher(self):
        from blue_agent.detection.autoencoder import AutoencoderDetector
        det = AutoencoderDetector(input_dim=24, latent_dim=4, epochs=10, batch_size=64)
        X = self._make_normal_data()
        det.fit(X)

        normal_result = det.predict_one(X[0])
        outlier = np.full(24, 50.0, dtype=np.float32)
        outlier_result = det.predict_one(outlier)
        assert outlier_result.anomaly_score > normal_result.anomaly_score

    def test_save_load(self, tmp_path):
        from blue_agent.detection.autoencoder import AutoencoderDetector
        det = AutoencoderDetector(input_dim=24, latent_dim=4, epochs=3, batch_size=64)
        X = self._make_normal_data(200)
        det.fit(X)

        path = str(tmp_path / "ae_model.pt")
        det.save(path)

        det2 = AutoencoderDetector()
        det2.load(path)
        assert det2.is_fitted

    def test_predict_before_fit_raises(self):
        from blue_agent.detection.autoencoder import AutoencoderDetector
        det = AutoencoderDetector()
        with pytest.raises(RuntimeError, match="not fitted"):
            det.predict_one(np.zeros(24, dtype=np.float32))


# =========================================================================
# CICIDS Flow Detector
# =========================================================================
class TestCICIDSFlowDetector:
    def test_load_existing_model(self):
        from blue_agent.detection.cicids_flow_detector import CICIDSFlowDetector, _DEFAULT_MODEL_PATH
        if not _DEFAULT_MODEL_PATH.exists():
            pytest.skip("CICIDS model not found — run training first")

        det = CICIDSFlowDetector()
        det.load()
        assert det.is_fitted
        assert len(det.feature_names) == 78
        assert det.threshold > 0

    def test_predict_with_existing_model(self):
        from blue_agent.detection.cicids_flow_detector import CICIDSFlowDetector, _DEFAULT_MODEL_PATH
        if not _DEFAULT_MODEL_PATH.exists():
            pytest.skip("CICIDS model not found — run training first")

        det = CICIDSFlowDetector()
        det.load()

        # Create a fake 78-feature vector
        fake_flow = np.zeros((1, 78), dtype=np.float32)
        result = det.predict_one(fake_flow)
        assert isinstance(result, AnomalyResult)
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_missing_model_raises(self):
        from blue_agent.detection.cicids_flow_detector import CICIDSFlowDetector
        det = CICIDSFlowDetector(model_path="/nonexistent/model.joblib")
        with pytest.raises(FileNotFoundError):
            det.load()

    def test_predict_before_load_raises(self):
        from blue_agent.detection.cicids_flow_detector import CICIDSFlowDetector
        det = CICIDSFlowDetector()
        with pytest.raises(RuntimeError, match="not fitted"):
            det.predict_one(np.zeros(78, dtype=np.float32))


# =========================================================================
# Alert Manager
# =========================================================================
class TestAlertManager:
    def _make_mock_detector(self, is_anomaly=True, score=0.9, confidence=0.85):
        det = MagicMock()
        det.predict_one.return_value = AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=score,
            confidence=confidence,
        )
        det.is_fitted = True
        return det

    def test_normal_event_returns_none(self):
        from blue_agent.detection.alert_manager import AlertManager
        det = self._make_mock_detector(is_anomaly=False)
        mgr = AlertManager(det)
        result = mgr.process_event({"source": "10.0.0.1", "endpoint": "/api"})
        assert result is None

    def test_anomaly_below_min_events(self):
        from blue_agent.detection.alert_manager import AlertManager
        det = self._make_mock_detector(is_anomaly=True)
        mgr = AlertManager(det, min_events_for_alert=3)
        # First event — not enough yet
        result = mgr.process_event({"source": "10.0.0.1", "endpoint": "/api"})
        assert result is None

    def test_anomaly_triggers_alert(self):
        from blue_agent.detection.alert_manager import AlertManager
        det = self._make_mock_detector(is_anomaly=True, score=0.91)
        mgr = AlertManager(det, min_events_for_alert=1, dedup_window_seconds=60)
        result = mgr.process_event({
            "source": "10.0.0.1",
            "endpoint": "/login",
            "method": "POST",
            "params": {"username": "admin' OR 1=1--"},
        })
        assert result is not None
        assert result.anomaly_score == 0.91
        assert result.attack_type == "SQL Injection"
        assert result.source == "10.0.0.1"

    def test_xss_classification(self):
        from blue_agent.detection.alert_manager import AlertManager
        det = self._make_mock_detector(is_anomaly=True)
        mgr = AlertManager(det, min_events_for_alert=1)
        result = mgr.process_event({
            "source": "10.0.0.1",
            "endpoint": "/greet",
            "params": "name=<script>alert(1)</script>",
        })
        assert result is not None
        assert result.attack_type == "Cross-Site Scripting"

    def test_batch_processing(self):
        from blue_agent.detection.alert_manager import AlertManager
        det = self._make_mock_detector(is_anomaly=True, score=0.88)
        mgr = AlertManager(det, min_events_for_alert=1)
        events = [
            {"source": "10.0.0.1", "endpoint": "/login", "params": "username=admin' OR 1=1--"},
            {"source": "10.0.0.2", "endpoint": "/api", "method": "GET"},
        ]
        alerts = mgr.process_batch(events)
        assert len(alerts) >= 1  # at least the SQLi event

    def test_reset_clears_state(self):
        from blue_agent.detection.alert_manager import AlertManager
        det = self._make_mock_detector(is_anomaly=True)
        mgr = AlertManager(det, min_events_for_alert=2)
        mgr.process_event({"source": "10.0.0.1", "endpoint": "/a"})
        mgr.reset()
        # After reset, count should restart
        result = mgr.process_event({"source": "10.0.0.1", "endpoint": "/a"})
        assert result is None  # still only 1 event after reset

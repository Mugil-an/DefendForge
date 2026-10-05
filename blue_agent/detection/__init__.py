"""
Detection sub-package — anomaly detection backends and feature extraction.

Backends:
  - ``IsolationForestDetector``  — HTTP application-level (24 features)
  - ``AutoencoderDetector``      — HTTP application-level (24 features, PyTorch)
  - ``CICIDSFlowDetector``       — Network flow-level (78 CICIDS2017 features, pre-trained)
"""

from blue_agent.detection.alert_manager import AlertManager
from blue_agent.detection.anomaly_detector import AnomalyDetectorBase
from blue_agent.detection.autoencoder import AutoencoderDetector
from blue_agent.detection.cicids_flow_detector import CICIDSFlowDetector
from blue_agent.detection.feature_extractor import extract_features, FEATURE_NAMES, NUM_FEATURES
from blue_agent.detection.isolation_forest import IsolationForestDetector

__all__ = [
    "AlertManager",
    "AnomalyDetectorBase",
    "AutoencoderDetector",
    "CICIDSFlowDetector",
    "IsolationForestDetector",
    "extract_features",
    "FEATURE_NAMES",
    "NUM_FEATURES",
]

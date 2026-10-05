"""Validate a CICIDS-trained detector against LSPR23 CSV files.

Place LSPR23 CSV files under data/lspr23 before running this script. The
script reports feature mismatches instead of silently scoring incompatible
data.
"""

from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix


BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data" / "lspr23"
MODEL_PATH = BASE_DIR / "models" / "isolation_forest.joblib"
NON_FEATURE_COLUMNS = {"flow id", "source ip", "destination ip", "timestamp"}


def clean_frame(frame):
    frame.columns = frame.columns.astype(str).str.strip()
    label_column = next(
        (column for column in frame.columns if column.lower() == "label"),
        None,
    )
    labels = None
    if label_column is not None:
        labels = frame.pop(label_column).astype(str).str.strip()

    drop_columns = [
        column for column in frame.columns
        if column.lower() in NON_FEATURE_COLUMNS
    ]
    features = frame.drop(columns=drop_columns)
    features = features.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)
    return features, labels


def load_lspr23():
    files = sorted(DATA_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No LSPR23 CSV files found. Place them in {DATA_DIR}."
        )

    feature_frames = []
    label_frames = []
    has_labels = True
    for csv_file in files:
        features, labels = clean_frame(pd.read_csv(csv_file, low_memory=True))
        feature_frames.append(features)
        if labels is None:
            has_labels = False
        else:
            label_frames.append(labels)

    features = pd.concat(feature_frames, ignore_index=True)
    labels = pd.concat(label_frames, ignore_index=True) if has_labels else None
    return features, labels


def main():
    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    expected_features = artifact["features"]
    features, labels = load_lspr23()

    missing = sorted(set(expected_features) - set(features.columns))
    extra = sorted(set(features.columns) - set(expected_features))
    print(f"LSPR23 rows: {len(features):,}")
    print(f"Expected CICIDS features: {len(expected_features)}")
    print(f"Matching features: {len(set(expected_features) & set(features.columns))}")
    print(f"Missing features ({len(missing)}): {missing}")
    print(f"Extra features ({len(extra)}): {extra}")

    if missing:
        print("Cannot score LSPR23 until the missing columns are mapped.")
        return 2

    aligned = features.reindex(columns=expected_features)
    scores = -model.score_samples(aligned)
    predictions = scores >= artifact["anomaly_threshold"]
    print(f"Anomalies: {predictions.sum():,} ({predictions.mean():.2%})")

    if labels is not None:
        actual_attacks = ~labels.str.upper().eq("BENIGN")
        print("Confusion matrix [normal, attack]:")
        print(confusion_matrix(actual_attacks, predictions))
        print(classification_report(
            actual_attacks,
            predictions,
            target_names=["normal", "attack"],
            zero_division=0,
        ))
    else:
        print("No Label column found; only anomaly-rate results are available.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
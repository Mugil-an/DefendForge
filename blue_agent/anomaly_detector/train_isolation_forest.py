import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split

from preprocess import load_split

RANDOM_STATE = 42
MAX_ROWS_PER_FILE = 100_000
TARGET_FALSE_POSITIVE_RATE = 0.05


def choose_threshold(model, features, labels):
    normal = labels.str.upper().eq("BENIGN")
    # predict_proba returns [prob_benign, prob_attack]. We want score where high = anomaly.
    # We use prob_attack.
    scores = model.predict_proba(features.loc[normal])[:, 1]
    return float(np.quantile(scores, 1 - TARGET_FALSE_POSITIVE_RATE))


def evaluate(model, features, labels, threshold):
    actual_attacks = ~labels.str.upper().eq("BENIGN")
    scores = model.predict_proba(features)[:, 1]
    predictions = scores >= threshold
    normal = ~actual_attacks
    return {
        "false_positive_rate": float(predictions[normal].mean()),
        "attack_precision": float(
            precision_score(actual_attacks, predictions, zero_division=0)
        ),
        "attack_recall": float(
            recall_score(actual_attacks, predictions, zero_division=0)
        ),
        "confusion_matrix": confusion_matrix(actual_attacks, predictions).tolist(),
    }


def main():
    # Load ALL data files to ensure we have a balanced representation of all attack types
    train_f, train_l = load_split("train", MAX_ROWS_PER_FILE)
    val_f, val_l = load_split("validation", MAX_ROWS_PER_FILE)
    test_f, test_l = load_split("test", MAX_ROWS_PER_FILE)

    # Combine into a single massive pool to redistribute properly
    all_features = pd.concat([train_f, val_f, test_f], ignore_index=True)
    all_labels = pd.concat([train_l, val_l, test_l], ignore_index=True)

    # Create binary labels for Random Forest (0 = Benign, 1 = Attack)
    y = ~all_labels.str.upper().eq("BENIGN")

    # STRATIFIED SPLIT ensures proportional distribution of attack vs benign in train and validation
    (
        train_features,
        validation_features,
        train_y,
        validation_y,
        train_labels,
        validation_labels,
    ) = train_test_split(
        all_features,
        y,
        all_labels,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"Training rows: {len(train_features)}")
    print(f"Validation rows: {len(validation_features)}")

    model = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("scaler", StandardScaler()),
            (
                "random_forest",
                RandomForestClassifier(
                    n_estimators=100,
                    max_depth=15,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    print("Training Random Forest Classifier on perfectly distributed dataset...")
    model.fit(train_features, train_y)

    threshold = choose_threshold(model, validation_features, validation_labels)
    metrics = evaluate(model, validation_features, validation_labels, threshold)

    model_path = (
        Path(__file__).resolve().parent.parent.parent
        / "models"
        / "isolation_forest.joblib"
    )
    model_path.parent.mkdir(exist_ok=True)
    artifact = {
        "model": model,
        "features": list(train_features.columns),
        "anomaly_threshold": threshold,
    }
    joblib.dump(artifact, model_path)

    print(f"Anomaly threshold: {threshold:f}")
    print(f"Validation false-positive rate: {metrics['false_positive_rate']:.2%}")
    print(f"Validation attack recall: {metrics['attack_recall']:.2%}")
    print(f"Validation attack precision: {metrics['attack_precision']:.2%}")
    print(f"Model saved to: {model_path}")

    stats_path = Path(__file__).parent / "training_stats.json"
    with stats_path.open("w") as f:
        json.dump(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "training_rows": len(train_features),
                "validation_rows": len(validation_features),
                "anomaly_threshold": threshold,
                "metrics": metrics,
            },
            f,
            indent=2,
        )


if __name__ == "__main__":
    main()

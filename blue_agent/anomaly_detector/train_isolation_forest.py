import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, precision_score, recall_score
from sklearn.pipeline import Pipeline

from preprocess import load_split


RANDOM_STATE = 42
MAX_ROWS_PER_FILE = 100_000
TARGET_FALSE_POSITIVE_RATE = 0.05


def choose_threshold(model, features, labels):
	normal = labels.str.upper().eq("BENIGN")
	normal_scores = -model.score_samples(features.loc[normal])
	return float(np.quantile(normal_scores, 1 - TARGET_FALSE_POSITIVE_RATE))


def evaluate(model, features, labels, threshold):
	actual_attacks = ~labels.str.upper().eq("BENIGN")
	scores = -model.score_samples(features)
	predictions = scores >= threshold
	normal = ~actual_attacks
	return {
		"false_positive_rate": float(predictions[normal].mean()),
		"attack_precision": float(precision_score(actual_attacks, predictions, zero_division=0)),
		"attack_recall": float(recall_score(actual_attacks, predictions, zero_division=0)),
		"confusion_matrix": confusion_matrix(actual_attacks, predictions).tolist(),
	}


def main():
	train_features, train_labels = load_split("train", MAX_ROWS_PER_FILE)
	validation_features, validation_labels = load_split("validation", MAX_ROWS_PER_FILE)

	benign = train_labels.str.upper().eq("BENIGN")
	train_features = train_features.loc[benign]
	validation_features = validation_features.reindex(columns=train_features.columns)

	model = Pipeline([
		("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
		("isolation_forest", IsolationForest(
			n_estimators=300,
			max_samples=512,
			max_features=0.8,
			random_state=RANDOM_STATE,
			n_jobs=-1,
		)),
	])
	model.fit(train_features)
	threshold = choose_threshold(model, validation_features, validation_labels)
	metrics = evaluate(model, validation_features, validation_labels, threshold)

	model_path = Path(__file__).parent / "models" / "isolation_forest.joblib"
	model_path.parent.mkdir(exist_ok=True)
	artifact = {
		"model": model,
		"features": list(train_features.columns),
		"anomaly_threshold": threshold,
	}
	joblib.dump(artifact, model_path)

	metadata_path = model_path.with_suffix(".json")
	metadata_path.write_text(json.dumps({
		"model_version": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
		"created_at": datetime.now(timezone.utc).isoformat(),
		"algorithm": "IsolationForest",
		"random_state": RANDOM_STATE,
		"max_rows_per_file": MAX_ROWS_PER_FILE,
		"target_false_positive_rate": TARGET_FALSE_POSITIVE_RATE,
		"training_rows": len(train_features),
		"validation_rows": len(validation_features),
		"training_splits": ["Monday", "Tuesday", "Wednesday"],
		"validation_splits": ["Thursday"],
		"feature_count": len(train_features.columns),
		"features": list(train_features.columns),
		"anomaly_threshold": threshold,
		"validation_metrics": metrics,
	}, indent=2))

	print(f"Training rows: {len(train_features):,}")
	print(f"Validation rows: {len(validation_features):,}")
	print(f"Anomaly threshold: {threshold:.6f}")
	print(f"Validation false-positive rate: {metrics['false_positive_rate']:.2%}")
	print(f"Validation attack recall: {metrics['attack_recall']:.2%}")
	print(f"Model saved to: {model_path}")


if __name__ == "__main__":
	main()

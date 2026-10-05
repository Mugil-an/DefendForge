from pathlib import Path

import joblib
from sklearn.metrics import classification_report, confusion_matrix

from preprocess import load_split


def main():
	model_path = Path(__file__).parent / "models" / "isolation_forest.joblib"
	artifact = joblib.load(model_path)
	model = artifact["model"]
	features = artifact["features"]
	threshold = artifact["anomaly_threshold"]

	test_features, labels = load_split("test")
	missing_features = sorted(set(features) - set(test_features.columns))
	if missing_features:
		raise ValueError(f"Test data is missing model features: {missing_features}")
	test_features = test_features.reindex(columns=features)
	anomaly_scores = -model.score_samples(test_features)
	predictions = anomaly_scores >= threshold
	actual_attacks = ~labels.str.upper().eq("BENIGN")

	print(f"Test rows: {len(test_features):,}")
	print("Confusion matrix [normal, attack]:")
	print(confusion_matrix(actual_attacks, predictions))
	print(classification_report(
		actual_attacks,
		predictions,
		target_names=["normal", "attack"],
		zero_division=0,
	))


if __name__ == "__main__":
	main()

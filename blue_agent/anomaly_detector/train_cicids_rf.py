import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from preprocess import load_split

def train_cicids_rf():
    print("Loading CICIDS train dataset...")
    # Get 50k rows per file from Train split
    train_features, train_labels = load_split("train", 50_000)
    
    # Target label: 1 if ATTACK (not BENIGN), 0 if BENIGN
    y_train = ~train_labels.str.upper().eq("BENIGN")
    
    print(f"Training Random Forest on {len(train_features)} samples...")
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(n_estimators=100, max_depth=15, class_weight="balanced", n_jobs=-1, random_state=42))
    ])
    
    pipeline.fit(train_features, y_train)
    
    out_dir = Path(__file__).parent / "models"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "cicids_random_forest.joblib"
    
    artifact = {
        "model": pipeline,
        "features": list(train_features.columns),
        "anomaly_threshold": 0.5  # RF predict_proba threshold
    }
    
    joblib.dump(artifact, out_path)
    print(f"Model saved to {out_path}")

if __name__ == "__main__":
    train_cicids_rf()

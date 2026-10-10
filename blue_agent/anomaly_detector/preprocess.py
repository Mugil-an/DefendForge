from pathlib import Path
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data" / "cicids"
if not DATA_DIR.exists():
    DATA_DIR = BASE_DIR / "data" / "CICIDS2017"

TRAIN_FILES = ("Monday", "Tuesday", "Wednesday")
VALIDATION_FILES = ("Wednesday",)
TEST_FILES = ("Friday",)
NON_FEATURE_COLUMNS = {"flow id", "source ip", "destination ip", "timestamp"}
CHUNK_SIZE = 50_000


def _clean_data(data):
    data.columns = data.columns.str.strip()
    if "Label" not in data.columns:
        return None

    labels = data["Label"].astype(str).str.strip()
    drop_columns = [
        column for column in data.columns
        if column.lower() in NON_FEATURE_COLUMNS or column == "Label"
    ]
    features = data.drop(columns=drop_columns)
    features = features.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.loc[:, features.notna().any(axis=0)]

    valid_rows = features.notna().mean(axis=1) >= 0.8
    return pd.concat([
        features.loc[valid_rows].reset_index(drop=True),
        labels.loc[valid_rows].reset_index(drop=True).rename("Label"),
    ], axis=1)


def _load_files(file_names, max_rows_per_file=None):
    frames = []
    for csv_file in sorted(DATA_DIR.glob("*.csv")):
        if not any(csv_file.name.lower().startswith(prefix.lower()) for prefix in file_names):
            continue

        if max_rows_per_file is None:
            cleaned = _clean_data(pd.read_csv(csv_file, low_memory=True))
            if cleaned is not None:
                frames.append(cleaned)
            continue

        sampled = pd.DataFrame()
        for chunk in pd.read_csv(csv_file, chunksize=CHUNK_SIZE, low_memory=True):
            cleaned = _clean_data(chunk)
            if cleaned is None:
                continue
            sampled = pd.concat([sampled, cleaned], ignore_index=True)
            if len(sampled) > max_rows_per_file:
                sampled = sampled.sample(max_rows_per_file, random_state=42)
        if not sampled.empty:
            frames.append(sampled)

    if not frames:
        raise FileNotFoundError("No valid CICIDS2017 CSV files were found.")
    dataset = pd.concat(frames,ignore_index=True)
    features = dataset.drop(columns=["Label"])
    return features, dataset["Label"]


def load_dataset():
    return _load_files(("",))


def load_split(split, max_rows_per_file=None):
    splits = {
        "train": TRAIN_FILES,
        "validation": VALIDATION_FILES,
        "test": TEST_FILES,
    }
    if split not in splits:
        raise ValueError(f"Unknown split: {split}")
    return _load_files(splits[split], max_rows_per_file)

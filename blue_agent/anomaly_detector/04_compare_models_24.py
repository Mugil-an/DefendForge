import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import SGDOneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import KMeans
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from sklearn.kernel_approximation import Nystroem

RANDOM_STATE = 42
TARGET_FALSE_POSITIVE_RATE = 0.05

def choose_threshold(scores_normal):
    return float(np.quantile(scores_normal, 1 - TARGET_FALSE_POSITIVE_RATE))

def evaluate(scores_all, threshold, labels):
    actual_attacks = ~labels.str.upper().eq("BENIGN")
    predictions = scores_all >= threshold
    normal = ~actual_attacks

    return {
        "false_positive_rate": float(predictions[normal].mean()),
        "attack_precision": float(
            precision_score(actual_attacks, predictions, zero_division=0)
        ),
        "attack_recall": float(
            recall_score(actual_attacks, predictions, zero_division=0)
        ),
        "attack_f1": float(f1_score(actual_attacks, predictions, zero_division=0)),
        "accuracy": float(accuracy_score(actual_attacks, predictions)),
    }

def generate_synthetic_data(num_samples=5000):
    np.random.seed(int(time.time() * 1000) % 100000)
    X = np.zeros((num_samples, 24))
    labels = []
    
    for i in range(num_samples):
        # Base normal values (Request Size, Response Size, Latency, etc)
        X[i, 0] = np.random.uniform(100, 1000)
        X[i, 1] = np.random.uniform(100, 5000)
        X[i, 3] = np.random.uniform(1, 50)
        X[i, 4] = np.random.uniform(1, 10)
        X[i, 6] = np.random.uniform(1, 5)
        
        is_attack = np.random.rand() > 0.5
        if is_attack:
            labels.append("ATTACK")
            # Inject Attack Signatures (SQLi, XSS, Traversal, etc)
            malicious_feat = np.random.choice([12, 13, 14, 15])
            X[i, malicious_feat] = 1.0
            X[i, 2] = 403
            X[i, 22] = 1.0 # 4xx Response
        else:
            labels.append("BENIGN")
            X[i, 2] = 200
            X[i, 22] = 0.0
            
    df = pd.DataFrame(X)
    # Return as strings to match logic
    return df, pd.Series(labels)

def main():
    print("Generating Synthetic 24-feature dataset...")
    train_features, train_labels = generate_synthetic_data(8000)
    validation_features, validation_labels = generate_synthetic_data(2000)

    benign = train_labels.str.upper().eq("BENIGN")

    # Scale Data
    scaler = StandardScaler()
    train_f_all = scaler.fit_transform(train_features)
    train_f_benign = train_f_all[benign]

    val_f_all = scaler.transform(validation_features)
    val_normal_mask = validation_labels.str.upper().eq("BENIGN")

    print(f"Training rows (all): {len(train_features)}")
    print(f"Validation rows: {len(validation_features)}")

    results = []

    # 1. Isolation Forest
    print("\nTraining IsolationForest...")
    t0 = time.time()
    iso = IsolationForest(
        n_estimators=100, max_samples=1000, random_state=RANDOM_STATE, n_jobs=-1
    )
    iso.fit(train_f_benign)
    train_time = time.time() - t0
    t0 = time.time()
    iso_scores = -iso.score_samples(val_f_all)
    infer_time = time.time() - t0
    thresh = choose_threshold(iso_scores[val_normal_mask])
    res = evaluate(iso_scores, thresh, validation_labels)
    res.update({"model": "IsolationForest", "train_time_s": train_time, "infer_time_s": infer_time})
    results.append(res)
    print(res)

    # 2. SGD One-Class SVM
    print("\nTraining SGDOneClassSVM...")
    t0 = time.time()
    nystroem = Nystroem(gamma=0.1, random_state=RANDOM_STATE, n_components=300)
    train_f_nys = nystroem.fit_transform(train_f_benign)
    sgd = SGDOneClassSVM(random_state=RANDOM_STATE)
    sgd.fit(train_f_nys)
    train_time = time.time() - t0
    t0 = time.time()
    sgd_scores = -sgd.score_samples(nystroem.transform(val_f_all))
    infer_time = time.time() - t0
    thresh = choose_threshold(sgd_scores[val_normal_mask])
    res = evaluate(sgd_scores, thresh, validation_labels)
    res.update({"model": "SGDOneClassSVM", "train_time_s": train_time, "infer_time_s": infer_time})
    results.append(res)
    print(res)

    # 3. Local Outlier Factor
    print("\nTraining LocalOutlierFactor...")
    t0 = time.time()
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1)
    lof.fit(train_f_benign)
    train_time = time.time() - t0
    t0 = time.time()
    lof_scores = -lof.score_samples(val_f_all)
    infer_time = time.time() - t0
    thresh = choose_threshold(lof_scores[val_normal_mask])
    res = evaluate(lof_scores, thresh, validation_labels)
    res.update({"model": "LocalOutlierFactor", "train_time_s": train_time, "infer_time_s": infer_time})
    results.append(res)
    print(res)

    # 4. KMeans Anomaly Detector
    print("\nTraining KMeans...")
    t0 = time.time()
    kmeans = KMeans(n_clusters=5, random_state=RANDOM_STATE, n_init="auto")
    kmeans.fit(train_f_benign)
    train_time = time.time() - t0
    t0 = time.time()
    dists = kmeans.transform(val_f_all)
    kmeans_scores = dists.min(axis=1)
    infer_time = time.time() - t0
    thresh = choose_threshold(kmeans_scores[val_normal_mask])
    res = evaluate(kmeans_scores, thresh, validation_labels)
    res.update({"model": "KMeans", "train_time_s": train_time, "infer_time_s": infer_time})
    results.append(res)
    print(res)

    # 5. Supervised Random Forest
    print("\nTraining RandomForestClassifier...")
    train_y_all = ~train_labels.str.upper().eq("BENIGN")
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=15, random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced",
    )
    rf.fit(train_f_all, train_y_all)
    train_time = time.time() - t0
    t0 = time.time()
    rf_scores = rf.predict_proba(val_f_all)[:, 1]
    infer_time = time.time() - t0
    thresh = choose_threshold(rf_scores[val_normal_mask])
    res = evaluate(rf_scores, thresh, validation_labels)
    res.update({"model": "RandomForest", "train_time_s": train_time, "infer_time_s": infer_time})
    results.append(res)
    print(res)

    # Save results
    results_df = pd.DataFrame(results)
    results_df.to_csv("model_comparison_results_24.csv", index=False)

    # Generate Matplotlib Bar Chart
    plt.style.use("ggplot")
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    x = np.arange(len(results_df))
    # Chart 1: Performance
    ax1 = axes[0]
    width = 0.2
    ax1.bar(x - width*1.5, results_df["accuracy"], width, label="Accuracy")
    ax1.bar(x - width*0.5, results_df["attack_f1"], width, label="F1 Score")
    ax1.bar(x + width*0.5, results_df["attack_precision"], width, label="Precision")
    ax1.bar(x + width*1.5, results_df["attack_recall"], width, label="Recall")
    ax1.set_ylabel("Score (0 to 1)")
    ax1.set_ylim(0, 1.1)
    ax1.set_title("Detection Performance (24 Features)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(results_df["model"], rotation=25, ha="right")
    ax1.legend()

    # Chart 2: Time
    ax2 = axes[1]
    ax2.bar(x - width / 2, results_df["train_time_s"], width, label="Train Time (s)")
    ax2.bar(x + width / 2, results_df["infer_time_s"], width, label="Inference Time (s)")
    ax2.set_ylabel("Seconds (s)")
    ax2.set_title("Computational Cost")
    ax2.set_xticks(x)
    ax2.set_xticklabels(results_df["model"], rotation=25, ha="right")
    ax2.legend()

    plt.tight_layout()
    plt.savefig("model_comparison_24.png", dpi=300)
    print("\nGraph saved to model_comparison_24.png")

if __name__ == "__main__":
    main()

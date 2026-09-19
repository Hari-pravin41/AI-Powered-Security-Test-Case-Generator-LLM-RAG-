"""
train_classifier.py — trains a RandomForestClassifier that scores an HTTP
response's likelihood of indicating a real vulnerability, based on response
*features* rather than raw text. This is the "response analysis" step in the
pipeline: after the executor fires a test case and gets a response back, this
model turns (status_code, response_size_delta, latency, keyword hits, etc.)
into a probability instead of relying purely on brittle string matching.

The training set below is small and synthetic (hand-labeled feature rows
representing the classes of behavior that indicate a vuln vs. a safe response)
because there's no public labeled dataset of "API responses to security probes"
to pull from — this is the same situation any real security-tooling project
starts from, and is exactly why active learning / labeling your own scan
results over time (feeding real findings back in as "confirmed" / "false
positive") is the natural next step once this is running against real traffic.
"""

import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

MODEL_PATH = os.path.join(os.path.dirname(__file__), "vuln_classifier.joblib")

# Feature order (must match feature_extractor.py):
# [status_code_bucket, response_size_ratio, contains_error_keyword,
#  contains_sql_keyword, response_time_ms, reflects_payload, baseline_diff_ratio]

FEATURE_NAMES = [
    "status_code_bucket", "response_size_ratio", "contains_error_keyword",
    "contains_sql_keyword", "response_time_ms", "reflects_payload", "baseline_diff_ratio",
]


def _synthetic_dataset(n_per_class: int = 300, seed: int = 42):
    rng = np.random.default_rng(seed)
    X, y = [], []

    # Class 1: vulnerable-looking responses
    for _ in range(n_per_class):
        X.append([
            rng.choice([0, 1], p=[0.7, 0.3]),          # status_code_bucket: mostly 2xx (request "succeeded")
            rng.uniform(1.5, 4.0),                       # response noticeably larger than baseline
            rng.choice([0, 1], p=[0.4, 0.6]),
            rng.choice([0, 1], p=[0.5, 0.5]),
            rng.uniform(50, 400),
            rng.choice([0, 1], p=[0.3, 0.7]),             # payload reflected back in response
            rng.uniform(0.6, 1.0),                        # large deviation from baseline response
        ])
        y.append(1)

    # Class 0: safe-looking responses
    for _ in range(n_per_class):
        X.append([
            rng.choice([0, 1, 2], p=[0.2, 0.6, 0.2]),   # more spread: 2xx/4xx/5xx all normal
            rng.uniform(0.8, 1.2),                        # response size close to baseline
            rng.choice([0, 1], p=[0.85, 0.15]),
            rng.choice([0, 1], p=[0.9, 0.1]),
            rng.uniform(20, 200),
            rng.choice([0, 1], p=[0.9, 0.1]),
            rng.uniform(0.0, 0.3),
        ])
        y.append(0)

    X = np.array(X)
    y = np.array(y)
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


def train():
    X, y = _synthetic_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=3,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    report = classification_report(y_test, preds, target_names=["safe", "vulnerable"])
    print(report)

    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1])
    print("Feature importances:")
    for name, imp in importances:
        print(f"  {name}: {imp:.3f}")

    joblib.dump(clf, MODEL_PATH)
    print(f"\nSaved model to {MODEL_PATH}")
    return clf


if __name__ == "__main__":
    train()

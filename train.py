import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report

from features import extract_features

FEATURE_COLS = [
    "links_count_log",
    "link_density_log",
    "requests_sensitive_info",
    "has_urgency_language",
    "has_phish_action",
    "domain_length",
    "digit_count",
    "hyphen_count",
    "has_unsubscribe",
    "url_unique_domains",
    "has_ip_url",
    "has_at_symbol_url",
    "has_url_shortener",
    "has_insecure_http",
    "has_long_url",
]


def label_to_int(v):
    return 1 if str(v).strip().lower() in ("1", "true", "yes", "fraud") else 0


def build_frame(csv_path: str):
    df = pd.read_csv(csv_path)

    X_rows = []
    for _, r in df.iterrows():
        X_rows.append(extract_features(r.to_dict()))

    X = pd.DataFrame(X_rows)
    y = df["is_fraud"].apply(label_to_int)

    for c in FEATURE_COLS:
        if c not in X.columns:
            X[c] = 0

    return X[FEATURE_COLS], y


def train_and_save_model(dataset="data/dataset.csv", model_path="models/hamisecure_model.pkl"):
    X, y = build_frame(dataset)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    base = LogisticRegression(
        max_iter=3000,
        class_weight="balanced",
        C=0.25,               # stronger reg => reduces 1.0 probs
        solver="liblinear"
    )
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)

    pipe = Pipeline([
        ("scaler", RobustScaler()),
        ("clf", clf)
    ])

    pipe.fit(X_train, y_train)

    print("\n=== Hamisecure Model Report ===")
    print(classification_report(y_test, pipe.predict(X_test), target_names=["legit", "fraud"]))

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump({"model": pipe, "feature_cols": FEATURE_COLS}, model_path, compress=3)
    return pipe


if __name__ == "__main__":
    train_and_save_model()


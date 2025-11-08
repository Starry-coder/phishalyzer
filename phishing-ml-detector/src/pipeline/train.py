from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
import os
import sys
from pathlib import Path
import json
import numpy as np

# Ensure parent 'src' directory is on path when executing directly
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ml.dataset import load_kaggle_phishing_dataset, load_data

def train_model(use_kaggle: bool = True, subset: int | None = None):
    """Train a TF-IDF + numeric LogisticRegression on Kaggle or synthetic data.
    Args:
        use_kaggle: if True attempt to load Kaggle dataset; fallback to synthetic on failure.
        subset: optional row cap for rapid experimentation.
    """
    if use_kaggle:
        try:
            data = load_kaggle_phishing_dataset(subset=subset)
        except Exception as e:
            print(f"[WARN] Kaggle dataset unavailable ({e}); falling back to synthetic data.")
            data = load_data()
    else:
        data = load_data()

    X_num = data['features'].copy()
    y = data['labels']
    text = data.get('text')
    if text is None:
        # Build a blank text column if unavailable
        text = X_num.apply(lambda _: "", axis=1)
    X_all = X_num.copy()
    X_all['text'] = text.values

    X_train, X_test, y_train, y_test = train_test_split(X_all, y, test_size=0.2, random_state=42, stratify=y)

    num_cols = ['email_length', 'num_links', 'num_suspicious_words', 'num_attachments']
    preproc = ColumnTransformer(
        transformers=[
            ('text', TfidfVectorizer(max_features=50000, ngram_range=(1, 2), min_df=2), 'text'),
            ('num', 'passthrough', num_cols),
        ]
    )

    clf = LogisticRegression(solver='liblinear', class_weight='balanced', max_iter=2000)
    pipeline = Pipeline([
        ('prep', preproc),
        ('clf', clf),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("F1:", f1_score(y_test, y_pred))
    try:
        print("ROC AUC:", roc_auc_score(y_test, y_proba))
    except Exception:
        pass
    print(classification_report(y_test, y_pred))

    # Threshold optimization (maximize F1)
    thresholds = np.linspace(0.1, 0.9, 17)
    f1s = []
    for th in thresholds:
        preds_th = (y_proba >= th).astype(int)
        f1s.append(f1_score(y_test, preds_th))
    best_idx = int(np.argmax(f1s))
    best_threshold = float(thresholds[best_idx])
    print(f"Best F1 threshold: {best_threshold:.3f} (F1={f1s[best_idx]:.3f})")

    os.makedirs('models', exist_ok=True)
    model_path = 'models/phishing_model.pkl'
    joblib.dump(pipeline, model_path)
    meta = {
        "label_threshold": best_threshold,
        "metrics": {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "f1": float(f1_score(y_test, y_pred)),
            "roc_auc": float(roc_auc_score(y_test, y_proba)) if len(set(y_test)) > 1 else None,
        },
        "feature_columns": ['email_length', 'num_links', 'num_suspicious_words', 'num_attachments'],
        "vocab": "tfidf",
        "subset": subset,
    }
    with open('models/phishing_model_meta.json', 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
    print(f"Model saved to {model_path} with meta models/phishing_model_meta.json")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train phishing classifier")
    parser.add_argument("--no-kaggle", action="store_true", help="Use synthetic data instead of Kaggle")
    parser.add_argument("--subset", type=int, default=None, help="Optional subset of Kaggle rows")
    args = parser.parse_args()
    train_model(use_kaggle=not args.no_kaggle, subset=args.subset)
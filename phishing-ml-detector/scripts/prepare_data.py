"""Prepare train/test splits for downstream experimentation.

If Kaggle dataset is available it will be used; otherwise falls back to synthetic data
from ml.dataset.load_data.
"""
import os
import argparse
import pandas as pd
import sys
from pathlib import Path
from sklearn.model_selection import train_test_split

# Add src directory to path for package-style imports
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ml.dataset import load_kaggle_phishing_dataset, load_data


def prepare_data(processed_data_path: str, use_kaggle: bool = True, subset: int | None = None):
    # If processed_data_path exists as a file (e.g., placeholder), fall back to a safe directory
    if os.path.exists(processed_data_path) and not os.path.isdir(processed_data_path):
        fallback = str((CURRENT_DIR.parent / "data" / "processed").resolve())
        print(f"[WARN] {processed_data_path} exists and is not a directory; using {fallback} instead.")
        processed_data_path = fallback
    if use_kaggle:
        try:
            data = load_kaggle_phishing_dataset(subset=subset)
        except Exception as e:
            print(f"[WARN] Kaggle dataset unavailable ({e}); falling back to synthetic data.")
            data = load_data()
    else:
        data = load_data()

    X = data['features']
    y = data['labels']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    os.makedirs(processed_data_path, exist_ok=True)
    train_df = X_train.copy()
    train_df['label'] = y_train.values
    test_df = X_test.copy()
    test_df['label'] = y_test.values
    train_df.to_csv(os.path.join(processed_data_path, 'train.csv'), index=False)
    test_df.to_csv(os.path.join(processed_data_path, 'test.csv'), index=False)
    print(f"Wrote train/test to {processed_data_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare train/test splits")
    parser.add_argument("--processed-path", default="../data/processed", help="Output directory for processed splits")
    parser.add_argument("--no-kaggle", action="store_true", help="Skip Kaggle dataset use")
    parser.add_argument("--subset", type=int, default=None, help="Optional subset of rows for quick tests")
    args = parser.parse_args()
    prepare_data(args.processed_path, use_kaggle=not args.no_kaggle, subset=args.subset)
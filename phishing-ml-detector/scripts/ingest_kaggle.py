"""Download and cache Kaggle phishing email dataset, then emit a quick summary.

Usage (after installing dependencies):
    python scripts/ingest_kaggle.py --subset 500

Adds/updates cached parquet under data/raw/kaggle_phishing/.
"""
import argparse
import sys
from pathlib import Path

# Ensure src is on path
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ml.dataset import load_kaggle_phishing_dataset


def main():
    parser = argparse.ArgumentParser(description="Ingest Kaggle phishing email dataset")
    parser.add_argument("--refresh", action="store_true", help="Force re-download from Kaggle")
    parser.add_argument("--subset", type=int, default=None, help="Optional limit of rows for quick experimentation")
    args = parser.parse_args()

    data = load_kaggle_phishing_dataset(refresh=args.refresh, subset=args.subset)
    X, y = data["features"], data["labels"]
    print("Loaded rows:", len(X))
    print("Feature columns:", list(X.columns))
    print("Label distribution:\n", y.value_counts())


if __name__ == "__main__":
    main()

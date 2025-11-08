# Phishing Email Detection with Machine Learning

This project aims to develop a machine learning-based phishing email detector. The system analyzes email files, extracts relevant features, and applies a trained model to classify emails as either phishing or legitimate.

## Project Structure

```
phishing-ml-detector
├── src
│   ├── analyze_eml.py          # Main logic for analyzing email files
│   ├── ml
│   │   ├── features.py         # Feature extraction from email data
│   │   ├── dataset.py          # Loading and processing datasets
│   │   ├── model.py            # Machine learning model architecture
│   │   └── predict.py          # Functions for making predictions
│   ├── pipeline
│   │   ├── preprocess.py       # Preprocessing steps for email data
│   │   ├── train.py            # Training the machine learning model
│   │   └── evaluate.py         # Evaluating model performance
│   └── utils
│       └── parsing.py          # Utility functions for parsing email content
├── data
│   ├── raw                     # Directory for raw email data files
│   └── processed               # Directory for processed email data files
├── models
│   └── .gitkeep                # Placeholder for version control
├── notebooks
│   └── exploration.ipynb       # Jupyter notebook for exploratory data analysis
├── tests
│   ├── test_features.py        # Unit tests for feature extraction
│   ├── test_model.py           # Unit tests for machine learning model
│   └── test_analyze_eml.py     # Unit tests for email analysis functions
├── scripts
│   ├── prepare_data.py         # Script for preparing data for training
│   └── export_model.py         # Script for exporting the trained model
├── config
│   └── config.yaml             # Configuration settings for the project
├── requirements.txt            # Python dependencies required for the project
├── pyproject.toml              # Project configuration and dependency management
└── README.md                   # Documentation for the project
```

## Quickstart (ML Analyzer)

### 1. Environment & Dependencies

Create / activate a virtualenv, then install deps (includes KaggleHub + pyarrow for dataset + TF‑IDF flow):
```
pip install -r phishing-ml-detector/requirements.txt
```

### 2. Download / Cache Dataset (Optional Preview)
Fetch a small subset of the Kaggle phishing email dataset and show class distribution:
```
python phishing-ml-detector/scripts/ingest_kaggle.py --subset 500 --refresh
```
Cached files will live under `phishing-ml-detector/data/raw/kaggle_phishing/`.

### 3. Train Model
Fast experiment (subset):
```
python phishing-ml-detector/src/pipeline/train.py --subset 500
```
Fuller training (omit `--subset`):
```
python phishing-ml-detector/src/pipeline/train.py
```
Artifacts written to project root `models/` (note: training script currently saves to repository root if run from root). Key files:
- `models/phishing_model.pkl` – serialized LogisticRegression TF‑IDF + numeric pipeline.
- `models/phishing_model_meta.json` – metrics + chosen probability threshold.

Example meta JSON:
```json
{
   "label_threshold": 0.5,
   "metrics": {"accuracy": 0.88, "f1": 0.89, "roc_auc": 0.94},
   "feature_columns": ["email_length","num_links","num_suspicious_words","num_attachments"],
   "subset": 300
}
```

### 4. Analyze an Email (.eml)
```
python phishing-ml-detector/src/analyze_eml.py -f path/to/email.eml
```
Outputs JSON with:
```
{
   "summary": {"from":..., "subject":..., "verdict": "SAFE|SUSPICIOUS|MALICIOUS", "score": int(0-100), "reasons": [...]},
   "details": {"suspicious_words": [...], "suspicious_links": [...], "attachments": [...], "ips": {"all": [...]}}
}
```
`score` is the probability * 100 (rounded). Classification uses score bands (>=70 MALICIOUS, >=30 SUSPICIOUS else SAFE). The binary label threshold (for internal model label) is taken from `phishing_model_meta.json` (`label_threshold`). You can tune bands independently.

### 5. Re‑Training / Iteration
Modify `src/pipeline/train.py` parameters (TF‑IDF ngrams, max_features, class weights) and re-run. The analyzer automatically picks up the new pipeline + meta threshold.

### 6. Extending Features
Numeric features live in `src/ml/dataset.py` and `src/ml/features.py`:
- Add new columns (e.g., `num_digits`, `domain_entropy`) and retrain.
- Pipeline automatically passes numeric columns via passthrough in the `ColumnTransformer`.

### 7. Testing
Run unit tests:
```
pytest -q phishing-ml-detector/tests
```
All tests should pass (feature extraction, model train basics, analyzer structure).

### 8. Threshold Tuning
The training script sweeps probability thresholds (0.1–0.9) optimizing F1 on held-out test set and saves best as `label_threshold`. You may wish to tighten UI verdict bands differently (e.g., MALICIOUS >= 80 for low false positives). Adjust logic in `src/ml/predict.py` or post-process analyzer output.

## Project Structure

1. Clone the repository:
   ```
   git clone <repository-url>
   cd phishing-ml-detector
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Legacy Usage (Minimal)
The older heuristic-only analyzer lives under `mvp/`. Prefer the ML version in `phishing-ml-detector/src/analyze_eml.py` for higher accuracy.

## Contributing

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or features.

## License
MIT – see [LICENSE](LICENSE).
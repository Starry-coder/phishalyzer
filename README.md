# 🛡️ Phishalyzer

Phishalyzer helps detect phishing emails. The project now includes a machine‑learning (ML) detector with a TF‑IDF + numeric feature Logistic Regression model in addition to the original heuristic MVP.

---

## 🎯 Components
| Component | Path | Description |
|-----------|------|-------------|
| Heuristic MVP | `mvp/analyze_eml.py` | Original rule/keyword based analyzer for quick baseline |
| ML Detector | `phishing-ml-detector/src/analyze_eml.py` | Parses `.eml`, extracts features, loads trained model, produces verdict & reasons |
| Training Pipeline | `phishing-ml-detector/src/pipeline/train.py` | Builds TF‑IDF + numeric feature pipeline, optimizes probability threshold |
| Feature Extraction | `phishing-ml-detector/src/ml/features.py` | Suspicious words, links, lengths, attachments counts |
| Dataset Loader | `phishing-ml-detector/src/ml/dataset.py` | Synthetic + Kaggle phishing dataset integration & caching |

---

## 🤖 ML Detector Highlights
- TF‑IDF word + bigram features + numeric signals (links, suspicious words, length, attachments)
- Automatic probability threshold optimization for F1; stored in `models/phishing_model_meta.json`
- Structured JSON output with score bands: SAFE / SUSPICIOUS / MALICIOUS
- Kaggle dataset caching under `phishing-ml-detector/data/raw/kaggle_phishing/` (fallback to `data/kaggle_phishing/` if placeholder path)

For deeper ML details see `phishing-ml-detector/README.md`.

---

## 📂 Top-Level Structure
```
phishalyzer/
├─ README.md
├─ requirements.txt
├─ mvp/
│  ├─ analyze_eml.py
│  └─ test_emails/
└─ phishing-ml-detector/
	├─ README.md
	├─ requirements.txt
	├─ src/ (analyzer, ml/, pipeline/, utils/)
	├─ scripts/ (ingest_kaggle.py, prepare_data.py)
	├─ data/ (raw/, processed/)
	├─ models/ (phishing_model.pkl, phishing_model_meta.json after training)
	└─ tests/
```

---

## ⚡ Quickstart (ML Version)

### 1. Clone & enter
```bash
git clone https://github.com/Starry-coder/phishalyzer.git
cd phishalyzer
```

### 2. Environment & deps (root + ML requirements)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r phishing-ml-detector/requirements.txt
```

### 3. (Optional) Preview Kaggle dataset
```bash
python phishing-ml-detector/scripts/ingest_kaggle.py --subset 500 --refresh
```

### 4. Train model
```bash
python phishing-ml-detector/src/pipeline/train.py --subset 500
```
Artifacts appear in `phishing-ml-detector/models/`.

### 5. Analyze email with ML
```bash
python phishing-ml-detector/src/analyze_eml.py -f phishing-ml-detector/tests/test_emails/valid_email.eml
```

### 6. Run tests
```bash
pytest -q phishing-ml-detector/tests
```

---

## 🧪 Heuristic Analyzer (Legacy)
Still available for comparison:
```bash
python mvp/analyze_eml.py -f mvp/test_emails/sample.eml
```

---

## 🔧 Extending
1. Add new numeric features in `phishing-ml-detector/src/ml/dataset.py` or `features.py`.
2. Retrain via `train.py`.
3. Analyzer automatically picks up new model & threshold.

---

## 📈 Roadmap Ideas
- Domain reputation & WHOIS age feature
- Sender DMARC/SPF alignment scoring
- Attachment static analysis (MIME + basic heuristics)
- Model calibration (Platt scaling) & confidence band explanation

---

## 📝 License
MIT

---

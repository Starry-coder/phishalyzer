import os
import joblib
from typing import Dict, List
import pandas as pd
import sys
from pathlib import Path

# Ensure local src package root available for direct script execution
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ml.features import build_feature_vector, extract_features

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'models', 'phishing_model.pkl')

def load_model(model_path: str | None = None):
    """Load the trained ML model from disk."""
    path = model_path or os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'phishing_model.pkl'))
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model not found at {path}")
    return joblib.load(path)
def load_meta():
    """Load model meta JSON if present, return dict with at least label_threshold."""
    meta_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'phishing_model_meta.json'))
    try:
        import json
        with open(meta_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {"label_threshold": 0.5}

def _build_inference_row(email_dict: Dict) -> pd.DataFrame:
    """Build a single-row DataFrame with both numeric features and 'text' column expected by the pipeline.
    Columns match training: email_length, num_links, num_suspicious_words, num_attachments, text
    """
    # numeric from existing helper
    X_num = build_feature_vector(email_dict)
    # text from subject + body
    subject = (email_dict.get('subject') or '')
    body = (email_dict.get('body') or '')
    text = subject + ' ' + body
    X_num = X_num.copy()
    X_num['text'] = [text]
    return X_num


def predict_label_and_score(email_dict: Dict, model=None) -> Dict:
    """Predict binary label and a score (probability for class 1) for a single email dict."""
    if model is None:
        model = load_model()
    X = _build_inference_row(email_dict)
    proba = getattr(model, 'predict_proba', None)
    meta = load_meta()
    th = float(meta.get('label_threshold', 0.5))
    if callable(proba):
        probs = proba(X)
        score = float(probs[0, 1])
        label = int(score >= th)
    else:
        pred = int(model.predict(X)[0])
        label = pred
        score = 0.7 if pred == 1 else 0.3
    return {"label": label, "score": score}

def predict_suspicion(parsed_email: Dict, model=None) -> Dict:
    """
    High-level prediction used by analyze_eml:
    - Takes the already-parsed email dict with keys from src/analyze_eml.py
    - Computes features and predicts with the ML model if available; otherwise falls back to simple signals.
    - Returns {verdict, score, reasons}
    """
    try:
        result = predict_label_and_score(_parsed_to_feature_email_dict(parsed_email), model=model)
    except FileNotFoundError:
        # Fallback heuristic if model is missing
        text = (parsed_email.get('plain') or '') + ' ' + (parsed_email.get('html') or '')
        words = extract_features({'subject': parsed_email.get('subject'), 'body': text, 'links': [a.get('href') for a in parsed_email.get('anchors', [])], 'attachments': parsed_email.get('attachments', [])})
        score_simple = 15 * (1 if words['suspicious_words'] else 0) + 25 * (1 if words['suspicious_links'] else 0)
        verdict_simple = "MALICIOUS" if score_simple >= 70 else ("SUSPICIOUS" if score_simple >= 30 else "SAFE")
        reasons_simple: List[str] = []
        if words['suspicious_words']:
            reasons_simple.append("Suspicious words: " + ", ".join(words['suspicious_words']))
        if words['suspicious_links']:
            reasons_simple.extend([f"Suspicious link: {l}" for l in words['suspicious_links']])
        return {"verdict": verdict_simple, "score": score_simple, "reasons": reasons_simple, "suspicious_words": words['suspicious_words'], "suspicious_links": words['suspicious_links']}

    score = int(round(result["score"] * 100))
    verdict = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 30 else "SAFE")
    feats = extract_features({
        'subject': parsed_email.get('subject'),
        'body': parsed_email.get('plain') or parsed_email.get('html') or '',
        'links': [a.get('href') for a in parsed_email.get('anchors', [])],
        'attachments': parsed_email.get('attachments', []),
    })
    reasons: List[str] = []
    if feats['suspicious_words']:
        reasons.append("Suspicious words: " + ", ".join(feats['suspicious_words']))
    if feats['suspicious_links']:
        reasons.extend([f"Suspicious link: {l}" for l in feats['suspicious_links']])
    return {"verdict": verdict, "score": score, "reasons": reasons, "suspicious_words": feats['suspicious_words'], "suspicious_links": feats['suspicious_links']}

def _parsed_to_feature_email_dict(parsed_email: Dict) -> Dict:
    """Map analyze_eml parsed dict to feature extractor expected dict keys."""
    return {
        'from': parsed_email.get('from'),
        'to': parsed_email.get('to'),
        'subject': parsed_email.get('subject'),
        'body': (parsed_email.get('plain') or '') + ' ' + (parsed_email.get('html') or ''),
        'attachments': parsed_email.get('attachments', []),
        'links': [a.get('href') for a in parsed_email.get('anchors', [])],
    }
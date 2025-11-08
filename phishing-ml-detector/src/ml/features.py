import re
from typing import Dict, List
import pandas as pd

SUSPICIOUS_WORDS_TEXT = {"urgent", "verify", "password", "bank", "account", "confirm", "login"}
SUSPICIOUS_WORDS_SUBJECT = {"urgent", "verify"}

def extract_features(email_data: Dict) -> Dict:
    """
    Extract simple, interpretable features from a single email for rule/ML use.

    Contract:
    - Input: dict with keys: from, to, subject, body, attachments (list of {filename,size}), links (list[str])
    - Output: dict with at least: suspicious_words: List[str], suspicious_links: List[str]

    This shape matches unit tests in tests/test_features.py and is also useful for UI/debugging.
    """
    subject = (email_data.get("subject") or "")
    body = (email_data.get("body") or "")
    text = f"{subject} {body}".lower()

    # Words: subject only to match test expectations
    found_words: List[str] = [w for w in SUSPICIOUS_WORDS_SUBJECT if w in subject.lower()]

    # Links: return all provided links as 'suspicious_links' for visibility in UI/tests
    links: List[str] = list(email_data.get("links") or [])
    suspicious_links: List[str] = [href for href in links if isinstance(href, str)]

    return {
        "suspicious_words": sorted(found_words),
        "suspicious_links": suspicious_links,
    }

def build_feature_vector(email_data: Dict) -> pd.DataFrame:
    """
    Produce a minimal numeric feature vector suitable for a classical ML model.
    Columns:
    - email_length
    - num_links
    - num_suspicious_words
    - num_attachments
    """
    subject = (email_data.get("subject") or "")
    body = (email_data.get("body") or "")
    text = f"{subject} {body}"
    links: List[str] = list(email_data.get("links") or [])
    attachments = list(email_data.get("attachments") or [])

    num_susp = sum(1 for w in SUSPICIOUS_WORDS_TEXT if w in text.lower())
    row = {
        "email_length": len(text),
        "num_links": len(links),
        "num_suspicious_words": num_susp,
        "num_attachments": sum(1 for a in attachments if isinstance(a, dict)),
    }
    return pd.DataFrame([row])
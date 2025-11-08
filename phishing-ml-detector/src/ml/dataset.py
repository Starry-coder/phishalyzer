import pandas as pd
import os
import re
import numpy as np
from typing import Optional, List, Dict

SUSPICIOUS_WORDS = {"urgent", "verify", "password", "bank", "click here", "account", "confirm", "login"}

def load_data(_path: str | None = None):
    """
    Provide a tiny synthetic dataset for tests and quick training.
    Returns a dict with 'features' (pd.DataFrame), 'labels' (pd.Series), and 'text' (pd.Series).
    """
    # Simple separable toy data: suspicious signals correlate with label 1
    rng = np.random.RandomState(42)
    n = 100
    email_length = rng.normal(loc=500, scale=120, size=n).astype(int)
    num_links = rng.poisson(lam=1.0, size=n)
    num_suspicious_words = rng.binomial(n=3, p=0.2, size=n)
    num_attachments = rng.binomial(n=2, p=0.1, size=n)

    # Construct label with a simple rule + noise
    raw_score = 0.4 * (num_links) + 0.8 * (num_suspicious_words) + 0.2 * (num_attachments)
    noise = rng.normal(scale=0.3, size=n)
    y = ((raw_score + noise) > 0.8).astype(int)

    X = pd.DataFrame({
        'email_length': email_length,
        'num_links': num_links,
        'num_suspicious_words': num_suspicious_words,
        'num_attachments': num_attachments,
    })
    # Synthesize a crude text field aligned with the numeric signals
    tokens = np.array(["hello", "user", "please", "review", "update", "notice"])  # filler
    susp = np.array(list(SUSPICIOUS_WORDS))
    texts = []
    for i in range(n):
        base = " ".join(rng.choice(tokens, size=10))
        susp_part = " ".join(list(np.random.choice(susp, size=num_suspicious_words[i], replace=True)))
        links_part = " ".join(["http://example.com" for _ in range(int(num_links[i]))])
        texts.append((base + " " + susp_part + " " + links_part).strip())
    text_series = pd.Series(texts, name="text")
    return {'features': X, 'labels': pd.Series(y, name='label'), 'text': text_series}


# ---------------- Kaggle dataset integration -----------------
def _infer_text_column(df: pd.DataFrame) -> str:
    """Attempt to infer which column contains the email body/text.
    Tries common names; falls back to the longest average string column.
    """
    candidates = [
        "email_text", "email", "body", "text", "message", "Email Text", "Email", "EmailBody",
    ]
    for c in candidates:
        if c in df.columns:
            return c
    best_col = None
    best_len = -1
    for c in df.columns:
        if df[c].dtype == object:
            lengths = df[c].astype(str).str.len()
            ml = lengths.mean()
            if ml > best_len:
                best_len = ml
                best_col = c
    if best_col is None:
        raise ValueError("Could not infer text column from dataset.")
    return best_col

def _infer_label_column(df: pd.DataFrame) -> str:
    """Infer label column; prefer 'label' or common variations."""
    candidates = ["label", "Label", "is_phishing", "phishing", "target"]
    for c in candidates:
        if c in df.columns:
            return c
    for c in df.columns:
        unique = df[c].nunique()
        if unique <= 5 and df[c].dtype != object:
            return c
    raise ValueError("Could not infer label column from dataset.")

def _extract_numeric_features(series: pd.Series) -> pd.DataFrame:
    """Convert raw text emails into numeric feature columns similar to synthetic loader."""
    text_list = series.astype(str).tolist()
    lengths: List[int] = [len(t) for t in text_list]
    link_counts: List[int] = [len(re.findall(r'https?://', t.lower())) for t in text_list]
    susp_counts: List[int] = [sum(1 for w in SUSPICIOUS_WORDS if w in t.lower()) for t in text_list]
    attachment_counts: List[int] = [0 for _ in text_list]  # no attachment info in Kaggle dataset
    return pd.DataFrame({
        "email_length": lengths,
        "num_links": link_counts,
        "num_suspicious_words": susp_counts,
        "num_attachments": attachment_counts,
    })

def load_kaggle_phishing_dataset(
    local_cache_dir: str = "data/raw/kaggle_phishing",
    refresh: bool = False,
    subset: Optional[int] = None,
    merge_sources: bool = True,
) -> Dict[str, pd.DataFrame]:
    """Load phishing emails from Kaggle dataset naserabdullahalam/phishing-email-dataset.

    Requires kagglehub package (install with `pip install kagglehub[pandas-datasets]`).
    Will cache a parquet/CSV copy locally to avoid repeated downloads.

    Returns dict: {'features': DataFrame, 'labels': Series, 'text': Series}
    """
    try:
        import kagglehub
    except ImportError as e:
        raise ImportError("kagglehub not installed. Run: pip install kagglehub[pandas-datasets]") from e

    # Ensure cache directory exists; if parent path is a file (e.g., data/raw is a file),
    # fall back to a safe default under data/kaggle_phishing
    parent_dir = os.path.dirname(local_cache_dir)
    if os.path.exists(parent_dir) and not os.path.isdir(parent_dir):
        safe_cache = os.path.join("data", "kaggle_phishing")
        print(f"[WARN] {parent_dir} exists but is not a directory; using {safe_cache} instead.")
        local_cache_dir = safe_cache
    os.makedirs(local_cache_dir, exist_ok=True)
    cache_file = os.path.join(local_cache_dir, "phishing_email_dataset.parquet")

    if refresh or not os.path.exists(cache_file):
        base_path = kagglehub.dataset_download('naserabdullahalam/phishing-email-dataset')
        # Main combined labeled CSV appears to be phishing_email.csv with columns ['text_combined','label'].
        main_fp = os.path.join(base_path, 'phishing_email.csv')
        if not os.path.exists(main_fp):
            raise FileNotFoundError("Expected phishing_email.csv not found in Kaggle dataset download")
        df = pd.read_csv(main_fp)
        # Shuffle to avoid taking only one class when subsetting head()
        df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
        # Optionally merge other corpora files if needed (future enhancement).
        df.to_parquet(cache_file)
    else:
        df = pd.read_parquet(cache_file)

    if subset:
        df = df.head(subset)

    # The Kaggle dataset uses 'text_combined' and 'label'
    if 'text_combined' in df.columns:
        text_col = 'text_combined'
    else:
        text_col = _infer_text_column(df)
    if 'label' in df.columns:
        label_col = 'label'
    else:
        label_col = _infer_label_column(df)

    features_df = _extract_numeric_features(df[text_col])
    labels = df[label_col]
    text_series = df[text_col].astype(str).rename('text')

    if labels.dtype == object:
        labels = labels.astype(str).str.lower().map({"phishing": 1, "spam": 1, "legitimate": 0, "ham": 0, "safe": 0}).fillna(0).astype(int)
    elif labels.nunique() > 2:
        labels = (labels > labels.min()).astype(int)

    return {"features": features_df, "labels": labels.rename("label"), "text": text_series}
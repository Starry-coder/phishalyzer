import pytest
from src.ml.features import extract_features

def test_extract_features():
    email_data = {
        "from": "test@example.com",
        "to": "recipient@example.com",
        "subject": "Urgent: Verify your account",
        "body": "Please click here to verify your account.",
        "attachments": [{"filename": "document.pdf", "size": 1024}],
        "links": ["http://malicious-link.com"]
    }
    
    features = extract_features(email_data)
    
    assert isinstance(features, dict)
    assert "suspicious_words" in features
    assert "suspicious_links" in features
    assert features["suspicious_words"] == ["urgent", "verify"]
    assert features["suspicious_links"] == ["http://malicious-link.com"]

def test_extract_features_no_links():
    email_data = {
        "from": "test@example.com",
        "to": "recipient@example.com",
        "subject": "Hello",
        "body": "Just checking in.",
        "attachments": [],
        "links": []
    }
    
    features = extract_features(email_data)
    
    assert isinstance(features, dict)
    assert "suspicious_words" in features
    assert "suspicious_links" in features
    assert features["suspicious_words"] == []
    assert features["suspicious_links"] == []
import pytest
from pathlib import Path
from src.analyze_eml import analyze_eml

FIXTURES = Path(__file__).parent / "test_emails"

@pytest.mark.parametrize("name", [
    "valid_email.eml",
    "suspicious_email.eml",
    "malicious_email.eml",
])
def test_analyze_eml_basic_structure(name):
    path = FIXTURES / name
    result = analyze_eml(str(path))
    summary = result["summary"]
    assert {"from", "subject", "verdict", "score", "reasons"}.issubset(summary.keys())
    assert isinstance(summary["score"], int)
    assert 0 <= summary["score"] <= 100

def test_analyze_eml_invalid_file():
    with pytest.raises(FileNotFoundError):
        analyze_eml(str(FIXTURES / "does_not_exist.eml"))
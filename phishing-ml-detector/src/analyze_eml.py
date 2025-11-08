#!/usr/bin/env python3
"""
Phishing Email Analyzer with ML Integration
Usage:
    python analyze_eml.py path/to/email.eml
Output: JSON printed to stdout (only important info)
"""
import sys
import json
import argparse
from email.parser import BytesParser
from email import policy
import os, sys
from pathlib import Path

# Ensure relative imports work when run inside tests (pytest adds project root)
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ml.predict import predict_suspicion
from utils.parsing import extract_parts, extract_links_from_html, extract_ips_from_received

# --- Parse eml ---
def parse_eml(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg

# --- Main analyzer ---
def analyze_eml(path):
    msg = parse_eml(path)
    headers = dict(msg.items())

    plain, html, attachments = extract_parts(msg)
    anchors = extract_links_from_html(html)
    recvd_ips = extract_ips_from_received(msg.get_all("Received"))

    parsed = {
        "from": headers.get("From", ""),
        "to": headers.get("To", ""),
        "subject": headers.get("Subject", ""),
        "date": headers.get("Date", ""),
        "return_path": headers.get("Return-Path", ""),
        "plain": plain,
        "html": html,
        "attachments": attachments,
        "anchors": anchors,
        "received_ips": recvd_ips,
    }

    # Use ML model to predict suspicion
    prediction = predict_suspicion(parsed)

    # final output
    out = {
        "summary": {
            "from": parsed["from"],
            "subject": parsed["subject"],
            "verdict": prediction["verdict"],
            "score": prediction["score"],
            "reasons": prediction["reasons"]
        },
        "details": {
            "suspicious_words": prediction.get("suspicious_words", []),
            "suspicious_links": prediction.get("suspicious_links", []),
            "attachments": parsed["attachments"],
            "ips": {"all": parsed["received_ips"]}
        }
    }

    # JSON output
    print("\n=== JSON Output ===")
    print(json.dumps(out, indent=4))

    return out

# --- CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing Email Analyzer with ML Integration")
    parser.add_argument("-f", "--file", required=True, help="Path to the .eml file to analyze.")
    args = parser.parse_args()
    analyze_eml(args.file)
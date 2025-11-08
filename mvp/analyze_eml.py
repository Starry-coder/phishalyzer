#!/usr/bin/env python3
"""
Minimal Phishing Email Analyzer
Usage:
    python analyze_eml.py path/to/email.eml
Output: JSON printed to stdout (only important info)
"""
import sys, re, json, difflib, argparse
from email.parser import BytesParser
from email import policy
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import Fore, Style, Back, init

init(autoreset=True)

# --- Helpers for highlighting ---
def highlight(text): return f"{Fore.RED}{text}{Style.RESET_ALL}"
def verdict_highlight(text): return f"{Back.YELLOW}{Fore.RED}{text}{Style.RESET_ALL}"

# --- Parse eml ---
def parse_eml(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg

def extract_parts(msg):
    plain, html, attachments = "", "", []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        if ctype == "text/plain" and disp != "attachment":
            plain += part.get_content()
        elif ctype == "text/html" and disp != "attachment":
            html += part.get_content()
        elif disp == "attachment" or part.get_filename():
            fname = part.get_filename()
            payload = part.get_payload(decode=True)
            attachments.append({"filename": fname, "size": len(payload) if payload else 0})
    return plain.strip(), html.strip(), attachments

def extract_links_from_html(html):
    anchors = []
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            anchors.append({"href": a["href"].strip(), "text": a.get_text(strip=True)})
    return anchors

def extract_ips_from_received(received_headers):
    ips = set()
    for r in received_headers or []:
        ips.update(re.findall(r'\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]', r))
    return list(ips)

def domain_of(value):
    if not value: return ""
    m = re.search(r'@([\w\.-]+)', value)
    if m: return m.group(1).lower()
    try: return urlparse(value).hostname or value.lower()
    except: return value.lower()

# --- Suspicious heuristics ---
SUSPICIOUS_WORDS = {"urgent","verify","password","bank","click here","account","confirm","login"}

def detect_heuristics(parsed):
    score, reasons, sus_links = 0, [], []

    # suspicious words
    body_text = (parsed["plain"] + " " + parsed["html"]).lower()
    found = [w for w in SUSPICIOUS_WORDS if w in body_text]
    if found:
        score += 15
        reasons.append("Suspicious words: " + ", ".join(found))
        parsed["suspicious_words"] = found
    else:
        parsed["suspicious_words"] = []

    # link mismatches
    for a in parsed["anchors"]:
        href, text = a.get("href",""), a.get("text","")
        text_domains = re.findall(r'[\w\.-]+\.[a-z]{2,}', text)
        if text_domains and domain_of(text_domains[0]) not in href:
            score += 25
            sus_links.append(href)
            reasons.append(f"Link mismatch: text='{text}' href='{href}'")

        # suspicious TLDs
        if href and href.lower().endswith((".ru",".xyz",".top",".club")):
            score += 20
            sus_links.append(href)
            reasons.append(f"Suspicious TLD in link: {href}")

    parsed["suspicious_links"] = list(set(sus_links))

    # mismatched domains (From vs Return-Path)
    from_dom, rp_dom = domain_of(parsed["from"]), domain_of(parsed["return_path"])
    if from_dom and rp_dom and from_dom != rp_dom:
        score += 30
        reasons.append(f"From domain ({from_dom}) != Return-Path ({rp_dom})")

    # suspicious attachments
    for a in parsed["attachments"]:
        if a["filename"] and a["filename"].lower().endswith((".exe",".js",".bat",".scr",".ps1")):
            score += 40
            reasons.append(f"Suspicious attachment: {a['filename']}")

    # suspicious domain
    if from_dom.endswith((".xyz",".ru",".top",".club")):
        score += 20
        reasons.append(f"Suspicious sender domain TLD: {from_dom}")

    # suspicious IPs (placeholder — real check would use reputation API)
    if parsed["suspicious_ips"]:
        score += 40
        reasons.append("Suspicious IPs found: " + ", ".join(parsed["suspicious_ips"]))

    # verdict
    verdict = "SAFE"
    if score >= 70: verdict = "MALICIOUS"
    elif score >= 30: verdict = "SUSPICIOUS"

    return {"score": score, "verdict": verdict, "reasons": reasons}

# --- Main analyzer ---
def analyze_eml(path):
    msg = parse_eml(path)
    headers = dict(msg.items())

    plain, html, attachments = extract_parts(msg)
    anchors = extract_links_from_html(html)
    recvd_ips = extract_ips_from_received(msg.get_all("Received"))
    
    parsed = {
        "from": headers.get("From",""),
        "to": headers.get("To",""),
        "subject": headers.get("Subject",""),
        "date": headers.get("Date",""),
        "return_path": headers.get("Return-Path",""),
        "plain": plain,
        "html": "",
        "attachments": attachments,
        "anchors": anchors,
        "received_ips": recvd_ips,
        "suspicious_ips": []  # placeholder
    }

    heur = detect_heuristics(parsed)

    # final output
    out = {
        "summary": {
            "from": parsed["from"],
            "subject": parsed["subject"],
            "verdict": heur["verdict"],
            "score": heur["score"],
            "reasons": heur["reasons"]
        },
        "details": {
            "suspicious_words": parsed["suspicious_words"],
            "suspicious_links": parsed["suspicious_links"],
            "attachments": parsed["attachments"],
            "ips": {"all": parsed["received_ips"], "suspicious": parsed["suspicious_ips"]}
        }
    }

    # print clean summary
    print("\n=== Email Analysis ===")
    print(f"From: {parsed['from']}")
    print(f"Subject: {parsed['subject']}")
    if parsed["suspicious_links"]:
        print("\nSuspicious Links:")
        for l in parsed["suspicious_links"]:
            print(" -", highlight(l))
    print("Verdict:", verdict_highlight(heur["verdict"]))

    # JSON output
    print("\n=== JSON Output ===")
    print(json.dumps(out, indent=4))

    return out

# --- CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal Phishing Email Analyzer")
    parser.add_argument("-f", "--file", required=True, help="Path to the .eml file to analyze.")
    args = parser.parse_args()
    analyze_eml(args.file)

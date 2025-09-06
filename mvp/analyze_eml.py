#!/usr/bin/env python3
"""
MVP Phishing Email Analyzer
Usage:
    python analyze_eml.py path/to/email.eml
Output: JSON printed to stdout
"""
import sys, re, json, difflib, email
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import Fore, Style, init, Back

init(autoreset=True)

def highlight(text):
    """Return suspicious text highlighted in red."""
    return f"{Fore.RED}{text}{Style.RESET_ALL}"

def verdict_highlight(text):
    """Return verdict highlighted in red text with yellow background."""
    return f"{Back.YELLOW}{Fore.RED}{text}{Style.RESET_ALL}"

def analyze_email(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = email.message_from_file(f)

    print("\n=== Email Analysis ===")

    analysis_results = {
        "headers": dict(msg.items()),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "body_text": "",
        "urls": [],
        "attachments": [],
        "suspicious_words": [],
        "verdict": ""
    }

    # --- Check sender ---
    sender = analysis_results["from"]
    if not sender.endswith("@legitdomain.com"):
        print(f"From: {highlight(sender)}")
    else:
        print(f"From: {sender}")

    # --- Subject ---
    subject = analysis_results["subject"]
    if re.search(r"(urgent|verify|password|bank|login)", subject, re.I):
        print(f"Subject: {highlight(subject)}")
    else:
        print(f"Subject: {subject}")

    # --- Extract body text ---
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition"))

            # Attachments
            if "attachment" in cdispo:
                filename = part.get_filename()
                if filename:
                    analysis_results["attachments"].append(filename)
                continue

            # Plain text parts
            if ctype == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode(errors="ignore")
                except:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
        except:
            body = str(msg.get_payload())

    analysis_results["body_text"] = body

    # --- Links in body ---
    print("\nLinks Found:")
    urls = re.findall(r"http[s]?://\S+", body)
    analysis_results["urls"] = urls
    if urls:
        for url in urls:
            print(f" - {highlight(url)}")
    else:
        print(" - None")

    # --- Suspicious words ---
    print("\nSuspicious Words:")
    suspicious_words = ["bank", "password", "click here", "verify", "urgent"]
    found = []
    for word in suspicious_words:
        if re.search(word, body, re.I):
            print(f" - {highlight(word)}")
            found.append(word)
    if not found:
        print(" - None")
    analysis_results["suspicious_words"] = found

    # --- Verdict ---
    if not sender.endswith("@legitdomain.com") or urls or found or analysis_results["attachments"]:
        verdict = "⚠️ Suspicious Email Detected!"
    else:
        verdict = "✅ Email Seems Safe."
    analysis_results["verdict"] = verdict

    print("\nVerdict:", verdict_highlight(verdict))

    # --- JSON Output (Detailed) ---
    print("\n=== JSON Output ===")
    print(json.dumps(analysis_results, indent=4))

# ---- Helpers ----
def parse_eml(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg, raw

def get_addresses(header_value):
    if not header_value: return []
    # crude extraction of emails
    return re.findall(r'[\w\.-]+@[\w\.-]+', header_value)

def extract_parts(msg):
    plain_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        if ctype == "text/plain" and disp != "attachment":
            try:
                plain_parts.append(part.get_content())
            except:
                pass
        elif ctype == "text/html" and disp != "attachment":
            try:
                html_parts.append(part.get_content())
            except:
                pass
        elif disp == "attachment" or part.get_filename():
            fname = part.get_filename()
            payload = part.get_payload(decode=True)
            attachments.append({"filename": fname, "size": len(payload) if payload else 0})
    return ("\n".join(plain_parts).strip(), "\n".join(html_parts).strip(), attachments)

def extract_links_from_html(html):
    anchors = []
    bare_urls = set()
    if not html:
        return anchors, list(bare_urls)
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        anchors.append({"href": a["href"].strip(), "text": a.get_text(strip=True)})
    # find URLs in text as fallback
    bare_urls.update(re.findall(r'https?://[^\s\'"<>]+', html))
    return anchors, list(bare_urls)

def extract_ips_from_received(received_headers):
    ips = set()
    if not received_headers:
        return []
    for r in received_headers:
        # common pattern: [1.2.3.4]
        ips.update(re.findall(r'\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]', r))
        # fallback: any IPv4-looking token
        ips.update(re.findall(r'(?<![:.\d])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![:.\d])', r))
    # filter invalid octets
    def valid_ip(ip):
        parts = ip.split(".")
        return len(parts)==4 and all(0 <= int(x) <= 255 for x in parts)
    return [ip for ip in ips if valid_ip(ip)]

def domain_of(email_or_host):
    if not email_or_host: return ""
    # if it's an email, extract domain; if URL/host, parse
    m = re.search(r'@([\w\.-]+)', email_or_host)
    if m:
        return m.group(1).lower()
    try:
        return urlparse(email_or_host).hostname or email_or_host.lower()
    except:
        return email_or_host.lower()

def similarity(a,b):
    return difflib.SequenceMatcher(None, a, b).ratio()

# ---- Heuristics / scoring ----
SUSPICIOUS_WORDS = {"urgent","immediately","verify","suspended","locked","click","password","bank","sso","account","update","confirm"}

def detect_heuristics(parsed):
    score = 0
    reasons = []

    # 1) From vs Return-Path domain mismatch
    from_dom = domain_of(parsed.get("from", ""))
    return_path_dom = domain_of(parsed.get("return_path", ""))
    if from_dom and return_path_dom and from_dom != return_path_dom:
        score += 30
        reasons.append(f"From domain ({from_dom}) != Return-Path ({return_path_dom})")

    # 2) Link mismatches
    for a in parsed.get("anchors", []):
        href = a.get("href","")
        text = a.get("text","")
        if href and text:
            # if visible text looks like a domain/URL but href points somewhere else
            text_domains = re.findall(r'[\w\.-]+\.[a-z]{2,}', text)
            if text_domains:
                # compare first domain-like token
                if domain_of(text_domains[0]) not in href:
                    score += 25
                    reasons.append(f"Anchor text/domain doesn't match href ({text} -> {href})")

    # 3) Suspicious words in body
    body = (parsed.get("plain","") + " " + parsed.get("html","")).lower()
    found = [w for w in SUSPICIOUS_WORDS if w in body]
    if found:
        score += 10
        reasons.append("Urgency/suspicious words found: " + ", ".join(found))

    # 4) Suspicious attachments
    for a in parsed.get("attachments", []):
        fn = (a.get("filename") or "").lower()
        if fn.endswith((".exe",".js",".bat",".scr",".ps1")):
            score += 50
            reasons.append(f"suspicious attachment type: {fn}")

    # 5) weird TLD or lookalike domain
    sender = parsed.get("from","")
    sender_dom = domain_of(sender)
    # simplistic check: many phishing use uncommon TLDs
    if sender_dom.endswith((".xyz",".top",".club",".ru")):
        score += 10
        reasons.append("Sender domain uses uncommon TLD: " + sender_dom)

    # 6) Received IP blacklisted (placeholder: heavy weight)
    if parsed.get("suspicious_ips"):
        score += 40
        reasons.append("Sending IPs flagged: " + ", ".join(parsed.get("suspicious_ips")))

    # clamp
    score = min(score, 100)
    verdict = "SAFE"
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    return {"score": score, "verdict": verdict, "reasons": reasons}

# ---- Analyzer entrypoint ----
def analyze_eml(path):
    msg, raw = parse_eml(path)
    headers = dict(msg.items())
    parsed = {
        "from": headers.get("From"),
        "to": headers.get("To"),
        "subject": headers.get("Subject"),
        "date": headers.get("Date"),
        "return_path": headers.get("Return-Path"),
        "raw_headers": headers,
    }
    plain, html, attachments = extract_parts(msg)
    parsed["plain"] = plain
    parsed["html"] = html
    parsed["attachments"] = attachments

    # links
    anchors, bare_urls = extract_links_from_html(html)
    parsed["anchors"] = anchors
    parsed["bare_urls"] = bare_urls

    # Received IPs
    recvs = msg.get_all("Received", [])
    ips = extract_ips_from_received(recvs)
    parsed["received_ips"] = ips

    # Placeholder for reputation lookups (to be implemented) -> put suspicious_ips if any found
    parsed["suspicious_ips"] = []  # populate after querying AbuseIPDB / VirusTotal

    # heuristic scoring
    heur = detect_heuristics(parsed)

    out = {
        "summary": {
            "from": parsed["from"],
            "subject": parsed["subject"],
            "verdict": heur["verdict"],
            "score": heur["score"],
            "reasons": heur["reasons"]
        },
        "details": parsed
    }
    return out

# ---- CLI ----
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_eml.py path/to/email.eml")
        sys.exit(1)
    analyze_email(sys.argv[1])

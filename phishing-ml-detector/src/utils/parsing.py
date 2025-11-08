import re
from bs4 import BeautifulSoup

SUSPICIOUS_WORDS = {"urgent", "verify", "password", "bank", "click here", "account", "confirm", "login"}

def extract_parts(msg):
    """Return plain text, html, and attachment summaries from email message."""
    plain, html, attachments = "", "", []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        if ctype == "text/plain" and disp != "attachment":
            try:
                plain += part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                plain += payload.decode(errors='ignore')
        elif ctype == "text/html" and disp != "attachment":
            try:
                html += part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                html += payload.decode(errors='ignore')
        elif disp == "attachment" or part.get_filename():
            fname = part.get_filename()
            payload = part.get_payload(decode=True)
            attachments.append({"filename": fname, "size": len(payload) if payload else 0})
    return plain.strip(), html.strip(), attachments

def extract_links_from_html(html: str):
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

def extract_email_features(email_content):
    """Legacy convenience: return simple counts for quick tests."""
    features = {}
    text = email_content or ""
    features['length'] = len(text)
    features['num_links'] = text.count('http')
    features['num_suspicious_words'] = sum(word in text.lower() for word in SUSPICIOUS_WORDS)
    return features

def parse_email_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        email_content = file.read()
    return email_content

def extract_features_from_emails(email_files):
    all_features = []
    for file in email_files:
        email_content = parse_email_file(file)
        features = extract_email_features(email_content)
        all_features.append(features)
    return all_features

# 🛡️ Phishing Email Analyzer

A project to analyze suspicious emails and detect phishing attempts.  
The tool parses `.eml` files, extracts headers, links, and attachments, applies heuristics, and generates a security verdict.  

---

## 🚀 Features (MVP)
- Parse `.eml` email files  
- Extract headers (From, Subject, Return-Path, Received, etc.)  
- Identify embedded links & mismatched domains  
- Detect urgency keywords and suspicious wording  
- Inspect attachments and flag risky file types  
- Basic heuristic scoring with verdict: **SAFE | SUSPICIOUS | MALICIOUS**  
- Output results as structured JSON  

---

## 🛠️ Tech Stack
- **Language:** Python 3.10+  
- **Libraries:** `email`, `beautifulsoup4`, `dnspython`, `dkimpy`, `pyspf`, `requests`  
- **Optional APIs:** VirusTotal, AbuseIPDB (future work)  

---

## 📂 Repository Structure
phish-analyzer/
├─ README.md # project overview
├─ requirements.txt # Python dependencies
├─ mvp/
│ ├─ analyze_eml.py # MVP CLI analyzer
│ └─ test_emails/ # sample .eml files for testing
├─ webapp/ # (future) Flask/React web UI
├─ sandbox/ # (future) sandbox integrations
└─ docs/ # project documentation

---

## ⚡ Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/<your-username>/phish-analyzer.git
cd phish-analyzer

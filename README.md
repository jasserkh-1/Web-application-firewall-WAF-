🛡️ Flask-WAF: Web Application Firewall
A lightweight yet powerful Web Application Firewall (WAF) built with Flask to detect and block common web attacks in real time. Designed for learning, research, and security enhancement, this project supports payload inspection across all HTTP request components.

⚙️ Features
✅ Brute-Force Protection
Detects repeated failed login attempts from the same IP and applies lockouts.

🔍 Payload Obfuscation Detection
Automatically decodes:

URL-encoded inputs

Base64 payloads

Hex-encoded strings
Ensures detection even if payloads are disguised.

📦 Multi-Layer Request Analysis
Inspects:

Headers

Body

Cookies

Query parameters

Path

🧠 Pattern Matching Engine
Detects common web attack signatures:

XSS (Cross-site Scripting)

LFI/RFI (Local/Remote File Inclusion)

RCE (Remote Code Execution)

SQLi (SQL Injection)

Command Injection

🛠️ Technologies
Flask (Python)

Regex-based pattern detection

Modular middleware structure

(Optional) Frontend Dashboard: React.js

🚀 Getting Started
Prerequisites
Python 3.8+

Flask

Installation

git clone https://github.com/jasserkh-1/Web-application-firewall-WAF-
cd flask-waf
pip install -r requirements.txt
python app.py
Example Usage
Send requests to /login to trigger brute-force detection:

Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/analyze" `
  -Method POST `
  -Headers @{
      "User-Agent" = "<script>alert('header_xss')</script>"
      "X-Forwarded-For" = "88.198.5.25"
  } `
  -Body (@{ payload = "" } | ConvertTo-Json) `
  -ContentType "application/json"

📁 Project Structure
php
Copier
Modifier
├── app.py                  # Flask app with WAF middleware
├── waf/                    # WAF logic (decoding, detection, logging)
│   ├── decoder.py
│   ├── detectors.py
│   └── logger.py
├── static/                 # Optional React frontend
├── templates/              # HTML templates (if using Flask frontend)
└── README.md

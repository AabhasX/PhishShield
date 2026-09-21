# PhishShield — Phishing URL Detection System

A web-based educational cybersecurity prototype that performs static URL analysis.

## What it does
- Accepts a URL from the user
- Extracts simple URL/domain features
- Calculates a 0–100 risk score
- Classifies the URL as SAFE, SUSPICIOUS, or HIGH RISK
- Explains the indicators that affected the score
- Stores recent scans in SQLite
- Shows dashboard statistics

## Detection indicators
The current rule engine checks:
- IP address as host
- URL length
- `@` symbol
- Punycode/IDN pattern
- many subdomains
- many hyphens
- common URL shorteners
- security-sensitive keywords
- HTTP instead of HTTPS
- extra `//` in the path
- percent-encoded characters

## Thresholds
0–30     SAFE
31–60    SUSPICIOUS
61–100   HIGH RISK

These are prototype thresholds, not a production security standard.

## Run
Install Python 3.10+.

Windows:
```text
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

macOS/Linux:
```text
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Important
The system does not visit, download from, or execute the submitted website. It analyzes the URL string locally. A SAFE result is not proof that a site is safe.

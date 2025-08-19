# Phishing Email Analyser

Parses raw RFC822 / .eml messages to extract indicators and compute a phishing risk score.

## Features
- Extracts headers (SPF/DKIM/DMARC results, Received chain anomalies)
- URL/domain extraction with basic reputation heuristics (length, punycode, TLD risk list placeholder)
- Body lexical analysis (urgency, financial lure terms, brand spoof tokens)
- Simple scoring + JSON report
- Pluggable ML classifier hook (placeholder function)

## Install
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```
python analyse_email.py samples/sample.eml --json-out report.json
```

## Output (example)
```
{
  "subject": "Important: Verify your account",
  "from_domain": "secure-payments.example",
  "scores": {
    "header_anomalies": 30,
    "body_urgency": 15,
    "suspicious_urls": 25,
    "lexical": 10
  },
  "total_score": 80,
  "risk_level": "high"
}
```

## Roadmap
- Integrate optional VirusTotal / URLhaus lookups (env-gated)
- Train lightweight fastText or scikit model for final probability fusion
- Add YARA-like pattern config file

## Disclaimer
Educational utility. Validate detections and respect privacy constraints.

#!/usr/bin/env python3
"""Phishing email analyser: parse .eml, extract indicators, compute heuristic score."""
from __future__ import annotations
import argparse
import email
import email.policy
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any
import tldextract

URGENT_TERMS = [r"urgent", r"immediately", r"action required", r"verify", r"password", r"suspend"]
LURE_TERMS = [r"invoice", r"payment", r"refund", r"account", r"security", r"update"]
URL_REGEX = re.compile(r"https?://[\w\-.:/?#%&=+]+", re.IGNORECASE)
PUNYCODE_PREFIX = "xn--"
RISK_TLDS = {"zip", "kim", "work", "top"}  # placeholder

@dataclass
class ScoreBreakdown:
    header_anomalies: int = 0
    body_urgency: int = 0
    suspicious_urls: int = 0
    lexical: int = 0

    def total(self) -> int:
        return self.header_anomalies + self.body_urgency + self.suspicious_urls + self.lexical


def parse_email(path: Path) -> email.message.EmailMessage:
    with path.open('rb') as f:
        return email.message_from_binary_file(f, policy=email.policy.default)


def extract_body(msg: email.message.EmailMessage) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                try:
                    return part.get_content().strip()
                except Exception:
                    continue
        return ""
    else:
        try:
            return msg.get_content().strip()
        except Exception:
            return ""


def analyse(msg: email.message.EmailMessage) -> Dict[str, Any]:
    scores = ScoreBreakdown()
    indicators: Dict[str, Any] = {}

    from_hdr = msg.get('From', '')
    subject = msg.get('Subject', '')
    auth_results = msg.get('Authentication-Results', '')
    received_headers = msg.get_all('Received', []) or []

    # Header anomaly heuristic examples
    if len(received_headers) <= 1:
        scores.header_anomalies += 15
    if 'spf=fail' in auth_results.lower():
        scores.header_anomalies += 15

    body = extract_body(msg)
    body_lower = body.lower()

    # Urgency / lure term scoring
    urgency_hits = sum(1 for t in URGENT_TERMS if t in body_lower)
    lure_hits = sum(1 for t in LURE_TERMS if t in body_lower)
    scores.body_urgency += min(urgency_hits * 5, 25)
    scores.lexical += min(lure_hits * 3, 15)

    # URL extraction & checks
    urls = URL_REGEX.findall(body)
    suspicious_url_score = 0
    suspicious_urls: List[str] = []
    for u in urls:
        ext = tldextract.extract(u)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        # Heuristics
        if len(domain) > 20:
            suspicious_url_score += 5
        if domain.startswith(PUNYCODE_PREFIX):
            suspicious_url_score += 10
        if ext.suffix in RISK_TLDS:
            suspicious_url_score += 5
        if re.search(r"\d{5,}", domain):
            suspicious_url_score += 5
        if suspicious_url_score:
            suspicious_urls.append(u)
    scores.suspicious_urls += min(suspicious_url_score, 30)

    total_score = scores.total()
    if total_score >= 70:
        risk_level = 'high'
    elif total_score >= 40:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    indicators.update({
        'subject': subject,
        'from': from_hdr,
        'scores': asdict(scores),
        'total_score': total_score,
        'risk_level': risk_level,
        'url_count': len(urls),
        'suspicious_urls': suspicious_urls,
    })
    return indicators


def main():
    ap = argparse.ArgumentParser(description="Analyse a raw .eml file for phishing indicators")
    ap.add_argument('eml_path', type=Path)
    ap.add_argument('--json-out', type=Path, help='Write JSON report path')
    args = ap.parse_args()

    msg = parse_email(args.eml_path)
    result = analyse(msg)

    if args.json_out:
        args.json_out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()

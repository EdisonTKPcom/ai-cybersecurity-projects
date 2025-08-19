# AI Cybersecurity Projects

Curated collection of small, focused AI-augmented security engineering utilities. Each subproject is self‑contained with its own README and (where needed) Python dependencies.

## Project Index

| Project | Purpose | Highlights |
|---------|---------|------------|
| `phishing-email-analyser` | Analyse raw email files (.eml) to surface phishing indicators & produce a structured risk score. | Header/URL heuristics, lexical urgency scoring, optional ML model hook. |
| `threat-detection-siem-queries` | Reference & starter library of SIEM detection queries across Splunk, Elastic, and Azure Sentinel (KQL). | Normalized naming, MITRE ATT&CK tagging, quick filter script. |
| `siem-alert-summariser` | Summarise high-volume SIEM alerts into an analyst-friendly daily digest. | Rule/severity aggregation, entity co-occurrence, timeline extraction, optional LLM hook. |

## Getting Started

Each Python-based project has an isolated `requirements.txt`. From inside a project directory:

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Navigation

```
phishing-email-analyser/
threat-detection-siem-queries/
siem-alert-summariser/
```

## Contributing

Feel free to open issues or PRs adding new detection content, heuristics, tests, or lightweight ML models. Keep external service calls optional and behind clear interfaces.

## Disclaimer

These tools are educational starters and should be validated & tuned before production use.
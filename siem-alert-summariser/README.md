# SIEM Alert Summariser

Aggregates raw SIEM alert exports (JSON lines) into a concise analyst digest with entity aggregation and timeline context. Optional LLM hook placeholder for natural language summary.

## Features
- Ingest NDJSON of alerts containing at minimum: `timestamp`, `rule_name`, `severity`, `src_ip`, `dst_ip`, `user`
- Aggregates by rule and severity
- Extracts top entities (users, src_ip, dst_ip)
- Builds chronological mini-timeline of first/last seen per rule
- Renders Markdown and JSON reports

## Install
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```
python summarise_alerts.py alerts.ndjson --markdown-out daily.md --json-out daily.json
```

## Sample Output (Markdown)
```
# Daily SIEM Digest
Date Range: 2025-08-14 10:00 UTC -> 2025-08-15 09:59 UTC

## Summary Table
| Rule | Severity | Count | First Seen | Last Seen |
|------|----------|-------|------------|-----------|
| Suspicious Encoded PowerShell | high | 12 | 10:05 | 11:47 |

## Top Entities
- Users: alice(9), bob(3)
- Src IPs: 10.1.2.5(7), 10.9.8.4(5)
- Dst IPs: 172.16.5.10(6)
```

## Roadmap
- Add entity relationship graph export
- Add risk scoring fusion
- Optional LLM summarisation via OPENAI_API_KEY (not implemented here)

## Disclaimer
Educational utility. Validate outputs before operational use.

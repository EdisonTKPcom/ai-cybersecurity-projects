# Threat Detection SIEM Queries

Cross-platform library of starter detection queries (Splunk SPL, Elastic Query DSL/KQL, Azure Sentinel KQL) with MITRE ATT&CK tagging.

## Structure
```
queries/
  splunk/
  elastic/
  sentinel/
meta/
  detections.yml
scripts/
  filter_queries.py
```

## Usage
Filter queries by tactic / platform:
```
python scripts/filter_queries.py --tactic TA0003 --platform splunk
```

## Adding Queries
1. Place the query file under the appropriate platform folder.
2. Update `meta/detections.yml` with metadata (id, name, tactic, technique, severity, filepath).

## Roadmap
- Add Sigma conversion script
- Add coverage report generator

## Disclaimer
Queries are examples; tune for your environment before production use.

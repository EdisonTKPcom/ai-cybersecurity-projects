#!/usr/bin/env python3
"""Summarise SIEM alerts from NDJSON into JSON + Markdown digest."""
from __future__ import annotations
import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from dateutil import parser as dtparser

@dataclass
class RuleAggregate:
    rule_name: str
    severity: str
    count: int
    first_seen: datetime
    last_seen: datetime

    def to_row(self):
        return [self.rule_name, self.severity, str(self.count), self.first_seen.strftime('%H:%M'), self.last_seen.strftime('%H:%M')]


def load_alerts(path: Path) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            alerts.append(obj)
        except json.JSONDecodeError:
            continue
    return alerts


def aggregate(alerts: List[Dict[str, Any]]):
    if not alerts:
        return [], {}, {}
    rule_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    users = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    for a in alerts:
        rule = a.get('rule_name', 'UNKNOWN')
        rule_groups[rule].append(a)
        if u := a.get('user'):
            users[u] += 1
        if s := a.get('src_ip'):
            src_ips[s] += 1
        if d := a.get('dst_ip'):
            dst_ips[d] += 1
    aggregates: List[RuleAggregate] = []
    for rule, group in rule_groups.items():
        severities = Counter([g.get('severity', 'unknown') for g in group])
        # pick highest severity by a simple custom order
        sev_order = {'critical':4, 'high':3, 'medium':2, 'low':1}
        severity = sorted(severities.keys(), key=lambda s: -sev_order.get(s,0))[0]
        times = [dtparser.parse(g['timestamp']) for g in group if 'timestamp' in g]
        first_seen = min(times)
        last_seen = max(times)
        aggregates.append(RuleAggregate(rule, severity, len(group), first_seen, last_seen))
    aggregates.sort(key=lambda r: (-r.count, r.rule_name))
    return aggregates, {'users': users, 'src_ips': src_ips, 'dst_ips': dst_ips}, {'start': min(a.first_seen for a in aggregates), 'end': max(a.last_seen for a in aggregates)}


def render_markdown(aggregates: List[RuleAggregate], entities, range_info):
    lines = []
    lines.append('# Daily SIEM Digest')
    if range_info:
        lines.append(f"Date Range: {range_info['start'].isoformat()} -> {range_info['end'].isoformat()}")
    lines.append('\n## Summary Table')
    lines.append('| Rule | Severity | Count | First Seen | Last Seen |')
    lines.append('|------|----------|-------|------------|-----------|')
    for agg in aggregates:
        r, s, c, f, l = agg.to_row()
        lines.append(f"| {r} | {s} | {c} | {f} | {l} |")
    lines.append('\n## Top Entities')
    def fmt(counter: Counter):
        return ', '.join(f"{k}({v})" for k, v in counter.most_common(5)) or 'None'
    lines.append(f"- Users: {fmt(entities['users'])}")
    lines.append(f"- Src IPs: {fmt(entities['src_ips'])}")
    lines.append(f"- Dst IPs: {fmt(entities['dst_ips'])}")
    return '\n'.join(lines) + '\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('alerts_path', type=Path, help='NDJSON alerts file')
    ap.add_argument('--markdown-out', type=Path)
    ap.add_argument('--json-out', type=Path)
    args = ap.parse_args()

    alerts = load_alerts(args.alerts_path)
    aggregates, entities, range_info = aggregate(alerts)

    result = {
        'rule_aggregates': [asdict(a) for a in aggregates],
        'entities': {k: dict(v) for k, v in entities.items()},
        'range': {k: v.isoformat() for k, v in range_info.items()} if range_info else {}
    }

    if args.json_out:
        args.json_out.write_text(json.dumps(result, indent=2))

    md = render_markdown(aggregates, entities, range_info)
    if args.markdown_out:
        args.markdown_out.write_text(md)
    print(md)

if __name__ == '__main__':
    main()

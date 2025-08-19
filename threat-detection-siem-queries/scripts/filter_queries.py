#!/usr/bin/env python3
"""Filter detection metadata by tactic / platform / severity."""
from __future__ import annotations
import argparse
import yaml
from pathlib import Path
from typing import List


def load_index(path: Path):
    return yaml.safe_load(path.read_text())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tactic')
    ap.add_argument('--technique')
    ap.add_argument('--platform')
    ap.add_argument('--severity')
    ap.add_argument('--index', type=Path, default=Path('meta/detections.yml'))
    args = ap.parse_args()

    detections = load_index(args.index)
    filtered: List[dict] = []
    for det in detections:
        if args.tactic and det['tactic'] != args.tactic:
            continue
        if args.technique and det['technique'] != args.technique:
            continue
        if args.platform and det['platform'] != args.platform:
            continue
        if args.severity and det['severity'] != args.severity:
            continue
        filtered.append(det)

    if not filtered:
        print("No detections matched criteria")
        return

    for det in filtered:
        print(f"{det['id']}: {det['name']} ({det['platform']}, {det['tactic']}, {det['technique']}, {det['severity']}) -> {det['filepath']}")

if __name__ == '__main__':
    main()

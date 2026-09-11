from __future__ import annotations

import argparse
from pathlib import Path

from .decision_engine import assess_endpoints
from .io import load_events
from .reporting import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Defensive endpoint isolation decision-support lab")
    parser.add_argument("input", help="Path to synthetic endpoint-event JSON")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args = parser.parse_args()

    events = load_events(args.input)
    findings = assess_endpoints(events)
    report = render_markdown(findings)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"assessed {len(findings)} hosts; report written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

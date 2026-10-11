#!/usr/bin/env python3
"""
Redcell runner. Attacks a target agent with the full probe suite, prints a
scorecard, and writes a Markdown report to reports/.

    python run.py                 # attack the built-in mock target
    python run.py --json          # also emit machine-readable results
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from redcell.probes import run_all
from redcell.target import MockAgent


def report_md(results) -> str:
    n = len(results)
    vuln = sum(r.succeeded for r in results)
    lines = [
        "# Redcell report",
        f"_generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}_",
        "",
        f"**{vuln}/{n} probes succeeded** (each success = a vulnerability present).",
        "",
        "| Probe | OWASP | ATLAS | Result | Evidence |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        flag = "🔴 VULN" if r.succeeded else "🟢 safe"
        ev = r.evidence.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{r.probe_id}` | {r.owasp} | {r.atlas} | {flag} | {ev} |")
    lines += ["", "> Mock target has planted weaknesses; a hardened agent should turn these green.",
              "> Swap in a real agent via the `.respond()` adapter interface to test production systems."]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    target = MockAgent()
    results = run_all(target)

    vuln = sum(r.succeeded for r in results)
    print(f"\nRedcell: {vuln}/{len(results)} probes succeeded\n")
    for r in results:
        print(f"  {'🔴 VULN' if r.succeeded else '🟢 safe':<8} {r.probe_id:<24} {r.owasp}")

    Path("reports").mkdir(exist_ok=True)
    out = Path("reports/latest.md")
    out.write_text(report_md(results))
    print(f"\nreport -> {out}")
    if args.json:
        jp = Path("reports/latest.json")
        jp.write_text(json.dumps([r.__dict__ for r in results], indent=2))
        print(f"json   -> {jp}")

    # exit non-zero if any vuln found -> lets CI gate a real agent on this
    raise SystemExit(1 if vuln else 0)


if __name__ == "__main__":
    main()

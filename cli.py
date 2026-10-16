#!/usr/bin/env python3
"""
Credential Detector CLI (v2.0)
Scan files, folders, zip archives, or launch the interactive Web GUI.
Evidence-based severity, separate confidence, context awareness, and report generation.

Usage:
    python cli.py scan ./path/to/folder
    python cli.py scan my_repo.zip
    python cli.py scan config.env --report report.html
    python cli.py gui
"""

import argparse
import json
import os
import sys
from pathlib import Path

from detector import (
    scan_file,
    scan_directory,
    scan_zip_bytes,
    group_findings_by_secret,
    SUPPORTED_EXTENSIONS,
)


def generate_txt_report(findings: list, grouped: list) -> str:
    lines = []
    crit = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    med = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")

    lines.append("=" * 75)
    lines.append(" CREDENTIAL & SECRET LEAK AUDIT REPORT")
    lines.append("=" * 75)
    lines.append(f" Total Findings: {len(findings)} | Unique Secrets: {len(grouped)}")
    lines.append(f" Critical: {crit} | High: {high} | Medium: {med} | Low/Info: {low}")
    lines.append("=" * 75)
    lines.append("")

    for idx, g in enumerate(grouped, start=1):
        lines.append(f"[{idx}] {g['label']} ({g['category']})")
        lines.append(f"    Evidence-based Severity : {g['severity']}")
        lines.append(f"    Detection Confidence    : {g['confidence']} ({g['confidence_reason']})")
        lines.append(f"    Impact Evidence         : {g['evidence']}")
        lines.append(f"    Masked Secret           : {g['redacted_secret']} (Entropy: {g['entropy']})")
        lines.append(f"    Occurrences ({len(g['occurrences'])}):")
        for occ in g["occurrences"]:
            lines.append(f"      - {occ['source']}:{occ['line']} [{occ['context_type']}]")
            lines.append(f"        Snippet: {occ['snippet']}")
        lines.append("-" * 75)

    return "\n".join(lines)


def generate_html_report(findings: list, grouped: list) -> str:
    crit = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    med = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Credential Audit Report</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; background: #0B0F17; color: #F3F4F6; padding: 2rem; }}
    h1 {{ color: #60A5FA; }}
    .stats {{ display: flex; gap: 1rem; margin: 1.5rem 0; }}
    .card {{ background: #121824; border: 1px solid #233044; padding: 1rem; border-radius: 8px; flex: 1; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }}
    .badge-Critical {{ background: rgba(239, 68, 68, 0.2); color: #EF4444; }}
    .badge-High {{ background: rgba(249, 115, 22, 0.2); color: #F97316; }}
    .badge-Medium {{ background: rgba(245, 158, 11, 0.2); color: #F59E0B; }}
    .badge-Low {{ background: rgba(16, 185, 129, 0.2); color: #10B981; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: #121824; border-radius: 8px; }}
    th, td {{ padding: 0.8rem 1rem; text-align: left; border-bottom: 1px solid #233044; font-size: 0.9rem; }}
    th {{ color: #94A3B8; text-transform: uppercase; font-size: 0.75rem; }}
    code {{ font-family: monospace; background: #1B2433; padding: 0.2rem 0.4rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>🛡️ Credential & Secret Audit Report</h1>
  <div class="stats">
    <div class="card"><strong>Total Findings:</strong> {len(findings)}</div>
    <div class="card"><strong>Unique Secrets:</strong> {len(grouped)}</div>
    <div class="card"><strong style="color: #EF4444;">Critical:</strong> {crit}</div>
    <div class="card"><strong style="color: #F97316;">High:</strong> {high}</div>
    <div class="card"><strong style="color: #F59E0B;">Medium:</strong> {med}</div>
    <div class="card"><strong style="color: #10B981;">Low:</strong> {low}</div>
  </div>

  <h2>Unique Secrets & Duplicate Occurrences</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Confidence</th>
        <th>Detection Rule</th>
        <th>Secret (Masked)</th>
        <th>Occurrences Across Files</th>
      </tr>
    </thead>
    <tbody>
"""
    for g in grouped:
        occ_html = "<br>".join([f"<code>{occ['source']}:{occ['line']}</code> [{occ['context_type']}]" for occ in g["occurrences"]])
        html += f"""
      <tr>
        <td><span class="badge badge-{g['severity']}">{g['severity']}</span></td>
        <td><strong>{g['confidence']}</strong><div style="font-size:0.75rem; color:#94A3B8;">{g['confidence_reason']}</div></td>
        <td><strong>{g['label']}</strong><div style="font-size:0.75rem; color:#94A3B8;">{g['category']}</div></td>
        <td><code>{g['redacted_secret']}</code></td>
        <td>{occ_html}</td>
      </tr>
"""

    html += """
    </tbody>
  </table>
</body>
</html>
"""
    return html


def print_cli_report(findings: list, grouped: list):
    if not findings:
        print("\n[OK] No leaked credentials or secrets detected.\n")
        return

    crit = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    med = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")

    print("\n" + "=" * 75)
    print(f" SCAN RESULTS: {len(findings)} Finding(s) across {len(grouped)} Unique Secret(s)")
    print("=" * 75)
    print(f" Critical: {crit}  |  High: {high}  |  Medium: {med}  |  Low/Info: {low}")
    print("=" * 75)

    for g in grouped:
        sev = g["severity"].upper()
        conf = g["confidence"].upper()
        print(f"\n [{sev}] {g['label']} ({g['category']})")
        print(f"   Confidence  : [{conf}] {g['confidence_reason']}")
        print(f"   Evidence    : {g['evidence']}")
        print(f"   Secret      : {g['redacted_secret']}  (Entropy: {g['entropy']})")
        print(f"   Occurrences ({len(g['occurrences'])} file location(s)):")
        for occ in g["occurrences"]:
            print(f"     - {occ['source']}:{occ['line']} [{occ['context_type']}]")
            print(f"       {occ['snippet']}")

    print("\n" + "=" * 75 + "\n")


def main():
    parser = argparse.ArgumentParser(
        prog="credential-detector",
        description="Evidence-based Credential & Secret Leak Detector.",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan files, directories, or zip archives")
    p_scan.add_argument("target", help="File, folder, or .zip archive to scan")
    p_scan.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_scan.add_argument("--report", help="Save report to file (.txt, .json, or .html)")

    # gui
    sub.add_parser("gui", help="Launch interactive local web GUI")

    args = parser.parse_args()

    if not args.command or args.command == "gui":
        import app
        app.main()
        return

    if args.command == "scan":
        target = Path(args.target)
        if target.is_file():
            findings = scan_file(str(target))
        elif target.is_dir():
            findings = scan_directory(str(target))
        else:
            print(f"[!] Path not found: {args.target}", file=sys.stderr)
            sys.exit(1)

        grouped = group_findings_by_secret(findings)

        if args.report:
            rep_path = Path(args.report)
            ext = rep_path.suffix.lower()
            if ext == ".json":
                rep_path.write_text(json.dumps({"findings": findings, "grouped": grouped}, indent=2), encoding="utf-8")
            elif ext == ".html":
                rep_path.write_text(generate_html_report(findings, grouped), encoding="utf-8")
            else:
                rep_path.write_text(generate_txt_report(findings, grouped), encoding="utf-8")
            print(f"[+] Saved audit report to: {rep_path.resolve()}")

        if args.json:
            print(json.dumps({"findings": findings, "grouped": grouped}, indent=2))
        elif not args.report:
            print_cli_report(findings, grouped)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CredWatch CLI
Evidence-based credential & secret leak auditing, multi-format export,
ZIP bomb/traversal defense, and interactive web GUI launcher.

Usage:
    python cli.py scan ./path/to/folder
    python cli.py scan my_repo.zip --report audit.html
    python cli.py scan config.env --json
    python cli.py scan ./src --exclude-placeholders
    python cli.py gui
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from detector import (
    Finding,
    ScanReport,
    create_scan_report,
    scan_single_file,
    scan_directory_tree,
    scan_zip_archive,
    group_findings,
    SUPPORTED_EXTENSIONS,
)


def print_cli_summary(report: ScanReport):
    """Print clean, structured terminal audit report."""
    print("\n" + "=" * 78)
    print(" CREDWATCH - CREDENTIAL & SECRET AUDIT REPORT")
    print("=" * 78)
    print(f" Total Findings         : {report.total_findings}")
    print(f" Unique Secrets         : {report.unique_secrets}")
    print(f" Exposure Occurrences   : {report.exposure_occurrences}")
    print(f" Duplicates Removed     : {report.duplicates_removed}")
    print(f" Placeholders Identified: {report.placeholder_count}")
    print(f" Files Scanned / Skipped: {len(report.files_scanned)} / {len(report.files_skipped)}")
    print(f" Scan Duration          : {report.scan_duration_seconds:.3f}s")
    print("-" * 78)
    print(" Severity Distribution:")
    for sev, count in report.findings_by_severity.items():
        if count > 0:
            print(f"   [{sev:<13}] : {count}")
    print("-" * 78)

    if not report.grouped:
        print("\n [OK] No credentials or secrets detected.\n")
        return

    for idx, g in enumerate(report.grouped, start=1):
        sev_tag = g["severity"].upper()
        conf_tag = g["confidence"].upper()
        print(f"\n[{idx}] [{sev_tag}] {g['rule_title']} ({g['category']})")
        print(f"    Rule ID         : {g['rule_id']}")
        print(f"    Confidence      : [{conf_tag}] {g['confidence_reason']}")
        print(f"    Status          : {g['placeholder_status']}")
        print(f"    Evidence        : {g['evidence']}")
        print(f"    Masked Secret   : {g['masked_secret']}  (Entropy: {g['entropy']})")
        print(f"    Remediation     : {g['remediation']}")
        print(f"    Exposures ({len(g['occurrences'])} location(s)):")
        for occ in g["occurrences"]:
            print(f"      - {occ['file_path']}:{occ['line']} [{occ['context_type']}]")
            print(f"        Snippet: {occ['snippet']}")

    if report.files_skipped:
        print("\n" + "-" * 78)
        print(" Skipped or Excluded Items:")
        for sk in report.files_skipped:
            print(f"   - {sk['file']}: {sk['reason']}")

    print("\n" + "=" * 78 + "\n")


def main():
    parser = argparse.ArgumentParser(
        prog="credential-detector",
        description="Enterprise-grade secret & credential leak detection engine.",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan files, directories, or zip archives")
    p_scan.add_argument("target", help="File, folder, or .zip archive to scan")
    p_scan.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_scan.add_argument("--report", help="Save report to file (.txt, .json, or .html)")
    p_scan.add_argument("--exclude-placeholders", action="store_true", help="Exclude test/placeholder values from report")

    # gui
    sub.add_parser("gui", help="Launch interactive local web GUI")

    args = parser.parse_args()

    if not args.command or args.command == "gui":
        import app
        app.main()
        return

    if args.command == "scan":
        target = Path(args.target)
        start_time = time.time()

        if not target.exists() and not str(args.target).endswith(".zip"):
            print(f"[!] Target path not found: {args.target}", file=sys.stderr)
            sys.exit(1)

        findings = []
        scanned_files = []
        skipped_files = []

        if target.is_file():
            if target.suffix.lower() == ".zip":
                try:
                    with open(target, "rb") as f:
                        findings, scanned_files, skipped_files = scan_zip_archive(f.read(), archive_name=target.name)
                except Exception as e:
                    print(f"[!] Unable to read ZIP archive: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                findings, scanned_files, skipped_files = scan_single_file(str(target))
        elif target.is_dir():
            findings, scanned_files, skipped_files = scan_directory_tree(str(target))
        else:
            print(f"[!] Path not supported: {args.target}", file=sys.stderr)
            sys.exit(1)

        duration = time.time() - start_time

        # Filter placeholders if requested
        if getattr(args, "exclude_placeholders", False):
            findings = [f for f in findings if not f.is_placeholder]

        report = create_scan_report(
            findings=findings,
            scanned_files=scanned_files,
            skipped_files=skipped_files,
            duration=duration,
        )

        if args.report:
            rep_path = Path(args.report)
            ext = rep_path.suffix.lower()
            if ext == ".json":
                rep_path.write_text(report.to_json(), encoding="utf-8")
            elif ext == ".html":
                rep_path.write_text(report.to_html(), encoding="utf-8")
            else:
                rep_path.write_text(report.to_txt(), encoding="utf-8")
            print(f"[+] Saved audit report to: {rep_path.resolve()}")

        if args.json:
            print(report.to_json())
        elif not args.report:
            print_cli_summary(report)


if __name__ == "__main__":
    main()

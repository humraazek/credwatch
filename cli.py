#!/usr/bin/env python3
"""
Credential Detector CLI
Scan files, folders, git history, or launch the interactive Web GUI.

Usage:
    python cli.py scan ./path/to/folder
    python cli.py scan config.env
    python cli.py gui
"""

import argparse
import json
import os
import sys
from pathlib import Path

from detector import scan_text, redact

DEFAULT_EXTENSIONS = {
    ".txt", ".md", ".log", ".json", ".jsonl", ".yaml", ".yml",
    ".env", ".cfg", ".conf", ".config", ".ini", ".toml",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".sh", ".bash", ".zsh", ".bat", ".ps1", ".cmd",
    ".xml", ".html", ".sql", ".properties",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next",
}


def scan_file(filepath: str) -> list:
    p = Path(filepath)
    if not p.is_file():
        return []
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return scan_text(content, source_name=str(p))
    except Exception:
        return []


def scan_directory(dirpath: str, extensions: set = None) -> list:
    findings = []
    root = Path(dirpath)
    if not root.is_dir():
        return findings

    for item in sorted(root.rglob("*")):
        if any(skip in item.parts for skip in SKIP_DIRS):
            continue
        if item.is_file():
            if extensions and item.suffix.lower() not in extensions and item.name != ".env":
                continue
            findings.extend(scan_file(str(item)))
    return findings


def print_cli_report(findings: list):
    if not findings:
        print("\n[OK] No leaked credentials or secrets detected.\n")
        return

    crit = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    med = sum(1 for f in findings if f["severity"] == "Medium")

    print("\n" + "=" * 70)
    print(f" SCAN RESULTS: {len(findings)} Potential Leaks Detected")
    print("=" * 70)
    print(f" Critical: {crit}  |  High: {high}  |  Medium: {med}")
    print("=" * 70)

    for f in findings:
        sev = f["severity"].upper()
        print(f"\n [{sev}] {f['label']} ({f['category']})")
        print(f"   Location : {f['source']}:{f['line']}")
        print(f"   Secret   : {f['redacted_secret']}  (Entropy: {f['entropy']})")
        print(f"   Snippet  : {f['snippet']}")

    print("\n" + "=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        prog="credential-detector",
        description="Inspect and detect leaked credentials, API keys, and passwords.",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan files or directories")
    p_scan.add_argument("target", help="File or folder path to scan")
    p_scan.add_argument("--json", action="store_true", help="Output results in JSON format")

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
            findings = scan_directory(str(target), extensions=DEFAULT_EXTENSIONS)
        else:
            print(f"[!] Path not found: {args.target}", file=sys.stderr)
            sys.exit(1)

        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            print_cli_report(findings)


if __name__ == "__main__":
    main()

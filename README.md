# 🛡️ Credential & Secret Leak Detector (v2.0)

An evidence-based, zero-dependency secret scanner and **interactive Web GUI** designed to prevent alert fatigue through **separated severity & confidence**, **context-aware file analysis**, and **cross-file deduplication**.

---

## 🎯 What's New in v2.0

### 1. Evidence-Based Severity (Blast Radius)
Labels reflect real-world privilege impact rather than generic warnings:
- 🔴 **Critical**: High-privilege infrastructure root credentials, live database URIs with passwords, cloud service account private keys (`AWS`, `GCP`, `Azure`), live Stripe keys.
- 🟠 **High**: Likely sensitive production credentials exposed in code or config (named app passwords, SMTP/database passwords, OAuth tokens, GitHub/GitLab PATs).
- 🟡 **Medium**: Suspicious secret-like values requiring review (unassigned high-entropy secrets, JWTs, ambiguous tokens).
- 🟢 **Low / Informational**: Test-environment secrets (e.g. `sk_test_*`), sandbox tokens, or secrets found in test/documentation files.

### 2. Separated Detection Confidence (Certainty)
Confidence is tracked independently from severity:
- **High**: Strict cryptographic/provider prefix match (`AKIA...`, `ghp_...`) + verified Shannon entropy.
- **Medium**: Known pattern with typical entropy or variable assignment.
- **Low**: Match located in documentation, mock fixtures, or marginal entropy.

### 3. Context & File Classification
Automatically detects where the secret lives and adjusts scoring:
- ⚙️ **Configuration**: `.env`, `.yaml`, `.json`, `.toml`, `.ini`, `.properties`, `.tf`, `Dockerfile`
- 💻 **Source Code**: `.py`, `.js`, `.ts`, `.go`, `.java`, `.sh`, `.sql`, etc.
- 💬 **Log / Conversation**: `.log`, `.txt`, `.jsonl`, chat transcripts
- 📚 **Documentation / Test**: `README.md`, `tests/`, `spec/`, `fixtures/` (automatically downgraded to prevent alert fatigue)

### 4. Cross-File Deduplication
When the same credential is repeated across multiple files (e.g. copied from `.env` into a test file and a log), the engine groups them by SHA-256 fingerprint, reporting occurrences together rather than triggering separate alerts.

### 5. In-Memory .ZIP Archive Scanning
Drop full zip archives of repositories, Slack exports, or backups. Unpacks and inspects all files completely in-memory with zero disk footprint.

---

## 🚀 Quick Start

### 1. Interactive Web GUI
```bash
python app.py
```
*Opens automatically at `http://127.0.0.1:5050` with drag-and-drop file upload, duplicate grouping toggle, and export buttons.*

### 2. Command-Line Interface (CLI)
```bash
# Scan a file or directory
python cli.py scan ./my-project

# Scan a zip archive
python cli.py scan repo_export.zip

# Generate an HTML or TXT audit report
python cli.py scan ./my-project --report audit.html
python cli.py scan ./my-project --report audit.txt

# Export raw JSON for CI/CD pipelines
python cli.py scan ./my-project --json
```

---

## 🧪 Run Automated Tests

```bash
python -m unittest discover -s tests -v
```
*(All 12 positive, negative, severity vs. confidence, and zip tests run in milliseconds using in-memory safe fixtures).*

---

## 📁 Repository Structure

```text
credential-detector/
├── app.py              # Interactive Web GUI v2.0 (Local server + Dashboard)
├── cli.py              # CLI runner with deduplication & HTML/TXT/JSON reports
├── detector.py         # Detection engine (Patterns, Entropy, Context, Deduplication)
├── tests/
│   ├── __init__.py
│   └── test_detector.py# Positive, negative, context & severity unit tests
└── README.md
```

## 📜 License

MIT License. Free for personal, educational, and commercial use.

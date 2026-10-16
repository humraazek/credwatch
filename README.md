# 🛡️ CredWatch

> **Zero-dependency, high-precision secret scanner and local GUI for developers and security teams.**  
> Detect exposed API keys, database passwords, tokens, and private keys across source code, logs, `.env` files, and ZIP archives—with zero false positives on normal code variables.

---

## 🛑 What Problem Does CredWatch Solve?

1. **Accidental Credential Exposure**: Developers frequently commit `.env` files, paste sensitive tokens into logs, or leave hardcoded database passwords in repositories. Once pushed, bots scrape and exploit them in seconds.
2. **Alert Fatigue from Traditional Scanners**: Many scanners blindly flag any line containing `"key"`, `"token"`, or `"password"`. They trigger hundreds of false alarms on benign code variables (`cacheKey`, `oldestKey`), environment reads (`process.env.AUTH_TOKEN`), and function arguments (`password: str`).
3. **Heavy, Complicated Tooling**: Existing tools often require complex Docker setups, Node.js runtimes, or external cloud subscriptions.
4. **Broken Severity Scoring**: Labeling a harmless unit test string (`password = "test123"`) as "CRITICAL" desensitizes engineers. CredWatch separates **Severity** (potential blast radius) from **Confidence** (pattern certainty) using evidence-based scoring.

---

## 💡 What Makes CredWatch Different?

- **⚡ Zero External Dependencies**: Runs entirely on the Python Standard Library (`json`, `re`, `ast`, `zipfile`, `http.server`). No `pip install` required.
- **🎯 Precision Filtering**: Distinguishes between literal hardcoded credentials and safe programming syntax (environment variable reads, method calls, property accesses, and TypeScript/Python type annotations).
- **🖥️ Minimalist Web GUI + Powerful CLI**: Includes both an interactive, dark-mode browser interface (with drag-and-drop and one-click masking reveal) and a scriptable CLI for CI/CD pipelines.
- **🛡️ Built-in Anti-DoS Protection**: Safely handles zip archives with decompression bomb protection (100x ratio cap, 50 MB uncompressed limit), path traversal defense (`../`), and ReDoS line-length guards.
- **🔒 100% Local & Private**: All scanning and archive parsing happen in local RAM. Zero telemetry, zero cloud calls, zero data retention.

---

## 🚀 Quick Start (Under 10 Seconds)

### Option A: Launch the Web GUI (Interactive)
```bash
python app.py
```
Open [http://127.0.0.1:5050](http://127.0.0.1:5050) in your browser. Drag and drop any repository `.zip` archive or paste text to scan instantly.

### Option B: Use the Command-Line Interface (CLI)
```bash
# Scan any directory or repository
python cli.py scan ./my-project

# Scan a single file or ZIP archive
python cli.py scan config.env
python cli.py scan repo_bundle.zip

# Export structured JSON for CI/CD pipelines
python cli.py scan ./src --json

# Generate a formatted audit report (HTML or TXT)
python cli.py scan ./my-project --report audit.html
python cli.py scan ./my-project --report audit.txt

# Exclude test/mock placeholders to view only live leaks
python cli.py scan ./my-project --exclude-placeholders
```

---

## 📂 Supported File Types

CredWatch supports deep inspection across configuration files, source code, archives, and unstructured logs:

| Category | Supported Formats |
| :--- | :--- |
| **Configurations** | `.env`, `.env.*`, `.yaml`, `.yml`, `.json`, `.toml`, `.ini`, `.cfg`, `.conf`, `.properties`, `.tf`, `.hcl`, `Dockerfile` |
| **Source Code** | `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.java`, `.go`, `.rb`, `.php`, `.sh`, `.bash`, `.sql`, `.cs`, `.cpp`, `.c` |
| **Logs & Text** | `.log`, `.txt`, `.jsonl`, terminal exports, conversational chat logs |
| **Documentation** | `.md`, `.rst`, `.adoc` |
| **Archives** | `.zip` archives (decompressed and scanned in-memory safely) |

---

## 🔍 Detected Credential Types

CredWatch scans for verified pattern formats, entropy, and assignment context:

- **Cloud Infrastructure**: AWS Access Key IDs (`AKIA...`), AWS Secret Access Keys.
- **Database Connection URIs**: `postgresql://`, `mysql://`, `mongodb://`, `redis://`, `mssql://` (with safe password redaction).
- **Payment & Financial**: Stripe Live Keys (`sk_live_...`), Stripe Test Keys (`sk_test_...`).
- **Platform & Git Tokens**: GitHub Personal Access Tokens (`ghp_...`).
- **Authentication & Cryptography**: JWT Signing Secrets, OpenAI API Keys (`sk-proj-...`), Private Keys (`BEGIN RSA PRIVATE KEY`), Application Symmetric Encryption Keys.
- **Service Credentials**: SMTP email passwords, Redis passwords, Service Account keys, and high-entropy password assignments.

---

## ⚖️ Evidence-Based Severity vs. Confidence

CredWatch separates **Severity** (impact if compromised) from **Confidence** (certainty of match):

### Severity (Blast Radius)
- **Critical**: Live infrastructure credentials (AWS production keys, production database URIs with passwords).
- **High**: Source code or configuration exposure of sensitive API keys, JWT signing secrets, or private tokens.
- **Medium**: High-entropy secret assignments in generic logs or documentation.
- **Low / Informational**: Sandbox tokens (Stripe `sk_test_*`), unit test credentials, or explicit mock values (`FAKE_`, `example`, `change_me`).

### Confidence (Pattern Evidence)
- **High**: Exact provider format + verified Shannon character entropy.
- **Medium**: Sensitive field name assignment with structured string.
- **Low**: Ambiguous context or detected within test/mock directories.

---

## 🔒 Security & Privacy Guarantees

1. **Safe Redaction by Default**: Raw cleartext secrets are **never** written to reports, terminal logs, or finding fingerprints. Fingerprints use one-way SHA-256 hashes (`secret_hash`).
2. **Local Loopback Only**: The web server binds strictly to `127.0.0.1:5050`, never exposing the port to external networks or `0.0.0.0`.
3. **No External Network Requests**: The tool makes zero outbound network calls.
4. **Decompression & Traversal Guards**: Malicious `.zip` files containing path traversal sequences (`../`) or zip bombs (compression ratio > 100x or > 50 MB) are automatically rejected.

---

## 🧪 Automated Testing

CredWatch includes an exhaustive test suite covering positive detections, negative false-positive regressions, AST parsers, safety limits, and archive scanning:

```bash
python -m unittest discover -s tests -v
```

```text
Ran 32 tests in 0.020s

OK
```

---

## 📜 License

MIT License. Free for personal, open-source, and commercial security auditing.

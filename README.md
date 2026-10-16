# 🛡️ Credential & Secret Leak Detector

An offline, zero-dependency tool and **interactive Web GUI** to detect accidentally leaked passwords, API keys, and credentials in **AI conversation logs, source code, config files, and environment files**.

---

## ✨ Features

- 🖥️ **Interactive Web GUI** — Drag & drop files or paste text with instant visual findings.
- 👁️ **Mask / Unmask Toggle** — Inspect what was caught safely on your own local screen.
- 🧪 **Built-in Test Presets** — Test AI chat leaks and config files with 1 click.
- 🧮 **Shannon Entropy Scoring** — Distinguishes real high-entropy passwords from plain English.
- 🚫 **False-Positive Suppression** — Automatically ignores placeholders like `your_password_here`, `<api_key>`, etc.
- 🔒 **100% Offline & Private** — Runs entirely on your local machine (`127.0.0.1`). Zero external network calls.
- ⚡ **Zero Dependencies** — Built with 100% Python standard library.

---

## 🚀 Quick Start

### 1. Launch the Interactive Web GUI
```bash
python app.py
```
*Your browser will automatically open to `http://127.0.0.1:5050`.*

### 2. Or use the Command-Line Interface (CLI)
```bash
# Scan a specific file
python cli.py scan ./ai_chat_log.json

# Scan an entire directory
python cli.py scan ./my-project

# Output results as JSON for automation / CI
python cli.py scan ./my-project --json
```

---

## 🔍 What It Detects

| Category | Examples |
|---|---|
| **Mail & Account Passwords** | Gmail / Google account passwords, Yahoo, Outlook, iCloud |
| **App & Service Passwords** | Instagram, Facebook, SSH, WiFi passwords, VPN, Redis, MySQL |
| **Email:Password Combos** | `user@company.com:SuperSecretPass!` |
| **Natural Language Leaks** | "my password is ...", "the password is ...", "login credentials: ..." |
| **Database URIs** | PostgreSQL, MySQL, MongoDB, Redis connection strings with credentials |
| **Cloud Provider Keys** | AWS Access Keys (`AKIA...`), GCP private keys, Azure connection strings |
| **Platform & AI Tokens** | GitHub PATs, GitLab PATs, OpenAI (`sk-...`), Anthropic, Stripe, Slack, SendGrid |
| **Private Keys & Auth** | RSA private keys, PGP blocks, JWT tokens |

---

## 🧪 Run Unit Tests

```bash
python -m unittest discover -s tests -v
```

---

## 📁 Repository Structure

```text
credential-detector/
├── app.py              # Web GUI application (Local server + Dashboard)
├── cli.py              # Command-line interface
├── detector.py         # Detection engine (Patterns, Entropy, Redaction)
├── tests/
│   └── test_detector.py# Automated unit tests (in-memory fixtures)
└── README.md
```

## 📜 License

MIT License. Free for personal, educational, and commercial use.

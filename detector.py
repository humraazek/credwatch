"""
Credential & Secret Leak Detector Engine
Core detection engine with regex patterns, Shannon entropy calculation,
and placeholder suppression to reduce false positives.
"""

import math
import re
from typing import List, Dict, Any

# Common placeholder substrings that indicate non-real secrets
PLACEHOLDER_WORDS = {
    "placeholder", "example", "changeme", "change_me", "change-me",
    "your_password", "yourpassword", "your-password", "<password>",
    "todo", "fixme", "xxxx", "dummy", "sample", "<api_key>", "<token>",
    "your_key", "your_token", "insert_here", "replace_me", "fill_me"
}


def calc_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder(val: str) -> bool:
    """Check if the string is an obvious placeholder or documentation value."""
    cleaned = val.strip().lower()
    for word in PLACEHOLDER_WORDS:
        if word in cleaned:
            return True
    return False


def redact(value: str, show_chars: int = 4) -> str:
    """Mask a secret value for safe reporting."""
    if len(value) <= show_chars + 2:
        return "*" * len(value)
    masked_len = min(16, len(value) - show_chars)
    return value[:show_chars] + ("*" * masked_len)


# -------------------------------------------------------------------
# Pattern Definitions
# -------------------------------------------------------------------
PATTERNS = [
    # Cloud Provider Keys
    {
        "id": "aws-access-key",
        "label": "AWS Access Key ID",
        "category": "Cloud Credentials",
        "regex": re.compile(r"(?:^|[^A-Z0-9])(?P<secret>AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"),
        "severity": "Critical",
        "min_entropy": 2.5,
    },
    {
        "id": "aws-secret-key",
        "label": "AWS Secret Access Key",
        "category": "Cloud Credentials",
        "regex": re.compile(r"(?:aws_secret_access_key|secret.?key)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE),
        "severity": "Critical",
        "min_entropy": 3.0,
    },
    {
        "id": "gcp-service-account",
        "label": "GCP Service Account Private Key",
        "category": "Cloud Credentials",
        "regex": re.compile(r'"private_key"\s*:\s*"(?P<secret>-----BEGIN (?:RSA )?PRIVATE KEY-----[^"]+)"'),
        "severity": "Critical",
        "min_entropy": 0.0,
    },
    {
        "id": "azure-connection-string",
        "label": "Azure Connection String",
        "category": "Cloud Credentials",
        "regex": re.compile(r"(?:AccountKey|SharedAccessKey)\s*=\s*(?P<secret>[A-Za-z0-9+/=]{30,})", re.IGNORECASE),
        "severity": "Critical",
        "min_entropy": 3.0,
    },

    # Developer & Platform Tokens
    {
        "id": "github-pat-classic",
        "label": "GitHub Personal Access Token (Classic)",
        "category": "Platform Tokens",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>ghp_[A-Za-z0-9]{36,})"),
        "severity": "Critical",
        "min_entropy": 3.0,
    },
    {
        "id": "github-pat-fine",
        "label": "GitHub Fine-Grained Token",
        "category": "Platform Tokens",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>github_pat_[A-Za-z0-9_]{30,})"),
        "severity": "Critical",
        "min_entropy": 3.0,
    },
    {
        "id": "gitlab-pat",
        "label": "GitLab Personal Access Token",
        "category": "Platform Tokens",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>glpat-[A-Za-z0-9\-]{20,})"),
        "severity": "Critical",
        "min_entropy": 2.5,
    },

    # AI & API Services
    {
        "id": "openai-api-key",
        "label": "OpenAI API Key",
        "category": "API Keys",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>sk-(?:proj-)?[A-Za-z0-9_\-]{30,})"),
        "severity": "Critical",
        "min_entropy": 3.0,
    },
    {
        "id": "anthropic-api-key",
        "label": "Anthropic API Key",
        "category": "API Keys",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>sk-ant-[A-Za-z0-9_\-]{30,})"),
        "severity": "Critical",
        "min_entropy": 3.0,
    },
    {
        "id": "stripe-api-key",
        "label": "Stripe API Key",
        "category": "API Keys",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})"),
        "severity": "Critical",
        "min_entropy": 2.8,
    },
    {
        "id": "slack-bot-token",
        "label": "Slack Bot Token",
        "category": "API Keys",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,})"),
        "severity": "Critical",
        "min_entropy": 2.8,
    },
    {
        "id": "sendgrid-api-key",
        "label": "SendGrid API Key",
        "category": "API Keys",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
        "severity": "Critical",
        "min_entropy": 2.8,
    },
    {
        "id": "google-api-key",
        "label": "Google API Key",
        "category": "API Keys",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>AIza[0-9A-Za-z\-_]{35})"),
        "severity": "High",
        "min_entropy": 3.0,
    },

    # Database Connections with Credentials
    {
        "id": "db-connection-string",
        "label": "Database URI with Credentials",
        "category": "Database Credentials",
        "regex": re.compile(
            r"(?P<secret>(?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|mssql|sqlserver)"
            r"://[^\s:]+:[^\s@]+@[^\s]+)",
            re.IGNORECASE,
        ),
        "severity": "Critical",
        "min_entropy": 0.0,
    },

    # Private Keys & Certificates
    {
        "id": "private-key-rsa",
        "label": "Private Key Header (RSA/EC/SSH)",
        "category": "Cryptographic Keys",
        "regex": re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        "severity": "Critical",
        "min_entropy": 0.0,
    },

    # Gmail & Google Passwords
    {
        "id": "gmail-password",
        "label": "Gmail / Google Account Password",
        "category": "Account Passwords",
        "regex": re.compile(
            r"(?:gmail|google)\s*(?:account\s+)?(?:password|pass|pwd)\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{4,})['\"]?",
            re.IGNORECASE,
        ),
        "severity": "Critical",
        "min_entropy": 1.5,
    },

    # Named Services / App Passwords
    {
        "id": "app-password",
        "label": "Application / Service Password",
        "category": "Account Passwords",
        "regex": re.compile(
            r"(?:facebook|instagram|twitter|linkedin|github|gitlab|bitbucket|azure|aws|"
            r"netflix|spotify|apple|icloud|outlook|hotmail|yahoo|discord|telegram|whatsapp|"
            r"slack|zoom|dropbox|paypal|stripe|twilio|heroku|vercel|netlify|digitalocean|"
            r"reddit|snapchat|tiktok|pinterest|wordpress|cpanel|phpmyadmin|"
            r"mysql|postgres|mongodb|redis|ssh|ftp|vpn|wifi|router)"
            r"\s*(?:password|pass|pwd|account\s*password|login)\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{4,})['\"]?",
            re.IGNORECASE,
        ),
        "severity": "Critical",
        "min_entropy": 1.5,
    },

    # Email + Password combo
    {
        "id": "email-password-combo",
        "label": "Email + Password Combination",
        "category": "Account Passwords",
        "regex": re.compile(
            r"(?P<secret>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
            r"\s*[/:|]\s*"
            r"(?P<password>[^\s]{4,})",
            re.IGNORECASE,
        ),
        "severity": "Critical",
        "min_entropy": 1.5,
    },

    # Natural Language Password ("my password is ...")
    {
        "id": "password-natural-language",
        "label": "Password in Natural Language",
        "category": "Chat & Conversation Leaks",
        "regex": re.compile(
            r"(?:my\s+password\s+is|password\s+is|the\s+password\s*[=:]\s*|"
            r"my\s+pass(?:word)?\s*[=:]\s*|"
            r"login\s+(?:with|using)\s+password\s*[=:]\s*|"
            r"credentials?\s*(?:are|is)\s*[=:]?\s*\S+\s*/\s*)"
            r"\s*['\"]?(?P<secret>[^\s'\"]{4,})['\"]?",
            re.IGNORECASE,
        ),
        "severity": "Critical",
        "min_entropy": 1.5,
    },

    # Config / Code Password Assignment
    {
        "id": "password-assignment",
        "label": "Hardcoded Password in Config/Code",
        "category": "Code & Config Secrets",
        "regex": re.compile(
            r"(?:password|passwd|pwd|db_pass|db_password|mysql_pwd|smtp_password|"
            r"email_password|admin_password|root_password|secret_key|master_key)"
            r"\s*[=:]\s*['\"](?P<secret>[^'\"]{4,})['\"]",
            re.IGNORECASE,
        ),
        "severity": "Critical",
        "min_entropy": 1.8,
    },
    {
        "id": "env-unquoted-secret",
        "label": "Unquoted Secret in Environment Variable",
        "category": "Code & Config Secrets",
        "regex": re.compile(
            r"(?:PASSWORD|PASSWD|SECRET_KEY|AUTH_TOKEN|PRIVATE_KEY)\s*=\s*(?P<secret>[^\s#'\"]{6,})",
        ),
        "severity": "High",
        "min_entropy": 2.0,
    },
    {
        "id": "jwt-token",
        "label": "JSON Web Token (JWT)",
        "category": "Auth Tokens",
        "regex": re.compile(r"(?:^|[^A-Za-z0-9._])(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,})"),
        "severity": "Medium",
        "min_entropy": 3.0,
    },
]


def scan_text(content: str, source_name: str = "Input") -> List[Dict[str, Any]]:
    """Scan string content and return a list of findings."""
    findings = []
    lines = content.splitlines()

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or len(line) > 5000:
            continue

        for pattern in PATTERNS:
            match = pattern["regex"].search(raw_line)
            if not match:
                continue

            secret_val = match.group("secret") if "secret" in match.groupdict() else match.group(0)
            secret_val = secret_val.strip()

            # 1. Ignore very short strings
            if len(secret_val) < 4:
                continue

            # 2. Ignore obvious placeholders
            if is_placeholder(secret_val):
                continue

            # 3. Check Shannon Entropy against pattern threshold
            entropy = calc_entropy(secret_val)
            min_entropy = pattern.get("min_entropy", 0.0)
            if entropy < min_entropy:
                continue

            findings.append({
                "source": source_name,
                "line": line_idx,
                "pattern_id": pattern["id"],
                "label": pattern["label"],
                "category": pattern["category"],
                "severity": pattern["severity"],
                "raw_secret": secret_val,
                "redacted_secret": redact(secret_val),
                "entropy": round(entropy, 2),
                "snippet": raw_line.strip()[:140],
            })

    return dedup_findings(findings)


import io
import zipfile

TEXT_EXTENSIONS = {
    ".txt", ".md", ".log", ".json", ".jsonl", ".yaml", ".yml",
    ".env", ".cfg", ".conf", ".config", ".ini", ".toml",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".sh", ".bash", ".zsh", ".bat", ".ps1", ".cmd",
    ".xml", ".html", ".sql", ".properties",
}


def scan_zip_bytes(zip_bytes: bytes, zip_name: str = "archive.zip") -> List[Dict[str, Any]]:
    """Scan all files inside a zip archive in-memory."""
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size > 10 * 1024 * 1024:
                    continue
                filename = info.filename
                ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                base_name = filename.rsplit("/", 1)[-1]
                if ext not in TEXT_EXTENSIONS and not base_name.startswith(".env") and base_name not in ("Dockerfile", "Makefile"):
                    continue
                try:
                    with z.open(info) as f:
                        content = f.read().decode("utf-8", errors="ignore")
                        file_findings = scan_text(content, source_name=f"{zip_name} > {filename}")
                        findings.extend(file_findings)
                except Exception:
                    continue
    except Exception as e:
        return []
    return dedup_findings(findings)


def dedup_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings based on line, source, and pattern."""
    seen = set()
    unique = []
    for f in findings:
        key = (f["source"], f["line"], f["pattern_id"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

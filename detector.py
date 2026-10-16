"""
Credential & Secret Leak Detector Engine (v2.0)
Evidence-Based Detection, Context-Aware Classification,
Separated Severity & Confidence, and Cross-File Deduplication.
"""

import hashlib
import io
import math
import os
import re
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Supported file extensions for scanning
SUPPORTED_EXTENSIONS = {
    # Configurations
    ".env", ".cfg", ".conf", ".config", ".ini", ".toml", ".properties",
    ".yaml", ".yml", ".json", ".xml", ".tf", ".hcl",
    # Source Code
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".sh", ".bash", ".zsh", ".bat", ".ps1", ".cmd", ".c", ".cpp", ".cs",
    ".rs", ".swift", ".kt", ".sql",
    # Logs & Chat Transcripts
    ".log", ".txt", ".jsonl",
    # Documentation
    ".md", ".rst", ".adoc",
}

# Special filenames without extensions
SPECIAL_FILENAMES = {
    "dockerfile", "makefile", "gemfile", "procfile", "vagrantfile",
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.test", ".env.staging", ".bashrc", ".zshrc"
}

# Directories to skip safely
EXCLUDED_DIRS = {
    "node_modules", ".git", ".svn", ".hg", "__pycache__",
    ".venv", "venv", "env", ".tox", "dist", "build", ".next",
    ".nuxt", ".output", "target", "vendor", ".idea", ".vscode"
}

# Substrings that strongly signal non-real placeholder values
PLACEHOLDER_SUBSTRINGS = [
    "placeholder", "example", "changeme", "change_me", "change-me",
    "your_password", "yourpassword", "your-password", "<password>",
    "todo", "fixme", "xxxx", "dummy", "sample", "<api_key>", "<token>",
    "your_key", "your_token", "insert_here", "replace_me", "fill_me",
    "fake", "test_key", "test_token", "not_real", "mock_key"
]

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per file cap
MAX_LINE_LENGTH = 5000


def calc_entropy(text: str) -> float:
    """Calculate the Shannon entropy (randomness) of a string."""
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
    """Check if the secret value matches common mock/placeholder patterns."""
    cleaned = val.strip().lower()
    for word in PLACEHOLDER_SUBSTRINGS:
        if word in cleaned:
            return True
    return False


def redact(value: str, show_chars: int = 4) -> str:
    """Mask a secret value for safe reporting."""
    if len(value) <= show_chars + 2:
        return "*" * len(value)
    masked_len = min(16, len(value) - show_chars)
    return value[:show_chars] + ("*" * masked_len)


def classify_context(filepath: str) -> str:
    """
    Classify the file into one of four context types:
    - Configuration (.env, yaml, toml, config)
    - Source Code (.py, .js, .go, etc.)
    - Log / Conversation (.log, transcripts)
    - Documentation / Test (README, tests/, mock/)
    """
    path_lower = filepath.replace("\\", "/").lower()
    parts = path_lower.split("/")
    filename = parts[-1]

    # Check if in a test or documentation folder
    if any(p in ("tests", "test", "__tests__", "spec", "mocks", "fixtures", "docs", "doc") for p in parts[:-1]):
        return "Documentation / Test"
    if filename.startswith("test_") or filename.endswith("_test.py") or filename.endswith(".spec.ts"):
        return "Documentation / Test"
    if filename.endswith(".md") or filename.endswith(".rst") or filename.endswith(".txt"):
        return "Documentation / Test" if "doc" in path_lower or "read" in filename else "Log / Conversation"

    ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

    if ext in (".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".xml", ".tf") or filename in SPECIAL_FILENAMES:
        return "Configuration"

    if ext in (".log", ".jsonl"):
        return "Log / Conversation"

    if ext in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sh", ".bash", ".c", ".cpp", ".cs", ".sql"):
        return "Source Code"

    return "Configuration" if "config" in path_lower else "Source Code"


# -------------------------------------------------------------------
# Pattern Definitions with Strict Base Severity and Impact Evidence
# -------------------------------------------------------------------
PATTERNS = [
    # 1. Cloud Provider Secrets (Critical Impact)
    {
        "id": "aws-access-key",
        "label": "AWS Access Key ID",
        "category": "Cloud Credentials",
        "severity": "Critical",
        "regex": re.compile(r"(?:^|[^A-Z0-9])(?P<secret>AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"),
        "min_entropy": 2.5,
        "evidence": "Exposes AWS account identity capable of querying CloudTrail, IAM, and cloud resources.",
    },
    {
        "id": "aws-secret-key",
        "label": "AWS Secret Access Key",
        "category": "Cloud Credentials",
        "severity": "Critical",
        "regex": re.compile(r"(?:aws_secret_access_key|secret.?key)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE),
        "min_entropy": 3.2,
        "evidence": "Paired with Access Key, grants full cryptographic signing of AWS STS and API calls.",
    },
    {
        "id": "gcp-service-account",
        "label": "GCP Service Account Private Key",
        "category": "Cloud Credentials",
        "severity": "Critical",
        "regex": re.compile(r'"private_key"\s*:\s*"(?P<secret>-----BEGIN (?:RSA )?PRIVATE KEY-----[^"]+)"'),
        "min_entropy": 0.0,
        "evidence": "High-privilege private key for Google Cloud IAM service account authentication.",
    },
    {
        "id": "azure-connection-string",
        "label": "Azure Storage / Service Connection String",
        "category": "Cloud Credentials",
        "severity": "Critical",
        "regex": re.compile(r"(?:AccountKey|SharedAccessKey)\s*=\s*(?P<secret>[A-Za-z0-9+/=]{30,})", re.IGNORECASE),
        "min_entropy": 3.0,
        "evidence": "Master access key providing read/write control over Azure cloud storage accounts.",
    },

    # 2. Database URIs with Embedded Credentials (Critical Impact)
    {
        "id": "db-connection-string",
        "label": "Database URI with Embedded Password",
        "category": "Database Credentials",
        "severity": "Critical",
        "regex": re.compile(
            r"(?P<secret>(?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|mssql|sqlserver)"
            r"://(?P<user>[^\s:]+):(?P<password>[^\s@]+)@(?P<host>[^\s/]+)[^\s]*)",
            re.IGNORECASE,
        ),
        "min_entropy": 0.0,
        "evidence": "Direct database connection URL with cleartext username and password.",
    },

    # 3. Cryptographic Private Keys (Critical Impact)
    {
        "id": "private-key-header",
        "label": "Private Key Header (RSA / EC / OpenSSH / PGP)",
        "category": "Cryptographic Keys",
        "severity": "Critical",
        "regex": re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----)"),
        "min_entropy": 0.0,
        "evidence": "Asymmetric private key used for TLS termination, SSH authentication, or signing.",
    },

    # 4. Source Control & Deployment Tokens (High Severity)
    {
        "id": "github-pat",
        "label": "GitHub Personal Access Token",
        "category": "Platform Tokens",
        "severity": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{30,}|gho_[A-Za-z0-9]{36,}))"),
        "min_entropy": 3.0,
        "evidence": "GitHub API token granting repository read/write access and git commit capabilities.",
    },
    {
        "id": "gitlab-pat",
        "label": "GitLab Access Token",
        "category": "Platform Tokens",
        "severity": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>glpat-[A-Za-z0-9\-]{20,})"),
        "min_entropy": 2.6,
        "evidence": "GitLab user or deploy token providing API and git repository access.",
    },

    # 5. API Keys (High Severity)
    {
        "id": "openai-api-key",
        "label": "OpenAI API Key",
        "category": "API Keys",
        "severity": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>sk-(?:proj-)?[A-Za-z0-9_\-]{30,})"),
        "min_entropy": 3.0,
        "evidence": "Paid billing API key for OpenAI model inference and account usage.",
    },
    {
        "id": "anthropic-api-key",
        "label": "Anthropic API Key",
        "category": "API Keys",
        "severity": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>sk-ant-[A-Za-z0-9_\-]{30,})"),
        "min_entropy": 3.0,
        "evidence": "Paid billing API key for Anthropic Claude API services.",
    },
    {
        "id": "stripe-live-key",
        "label": "Stripe Live Secret Key",
        "category": "Payment Gateways",
        "severity": "Critical",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,})"),
        "min_entropy": 2.8,
        "evidence": "Production live payment gateway key capable of charging cards and issuing refunds.",
    },
    {
        "id": "stripe-test-key",
        "label": "Stripe Test API Key",
        "category": "Payment Gateways",
        "severity": "Low",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>(?:sk|rk)_test_[A-Za-z0-9]{20,})"),
        "min_entropy": 2.8,
        "evidence": "Sandbox / test environment Stripe key (no live funds affected).",
    },
    {
        "id": "slack-bot-token",
        "label": "Slack Bot Token",
        "category": "Communication APIs",
        "severity": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,})"),
        "min_entropy": 2.8,
        "evidence": "Slack bot integration token capable of reading channel history and posting messages.",
    },
    {
        "id": "sendgrid-api-key",
        "label": "SendGrid API Key",
        "category": "Communication APIs",
        "severity": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
        "min_entropy": 2.8,
        "evidence": "Transactional mail sending key with spam/phishing reputation impact.",
    },
    {
        "id": "google-api-key",
        "label": "Google API / Maps Key",
        "category": "API Keys",
        "severity": "Medium",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>AIza[0-9A-Za-z\-_]{35})"),
        "min_entropy": 3.0,
        "evidence": "Google public client or service key. Scope depends on GCP quota/restrictions.",
    },

    # 6. Mail & Account Passwords (High Severity)
    {
        "id": "gmail-password",
        "label": "Gmail / Google Account Password",
        "category": "Account Passwords",
        "severity": "High",
        "regex": re.compile(
            r"(?:gmail|google)\s*(?:account\s+)?(?:password|pass|pwd)\s*(?:[=:]|\bis\b)\s*['\"]?(?P<secret>[^\s'\"]{4,})['\"]?",
            re.IGNORECASE,
        ),
        "min_entropy": 1.5,
        "evidence": "Cleartext user account password for Google / Gmail services.",
    },
    {
        "id": "app-password",
        "label": "Service Account / Infrastructure Password",
        "category": "Account Passwords",
        "severity": "High",
        "regex": re.compile(
            r"(?:facebook|instagram|twitter|linkedin|github|gitlab|bitbucket|azure|aws|"
            r"netflix|spotify|apple|icloud|outlook|hotmail|yahoo|discord|telegram|whatsapp|"
            r"slack|zoom|dropbox|paypal|twilio|heroku|vercel|netlify|digitalocean|"
            r"reddit|snapchat|tiktok|pinterest|wordpress|cpanel|phpmyadmin|"
            r"mysql|postgres|mongodb|redis|ssh|ftp|vpn|wifi|router)"
            r"\s*(?:password|pass|pwd|account\s*password|login)\s*(?:[=:]|\bis\b)\s*['\"]?(?P<secret>[^\s'\"]{4,})['\"]?",
            re.IGNORECASE,
        ),
        "min_entropy": 1.5,
        "evidence": "Named infrastructure or application login password.",
    },
    {
        "id": "email-password-combo",
        "label": "Email + Password Combo",
        "category": "Account Passwords",
        "severity": "High",
        "regex": re.compile(
            r"(?P<secret>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
            r"\s*[/:|]\s*"
            r"(?P<password>[^\s]{4,})",
            re.IGNORECASE,
        ),
        "min_entropy": 1.5,
        "evidence": "Paired email identity and authentication password.",
    },
    {
        "id": "password-natural-language",
        "label": "Password Shared in Conversation",
        "category": "Conversation Leaks",
        "severity": "High",
        "regex": re.compile(
            r"(?:my\s+password\s+is|password\s+is|the\s+password\s*[=:]\s*|"
            r"my\s+pass(?:word)?\s*[=:]\s*|"
            r"login\s+(?:with|using)\s+password\s*[=:]\s*|"
            r"credentials?\s*(?:are|is)\s*[=:]?\s*\S+\s*/\s*)"
            r"\s*['\"]?(?P<secret>[^\s'\"]{3,})['\"]?",
            re.IGNORECASE,
        ),
        "min_entropy": 1.5,
        "evidence": "Password explicitly stated in user chat prompt or conversation history.",
    },

    # 7. Hardcoded Config Passwords (Medium/High)
    {
        "id": "password-assignment",
        "label": "Hardcoded Password / Key in Code or Config",
        "category": "Code & Config Secrets",
        "severity": "High",
        "regex": re.compile(
            r"(?:database_?password|databasePassword|db_?pass(?:word)?|secret_?key|secretKey|"
            r"api_?token|apiToken|api_?key|apiKey|jwt_?(?:signing_?)?secret|jwtSecret|"
            r"encryption_?key|encryptionKey|admin_?password|adminPassword|smtp_?password|smtpPassword|"
            r"redis_?password|redisPassword|service_?account_?key|serviceAccountKey|"
            r"cloud_?secret|cloudSecret|Database\s+password|Admin\s+password|API\s+key|"
            r"JWT\s+(?:signing\s+)?secret|Encryption\s+key|Cloud\s+secret|password|passwd|pwd)"
            r"\s*[=:]\s*['\"]?(?P<secret>[^\s,'\"#]{4,})['\"]?",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Explicit password or secret key assignment in source code, log, or configuration.",
    },
    {
        "id": "env-unquoted-secret",
        "label": "High-Entropy Secret in Environment Variable",
        "category": "Code & Config Secrets",
        "severity": "Medium",
        "regex": re.compile(
            r"(?:[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|AUTH)[A-Za-z0-9_]*)\s*=\s*['\"]?(?P<secret>[^\s#'\"]{6,})['\"]?",
        ),
        "min_entropy": 1.5,
        "evidence": "Unquoted secret value assigned in environment variable definition.",
    },
    {
        "id": "jwt-token",
        "label": "JSON Web Token (JWT)",
        "category": "Auth Tokens",
        "severity": "Medium",
        "regex": re.compile(r"(?:^|[^A-Za-z0-9._])(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,})"),
        "min_entropy": 3.0,
        "evidence": "Signed session or identity token. May contain user claims or service authorization.",
    },
]


def compute_confidence(
    pattern: Dict[str, Any],
    secret_val: str,
    raw_line: str,
    context_type: str,
    entropy: float
) -> Tuple[str, str]:
    """
    Compute detection confidence separately from severity.
    Returns (confidence_level, rationale).
    Levels: High, Medium, Low
    """
    # 1. If in Documentation / Test context, certainty remains, but likelihood of live exposure is Low/Medium
    if context_type == "Documentation / Test":
        return ("Low", "Found in test/documentation context; likely a mock or example.")

    # 2. Strong structural patterns with high entropy
    if pattern["id"] in ("aws-access-key", "github-pat", "stripe-live-key", "slack-bot-token", "private-key-header"):
        if entropy >= pattern.get("min_entropy", 2.5):
            return ("High", "Strict cryptographic or provider pattern match with high entropy.")
        else:
            return ("Medium", "Pattern matched but character randomness is lower than typical production keys.")

    if pattern["id"] == "db-connection-string":
        return ("High", "Complete database connection URI with username, password, and host.")

    # 3. Variable assignments
    if pattern["id"] == "password-assignment":
        if entropy > 2.8 and not is_placeholder(secret_val):
            return ("High", "Explicit password variable with high-entropy randomized string.")
        elif entropy > 1.8:
            return ("Medium", "Explicit password variable assignment.")
        else:
            return ("Low", "Generic password variable with dictionary or simple word.")

    # 4. Natural language & conversation
    if pattern["id"] in ("gmail-password", "app-password", "password-natural-language"):
        if entropy >= 2.5:
            return ("High", "Natural language password mention with strong random passphrase.")
        return ("Medium", "Natural language password statement requiring contextual verification.")

    if entropy >= pattern.get("min_entropy", 2.0):
        return ("Medium", "Standard credential regex match with verified entropy.")

    return ("Low", "Potential secret with marginal entropy score.")


def compute_evidence_severity(base_severity: str, confidence: str, context_type: str, is_test_pattern: bool) -> str:
    """
    Adjust severity based on concrete evidence:
    - If confidence is Low or in documentation/test, downgrade severity to avoid alert fatigue.
    - Test-only keys (like sk_test_*) are strictly Low / Informational.
    """
    if is_test_pattern:
        return "Low"

    if context_type == "Documentation / Test":
        if base_severity in ("Critical", "High"):
            return "Medium"
        return "Low"

    if confidence == "Low":
        if base_severity == "Critical":
            return "Medium"
        elif base_severity == "High":
            return "Low"
        return "Low"

    return base_severity


def secret_fingerprint(secret: str) -> str:
    """Generate a SHA-256 fingerprint for deduplication across files."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def scan_text(content: str, source_name: str = "Input") -> List[Dict[str, Any]]:
    """Scan string content with context analysis, separated confidence, and severity."""
    findings = []
    lines = content.splitlines()
    context_type = classify_context(source_name)

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or len(line) > MAX_LINE_LENGTH:
            continue

        line_findings = []
        has_primary = False
        primary_ids = {
            "db-connection-string", "aws-access-key", "aws-secret-key",
            "github-pat", "gitlab-pat", "stripe-live-key", "stripe-test-key",
            "openai-api-key", "anthropic-api-key", "slack-bot-token",
            "sendgrid-api-key", "private-key-header", "gcp-service-account",
            "azure-connection-string", "gmail-password", "app-password"
        }

        for pattern in PATTERNS:
            match = pattern["regex"].search(raw_line)
            if not match:
                continue

            secret_val = match.group("secret") if "secret" in match.groupdict() else match.group(0)
            secret_val = secret_val.strip()

            # Ignore tiny fragments
            if len(secret_val) < 4:
                continue

            entropy = calc_entropy(secret_val)
            min_ent = pattern.get("min_entropy", 0.0)
            if entropy < min_ent:
                continue

            is_mock_value = is_placeholder(secret_val)
            is_test_pat = (pattern["id"] == "stripe-test-key")

            if is_mock_value:
                confidence = "Low"
                conf_reason = "Identified as placeholder, example, or test credential."
                severity = "Low"
            else:
                confidence, conf_reason = compute_confidence(pattern, secret_val, raw_line, context_type, entropy)
                severity = compute_evidence_severity(pattern["severity"], confidence, context_type, is_test_pat)

            fp = secret_fingerprint(secret_val)

            finding = {
                "source": source_name,
                "line": line_idx,
                "context_type": context_type,
                "pattern_id": pattern["id"],
                "label": pattern["label"],
                "category": pattern["category"],
                "severity": severity,
                "confidence": confidence,
                "confidence_reason": conf_reason,
                "evidence": pattern.get("evidence", ""),
                "raw_secret": secret_val,
                "redacted_secret": redact(secret_val),
                "entropy": round(entropy, 2),
                "fingerprint": fp,
                "snippet": raw_line.strip()[:140],
            }
            line_findings.append(finding)
            if pattern["id"] in primary_ids:
                has_primary = True

        # If a high-specificity pattern matched on this line, suppress generic fallbacks
        if has_primary and len(line_findings) > 1:
            line_findings = [f for f in line_findings if f["pattern_id"] not in ("email-password-combo", "env-unquoted-secret", "password-assignment")]

        findings.extend(line_findings)

    return findings


def group_findings_by_secret(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group findings by unique secret fingerprint across files to identify
    duplicates and reduce alert fatigue.
    """
    grouped: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        fp = f["fingerprint"]
        if fp not in grouped:
            grouped[fp] = {
                "fingerprint": fp,
                "label": f["label"],
                "category": f["category"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "confidence_reason": f["confidence_reason"],
                "evidence": f["evidence"],
                "redacted_secret": f["redacted_secret"],
                "raw_secret": f["raw_secret"],
                "entropy": f["entropy"],
                "occurrences": [],
            }
        occ_key = (f["source"], f["line"])
        if not any((occ["source"], occ["line"]) == occ_key for occ in grouped[fp]["occurrences"]):
            grouped[fp]["occurrences"].append({
                "source": f["source"],
                "line": f["line"],
                "context_type": f["context_type"],
                "snippet": f["snippet"],
            })

    return list(grouped.values())


def scan_file(filepath: str) -> List[Dict[str, Any]]:
    """Scan a single local file safely."""
    p = Path(filepath)
    if not p.is_file():
        return []

    # Check file size cap
    try:
        if p.stat().st_size > MAX_FILE_SIZE:
            return []
    except OSError:
        return []

    # Check extension / special names
    ext = p.suffix.lower()
    if ext == ".zip":
        try:
            with open(p, "rb") as f:
                return scan_zip_bytes(f.read(), zip_name=p.name)
        except Exception:
            return []

    if ext and ext not in SUPPORTED_EXTENSIONS and p.name.lower() not in SPECIAL_FILENAMES:
        return []

    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return scan_text(content, source_name=str(p))
    except Exception:
        return []


def scan_directory(dirpath: str) -> List[Dict[str, Any]]:
    """Scan a full directory recursively with safe exclusions."""
    findings = []
    root = Path(dirpath)
    if not root.is_dir():
        return findings

    for item in sorted(root.rglob("*")):
        if any(skip in item.parts for skip in EXCLUDED_DIRS):
            continue
        if item.is_file():
            findings.extend(scan_file(str(item)))

    return findings


def scan_zip_bytes(zip_bytes: bytes, zip_name: str = "archive.zip") -> List[Dict[str, Any]]:
    """Scan all files inside a zip archive in-memory safely."""
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size > MAX_FILE_SIZE:
                    continue

                filename = info.filename
                parts = filename.replace("\\", "/").split("/")
                if any(p in EXCLUDED_DIRS for p in parts[:-1]):
                    continue

                ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                base_name = parts[-1].lower()

                if ext not in SUPPORTED_EXTENSIONS and base_name not in SPECIAL_FILENAMES:
                    continue

                try:
                    with z.open(info) as f:
                        content = f.read().decode("utf-8", errors="ignore")
                        file_findings = scan_text(content, source_name=f"{zip_name} > {filename}")
                        findings.extend(file_findings)
                except Exception:
                    continue
    except Exception:
        return []

    return findings

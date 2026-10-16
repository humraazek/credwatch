"""
CredWatch - Credential & Secret Leak Detection Engine
Enterprise-grade secret detection, multi-format AST/regex parsing,
context-aware evidence scoring, cross-file deduplication, and ZIP bomb/traversal guards.

Zero external dependencies - Uses Python standard library only.
"""

import ast
import base64
import hashlib
import io
import json
import math
import os
import re
import sys
import time
import urllib.parse
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

# ---------------------------------------------------------------------------
# Configuration & Limits
# ---------------------------------------------------------------------------
MAX_FILE_SIZE = 10 * 1024 * 1024        # 10 MB limit per file
MAX_ZIP_UNCOMPRESSED = 50 * 1024 * 1024  # 50 MB total archive uncompressed limit
MAX_ZIP_FILES = 5000                    # Max files in a single archive
MAX_ZIP_RATIO = 100                     # Compression ratio threshold for zip bombs
MAX_LINE_LENGTH = 5000                  # Max length of single line to inspect
MAX_RECURSION_DEPTH = 15                # Max directory recursion depth

# Supported file extensions
SUPPORTED_EXTENSIONS = {
    # Configurations
    ".env", ".cfg", ".conf", ".config", ".ini", ".toml", ".properties",
    ".yaml", ".yml", ".json", ".xml", ".tf", ".hcl",
    # Source Code
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".sh", ".bash", ".zsh", ".bat", ".ps1", ".cmd", ".c", ".cpp", ".cs",
    ".rs", ".swift", ".kt", ".sql",
    # Logs & Plain Text
    ".log", ".txt", ".jsonl",
    # Documentation
    ".md", ".rst", ".adoc",
}

# Supported filenames without extensions
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

# Configurable placeholder keywords
PLACEHOLDER_KEYWORDS = [
    "fake", "not_real", "do_not_use", "example", "your_api_key",
    "change_me", "changeme", "change-me", "your_password", "yourpassword",
    "your-password", "<password>", "todo", "fixme", "xxxx", "dummy",
    "sample", "<api_key>", "<token>", "your_key", "your_token",
    "insert_here", "replace_me", "fill_me", "test_key", "test_token",
    "mock_key", "mock_password", "invalid"
]

# Sensitive keys for structured dictionary/JSON/YAML inspection
SENSITIVE_KEY_NAMES = {
    "secret_key", "secretkey", "db_password", "dbpassword", "database_password",
    "databasepassword", "api_token", "apitoken", "api_key", "apikey",
    "aws_secret_access_key", "awssecretaccesskey", "encryption_key",
    "encryptionkey", "jwt_secret", "jwtsecret", "password", "passwd", "pwd",
    "connection_string", "connectionstring", "access_key_id", "accesskeyid",
    "secret_access_key", "secretaccesskey", "payment_secret", "paymentsecret",
    "payment_api_key", "service_account_key", "serviceaccountkey", "private_key",
    "privatekey", "auth_token", "authtoken", "cloud_secret", "cloudsecret",
    "admin_password", "adminpassword", "smtp_password", "smtppassword",
    "redis_password", "redispassword", "mysql_password", "mysql_pwd"
}

# Semantic credential identifier roots
CREDENTIAL_KEY_ROOTS = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "private_key", "access_key", "auth_token", "access_token", "refresh_token",
    "encryption_key", "service_account_key", "master_key", "signing_key", "client_secret"
)

# Standard metadata suffixes that indicate non-secret attributes or collections
METADATA_KEY_SUFFIXES = (
    "s", "_type", "_count", "_limit", "_length", "_size", "_id", "_path", "_name",
    "_algorithm", "_format", "_curve", "_alias", "_event", "_code", "type", "count", "limit"
)

# Values that represent language types, keywords, or non-secrets
NON_SECRET_VALUES = {
    # Language types
    "str", "string", "String", "int", "integer", "Integer", "float", "Float",
    "bool", "boolean", "Boolean", "bytes", "byte", "dict", "Dict", "list", "List",
    "tuple", "Tuple", "set", "Set", "any", "Any", "void", "Void", "never", "Never",
    "optional", "Optional", "union", "Union", "callable", "Callable", "iterable",
    # Language keywords & literals
    "null", "Null", "NULL", "nil", "Nil", "none", "None", "NONE", "undefined",
    "true", "True", "TRUE", "false", "False", "FALSE",
    "nan", "NaN", "infinity", "Infinity",
    # Common non-secret settings
    "empty", "default", "auto", "disabled", "enabled", "required", "optional",
    "standard", "custom", "inherit", "inline", "block", "hidden", "visible",
    "development", "production", "staging", "testing", "localhost", "127.0.0.1",
}


def clean_key_name(raw_k: str) -> str:
    """Strip variable declaration keywords and normalize key name."""
    cleaned = re.sub(
        r"^(?:const|let|var|export|public|private|protected|static|readonly)\s+",
        "",
        raw_k.strip(),
        flags=re.IGNORECASE,
    )
    return cleaned.strip().lower().replace("-", "_").replace(" ", "_")


def is_sensitive_key_name(raw_k: str) -> bool:
    """Check if an identifier semantically represents a credential or secret."""
    k = clean_key_name(raw_k)
    if k in SENSITIVE_KEY_NAMES:
        return True
    # Plural collections (e.g. tokens, keys, sensitive_keys) or metadata metrics (count, type)
    if any(k.endswith(suffix) for suffix in METADATA_KEY_SUFFIXES):
        if not (k in ("password", "secret") or k.endswith(("_password", "_secret"))):
            return False
    # Check for genuine credential roots
    if any(root in k for root in CREDENTIAL_KEY_ROOTS):
        return True
    if k == "token" or k.endswith("_token"):
        return True
    return False


def is_valid_secret_assignment(key_name: str, secret_val: str, raw_line: str, context_type: str = "Source Code") -> bool:
    """Precision filter to prevent code variables, expressions, and non-secrets from flagging."""
    # 1. Reject non-credential keys
    if not is_sensitive_key_name(key_name):
        return False

    # 2. Reject non-secret values (types, booleans, nulls, settings)
    val_clean = secret_val.strip("'\";,()[]{}\\`").strip()
    if val_clean.lower() in {v.lower() for v in NON_SECRET_VALUES}:
        return False

    # 3. Reject reading environment variables or config managers
    if any(secret_val.startswith(p) for p in ("process.env", "os.environ", "os.getenv", "env.", "System.getenv", "config.get", "dotenv", "settings.")):
        return False

    # 4. Reject code expressions and method calls across all contexts
    if any(secret_val.startswith(p) for p in ("args.", "self.", "this.", "req.", "request.", "params.", "options.", "client.", "cache.", "getpass.", "input(", "prompt(")):
        return False
    if any(char in secret_val for char in ("(", ")", "=>", "{", "}", "[", "]", "`", "$", "?")):
        return False

    # In source code, reject unquoted bare variable identifiers or property access (e.g. password = old_password or f.raw_secret)
    if context_type == "Source Code":
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*$", secret_val):
            quoted_pattern = re.compile(rf"""['"]{re.escape(secret_val)}['"]""")
            if not quoted_pattern.search(raw_line):
                return False

    # 5. Reject Python type hints: e.g. def foo(password: str)
    if re.search(r":\s*(?:str|int|float|bool|bytes|dict|list|tuple|Optional|Union|Any)\b", raw_line):
        if not re.search(r"=\s*['\"][^'\"]+['\"]", raw_line):
            return False

    return True


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    finding_id: str
    rule_id: str
    rule_title: str
    category: str
    severity: str              # Critical, High, Medium, Low, Informational
    confidence: str            # High, Medium, Low
    confidence_reason: str
    is_placeholder: bool
    placeholder_status: str    # "Live Candidate", "Likely Test / Placeholder Value", "Test / Sandbox API Key"
    context_type: str          # Configuration, Source Code, Log / Conversation, Documentation / Test
    file_path: str             # Normalized file path
    line: int
    column: int
    raw_secret: str
    masked_secret: str
    secret_hash: str           # SHA-256 hash (never raw secret)
    entropy: float
    evidence: str
    remediation: str
    snippet: str
    legacy_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["pattern_id"] = self.legacy_id or self.rule_id
        d["label"] = self.rule_title
        d["source"] = self.file_path
        d["redacted_secret"] = self.masked_secret
        d["fingerprint"] = self.secret_hash
        return d


@dataclass
class ScanReport:
    total_findings: int
    unique_secrets: int
    exposure_occurrences: int
    duplicates_removed: int
    files_scanned: List[str]
    files_skipped: List[Dict[str, str]]
    placeholder_count: int
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    scan_duration_seconds: float
    findings: List[Dict[str, Any]]
    grouped: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_txt(self) -> str:
        lines = []
        lines.append("=" * 78)
        lines.append(" CREDWATCH - CREDENTIAL & SECRET AUDIT REPORT")
        lines.append("=" * 78)
        lines.append(f" Total Findings         : {self.total_findings}")
        lines.append(f" Unique Secrets         : {self.unique_secrets}")
        lines.append(f" Exposure Occurrences   : {self.exposure_occurrences}")
        lines.append(f" Duplicate Matches Purged: {self.duplicates_removed}")
        lines.append(f" Placeholders Identified: {self.placeholder_count}")
        lines.append(f" Files Scanned / Skipped: {len(self.files_scanned)} / {len(self.files_skipped)}")
        lines.append(f" Scan Duration          : {self.scan_duration_seconds:.3f}s")
        lines.append("-" * 78)
        lines.append(" Findings by Severity:")
        for sev, count in self.findings_by_severity.items():
            lines.append(f"   - {sev:<14}: {count}")
        lines.append(" Findings by Category:")
        for cat, count in self.findings_by_category.items():
            lines.append(f"   - {cat:<24}: {count}")
        lines.append("=" * 78)
        lines.append("")

        for idx, g in enumerate(self.grouped, start=1):
            lines.append(f"[{idx}] {g['rule_title']} ({g['category']})")
            lines.append(f"    Rule ID                 : {g['rule_id']}")
            lines.append(f"    Evidence-based Severity : {g['severity']}")
            lines.append(f"    Detection Confidence    : {g['confidence']} ({g['confidence_reason']})")
            lines.append(f"    Placeholder Status      : {g['placeholder_status']}")
            lines.append(f"    Impact Evidence         : {g['evidence']}")
            lines.append(f"    Masked Secret           : {g['masked_secret']} (Entropy: {g['entropy']})")
            lines.append(f"    Recommended Remediation : {g['remediation']}")
            lines.append(f"    Exposures ({len(g['occurrences'])} location(s)):")
            for occ in g["occurrences"]:
                lines.append(f"      - {occ['file_path']}:{occ['line']} [{occ['context_type']}]")
                lines.append(f"        Snippet: {occ['snippet']}")
            lines.append("-" * 78)

        if self.files_skipped:
            lines.append("")
            lines.append(" Skipped / Excluded Files:")
            for sk in self.files_skipped:
                lines.append(f"   - {sk['file']}: {sk['reason']}")
            lines.append("-" * 78)

        return "\n".join(lines)

    def to_html(self) -> str:
        crit = self.findings_by_severity.get("Critical", 0)
        high = self.findings_by_severity.get("High", 0)
        med = self.findings_by_severity.get("Medium", 0)
        low = self.findings_by_severity.get("Low", 0)
        info = self.findings_by_severity.get("Informational", 0)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CredWatch - Security Audit Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0A0A0A; color: #EEEEEE; padding: 2rem; line-height: 1.5; }}
    h1 {{ color: #FFFFFF; font-weight: 700; margin-bottom: 0.5rem; }}
    .subtitle {{ color: #888888; font-size: 0.9rem; margin-bottom: 2rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .stat-card {{ background: #141414; border: 1px solid #262626; border-radius: 6px; padding: 1rem; }}
    .stat-label {{ font-size: 0.75rem; text-transform: uppercase; color: #888888; margin-bottom: 0.25rem; }}
    .stat-val {{ font-size: 1.4rem; font-weight: bold; color: #FFFFFF; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.55rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }}
    .badge-Critical {{ background: rgba(255, 69, 58, 0.2); color: #FF453A; border: 1px solid #FF453A; }}
    .badge-High {{ background: rgba(255, 159, 10, 0.2); color: #FF9F0A; border: 1px solid #FF9F0A; }}
    .badge-Medium {{ background: rgba(255, 214, 10, 0.2); color: #FFD60A; border: 1px solid #FFD60A; }}
    .badge-Low {{ background: rgba(48, 209, 88, 0.2); color: #30D158; border: 1px solid #30D158; }}
    .badge-Informational {{ background: rgba(142, 142, 147, 0.2); color: #8E8E93; border: 1px solid #8E8E93; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: #141414; border: 1px solid #262626; border-radius: 6px; overflow: hidden; }}
    th, td {{ padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid #262626; font-size: 0.88rem; }}
    th {{ background: #1A1A1A; color: #888888; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.05em; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #1F1F1F; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.82rem; }}
    .occ-block {{ margin: 0.3rem 0; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.8rem; color: #CCCCCC; }}
  </style>
</head>
<body>
  <h1>CredWatch - Security Audit Report</h1>
  <div class="subtitle">Evidence-based severity scoring, safe credential masking, and verified cross-file deduplication.</div>
  
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-label">Total Findings</div><div class="stat-val">{self.total_findings}</div></div>
    <div class="stat-card"><div class="stat-label">Unique Secrets</div><div class="stat-val">{self.unique_secrets}</div></div>
    <div class="stat-card"><div class="stat-label">Critical</div><div class="stat-val" style="color: #FF453A;">{crit}</div></div>
    <div class="stat-card"><div class="stat-label">High</div><div class="stat-val" style="color: #FF9F0A;">{high}</div></div>
    <div class="stat-card"><div class="stat-label">Medium</div><div class="stat-val" style="color: #FFD60A;">{med}</div></div>
    <div class="stat-card"><div class="stat-label">Low / Placeholders</div><div class="stat-val" style="color: #30D158;">{low + info}</div></div>
    <div class="stat-card"><div class="stat-label">Duplicates Removed</div><div class="stat-val">{self.duplicates_removed}</div></div>
  </div>

  <h2>Distinct Secrets & Exposure Locations</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Confidence</th>
        <th>Rule & Category</th>
        <th>Masked Secret</th>
        <th>Status</th>
        <th>Exposure Locations</th>
      </tr>
    </thead>
    <tbody>
"""
        for g in self.grouped:
            occ_rows = "".join(f"<div class='occ-block'><code>{occ['file_path']}:{occ['line']}</code> [{occ['context_type']}]<br><small style='color:#777'>{occ['snippet']}</small></div>" for occ in g["occurrences"])
            html += f"""
      <tr>
        <td><span class="badge badge-{g['severity']}">{g['severity']}</span></td>
        <td><strong>{g['confidence']}</strong><div style="font-size:0.75rem; color:#888;">{g['confidence_reason']}</div></td>
        <td><strong>{g['rule_title']}</strong><div style="font-size:0.75rem; color:#888;"><code>{g['rule_id']}</code> &bull; {g['category']}</div></td>
        <td><code>{g['masked_secret']}</code></td>
        <td><span style="font-size:0.78rem; color:#AAA;">{g['placeholder_status']}</span></td>
        <td>{occ_rows}</td>
      </tr>
"""
        html += """
    </tbody>
  </table>
</body>
</html>
"""
        return html


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------
def normalize_path(path_str: str) -> str:
    """Normalize file path representation across Windows and POSIX."""
    if not path_str:
        return "input"
    cleaned = path_str.replace("\\", "/")
    return os.path.normpath(cleaned).replace("\\", "/")


def calc_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
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


def is_placeholder_value(val: str, keywords: Optional[List[str]] = None) -> bool:
    """Detect if a value is explicitly designated as fake, sample, or placeholder."""
    cleaned = val.strip().lower()
    # Check if value starts with sk_test_ -> that is specifically a Stripe test key, not a generic mock string
    if cleaned.startswith("sk_test_") or cleaned.startswith("rk_test_"):
        return False
    kw_list = keywords or PLACEHOLDER_KEYWORDS
    for kw in kw_list:
        if kw in cleaned:
            return True
    return False

# Backward compatibility alias
is_placeholder = is_placeholder_value


def mask_secret(value: str, show_chars: int = 4) -> str:
    """Safely redact secret value, keeping initial characters for triage."""
    if len(value) <= show_chars + 2:
        return "*" * len(value)
    masked_part = "*" * min(16, len(value) - show_chars)
    return value[:show_chars] + masked_part


def mask_database_uri(uri_str: str) -> str:
    """Safely redact credentials from database URI while preserving scheme and host."""
    try:
        parsed = urllib.parse.urlsplit(uri_str)
        if parsed.password:
            user = parsed.username or ""
            netloc = f"{user}:********@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        pass
    # Fallback regex mask
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:********@", uri_str)


def safe_snippet(raw_line: str, raw_secret: str, masked_secret: str) -> str:
    """Safely redact raw secret inside code snippet."""
    if raw_secret in raw_line:
        clean = raw_line.replace(raw_secret, masked_secret)
    else:
        clean = raw_line
    return clean.strip()[:140]


def compute_secret_hash(val: str) -> str:
    """Deterministic, irreversible hash of secret for stable grouping and fingerprints."""
    return hashlib.sha256(val.strip().encode("utf-8")).hexdigest()[:16]


def is_binary_file(sample_bytes: bytes) -> bool:
    """Check for null bytes indicating binary content."""
    return b"\x00" in sample_bytes[:8192]


def classify_context(filepath: str) -> str:
    """Classify file context into standard categories."""
    p_lower = filepath.replace("\\", "/").lower()
    parts = p_lower.split("/")
    filename = parts[-1]

    # Check documentation or test paths
    if any(p in ("tests", "test", "__tests__", "spec", "mocks", "fixtures", "docs", "doc") for p in parts[:-1]):
        return "Documentation / Test"
    if filename.startswith("test_") or filename.endswith("_test.py") or filename.endswith(".spec.ts") or filename.endswith(".test.js"):
        return "Documentation / Test"
    if filename.endswith(".md") or filename.endswith(".rst") or filename.endswith(".adoc"):
        return "Documentation / Test"

    ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

    if ext in (".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".xml", ".tf", ".hcl") or filename in SPECIAL_FILENAMES:
        return "Configuration"

    if ext in (".log", ".txt", ".jsonl") or filename in ("input", "paste", "pasted_text", "stdin", "clip", "raw", ""):
        return "Log / Conversation"

    if ext in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sh", ".bash", ".c", ".cpp", ".cs", ".sql"):
        return "Source Code"

    return "Configuration" if "config" in p_lower else "Log / Conversation"


# ---------------------------------------------------------------------------
# Detection Rules (Configurable & Categorized)
# ---------------------------------------------------------------------------
RULES = [
    {
        "id": "SEC-AWS-001",
        "legacy_id": "aws-access-key",
        "title": "AWS Access Key ID",
        "category": "Cloud Credentials",
        "base_severity": "Critical",
        "base_confidence": "High",
        "regex": re.compile(r"(?:^|[^A-Z0-9])(?P<secret>AKIA[0-9A-Z]{16,28})(?:[^A-Z0-9]|$)"),
        "min_entropy": 2.2,
        "evidence": "AWS IAM access key ID format starting with AKIA.",
        "remediation": "Revoke the IAM access key in the AWS Console, inspect CloudTrail for unauthorized activity, and use AWS Secrets Manager or IAM roles.",
    },
    {
        "id": "SEC-AWS-002",
        "legacy_id": "aws-secret-access-key",
        "title": "AWS Secret Access Key",
        "category": "Cloud Credentials",
        "base_severity": "Critical",
        "base_confidence": "High",
        "regex": re.compile(r"""(?:aws_secret_access_key|secret_access_key|aws_secret|AWS_SECRET_ACCESS_KEY|cloud_secret)['"]?\s*[:=]\s*['"]?(?P<secret>[A-Za-z0-9/+=_]{16,})['"]?""", re.IGNORECASE),
        "min_entropy": 2.0,
        "evidence": "AWS Secret Access Key configuration assignment.",
        "remediation": "Rotate AWS credentials immediately, ensure IAM users use MFA, and bind services to temporary STS credentials.",
    },
    {
        "id": "SEC-DB-001",
        "legacy_id": "db-connection-string",
        "title": "Database Connection String with Credentials",
        "category": "Database Credentials",
        "base_severity": "Critical",
        "base_confidence": "High",
        "regex": re.compile(
            r"""(?P<secret>(?:postgresql|postgres|mysql|mongodb|mongodb\+srv|redis|mssql|sqlserver)://[^\s:'"]+:[^\s@'"]+@[^\s/'"]+[^\s'"]*)""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.0,
        "evidence": "RFC-compliant database URI with embedded cleartext username and password.",
        "remediation": "Move database credentials to environment variables or secret vaults and configure mutual TLS authentication.",
    },
    {
        "id": "SEC-KEY-001",
        "legacy_id": "private-key-header",
        "title": "Asymmetric Private Key Header",
        "category": "Cryptographic Keys",
        "base_severity": "Critical",
        "base_confidence": "High",
        "regex": re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----)"),
        "min_entropy": 0.0,
        "evidence": "Cryptographic private key header block used for TLS termination, SSH access, or signature generation.",
        "remediation": "Immediately re-issue certificates and regenerate keypairs. Ensure private keys are never committed to version control.",
    },
    {
        "id": "SEC-PLAT-001",
        "legacy_id": "github-pat",
        "title": "GitHub Access Token",
        "category": "Platform Tokens",
        "base_severity": "High",
        "base_confidence": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{30,}|gho_[A-Za-z0-9]{36,}))"),
        "min_entropy": 2.8,
        "evidence": "Personal access token matching GitHub token structure and prefix specifications.",
        "remediation": "Revoke the token in GitHub Settings > Developer settings > Personal access tokens, review recent audit log actions, and grant minimum necessary scopes.",
    },
    {
        "id": "SEC-PAY-001",
        "legacy_id": "stripe-live-key",
        "title": "Stripe Live Secret Key",
        "category": "Payment Gateways",
        "base_severity": "Critical",
        "base_confidence": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>(?:sk|rk)_live_[A-Za-z0-9_]{20,})"),
        "min_entropy": 2.8,
        "evidence": "Production live Stripe secret key capable of authorizing financial transactions.",
        "remediation": "Roll the secret key in the Stripe Dashboard immediately and review account webhooks.",
    },
    {
        "id": "SEC-PAY-002",
        "legacy_id": "stripe-test-key",
        "title": "Stripe Test API Key",
        "category": "Payment Gateways",
        "base_severity": "Low",
        "base_confidence": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>(?:sk|rk)_test_[A-Za-z0-9_]{16,})"),
        "min_entropy": 2.0,
        "evidence": "Stripe test/sandbox environment API key (no production financial capability).",
        "remediation": "Avoid hardcoding sandbox keys in production codebases; use environment-specific config files.",
    },
    {
        "id": "SEC-AI-001",
        "legacy_id": "openai-api-key",
        "title": "OpenAI API Key",
        "category": "API Keys",
        "base_severity": "High",
        "base_confidence": "High",
        "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(?P<secret>sk-(?:proj-)?[A-Za-z0-9_\-]{30,})"),
        "min_entropy": 2.8,
        "evidence": "OpenAI platform API token capable of billed model consumption and API operations.",
        "remediation": "Revoke the API key in the OpenAI platform dashboard and set usage spending limits.",
    },
    {
        "id": "SEC-JWT-001",
        "legacy_id": "jwt-signing-secret",
        "title": "JWT Signing Secret",
        "category": "JWT Signing Secrets",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""['"]?(?:jwt_secret|jwt_signing_secret|jwtsecret)['"]?\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Secret key used to cryptographically sign and verify JSON Web Tokens.",
        "remediation": "Store JWT secrets in hardware security modules (HSM) or secret vaults and rotate signing keys periodically.",
    },
    {
        "id": "SEC-ENC-001",
        "legacy_id": "encryption-key",
        "title": "Application Encryption Key",
        "category": "Encryption Keys",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""['"]?(?:encryption_key|encryptionkey)['"]?\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Symmetric encryption key used for application-level data protection.",
        "remediation": "Use KMS or envelope encryption rather than storing raw encryption keys in code or configuration.",
    },
    {
        "id": "SEC-SMTP-001",
        "legacy_id": "smtp-password",
        "title": "SMTP Service Password",
        "category": "SMTP & Service Credentials",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""['"]?(?:smtp_password|smtppassword|mail_password)['"]?\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Authentication password for outbound SMTP email services.",
        "remediation": "Rotate mail server passwords and restrict SMTP access to known sender IP addresses.",
    },
    {
        "id": "SEC-REDIS-001",
        "legacy_id": "redis-password",
        "title": "Redis Authentication Password",
        "category": "Database Credentials",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""['"]?(?:redis_password|redispassword)['"]?\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Cleartext password for Redis cache/database authentication.",
        "remediation": "Enable Redis ACLs with TLS encryption and store authentication passwords in secret managers.",
    },
    {
        "id": "SEC-SRV-001",
        "legacy_id": "service-account-key",
        "title": "Service Account Credential",
        "category": "Service Credentials",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""['"]?(?:service_account_key|serviceaccountkey)['"]?\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Service account authentication key or secret token.",
        "remediation": "Use workload identity federation or IAM instance profiles instead of static service account keys.",
    },
    {
        "id": "SEC-API-001",
        "legacy_id": "api-key",
        "title": "API Key / Access Token",
        "category": "API Keys",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""['"]?(?:api_key|apikey|api_token|apitoken|payment_api_key)['"]?\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Authentication token or API key assigned in code or configuration.",
        "remediation": "Revoke and regenerate exposed API keys and enforce rate limiting and IP allowlisting.",
    },
    {
        "id": "SEC-GMAIL-001",
        "legacy_id": "gmail-password",
        "title": "Natural Language Account Password",
        "category": "Passwords & Credentials",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""(?:my\s+)?gmail\s+password\s+(?:is\s+)?['"]?(?P<secret>[^\s,'\"#;]{6,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 1.0,
        "evidence": "User communication exposing email/account credentials in plain text.",
        "remediation": "Immediately reset account passwords, enable multi-factor authentication (MFA), and purge conversational logs.",
    },
    {
        "id": "SEC-PASS-001",
        "legacy_id": "password-assignment",
        "title": "Hardcoded Password / Credential Assignment",
        "category": "Passwords & Credentials",
        "base_severity": "High",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""['"]?(?P<key>[a-zA-Z0-9_\s]{2,30})['"]?\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
        ),
        "min_entropy": 0.5,
        "evidence": "Key-value credential assignment targeting authentication variables.",
        "remediation": "Externalize hardcoded credentials to protected environment variables or secrets vaults.",
    },
    {
        "id": "SEC-TXT-001",
        "legacy_id": "plaintext-credential-text",
        "title": "Plaintext Credential in Text / Documentation",
        "category": "Documentation Leaks",
        "base_severity": "Medium",
        "base_confidence": "Medium",
        "regex": re.compile(
            r"""(?P<label>Database\s+password|Admin\s+password|API\s+key|JWT\s+(?:signing\s+)?secret|Encryption\s+key|Cloud\s+secret)\s*[:=]\s*['"]?(?P<secret>[^\s,'\"#;]{4,})['"]?""",
            re.IGNORECASE,
        ),
        "min_entropy": 0.5,
        "evidence": "Free-form text statement exposing application credentials in plain text.",
        "remediation": "Sanitize internal documentation and remove sample credentials from shared logs.",
    },
]


# ---------------------------------------------------------------------------
# Evidence-Based Severity & Confidence Logic
# ---------------------------------------------------------------------------
def compute_scores(
    rule: Dict[str, Any],
    secret_val: str,
    context_type: str,
    entropy: float,
    is_mock: bool,
) -> Tuple[str, str, str, str]:
    """
    Compute evidence-based severity and separate detection confidence.
    Returns: (severity, confidence, confidence_reason, placeholder_status)
    """
    # Special case: Stripe sandbox/test keys have High confidence of format, but Low severity impact
    if rule["id"] == "SEC-PAY-002":
        return (
            "Low",
            "High",
            "Valid Stripe test API key format (sandbox environment; cannot perform live financial transactions).",
            "Test / Sandbox API Key",
        )

    if is_mock:
        return (
            "Low",
            "Low",
            "Identified as placeholder, example, or test credential convention.",
            "Likely Test / Placeholder Value",
        )

    # Base confidence calculation
    base_conf = rule.get("base_confidence", "Medium")
    base_sev = rule.get("base_severity", "Medium")

    # High-entropy provider keys
    if rule["id"] in ("SEC-AWS-001", "SEC-AWS-002", "SEC-DB-001", "SEC-KEY-001", "SEC-PLAT-001", "SEC-PAY-001", "SEC-AI-001"):
        if entropy >= rule.get("min_entropy", 2.2):
            confidence = "High"
            conf_reason = "Strict provider structure and verified character entropy."
        else:
            confidence = "Medium"
            conf_reason = "Matched provider regex pattern, but entropy is lower than production baseline."
    else:
        if entropy >= 3.0:
            confidence = "High"
            conf_reason = "Strong assignment context with high-entropy randomized string."
        elif entropy >= 1.5:
            confidence = "Medium"
            conf_reason = "Plausible credential based on field naming and value structure."
        else:
            confidence = "Low"
            conf_reason = "Weak evidence; low-entropy dictionary or sequential string."

    # Downgrade context if in test or docs
    if context_type == "Documentation / Test":
        confidence = "Low"
        conf_reason = "Discovered within test suite or documentation directory."
        severity = "Medium" if base_sev == "Critical" else "Low"
    else:
        # Evidence-based severity calculation
        if confidence == "Low":
            severity = "Medium" if base_sev == "Critical" else "Low"
        else:
            severity = base_sev

    return (severity, confidence, conf_reason, "Live Candidate")


# ---------------------------------------------------------------------------
# Specialized Structured Content Parsers
# ---------------------------------------------------------------------------
def find_line_and_col(lines: List[str], target_str: str, key_hint: Optional[str] = None) -> Tuple[int, int, str]:
    """Find line number, 1-based column, and snippet for a target secret."""
    for idx, raw_line in enumerate(lines, start=1):
        if key_hint and key_hint.lower() in raw_line.lower():
            col = raw_line.find(target_str)
            col_1 = col + 1 if col != -1 else 1
            return (idx, col_1, raw_line.strip()[:140])
        elif target_str in raw_line:
            col = raw_line.find(target_str)
            col_1 = col + 1 if col != -1 else 1
            return (idx, col_1, raw_line.strip()[:140])
    return (1, 1, lines[0].strip()[:140] if lines else "")


def parse_and_scan_json(content: str, filepath: str) -> Optional[List[Finding]]:
    """Recursively parse JSON object and inspect nested keys safely."""
    try:
        data = json.loads(content)
    except Exception:
        return None  # Fallback to regex line scanning if not valid JSON

    lines = content.splitlines()
    context_type = classify_context(filepath)
    findings: List[Finding] = []

    def walk_json(node: Any, parent_key: str = ""):
        if isinstance(node, dict):
            for k, v in node.items():
                walk_json(v, parent_key=k)
        elif isinstance(node, list):
            for item in node:
                walk_json(item, parent_key=parent_key)
        elif isinstance(node, (str, int, float)) and parent_key:
            val_str = str(node).strip()
            if len(val_str) < 4:
                return

            normalized_key = parent_key.lower().replace("-", "_").replace(" ", "_")

            matched_rule = None
            if is_sensitive_key_name(normalized_key):
                if "connection" in normalized_key or "database_url" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-DB-001")
                elif "jwt" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-JWT-001")
                elif "encrypt" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-ENC-001")
                elif "smtp" in normalized_key or "mail" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-SMTP-001")
                elif "redis" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-REDIS-001")
                elif "service_account" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-SRV-001")
                elif "access_key_id" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-AWS-001")
                elif "secret_access_key" in normalized_key or "cloud_secret" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-AWS-002")
                elif ("payment" in normalized_key or val_str.startswith("sk_test_")) and val_str.startswith("sk_test_"):
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-PAY-002")
                elif "api" in normalized_key or "token" in normalized_key:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-API-001")
                else:
                    matched_rule = next(r for r in RULES if r["id"] == "SEC-PASS-001")
            else:
                for r in RULES:
                    if r["id"] not in ("SEC-PASS-001", "SEC-TXT-001"):
                        m = r["regex"].search(val_str)
                        if m:
                            matched_rule = r
                            break

            if matched_rule:
                line_num, col_num, raw_snippet = find_line_and_col(lines, val_str, key_hint=parent_key)
                if not is_valid_secret_assignment(parent_key, val_str, raw_snippet, context_type):
                    return

                entropy = calc_entropy(val_str)
                is_mock = is_placeholder_value(val_str)
                sev, conf, conf_reason, placeholder_status = compute_scores(
                    matched_rule, val_str, context_type, entropy, is_mock
                )

                line_num, col_num, raw_snippet = find_line_and_col(lines, val_str, key_hint=parent_key)
                norm_p = normalize_path(filepath)
                sec_hash = compute_secret_hash(val_str)
                f_id = hashlib.sha256(f"{norm_p}:{line_num}:{matched_rule['id']}:{sec_hash}".encode()).hexdigest()[:12]

                masked = mask_database_uri(val_str) if matched_rule["id"] == "SEC-DB-001" else mask_secret(val_str)
                snippet = safe_snippet(raw_snippet, val_str, masked)

                findings.append(Finding(
                    finding_id=f_id,
                    rule_id=matched_rule["id"],
                    rule_title=matched_rule["title"],
                    category=matched_rule["category"],
                    severity=sev,
                    confidence=conf,
                    confidence_reason=conf_reason,
                    is_placeholder=is_mock,
                    placeholder_status=placeholder_status,
                    context_type=context_type,
                    file_path=norm_p,
                    line=line_num,
                    column=col_num,
                    raw_secret=val_str,
                    masked_secret=masked,
                    secret_hash=sec_hash,
                    entropy=round(entropy, 2),
                    evidence=matched_rule["evidence"],
                    remediation=matched_rule["remediation"],
                    snippet=snippet,
                    legacy_id=matched_rule.get("legacy_id", ""),
                ))

    walk_json(data)
    return findings


def parse_and_scan_python(content: str, filepath: str) -> Optional[List[Finding]]:
    """Inspect Python AST for credential dictionary entries and variable assignments."""
    try:
        tree = ast.parse(content)
    except Exception:
        return None  # Fallback to line scanning on syntax error

    findings: List[Finding] = []
    lines = content.splitlines()
    context_type = classify_context(filepath)
    norm_p = normalize_path(filepath)

    def process_key_val(key_name: str, val_str: str, lineno: int, col_offset: int):
        raw_line = lines[lineno - 1] if 0 <= lineno - 1 < len(lines) else ""
        if len(val_str) < 4 or not is_valid_secret_assignment(key_name, val_str, raw_line, context_type):
            return
        clean_k = clean_key_name(key_name)
        if clean_k in SENSITIVE_KEY_NAMES or any(k in clean_k for k in ("password", "secret", "token", "key")):
            matched_rule = None
            if "jwt" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-JWT-001")
            elif "encrypt" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-ENC-001")
            elif "smtp" in clean_k or "mail" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-SMTP-001")
            elif "redis" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-REDIS-001")
            elif "service_account" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-SRV-001")
            elif "aws_secret" in clean_k or "secret_access" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-AWS-002")
            elif "access_key" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-AWS-001")
            elif "api" in clean_k or "token" in clean_k:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-API-001")
            else:
                matched_rule = next(r for r in RULES if r["id"] == "SEC-PASS-001")

            entropy = calc_entropy(val_str)
            if entropy < matched_rule.get("min_entropy", 0.5):
                return
            is_mock = is_placeholder_value(val_str)
            sev, conf, conf_reason, placeholder_status = compute_scores(
                matched_rule, val_str, context_type, entropy, is_mock
            )
            sec_hash = compute_secret_hash(val_str)
            f_id = hashlib.sha256(f"{norm_p}:{lineno}:{matched_rule['id']}:{sec_hash}".encode()).hexdigest()[:12]
            raw_snippet = lines[lineno - 1] if 0 <= lineno - 1 < len(lines) else ""
            masked = mask_secret(val_str)
            snippet = safe_snippet(raw_snippet, val_str, masked)
            findings.append(Finding(
                finding_id=f_id,
                rule_id=matched_rule["id"],
                rule_title=matched_rule["title"],
                category=matched_rule["category"],
                severity=sev,
                confidence=conf,
                confidence_reason=conf_reason,
                is_placeholder=is_mock,
                placeholder_status=placeholder_status,
                context_type=context_type,
                file_path=norm_p,
                line=lineno,
                column=col_offset + 1,
                raw_secret=val_str,
                masked_secret=masked,
                secret_hash=sec_hash,
                entropy=round(entropy, 2),
                evidence=matched_rule["evidence"],
                remediation=matched_rule["remediation"],
                snippet=snippet,
                legacy_id=matched_rule.get("legacy_id", ""),
            ))

    class SecretVisitor(ast.NodeVisitor):
        def visit_Dict(self, node: ast.Dict):
            for k_node, v_node in zip(node.keys, node.values):
                if k_node is not None and isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                    if isinstance(v_node, ast.Constant) and isinstance(v_node.value, str):
                        process_key_val(k_node.value, v_node.value, v_node.lineno, v_node.col_offset)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        process_key_val(target.id, node.value.value, node.value.lineno, node.value.col_offset)
            self.generic_visit(node)

    visitor = SecretVisitor()
    visitor.visit(tree)
    return findings


# ---------------------------------------------------------------------------
# General Scanning Engine
# ---------------------------------------------------------------------------
def scan_text_content(content: str, filepath: str) -> List[Finding]:
    """Scan content across any supported file type with reliable deduplication."""
    ext = "." + filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""

    # Try structured parsers where appropriate
    if ext == ".json":
        json_results = parse_and_scan_json(content, filepath)
        if json_results is not None:
            return deduplicate_line_findings(json_results)

    raw_findings: List[Finding] = []
    if ext == ".py":
        py_results = parse_and_scan_python(content, filepath)
        if py_results:
            raw_findings.extend(py_results)

    lines = content.splitlines()
    context_type = classify_context(filepath)
    norm_p = normalize_path(filepath)

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or len(line) > MAX_LINE_LENGTH or line.startswith(("#", "//", "/*", "*")):
            # Skip full comment lines for generic assignment matching
            pass

        # Check line against all rules
        for rule in RULES:
            # For SEC-PASS-001, only match if the key name is sensitive and not a non-secret code identifier
            if rule["id"] == "SEC-PASS-001":
                for m in rule["regex"].finditer(raw_line):
                    raw_key = m.group("key")
                    if is_sensitive_key_name(raw_key):
                        val = m.group("secret").strip()
                        if len(val) >= 4 and is_valid_secret_assignment(raw_key, val, raw_line, context_type):
                            entropy = calc_entropy(val)
                            if entropy < rule.get("min_entropy", 0.5):
                                continue
                            is_mock = is_placeholder_value(val)
                            sev, conf, conf_reason, placeholder_status = compute_scores(
                                rule, val, context_type, entropy, is_mock
                            )
                            sec_hash = compute_secret_hash(val)
                            f_id = hashlib.sha256(f"{norm_p}:{line_idx}:{rule['id']}:{sec_hash}".encode()).hexdigest()[:12]
                            masked = mask_secret(val)
                            snippet = safe_snippet(raw_line, val, masked)
                            raw_findings.append(Finding(
                                finding_id=f_id,
                                rule_id=rule["id"],
                                rule_title=rule["title"],
                                category=rule["category"],
                                severity=sev,
                                confidence=conf,
                                confidence_reason=conf_reason,
                                is_placeholder=is_mock,
                                placeholder_status=placeholder_status,
                                context_type=context_type,
                                file_path=norm_p,
                                line=line_idx,
                                column=m.start("secret") + 1,
                                raw_secret=val,
                                masked_secret=masked,
                                secret_hash=sec_hash,
                                entropy=round(entropy, 2),
                                evidence=rule["evidence"],
                                remediation=rule["remediation"],
                                snippet=snippet,
                                legacy_id=rule.get("legacy_id", ""),
                            ))
                continue

            # For SEC-TXT-001, map matched label to proper specialized rule
            if rule["id"] == "SEC-TXT-001":
                m = rule["regex"].search(raw_line)
                if m:
                    label = m.group("label").lower()
                    secret_val = m.group("secret").strip()
                    if len(secret_val) >= 4 and is_valid_secret_assignment(label, secret_val, raw_line, context_type):
                        target_rule = rule
                        if "jwt" in label:
                            target_rule = next(r for r in RULES if r["id"] == "SEC-JWT-001")
                        elif "encryption" in label:
                            target_rule = next(r for r in RULES if r["id"] == "SEC-ENC-001")
                        elif "api" in label:
                            target_rule = next(r for r in RULES if r["id"] == "SEC-API-001")
                        elif "cloud" in label:
                            target_rule = next(r for r in RULES if r["id"] == "SEC-AWS-002")
                        elif "database" in label or "admin" in label:
                            target_rule = next(r for r in RULES if r["id"] == "SEC-PASS-001")

                        entropy = calc_entropy(secret_val)
                        is_mock = is_placeholder_value(secret_val)
                        sev, conf, conf_reason, placeholder_status = compute_scores(
                            target_rule, secret_val, context_type, entropy, is_mock
                        )
                        sec_hash = compute_secret_hash(secret_val)
                        f_id = hashlib.sha256(f"{norm_p}:{line_idx}:{target_rule['id']}:{sec_hash}".encode()).hexdigest()[:12]
                        masked = mask_secret(secret_val)
                        snippet = safe_snippet(raw_line, secret_val, masked)
                        raw_findings.append(Finding(
                            finding_id=f_id,
                            rule_id=target_rule["id"],
                            rule_title=target_rule["title"],
                            category=target_rule["category"],
                            severity=sev,
                            confidence=conf,
                            confidence_reason=conf_reason,
                            is_placeholder=is_mock,
                            placeholder_status=placeholder_status,
                            context_type=context_type,
                            file_path=norm_p,
                            line=line_idx,
                            column=m.start("secret") + 1,
                            raw_secret=secret_val,
                            masked_secret=masked,
                            secret_hash=sec_hash,
                            entropy=round(entropy, 2),
                            evidence=target_rule["evidence"],
                            remediation=target_rule["remediation"],
                            snippet=snippet,
                            legacy_id=target_rule.get("legacy_id", ""),
                        ))
                continue

            # Standard regex rules
            m = rule["regex"].search(raw_line)
            if not m:
                continue

            secret_val = m.group("secret").strip() if "secret" in m.groupdict() else m.group(0).strip()
            if len(secret_val) < 4:
                continue

            if rule["id"] in ("SEC-AWS-002", "SEC-JWT-001", "SEC-ENC-001", "SEC-SMTP-001", "SEC-REDIS-001", "SEC-SRV-001", "SEC-API-001"):
                if not is_valid_secret_assignment(rule["title"], secret_val, raw_line, context_type):
                    continue

            entropy = calc_entropy(secret_val)
            min_ent = rule.get("min_entropy", 0.0)
            if entropy < min_ent:
                continue

            is_mock = is_placeholder_value(secret_val)
            sev, conf, conf_reason, placeholder_status = compute_scores(
                rule, secret_val, context_type, entropy, is_mock
            )

            sec_hash = compute_secret_hash(secret_val)
            f_id = hashlib.sha256(f"{norm_p}:{line_idx}:{rule['id']}:{sec_hash}".encode()).hexdigest()[:12]
            masked = mask_database_uri(secret_val) if rule["id"] == "SEC-DB-001" else mask_secret(secret_val)
            snippet = safe_snippet(raw_line, secret_val, masked)

            raw_findings.append(Finding(
                finding_id=f_id,
                rule_id=rule["id"],
                rule_title=rule["title"],
                category=rule["category"],
                severity=sev,
                confidence=conf,
                confidence_reason=conf_reason,
                is_placeholder=is_mock,
                placeholder_status=placeholder_status,
                context_type=context_type,
                file_path=norm_p,
                line=line_idx,
                column=m.start() + 1,
                raw_secret=secret_val,
                masked_secret=masked,
                secret_hash=sec_hash,
                entropy=round(entropy, 2),
                evidence=rule["evidence"],
                remediation=rule["remediation"],
                snippet=snippet,
                legacy_id=rule.get("legacy_id", ""),
            ))

    return deduplicate_line_findings(raw_findings)


def deduplicate_line_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate overlapping findings on the exact same file and line.
    Prioritizes specific provider rules over generic password assignment rules.
    """
    by_loc: Dict[Tuple[str, int], List[Finding]] = {}
    for f in findings:
        loc = (f.file_path, f.line)
        by_loc.setdefault(loc, []).append(f)

    deduped: List[Finding] = []
    for loc, items in by_loc.items():
        if len(items) == 1:
            deduped.append(items[0])
            continue

        # If multiple findings on same line:
        # Check if one is a specific provider rule
        specific = [it for it in items if it.rule_id not in ("SEC-PASS-001", "SEC-TXT-001")]
        if specific:
            seen_hashes = set()
            for sp in specific:
                if sp.secret_hash not in seen_hashes:
                    seen_hashes.add(sp.secret_hash)
                    deduped.append(sp)
        else:
            seen_hashes = set()
            for it in items:
                if it.secret_hash not in seen_hashes:
                    seen_hashes.add(it.secret_hash)
                    deduped.append(it)

    return deduped


def group_findings(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Group findings by unique secret hash across files.
    Preserves all distinct file exposure locations without duplicates.
    """
    grouped_map: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        h = f.secret_hash
        if h not in grouped_map:
            grouped_map[h] = {
                "secret_hash": h,
                "fingerprint": h,
                "rule_id": f.rule_id,
                "pattern_id": f.legacy_id or f.rule_id,
                "rule_title": f.rule_title,
                "label": f.rule_title,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "confidence_reason": f.confidence_reason,
                "is_placeholder": f.is_placeholder,
                "placeholder_status": f.placeholder_status,
                "masked_secret": f.masked_secret,
                "redacted_secret": f.masked_secret,
                "raw_secret": f.raw_secret,
                "entropy": f.entropy,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "occurrences": [],
            }

        # Deduplicate occurrences at (file_path, line)
        occ = {
            "file_path": f.file_path,
            "source": f.file_path,
            "line": f.line,
            "column": f.column,
            "context_type": f.context_type,
            "snippet": f.snippet,
        }
        if not any(o["file_path"] == occ["file_path"] and o["line"] == occ["line"] for o in grouped_map[h]["occurrences"]):
            grouped_map[h]["occurrences"].append(occ)

    return list(grouped_map.values())


# ---------------------------------------------------------------------------
# Safe Archive & File Processing
# ---------------------------------------------------------------------------
def scan_zip_archive(zip_bytes: bytes, archive_name: str = "archive.zip") -> Tuple[List[Finding], List[str], List[Dict[str, str]]]:
    """
    Scan ZIP archive in-memory with path traversal protection,
    zip bomb prevention, and file size quotas.
    """
    findings: List[Finding] = []
    scanned_files: List[str] = []
    skipped_files: List[Dict[str, str]] = []

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            total_uncompressed = sum(info.file_size for info in z.infolist())

            # Zip bomb checks
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED:
                skipped_files.append({
                    "file": archive_name,
                    "reason": f"Archive uncompressed size ({total_uncompressed} bytes) exceeds limit ({MAX_ZIP_UNCOMPRESSED} bytes)."
                })
                return (findings, scanned_files, skipped_files)

            if len(z.infolist()) > MAX_ZIP_FILES:
                skipped_files.append({
                    "file": archive_name,
                    "reason": f"Archive contains {len(z.infolist())} files, exceeding limit ({MAX_ZIP_FILES})."
                })
                return (findings, scanned_files, skipped_files)

            for info in z.infolist():
                if info.is_dir():
                    continue

                # Path traversal protection
                norm_fn = os.path.normpath(info.filename)
                if os.path.isabs(norm_fn) or ".." in Path(norm_fn).parts:
                    skipped_files.append({"file": info.filename, "reason": "Path traversal attempt detected in archive."})
                    continue

                # Compression ratio check
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_ZIP_RATIO:
                        skipped_files.append({"file": info.filename, "reason": f"Suspicious compression ratio ({ratio:.1f}x) rejected."})
                        continue

                # Extension & directory filters
                parts = info.filename.replace("\\", "/").split("/")
                if any(p in EXCLUDED_DIRS for p in parts[:-1]):
                    continue

                filename_lower = parts[-1].lower()
                ext = "." + filename_lower.rsplit(".", 1)[-1] if "." in filename_lower else ""

                if ext not in SUPPORTED_EXTENSIONS and filename_lower not in SPECIAL_FILENAMES:
                    skipped_files.append({"file": info.filename, "reason": "Unsupported file format."})
                    continue

                if info.file_size > MAX_FILE_SIZE:
                    skipped_files.append({"file": info.filename, "reason": "File size exceeds 10 MB limit."})
                    continue

                try:
                    with z.open(info) as f:
                        file_bytes = f.read()
                        if is_binary_file(file_bytes):
                            skipped_files.append({"file": info.filename, "reason": "Binary file skipped."})
                            continue
                        content = file_bytes.decode("utf-8", errors="replace")
                        display_path = f"{archive_name} > {info.filename}"
                        file_findings = scan_text_content(content, filepath=display_path)
                        findings.extend(file_findings)
                        scanned_files.append(display_path)
                except Exception as e:
                    skipped_files.append({"file": info.filename, "reason": f"Failed to read file: {str(e)}"})

    except zipfile.BadZipFile:
        skipped_files.append({"file": archive_name, "reason": "Corrupted or invalid ZIP archive."})
    except Exception as e:
        skipped_files.append({"file": archive_name, "reason": f"ZIP processing error: {str(e)}"})

    return (findings, scanned_files, skipped_files)


def scan_single_file(filepath: str) -> Tuple[List[Finding], List[str], List[Dict[str, str]]]:
    """Scan a single local file safely."""
    p = Path(filepath)
    if not p.is_file():
        return ([], [], [{"file": filepath, "reason": "File not found."}])

    # Symlink safety check: ensure target is within allowed scope
    try:
        if p.is_symlink() and not p.resolve().exists():
            return ([], [], [{"file": filepath, "reason": "Broken symbolic link."}])
    except Exception:
        pass

    try:
        if p.stat().st_size > MAX_FILE_SIZE:
            return ([], [], [{"file": filepath, "reason": "File exceeds 10 MB size limit."}])
    except OSError as e:
        return ([], [], [{"file": filepath, "reason": f"OS error: {e}"}])

    ext = p.suffix.lower()
    if ext == ".zip":
        try:
            with open(p, "rb") as f:
                return scan_zip_archive(f.read(), archive_name=p.name)
        except Exception as e:
            return ([], [], [{"file": filepath, "reason": f"Unable to read archive: {e}"}])

    if ext not in SUPPORTED_EXTENSIONS and p.name.lower() not in SPECIAL_FILENAMES:
        return ([], [], [{"file": filepath, "reason": "Unsupported file format."}])

    try:
        with open(p, "rb") as f:
            sample_bytes = f.read()
            if is_binary_file(sample_bytes):
                return ([], [], [{"file": filepath, "reason": "Binary file skipped."}])
            content = sample_bytes.decode("utf-8", errors="replace")
            findings = scan_text_content(content, filepath=str(p))
            return (findings, [normalize_path(str(p))], [])
    except Exception as e:
        return ([], [], [{"file": filepath, "reason": f"Read failure: {str(e)}"}])


def scan_directory_tree(dirpath: str, max_depth: int = MAX_RECURSION_DEPTH) -> Tuple[List[Finding], List[str], List[Dict[str, str]]]:
    """Scan a directory tree recursively with limits."""
    root = Path(dirpath)
    if not root.is_dir():
        return ([], [], [{"file": dirpath, "reason": "Not a directory."}])

    all_findings: List[Finding] = []
    scanned_files: List[str] = []
    skipped_files: List[Dict[str, str]] = []

    root_depth = len(root.resolve().parts)

    for item in sorted(root.rglob("*")):
        try:
            # Recursion depth limit
            if len(item.resolve().parts) - root_depth > max_depth:
                skipped_files.append({"file": str(item), "reason": f"Exceeded max recursion depth ({max_depth})."})
                continue

            # Excluded directories
            if any(p in EXCLUDED_DIRS for p in item.parts):
                continue

            if item.is_file():
                f_list, sc_list, sk_list = scan_single_file(str(item))
                all_findings.extend(f_list)
                scanned_files.extend(sc_list)
                skipped_files.extend(sk_list)
        except Exception as e:
            skipped_files.append({"file": str(item), "reason": f"Traversal error: {e}"})

    return (all_findings, scanned_files, skipped_files)


def create_scan_report(
    findings: List[Finding],
    scanned_files: List[str],
    skipped_files: List[Dict[str, str]],
    duration: float = 0.0,
    raw_findings_count: Optional[int] = None,
) -> ScanReport:
    """Construct a full ScanReport model with aggregated metrics."""
    grouped = group_findings(findings)
    total_findings = len(findings)
    unique_secrets = len(grouped)
    exposure_occurrences = sum(len(g["occurrences"]) for g in grouped)
    duplicates_removed = (raw_findings_count - total_findings) if raw_findings_count and raw_findings_count > total_findings else 0

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    cat_counts: Dict[str, int] = {}
    placeholder_count = 0

    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        if f.is_placeholder:
            placeholder_count += 1

    return ScanReport(
        total_findings=total_findings,
        unique_secrets=unique_secrets,
        exposure_occurrences=exposure_occurrences,
        duplicates_removed=duplicates_removed,
        files_scanned=scanned_files,
        files_skipped=skipped_files,
        placeholder_count=placeholder_count,
        findings_by_severity=sev_counts,
        findings_by_category=cat_counts,
        scan_duration_seconds=round(duration, 3),
        findings=[f.to_dict() for f in findings],
        grouped=grouped,
    )


# ---------------------------------------------------------------------------
# Backwards Compatibility API
# ---------------------------------------------------------------------------
def scan_text(content: str, source_name: str = "Input") -> List[Dict[str, Any]]:
    findings = scan_text_content(content, filepath=source_name)
    return [f.to_dict() for f in findings]


def scan_file(filepath: str) -> List[Dict[str, Any]]:
    findings, _, _ = scan_single_file(filepath)
    return [f.to_dict() for f in findings]


def scan_directory(dirpath: str) -> List[Dict[str, Any]]:
    findings, _, _ = scan_directory_tree(dirpath)
    return [f.to_dict() for f in findings]


def scan_zip_bytes(zip_bytes: bytes, zip_name: str = "archive.zip") -> List[Dict[str, Any]]:
    findings, _, _ = scan_zip_archive(zip_bytes, archive_name=zip_name)
    return [f.to_dict() for f in findings]


def group_findings_by_secret(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    typed_findings = []
    for f in findings:
        if isinstance(f, Finding):
            typed_findings.append(f)
        else:
            typed_findings.append(Finding(
                finding_id=f.get("finding_id", ""),
                rule_id=f.get("rule_id", f.get("pattern_id", "GENERIC")),
                rule_title=f.get("rule_title", f.get("label", "Secret")),
                category=f.get("category", "General"),
                severity=f.get("severity", "Medium"),
                confidence=f.get("confidence", "Medium"),
                confidence_reason=f.get("confidence_reason", ""),
                is_placeholder=f.get("is_placeholder", False),
                placeholder_status=f.get("placeholder_status", "Live Candidate"),
                context_type=f.get("context_type", "Source Code"),
                file_path=normalize_path(f.get("file_path", f.get("source", "input"))),
                line=f.get("line", 1),
                column=f.get("column", 1),
                raw_secret=f.get("raw_secret", ""),
                masked_secret=f.get("masked_secret", f.get("redacted_secret", "****")),
                secret_hash=f.get("secret_hash", f.get("fingerprint", "")),
                entropy=f.get("entropy", 0.0),
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation", ""),
                snippet=f.get("snippet", ""),
                legacy_id=f.get("legacy_id", f.get("pattern_id", "")),
            ))
    return group_findings(typed_findings)

"""
Comprehensive Test Suite for Credential Detector v2.0
Covers Positive cases, Negative cases, Severity vs. Confidence separation,
Context-Aware Classification, and Cross-File Deduplication.
"""

import io
import unittest
import zipfile
from detector import (
    scan_text,
    scan_zip_bytes,
    calc_entropy,
    is_placeholder,
    classify_context,
    group_findings_by_secret,
)


class TestPositiveDetections(unittest.TestCase):
    """Verify that genuine credentials in real formats are detected."""

    def test_aws_access_key(self):
        sample = "export AWS_ACCESS_KEY_ID=" + "AKIA" + "Z7X9Y1A2B3C4D5E6"
        findings = scan_text(sample, source_name="prod.env")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["pattern_id"], "aws-access-key")
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertEqual(findings[0]["confidence"], "High")

    def test_database_url_credentials(self):
        sample = "DATABASE_URL=postgresql://db_admin:K9#mQ2$vL8@prod-db.internal:5432/core"
        findings = scan_text(sample, source_name="config/database.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["pattern_id"], "db-connection-string")
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertEqual(findings[0]["confidence"], "High")

    def test_github_pat(self):
        sample = "GITHUB_TOKEN=" + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
        findings = scan_text(sample, source_name="deploy.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["pattern_id"], "github-pat")
        self.assertEqual(findings[0]["severity"], "High")

    def test_natural_language_gmail_password(self):
        sample = "User: my gmail password is P@ssw0rd_Secure_99!"
        findings = scan_text(sample, source_name="chat_export.log")
        self.assertTrue(any(f["pattern_id"] == "gmail-password" for f in findings))


class TestNegativeDetections(unittest.TestCase):
    """Verify that placeholders, safe documentation, and low-entropy values are rejected."""

    def test_placeholder_suppression(self):
        sample = """
        const db_pass = "your_password_here";
        const apiKey = "<api_key>";
        const token = "TODO_INSERT_TOKEN_HERE";
        """
        findings = scan_text(sample, source_name="sample.js")
        self.assertEqual(len(findings), 0)

    def test_normal_english_prose(self):
        sample = "Always choose a strong password that is difficult to guess."
        findings = scan_text(sample, source_name="guide.md")
        self.assertEqual(len(findings), 0)

    def test_low_entropy_rejection(self):
        # Even with a secret assignment, low entropy repetitive strings are ignored
        sample = 'const secret_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
        findings = scan_text(sample, source_name="code.js")
        self.assertEqual(len(findings), 0)


class TestSeverityAndConfidenceSeparation(unittest.TestCase):
    """Ensure confidence and severity are measured independently."""

    def test_test_keys_have_low_severity(self):
        # A test Stripe key has High confidence (we are confident it's a Stripe test key)
        # but Low severity (it cannot charge real money)
        sample = "STRIPE_KEY=" + "sk_" + "test_" + "1234567890abcdefghijklmn"
        findings = scan_text(sample, source_name="config.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Low")
        self.assertIn(findings[0]["confidence"], ("High", "Medium"))

    def test_credential_in_test_file_downgraded_severity(self):
        # A credential in a test folder should be downgraded from Critical to Medium/Low
        # to prevent alert fatigue
        sample = "AWS_KEY=" + "AKIA" + "Z7X9Y1A2B3C4D5E6"
        findings = scan_text(sample, source_name="tests/unit/test_auth.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["context_type"], "Documentation / Test")
        self.assertEqual(findings[0]["confidence"], "Low")
        self.assertEqual(findings[0]["severity"], "Medium")  # Downgraded from Critical


class TestContextClassification(unittest.TestCase):
    """Verify automatic classification of files by purpose."""

    def test_classify_contexts(self):
        self.assertEqual(classify_context("src/config/.env"), "Configuration")
        self.assertEqual(classify_context("server.js"), "Source Code")
        self.assertEqual(classify_context("history.log"), "Log / Conversation")
        self.assertEqual(classify_context("tests/test_login.py"), "Documentation / Test")
        self.assertEqual(classify_context("README.md"), "Documentation / Test")


class TestDeduplicationAndGrouping(unittest.TestCase):
    """Verify cross-file duplicate detection and grouping."""

    def test_duplicate_secret_grouping(self):
        token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
        content1 = f"TOKEN={token}"
        content2 = f"# duplicate in another file\nAUTH={token}"

        f1 = scan_text(content1, source_name="src/app.py")
        f2 = scan_text(content2, source_name="config/deploy.yml")

        all_findings = f1 + f2
        self.assertEqual(len(all_findings), 2)

        grouped = group_findings_by_secret(all_findings)
        self.assertEqual(len(grouped), 1)  # Grouped into 1 distinct secret
        self.assertEqual(len(grouped[0]["occurrences"]), 2)
        sources = [occ["source"] for occ in grouped[0]["occurrences"]]
        self.assertIn("src/app.py", sources)
        self.assertIn("config/deploy.yml", sources)


class TestZipArchiveScanning(unittest.TestCase):
    """Verify zip archive in-memory scanning."""

    def test_zip_scan(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("src/.env", "DATABASE_URL=postgres://user:SecretDbPass99@db.local:5432/app\n")
            z.writestr("docs/setup.md", "# Guide\nNothing to see here.\n")

        findings = scan_zip_bytes(buf.getvalue(), zip_name="codebase.zip")
        self.assertEqual(len(findings), 1)
        self.assertIn("codebase.zip > src/.env", findings[0]["source"])
        self.assertEqual(findings[0]["pattern_id"], "db-connection-string")


if __name__ == "__main__":
    unittest.main()

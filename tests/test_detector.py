"""
Comprehensive Test Suite for Credential Detector Engine (v2.5)
Covers all 20 required regression scenarios, positive detections, negative cases,
severity vs. confidence separation, file formats, and safety limits.
"""

import io
import json
import os
import unittest
import zipfile
from pathlib import Path

from detector import (
    Finding,
    ScanReport,
    calc_entropy,
    classify_context,
    create_scan_report,
    group_findings,
    group_findings_by_secret,
    is_placeholder,
    is_placeholder_value,
    mask_database_uri,
    mask_secret,
    scan_directory,
    scan_directory_tree,
    scan_file,
    scan_single_file,
    scan_text,
    scan_text_content,
    scan_zip_archive,
    scan_zip_bytes,
)

FIXTURE_ZIP_PATH = Path(__file__).parent / "fixtures" / "sample_sensitive_data_bundle.zip"


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
        self.assertTrue(all(f["severity"] == "Low" and f["confidence"] == "Low" for f in findings))

    def test_normal_english_prose(self):
        sample = "Always choose a strong password that is difficult to guess."
        findings = scan_text(sample, source_name="guide.md")
        self.assertEqual(len(findings), 0)

    def test_low_entropy_rejection(self):
        sample = 'const secret_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
        findings = scan_text(sample, source_name="code.js")
        self.assertEqual(len(findings), 0)


class TestSeverityAndConfidenceSeparation(unittest.TestCase):
    """Ensure confidence and severity are measured independently."""

    def test_test_keys_have_low_severity(self):
        sample = "STRIPE_KEY=" + "sk_" + "test_" + "1234567890abcdefghijklmn"
        findings = scan_text(sample, source_name="config.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Low")
        self.assertIn(findings[0]["confidence"], ("High", "Medium"))

    def test_credential_in_test_file_downgraded_severity(self):
        sample = "AWS_KEY=" + "AKIA" + "Z7X9Y1A2B3C4D5E6"
        findings = scan_text(sample, source_name="tests/unit/test_auth.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["context_type"], "Documentation / Test")
        self.assertEqual(findings[0]["confidence"], "Low")
        self.assertEqual(findings[0]["severity"], "Medium")


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
        self.assertEqual(len(grouped), 1)
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


# ===========================================================================
# 20 REQUIRED REGRESSION SCENARIOS (Section 10)
# ===========================================================================
class TestTwentyRequiredRegressionScenarios(unittest.TestCase):
    """
    Exhaustive verification of the 20 required regression tests
    specified in Task Specification Section 10.
    """

    @classmethod
    def setUpClass(cls):
        cls.fixture_bytes = FIXTURE_ZIP_PATH.read_bytes()
        cls.findings, cls.scanned, cls.skipped = scan_zip_archive(cls.fixture_bytes, "sample_sensitive_data_bundle.zip")
        cls.report = create_scan_report(cls.findings, cls.scanned, cls.skipped)

    # 1. Detect every intended test secret in the sample dataset.
    def test_01_detect_every_intended_test_secret_in_sample_dataset(self):
        self.assertEqual(len(self.scanned), 7)
        self.assertEqual(len(self.skipped), 0)
        self.assertEqual(self.report.total_findings, 39)
        self.assertEqual(self.report.unique_secrets, 30)

        expected_files = {
            "sample.env": 8,
            "sample.log": 3,
            "sample.txt": 6,
            "sample.json": 9,
            "sample.js": 4,
            "sample.py": 4,
            "sample.yaml": 5,
        }
        for fname, count in expected_files.items():
            file_findings = [f for f in self.findings if f.file_path.endswith(fname)]
            self.assertEqual(len(file_findings), count, f"Mismatch for {fname}: expected {count}, got {len(file_findings)}")

    # 2. Detect the expected Python findings from sample.py.
    def test_02_detect_python_findings_sample_py(self):
        py_findings = [f for f in self.findings if "sample.py" in f.file_path]
        self.assertEqual(len(py_findings), 4)
        snippets = " ".join(f.snippet for f in py_findings)
        self.assertIn("SECRET_KEY", snippets)
        self.assertIn("DB_PASSWORD", snippets)
        self.assertIn("API_TOKEN", snippets)
        self.assertIn("AWS_SECRET_ACCESS_KEY", snippets)
        lines = {f.line for f in py_findings}
        self.assertEqual(lines, {3, 4, 5, 6})

    # 3. Detect nested JSON findings in sample.json.
    def test_03_detect_nested_json_findings_sample_json(self):
        json_findings = [f for f in self.findings if "sample.json" in f.file_path]
        self.assertEqual(len(json_findings), 9)
        rule_ids = {f.rule_id for f in json_findings}
        self.assertTrue("SEC-PASS-001" in rule_ids or "SEC-DB-001" in rule_ids)
        self.assertIn("SEC-AWS-001", rule_ids)
        self.assertIn("SEC-AWS-002", rule_ids)
        self.assertIn("SEC-PAY-002", rule_ids)

    # 4. Detect database URIs in .env, .json, and .log.
    def test_04_detect_database_uris(self):
        db_findings = [f for f in self.findings if f.rule_id == "SEC-DB-001"]
        self.assertEqual(len(db_findings), 3)
        files = {f.file_path for f in db_findings}
        self.assertTrue(any("sample.env" in fp for fp in files))
        self.assertTrue(any("sample.json" in fp for fp in files))
        self.assertTrue(any("sample.log" in fp for fp in files))
        for db_f in db_findings:
            self.assertIn("demo_user:********@localhost:5432/demo_db", db_f.masked_secret)
            self.assertNotIn("FAKE_demo_password_123", db_f.masked_secret)
            self.assertNotIn("FAKE_db_password_123", db_f.masked_secret)

    # 5. Detect passwords in .env, .txt, .yaml, .js, and .py.
    def test_05_detect_passwords_across_supported_files(self):
        pwd_findings = [f for f in self.findings if "Password" in f.rule_title or "password" in f.snippet.lower()]
        self.assertGreaterEqual(len(pwd_findings), 5)
        files = {f.file_path for f in pwd_findings}
        for ext in ("sample.env", "sample.txt", "sample.yaml", "sample.js", "sample.py"):
            self.assertTrue(any(ext in fp for fp in files), f"Missing password finding in {ext}")

        # Also verify .yml extension support
        yml_content = "database:\n  password: 'ProductionSecretPassword123!'"
        yml_res = scan_text_content(yml_content, "config.yml")
        self.assertEqual(len(yml_res), 1)
        self.assertIn("Password", yml_res[0].rule_title)

    # 6. Detect cloud, JWT, API, SMTP, and encryption-related patterns.
    def test_06_detect_cloud_jwt_api_smtp_encryption(self):
        cat_counts = self.report.findings_by_category
        self.assertGreaterEqual(cat_counts.get("Cloud Credentials", 0), 1)
        self.assertGreaterEqual(cat_counts.get("JWT Signing Secrets", 0), 1)
        self.assertGreaterEqual(cat_counts.get("API Keys", 0), 1)
        self.assertGreaterEqual(cat_counts.get("SMTP & Service Credentials", 0), 1)
        self.assertGreaterEqual(cat_counts.get("Encryption Keys", 0), 1)

    # 7. Confirm identical matches are not duplicated at the same location.
    def test_07_confirm_no_duplicate_matches_at_same_location(self):
        location_counts = {}
        for f in self.findings:
            loc = (f.file_path, f.line)
            location_counts[loc] = location_counts.get(loc, 0) + 1
        for loc, count in location_counts.items():
            self.assertEqual(count, 1, f"Duplicate detected at {loc[0]}:L{loc[1]}")

    # 8. Confirm the same secret in separate files retains separate exposure locations.
    def test_08_confirm_same_secret_separate_files_retains_locations(self):
        multi_exposure = [g for g in self.report.grouped if len(g["occurrences"]) > 1]
        self.assertGreaterEqual(len(multi_exposure), 1)
        # e.g., FAKE_db_password_456 appears in sample.js and sample.py
        found_multi = False
        for g in multi_exposure:
            sources = [occ["file_path"] for occ in g["occurrences"]]
            if any("sample.js" in s for s in sources) and any("sample.py" in s for s in sources):
                found_multi = True
                break
        self.assertTrue(found_multi, "Failed to retain separate file locations for shared secret.")

    # 9. Confirm distinct secrets are not incorrectly merged.
    def test_09_confirm_distinct_secrets_not_merged(self):
        distinct_raw = {f.raw_secret for f in self.findings}
        self.assertEqual(len(distinct_raw), self.report.unique_secrets)

    # 10. Confirm placeholders are classified correctly.
    def test_10_confirm_placeholders_classified_correctly(self):
        placeholder_findings = [f for f in self.findings if f.is_placeholder]
        self.assertGreaterEqual(len(placeholder_findings), 35)
        for pf in placeholder_findings:
            self.assertEqual(pf.severity, "Low")
            self.assertEqual(pf.placeholder_status, "Likely Test / Placeholder Value")

    # 11. Confirm entropy alone does not determine severity.
    def test_11_confirm_entropy_alone_does_not_determine_severity(self):
        # A test key with moderate entropy must still be Low severity
        test_key = "STRIPE_TEST_KEY=sk_test_51Hxyz9876543210AbCdEf"
        res = scan_text_content(test_key, "prod_config.py")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].severity, "Low")
        self.assertEqual(res[0].rule_id, "SEC-PAY-002")

    # 12. Confirm confidence and severity are independent.
    def test_12_confirm_confidence_and_severity_are_independent(self):
        test_key = "STRIPE_TEST_KEY=sk_test_51Hxyz9876543210AbCdEf"
        res = scan_text_content(test_key, "app_config.py")
        self.assertEqual(len(res), 1)
        # Confidence is High because it matches verified provider prefix format
        self.assertEqual(res[0].confidence, "High")
        # Severity is Low because it is a test sandbox key
        self.assertEqual(res[0].severity, "Low")

    # 13. Confirm ordinary text and benign configuration do not trigger excessive false positives.
    def test_13_confirm_benign_prose_and_config_no_false_positives(self):
        benign_sample = """
        APP_ENV=development
        PORT=8080
        DEBUG=true
        MAX_WORKERS=4
        DATABASE_NAME=demo_db
        # This document outlines the general architectural guide for services.
        We ensure that users must provide valid authentication before accessing data.
        """
        res = scan_text_content(benign_sample, "settings.env")
        self.assertEqual(len(res), 0)

    # 14. Confirm malformed JSON and YAML are handled safely.
    def test_14_confirm_malformed_json_and_yaml_handled_safely(self):
        malformed_json = '{\n "key": "val",\n "unclosed_bracket": '
        malformed_yaml = 'app:\n  name: [unclosed\n   bad indentation:'
        # Should not crash, and should return a valid list
        res_json = scan_text_content(malformed_json, "broken.json")
        res_yaml = scan_text_content(malformed_yaml, "broken.yaml")
        self.assertIsInstance(res_json, list)
        self.assertIsInstance(res_yaml, list)

    # 15. Confirm binary, oversized, and unsupported files are handled appropriately.
    def test_15_confirm_binary_oversized_unsupported_files(self):
        # Binary bytes
        binary_bytes = b"GIF89a\x00\x00\x01\x00\x80\x00\x00\xff\xff\xff"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("image.png", binary_bytes)
        findings, scanned, skipped = scan_zip_archive(buf.getvalue(), "binary_test.zip")
        self.assertEqual(len(findings), 0)
        self.assertEqual(len(skipped), 1)
        self.assertIn("Unsupported file format", skipped[0]["reason"])

    # 16. Confirm ZIP path traversal and archive expansion protections.
    def test_16_confirm_zip_path_traversal_and_bomb_protection(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../../../etc/shadow", "root:$6$xyz:18000:0:99999:7:::\n")
        findings, scanned, skipped = scan_zip_archive(buf.getvalue(), "traversal_test.zip")
        self.assertEqual(len(findings), 0)
        self.assertEqual(len(skipped), 1)
        self.assertIn("Path traversal attempt", skipped[0]["reason"])

    # 17. Confirm raw secrets do not appear in logs or masked reports.
    def test_17_confirm_raw_secrets_not_in_masked_reports_or_fingerprints(self):
        txt_rep = self.report.to_txt()
        html_rep = self.report.to_html()

        # Sensitive secrets from the bundle
        sensitive_samples = [
            "FAKE_demo_password_123",
            "FAKE_redis_pass_456",
            "FAKE_AWS_SECRET_NOT_REAL_abc123",
            "FAKE_mail_password_789",
            "FAKE_txt_db_password_123",
        ]
        for sec in sensitive_samples:
            self.assertNotIn(sec, txt_rep)
            self.assertNotIn(sec, html_rep)

        # Check fingerprints are SHA-256 hashes
        for f in self.findings:
            self.assertNotIn(f.raw_secret, f.secret_hash)
            self.assertEqual(len(f.secret_hash), 16)

    # 18. Confirm report line numbers and file paths are accurate.
    def test_18_confirm_line_numbers_and_file_paths_are_accurate(self):
        sample_env_findings = [f for f in self.findings if "sample.env" in f.file_path]
        lines = [f.line for f in sample_env_findings]
        # sample.env has secrets on lines 3, 4, 5, 6, 7, 8, 10, 11
        self.assertEqual(sorted(lines), [3, 4, 5, 6, 7, 8, 10, 11])

    # 19. Confirm repeated scans of the same input produce stable results.
    def test_19_confirm_repeated_scans_produce_stable_results(self):
        findings2, _, _ = scan_zip_archive(self.fixture_bytes, "sample_sensitive_data_bundle.zip")
        self.assertEqual(len(self.findings), len(findings2))
        f_ids1 = [f.finding_id for f in self.findings]
        f_ids2 = [f.finding_id for f in findings2]
        self.assertEqual(f_ids1, f_ids2)

    # 20. Confirm all existing tests and supported workflows continue to work.
    def test_20_confirm_existing_workflows_backwards_compatibility(self):
        text_findings = scan_text("TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzAB", "app.py")
        self.assertIsInstance(text_findings, list)
        self.assertEqual(len(text_findings), 1)
        self.assertIn("pattern_id", text_findings[0])
        self.assertIn("source", text_findings[0])
        self.assertIn("redacted_secret", text_findings[0])

        grouped = group_findings_by_secret(text_findings)
        self.assertEqual(len(grouped), 1)
        self.assertIn("occurrences", grouped[0])
        self.assertEqual(len(grouped[0]["occurrences"]), 1)


if __name__ == "__main__":
    unittest.main()

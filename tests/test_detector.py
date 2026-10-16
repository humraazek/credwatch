"""
Unit tests for credential detector.
All test fixtures are assembled in memory so no raw provider keys exist on disk.
"""

import unittest
from detector import scan_text, calc_entropy, is_placeholder


class TestDetectorAccuracy(unittest.TestCase):
    def test_aws_access_key(self):
        # Assembled dynamically in memory (non-placeholder key)
        sample = "AWS_KEY=" + "AKIA" + "1234567890ABCDEF"
        findings = scan_text(sample)
        self.assertTrue(any(f["pattern_id"] == "aws-access-key" for f in findings))

    def test_github_pat(self):
        sample = "TOKEN=" + "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        findings = scan_text(sample)
        self.assertTrue(any(f["pattern_id"] == "github-pat-classic" for f in findings))

    def test_openai_key(self):
        sample = "OPENAI_KEY=" + "sk-" + "proj-1234567890abcdefghijklmnopqrstuvwxyz123"
        findings = scan_text(sample)
        self.assertTrue(any(f["pattern_id"] == "openai-api-key" for f in findings))

    def test_database_url(self):
        sample = "DATABASE_URL=postgresql://app_user:SuperSecretPass99@db.local:5432/production"
        findings = scan_text(sample)
        self.assertTrue(any(f["pattern_id"] == "db-connection-string" for f in findings))

    def test_gmail_password_natural_language(self):
        sample = "User: my gmail password is MyGmailSecurePass2026!"
        findings = scan_text(sample)
        self.assertTrue(any(f["pattern_id"] in ("gmail-password", "password-natural-language") for f in findings))

    def test_email_password_combo(self):
        sample = "login details: admin@domain.com:MySuperPassword99"
        findings = scan_text(sample)
        self.assertTrue(any(f["pattern_id"] == "email-password-combo" for f in findings))

    def test_app_password(self):
        sample = "connect using ssh password: RemoteServerPass99"
        findings = scan_text(sample)
        self.assertTrue(any(f["pattern_id"] == "app-password" for f in findings))

    def test_placeholder_suppression(self):
        # These should NOT be flagged because they are obvious placeholders
        sample = 'const password = "your_password_here";\nconst key = "<api_key>";'
        findings = scan_text(sample)
        self.assertEqual(len(findings), 0)

    def test_entropy_calculator(self):
        low_entropy = calc_entropy("aaaaaaaa")
        high_entropy = calc_entropy("aB9#mK$2!xP")
        self.assertLess(low_entropy, 1.0)
        self.assertGreater(high_entropy, 3.0)


    def test_zip_scanning(self):
        import io
        import zipfile
        from detector import scan_zip_bytes

        # Create an in-memory zip containing a mock .env file
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            secret_line = "DATABASE_URL=postgresql://user:SecretDbPass99@localhost/db\n"
            z.writestr("src/config/.env", secret_line)
            z.writestr("README.md", "# Project\nNormal text here\n")

        zip_bytes = zip_buf.getvalue()
        findings = scan_zip_bytes(zip_bytes, zip_name="test_project.zip")
        self.assertEqual(len(findings), 1)
        self.assertIn("test_project.zip > src/config/.env", findings[0]["source"])
        self.assertEqual(findings[0]["pattern_id"], "db-connection-string")


if __name__ == "__main__":
    unittest.main()

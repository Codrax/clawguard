"""End-to-end: the real CLI, against the fake API, in temporary folders."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from clawguard.cli import main

from fake_api import AGENT_KEY, USER_KEY, VAULT_ID, FakeOneClaw

SECRET = "sk_test_51HxYzAbCdEfGhIjKlMn"


class CliTest(unittest.TestCase):
    def setUp(self):
        self.api = FakeOneClaw().__enter__()
        self.api.add("stripe/secret", SECRET, created_at="2025-06-01T00:00:00Z")
        self.api.add("github/token", "ghp_0123456789abcdefghij", expires_at="2026-01-01T00:00:00Z")
        self.tmp = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"ONECLAW_API_KEY": USER_KEY, "ONECLAW_API_URL": self.api.url,
                                                "ONECLAW_VAULT_ID": VAULT_ID, "NO_COLOR": "1"}, clear=False)
        self.env.start()
        for k in ("ONECLAW_TOKEN", "ONECLAW_AGENT_ID"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.env.stop()
        os.chdir(self.old_cwd)
        self.tmp.cleanup()
        self.api.__exit__()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def write(self, rel, text):
        os.makedirs(os.path.dirname(rel) or ".", exist_ok=True)
        with open(rel, "w") as f:
            f.write(text)

    # ---------- scan ----------
    def test_scan_clean(self):
        self.write("app.py", "import os\nKEY = os.environ['STRIPE']\n")
        code, out, err = self.run_cli("scan")
        self.assertEqual(code, 0)
        self.assertIn("No vault secrets found", out)
        self.assertIn("read 2 secret(s) from 1 vault(s)", err)

    def test_scan_leak_never_prints_value(self):
        self.write("src/app.py", f"\nKEY = '{SECRET}'\n")
        code, out, err = self.run_cli("scan")
        self.assertEqual(code, 1)
        self.assertIn("src/app.py:2", out)
        self.assertIn("stripe/secret", out)
        self.assertNotIn(SECRET, out + err)

    def test_scan_json_and_sarif(self):
        self.write("a.txt", SECRET)
        code, out, _ = self.run_cli("scan", "-f", "json", "-q")
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertEqual(doc["findings"][0]["secret"], "stripe/secret")
        self.assertNotIn(SECRET, out)

        code, _, err = self.run_cli("scan", "-f", "sarif", "-o", "report.sarif")
        with open("report.sarif") as f:
            sarif = json.load(f)
        self.assertEqual(sarif["version"], "2.1.0")
        res = sarif["runs"][0]["results"][0]
        self.assertEqual(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "a.txt")
        self.assertIn("written to report.sarif", err)
        # the report itself must not trip the next scan
        os.remove("a.txt")
        self.assertEqual(self.run_cli("scan", "-q")[0], 0)

    def test_scan_prefix_limits_reads(self):
        self.write("a.txt", SECRET)
        code, _, err = self.run_cli("scan", "--prefix", "github/")
        self.assertEqual(code, 0)
        self.assertEqual(self.api.count("GET", f"/v1/vaults/{VAULT_ID}/secrets/stripe"), 0)

    def test_scan_skips_unreadable_and_cmek(self):
        self.api.forbidden.add((VAULT_ID, "github/token"))
        self.api.add("enc/x", "ciphertext-blob-123", cmek=True)
        code, _, err = self.run_cli("scan")
        self.assertIn("2 not readable", err)

    def test_scan_agent_key(self):
        os.environ["ONECLAW_API_KEY"] = AGENT_KEY
        os.environ.pop("ONECLAW_VAULT_ID")
        self.write("a.txt", SECRET)
        self.assertEqual(self.run_cli("scan", "-q")[0], 1)

    # ---------- audit ----------
    def test_audit_text(self):
        code, out, err = self.run_cli("audit")
        self.assertEqual(code, 1)  # github/token expired
        self.assertIn("EXPIRED", out)
        self.assertIn("STALE", out)
        self.assertIn("no values read", err)
        self.assertEqual(self.api.count("GET", f"/v1/vaults/{VAULT_ID}/secrets/"), 0)

    def test_audit_fail_on(self):
        self.assertEqual(self.run_cli("audit", "--fail-on", "none", "-q")[0], 0)
        self.assertEqual(self.run_cli("audit", "--fail-on", "bogus", "-q")[0], 2)

    def test_audit_markdown_and_json(self):
        _, out, _ = self.run_cli("audit", "-f", "markdown", "-q")
        self.assertIn("| Status | Secret |", out)
        _, out, _ = self.run_cli("audit", "-f", "json", "-q")
        self.assertEqual({s["status"] for s in json.loads(out)["secrets"]}, {"expired", "stale"})

    # ---------- vaults / errors ----------
    def test_vaults(self):
        code, out, _ = self.run_cli("vaults")
        self.assertEqual(code, 0)
        self.assertIn("app", out)

    def test_no_key(self):
        os.environ.pop("ONECLAW_API_KEY")
        code, _, err = self.run_cli("scan")
        self.assertEqual(code, 2)
        self.assertIn("ONECLAW_API_KEY", err)

    def test_rejected_key(self):
        os.environ["ONECLAW_API_KEY"] = "1ck_wrong_" + "z" * 30
        code, _, err = self.run_cli("audit")
        self.assertEqual(code, 3)
        self.assertIn("HTTP 401", err)


if __name__ == "__main__":
    unittest.main()

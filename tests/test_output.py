import io
import json
import unittest

from clawguard import __version__
from clawguard.audit import AuditRow
from clawguard.output import (RULE_ID, Style, audit_json, audit_markdown, audit_text, scan_json, scan_sarif,
                              scan_text, where)
from clawguard.scan import Finding

WORKTREE = Finding("src/app.py", 12, "stripe/secret", "app", "raw")
STAGED = Finding("settings.py", 3, "db/password", "app", "url", "staged")
HISTORY = Finding("config.yml", 2, "github/token", "app", "base64", "history", "3f9c2ab")


def render(fn, *args, **kw):
    buf = io.StringIO()  # not a tty, so no colour codes
    fn(*args, buf, **kw)
    return buf.getvalue()


def row(path, status, reason="", version=1, age=10):
    return AuditRow("app", path, "api_key", version, age, None, status, reason)


class WhereTest(unittest.TestCase):
    def test_locations(self):
        self.assertEqual(where(WORKTREE), "src/app.py:12")
        self.assertEqual(where(STAGED), "settings.py:3 (staged)")
        self.assertEqual(where(HISTORY), "config.yml:2 @ 3f9c2ab")
        self.assertEqual(where(Finding("a", 1, "s", "v", "raw", "history")), "a:1 @ ?")


class StyleTest(unittest.TestCase):
    def test_off_is_plain(self):
        self.assertEqual(Style(False).red("x"), "x")

    def test_on_wraps(self):
        self.assertEqual(Style(True).red("x"), "\033[31mx\033[0m")


class ScanOutputTest(unittest.TestCase):
    def test_text_clean(self):
        self.assertIn("No vault secrets found", render(scan_text, []))

    def test_text_findings(self):
        out = render(scan_text, [WORKTREE, HISTORY])
        self.assertIn("LEAK  src/app.py:12", out)
        self.assertIn("(base64)", out)
        self.assertNotIn("(raw)", out)
        self.assertIn("2 finding(s), 2 distinct secret(s)", out)
        self.assertIn("git history", out)

    def test_text_no_history_hint_without_history(self):
        self.assertNotIn("git history", render(scan_text, [WORKTREE]))

    def test_json(self):
        doc = json.loads(render(scan_json, [WORKTREE, HISTORY]))
        self.assertEqual(doc["version"], __version__)
        self.assertEqual(doc["findings"][1]["commit"], "3f9c2ab")
        self.assertNotIn("commit", doc["findings"][0])

    def test_json_round_trips_into_findings(self):
        # the GitHub Action rebuilds Finding objects from this JSON to write SARIF
        doc = json.loads(render(scan_json, [WORKTREE, STAGED, HISTORY]))
        self.assertEqual([Finding(**f) for f in doc["findings"]], [WORKTREE, STAGED, HISTORY])

    def test_sarif(self):
        doc = json.loads(render(scan_sarif, [WORKTREE, HISTORY]))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], RULE_ID)
        r0, r1 = run["results"]
        self.assertEqual(r0["locations"][0]["physicalLocation"]["region"]["startLine"], 12)
        self.assertIn("3f9c2ab", r1["message"]["text"])
        self.assertIn("base64", r1["message"]["text"])
        self.assertNotEqual(r0["partialFingerprints"], r1["partialFingerprints"])

    def test_sarif_empty(self):
        self.assertEqual(json.loads(render(scan_sarif, []))["runs"][0]["results"], [])


class AuditOutputTest(unittest.TestCase):
    ROWS = [row("gone", "expired", "expired 2 day(s) ago"), row("old", "stale", "written 200 days ago"),
            row("fine", "ok")]

    def test_text_hides_ok_by_default(self):
        out = render(audit_text, self.ROWS)
        self.assertIn("EXPIRED", out)
        self.assertNotIn("fine", out)
        self.assertIn("3 secret(s): 1 expired, 1 stale, 1 ok", out)

    def test_text_show_ok(self):
        self.assertIn("fine", render(audit_text, self.ROWS, show_ok=True))

    def test_text_empty_vault(self):
        self.assertEqual(render(audit_text, []), "0 secret(s): none\n")

    def test_markdown(self):
        out = render(audit_markdown, self.ROWS)
        self.assertTrue(out.startswith("## 1Claw vault audit"))
        self.assertIn("| 🔴 expired | `gone` |", out)
        self.assertEqual(out.count("\n| "), 4)  # header + three rows

    def test_json(self):
        doc = json.loads(render(audit_json, self.ROWS))
        self.assertEqual([s["status"] for s in doc["secrets"]], ["expired", "stale", "ok"])


if __name__ == "__main__":
    unittest.main()

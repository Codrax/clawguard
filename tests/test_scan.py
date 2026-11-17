import base64
import os
import subprocess
import tempfile
import unittest
import urllib.parse

from clawguard.scan import (Stats, build_needles, env_pairs, ignored, scan_bytes, scan_history, scan_staged,
                            scan_worktree, variants)

SECRET = "sk_test_51HxYzAbCdEfGhIjKlMn"
SECRETS = [("app", "stripe/secret", "api_key", SECRET)]


def needles(secrets=SECRETS, **kw):
    return build_needles(secrets, **kw)[0]


def sh(cwd, *args):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def git_repo(path):
    sh(path, "git", "init", "-q", "-b", "main")
    sh(path, "git", "config", "user.email", "test@example.invalid")
    sh(path, "git", "config", "user.name", "test")
    sh(path, "git", "config", "commit.gpgsign", "false")


def write(root, rel, text, mode="w"):
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full) or root, exist_ok=True)
    with open(full, mode) as f:
        f.write(text)


class NeedleTest(unittest.TestCase):
    def test_variants(self):
        v = variants(b"a+b/c=d?e&f")
        self.assertEqual(v["raw"], b"a+b/c=d?e&f")
        self.assertIn("url", v)
        self.assertEqual(base64.b64decode(v["base64"] + b"=" * (-len(v["base64"]) % 4)), b"a+b/c=d?e&f")

    def test_no_url_variant_when_identical(self):
        self.assertNotIn("url", variants(b"abcdefgh"))

    def test_short_values_skipped(self):
        n, short = build_needles([("v", "p", "password", "abc")])
        self.assertEqual((n, short), ([], 1))

    def test_env_type_split(self):
        text = "# comment\nexport DB_URL='postgres://u:longpassword@h/db'\nEMPTY=\nTOKEN=\"tok_1234567890\"\n"
        self.assertEqual(list(env_pairs(text))[0], ("DB_URL", "postgres://u:longpassword@h/db"))
        n, short = build_needles([("v", "prod/env", "env", text)], encodings=False)
        self.assertEqual({x.secret for x in n}, {"prod/env#DB_URL", "prod/env#TOKEN"})
        self.assertEqual(short, 1)

    def test_values_are_hidden_from_repr(self):
        self.assertNotIn(SECRET, repr(needles()))


class MatchTest(unittest.TestCase):
    def test_raw_match_and_line(self):
        data = f"a = 1\nkey = '{SECRET}'\n".encode()
        f = scan_bytes(data, needles(), "x.py")
        self.assertEqual([(x.file, x.line, x.secret, x.variant) for x in f], [("x.py", 2, "stripe/secret", "raw")])

    def test_base64_match(self):
        data = b"auth: " + base64.b64encode(SECRET.encode()) + b"\n"
        self.assertEqual(scan_bytes(data, needles(), "x")[0].variant, "base64")

    def test_url_encoded_match(self):
        value = "p@ss/word+with=chars"
        data = b"https://h/?k=" + urllib.parse.quote(value, safe="").encode()
        f = scan_bytes(data, needles([("app", "pw", "password", value)]), "x")
        self.assertEqual(f[0].variant, "url")

    def test_no_encodings_flag(self):
        data = base64.b64encode(SECRET.encode())
        self.assertEqual(scan_bytes(data, needles(encodings=False), "x"), [])

    def test_inline_allow(self):
        data = f"k = '{SECRET}'  # clawguard:allow test fixture\n".encode()
        self.assertEqual(scan_bytes(data, needles(), "x"), [])

    def test_one_finding_per_line(self):
        data = f"{SECRET} {SECRET}\n{SECRET}".encode()
        self.assertEqual([x.line for x in scan_bytes(data, needles(), "x")], [1, 2])

    def test_clean(self):
        self.assertEqual(scan_bytes(b"nothing here", needles(), "x"), [])


class IgnoreTest(unittest.TestCase):
    def test_patterns(self):
        self.assertTrue(ignored("tests/fixtures/a.txt", ["tests/fixtures/"]))
        self.assertTrue(ignored("deep/x.lock", ["*.lock"]))
        self.assertTrue(ignored("docs/a.md", ["docs/*"]))
        self.assertFalse(ignored("src/a.py", ["tests/", "*.lock"]))


class WorktreeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_plain_folder(self):
        write(self.root, "src/config.py", f"KEY = '{SECRET}'\n")
        write(self.root, "README.md", "clean\n")
        write(self.root, "node_modules/x.js", SECRET)
        write(self.root, "img.bin", b"\0\0" + SECRET.encode(), "wb")
        stats = Stats()
        f = scan_worktree(self.root, [], needles(), stats=stats)
        self.assertEqual([x.file for x in f], ["src/config.py"])
        self.assertEqual(stats.skipped_binary, 1)

    def test_size_limit(self):
        write(self.root, "big.txt", "x" * 2000 + SECRET)
        stats = Stats()
        self.assertEqual(scan_worktree(self.root, [], needles(), max_bytes=1000, stats=stats), [])
        self.assertEqual(stats.skipped_large, 1)

    def test_ignore_file_and_exclude(self):
        write(self.root, ".clawguardignore", "# fixtures\nfixtures/\n")
        write(self.root, "fixtures/a.txt", SECRET)
        write(self.root, "b.lock", SECRET)
        write(self.root, "c.txt", SECRET)
        f = scan_worktree(self.root, [], needles(), exclude=["*.lock"])
        self.assertEqual([x.file for x in f], ["c.txt"])

    def test_git_respects_gitignore(self):
        git_repo(self.root)
        write(self.root, ".gitignore", ".env\n")
        write(self.root, ".env", f"STRIPE={SECRET}\n")
        write(self.root, "app.py", f"k='{SECRET}'\n")
        write(self.root, "new_untracked.txt", SECRET)
        files = sorted(x.file for x in scan_worktree(self.root, [], needles()))
        self.assertEqual(files, ["app.py", "new_untracked.txt"])

    def test_paths_argument(self):
        write(self.root, "a/x.txt", SECRET)
        write(self.root, "b/y.txt", SECRET)
        self.assertEqual([x.file for x in scan_worktree(self.root, ["b"], needles())], ["b/y.txt"])


class GitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        git_repo(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_staged(self):
        write(self.root, "ok.txt", "fine\n")
        sh(self.root, "git", "add", "ok.txt")
        sh(self.root, "git", "commit", "-qm", "init")
        write(self.root, "settings.py", f"\n\nTOKEN = '{SECRET}'\n")
        sh(self.root, "git", "add", "settings.py")
        write(self.root, "unstaged.py", SECRET)  # not staged: must not be reported
        f = scan_staged(self.root, needles())
        self.assertEqual([(x.file, x.line, x.source) for x in f], [("settings.py", 3, "staged")])

    def test_staged_version_not_worktree_version(self):
        write(self.root, "a.py", f"k='{SECRET}'\n")
        sh(self.root, "git", "add", "a.py")
        write(self.root, "a.py", "k=os.environ['K']\n")  # fixed on disk but the leak is still staged
        self.assertEqual(len(scan_staged(self.root, needles())), 1)

    def test_history_finds_removed_secret(self):
        write(self.root, "config.yml", f"stripe: {SECRET}\n")
        sh(self.root, "git", "add", ".")
        sh(self.root, "git", "commit", "-qm", "add config")
        first = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=self.root, capture_output=True,
                               text=True).stdout.strip()
        write(self.root, "config.yml", "stripe: ${STRIPE_KEY}\n")
        sh(self.root, "git", "commit", "-qam", "use env")
        self.assertEqual(scan_worktree(self.root, [], needles()), [])
        f = scan_history(self.root, needles())
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].file, f[0].source), ("config.yml", "history"))
        self.assertTrue(first.startswith(f[0].commit) or f[0].commit.startswith(first))

    def test_history_on_other_branch(self):
        write(self.root, "a.txt", "clean\n")
        sh(self.root, "git", "add", ".")
        sh(self.root, "git", "commit", "-qm", "init")
        sh(self.root, "git", "checkout", "-qb", "feature")
        write(self.root, "leak.txt", SECRET)
        sh(self.root, "git", "add", ".")
        sh(self.root, "git", "commit", "-qm", "oops")
        sh(self.root, "git", "checkout", "-q", "main")
        self.assertEqual([x.file for x in scan_history(self.root, needles())], ["leak.txt"])

    def test_needs_git(self):
        with tempfile.TemporaryDirectory() as plain:
            with self.assertRaises(RuntimeError):
                scan_staged(plain, needles())


if __name__ == "__main__":
    unittest.main()

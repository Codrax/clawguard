import unittest

from clawguard.client import Client, ConfigError, Credentials, OneClawError, qpath

from fake_api import AGENT_KEY, OTHER_VAULT_ID, USER_KEY, VAULT_ID, FakeOneClaw


class CredentialsTest(unittest.TestCase):
    def test_from_env(self):
        c = Credentials.from_env({"ONECLAW_API_KEY": " " + USER_KEY + "\n", "ONECLAW_API_URL": "http://x/"})
        self.assertEqual(c.api_key, USER_KEY)
        self.assertEqual(c.api_url, "http://x")

    def test_agent_key_env_alias(self):
        c = Credentials.from_env({"ONECLAW_AGENT_API_KEY": AGENT_KEY})
        self.assertEqual(c.api_key, AGENT_KEY)

    def test_missing_and_bad_keys(self):
        with self.assertRaises(ConfigError):
            Credentials.from_env({}).check()
        with self.assertRaises(ConfigError):
            Credentials(api_key="sk-live-123").check()

    def test_key_file(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(USER_KEY + "\n")
        try:
            self.assertEqual(Credentials.from_env({}, api_key_file=f.name).api_key, USER_KEY)
        finally:
            os.unlink(f.name)
        with self.assertRaises(ConfigError):
            Credentials.from_env({}, api_key_file="/nonexistent/key")


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.api = FakeOneClaw().__enter__()
        self.api.add("stripe/secret", "sk_test_abcdefghijklmnop")
        self.api.add("db/password", "hunter2hunter2", typ="password")
        self.api.add("x/y", "other-vault-value", vault=OTHER_VAULT_ID)

    def tearDown(self):
        self.api.__exit__()

    def client(self, key=USER_KEY):
        return Client(Credentials(api_key=key, api_url=self.api.url))

    def test_user_key_flow(self):
        c = self.client()
        metas = c.list_secrets(VAULT_ID)
        self.assertEqual([m["path"] for m in metas], ["db/password", "stripe/secret"])
        self.assertNotIn("value", metas[0])
        self.assertEqual(c.get_secret(VAULT_ID, "stripe/secret")["value"], "sk_test_abcdefghijklmnop")
        self.assertEqual(self.api.count("POST", "/v1/auth/api-key-token"), 1)  # token reused

    def test_prefix(self):
        self.assertEqual([m["path"] for m in self.client().list_secrets(VAULT_ID, "db/")], ["db/password"])

    def test_agent_key_resolves_bound_vaults(self):
        c = self.client(AGENT_KEY)
        self.assertEqual([v["id"] for v in c.resolve_vaults([])], [VAULT_ID])
        self.assertEqual(self.api.count("GET", "/v1/vaults"), 0)

    def test_user_key_resolves_all_vaults(self):
        self.assertEqual({v["name"] for v in self.client().resolve_vaults([])}, {"app", "other"})

    def test_explicit_vault_wins(self):
        self.assertEqual(self.client(AGENT_KEY).resolve_vaults([OTHER_VAULT_ID])[0]["id"], OTHER_VAULT_ID)

    def test_refreshes_revoked_token_once(self):
        c = self.client()
        c.list_secrets(VAULT_ID)
        self.api.revoke_next_token = True
        c.list_secrets(VAULT_ID)
        self.assertEqual(self.api.count("POST", "/v1/auth/api-key-token"), 2)

    def test_bad_key(self):
        with self.assertRaises(OneClawError) as cm:
            self.client("1ck_wrong_" + "z" * 30).list_vaults()
        self.assertEqual(cm.exception.status, 401)
        self.assertIn("invalid api key", str(cm.exception))

    def test_forbidden_secret(self):
        self.api.forbidden.add((VAULT_ID, "db/password"))
        with self.assertRaises(OneClawError) as cm:
            self.client().get_secret(VAULT_ID, "db/password")
        self.assertEqual(cm.exception.status, 403)

    def test_unreachable(self):
        c = Client(Credentials(api_key=USER_KEY, api_url="http://127.0.0.1:9"), timeout=2)
        with self.assertRaises(OneClawError) as cm:
            c.list_vaults()
        self.assertEqual(cm.exception.status, 0)

    def test_calls_counted(self):
        c = self.client()
        c.list_vaults()
        self.assertEqual(c.calls, 2)


class PathTest(unittest.TestCase):
    def test_qpath(self):
        self.assertEqual(qpath("/a b/c?d/"), "a%20b/c%3Fd")


if __name__ == "__main__":
    unittest.main()

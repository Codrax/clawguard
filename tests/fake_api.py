"""A tiny in-process stand-in for the 1Claw Vault API, shaped like the public OpenAPI spec."""
from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER_KEY = "1ck_test_" + "u" * 32
AGENT_KEY = "ocv_test_" + "a" * 32
VAULT_ID = "11111111-1111-4111-8111-111111111111"
OTHER_VAULT_ID = "22222222-2222-4222-8222-222222222222"


class FakeOneClaw:
    def __init__(self):
        self.vaults = {VAULT_ID: {"id": VAULT_ID, "name": "app", "created_at": "2026-01-01T00:00:00Z"},
                       OTHER_VAULT_ID: {"id": OTHER_VAULT_ID, "name": "other", "created_at": "2026-01-01T00:00:00Z"}}
        self.secrets: dict[str, dict[str, dict]] = {VAULT_ID: {}, OTHER_VAULT_ID: {}}
        self.forbidden: set[tuple[str, str]] = set()
        self.requests: list[tuple[str, str]] = []
        self.revoke_next_token = False
        self.issued = 0
        self.valid_tokens: set[str] = set()
        self.agent_vaults = [VAULT_ID]

        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj=None):
                body = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _problem(self, code, detail):
                self._json(code, {"type": "about:blank", "title": "error", "status": code, "detail": detail})

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")

            def _authed(self):
                auth = self.headers.get("Authorization", "")
                tok = auth[7:] if auth.startswith("Bearer ") else ""
                if tok not in fake.valid_tokens:
                    self._problem(401, "invalid token")
                    return False
                if fake.revoke_next_token:
                    fake.revoke_next_token = False
                    fake.valid_tokens.discard(tok)
                    self._problem(401, "token revoked")
                    return False
                return True

            def _issue(self, extra=None):
                fake.issued += 1
                tok = f"jwt-{fake.issued}"
                fake.valid_tokens.add(tok)
                self._json(200, {"access_token": tok, "token_type": "Bearer", "expires_in": 900, **(extra or {})})

            def do_POST(self):
                fake.requests.append(("POST", self.path))
                body = self._body()
                if self.path == "/v1/auth/api-key-token":
                    if body.get("api_key") == USER_KEY:
                        return self._issue()
                    return self._problem(401, "invalid api key")
                if self.path == "/v1/auth/agent-token":
                    if body.get("api_key") == AGENT_KEY:
                        return self._issue({"agent_id": "agent-1", "vault_ids": fake.agent_vaults})
                    return self._problem(401, "invalid agent key")
                self._problem(404, "no route")

            def do_GET(self):
                fake.requests.append(("GET", self.path))
                if not self._authed():
                    return
                url = urllib.parse.urlsplit(self.path)
                parts = [urllib.parse.unquote(p) for p in url.path.split("/")[2:]]
                if parts == ["vaults"]:
                    return self._json(200, {"vaults": list(fake.vaults.values())})
                if len(parts) >= 3 and parts[0] == "vaults" and parts[2] == "secrets":
                    vid = parts[1]
                    if vid not in fake.secrets:
                        return self._problem(404, "vault not found")
                    if len(parts) == 3:
                        prefix = urllib.parse.parse_qs(url.query).get("prefix", [""])[0]
                        metas = [{k: v for k, v in s.items() if k != "value"}
                                 for p, s in sorted(fake.secrets[vid].items()) if p.startswith(prefix)]
                        return self._json(200, {"secrets": metas})
                    path = "/".join(parts[3:])
                    if (vid, path) in fake.forbidden:
                        return self._problem(403, "no policy grants read")
                    s = fake.secrets[vid].get(path)
                    if not s:
                        return self._problem(404, "secret not found")
                    return self._json(200, s)
                self._problem(404, "no route")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def add(self, path, value, typ="api_key", vault=VAULT_ID, version=1, created_at="2026-11-01T00:00:00Z",
            expires_at=None, is_disabled=False, cmek=False):
        s = {"id": f"id-{path}", "path": path, "type": typ, "value": value, "version": version,
             "created_at": created_at, "metadata": {}}
        if expires_at:
            s["expires_at"] = expires_at
        if is_disabled:
            s["is_disabled"] = True
        if cmek:
            s["cmek_encrypted"] = True
        self.secrets[vault][path] = s

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def count(self, method, prefix):
        return sum(1 for m, p in self.requests if m == method and p.startswith(prefix))

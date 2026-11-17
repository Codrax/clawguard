"""Minimal 1Claw Vault API client (https://docs.1claw.co), standard library only.

Only the calls clawguard needs:
    POST /v1/auth/api-key-token     1ck_ personal key  -> JWT
    POST /v1/auth/agent-token       ocv_ agent key     -> JWT (+ the vaults the agent is bound to)
    GET  /v1/vaults                 list vaults
    GET  /v1/vaults/{id}/secrets    list secret metadata (no values)
    GET  /v1/vaults/{id}/secrets/{path}   read one secret value
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from . import __version__

DEFAULT_API_URL = "https://api.1claw.co"
USER_AGENT = f"clawguard/{__version__} (+https://docs.1claw.co)"


class OneClawError(Exception):
    """An API call failed. `status` is the HTTP status, or 0 for a network error."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class ConfigError(Exception):
    """clawguard is not configured well enough to talk to 1Claw."""


@dataclass
class Credentials:
    """Where clawguard gets its access. Built from the environment, never from argv,
    so keys do not end up in shell history or `ps` output."""

    api_key: Optional[str] = None
    agent_id: Optional[str] = None
    token: Optional[str] = None  # a ready JWT, e.g. from `1claw login` (ONECLAW_TOKEN)
    api_url: str = DEFAULT_API_URL

    @classmethod
    def from_env(cls, env=None, api_key_file: Optional[str] = None, api_url: Optional[str] = None):
        env = os.environ if env is None else env
        key = (env.get("ONECLAW_API_KEY") or env.get("ONECLAW_AGENT_API_KEY") or "").strip() or None
        if api_key_file:
            try:
                with open(api_key_file, encoding="utf-8") as f:
                    key = f.read().strip() or None
            except OSError as e:
                raise ConfigError(f"cannot read API key file {api_key_file}: {e.strerror}") from e
        return cls(
            api_key=key,
            agent_id=(env.get("ONECLAW_AGENT_ID") or "").strip() or None,
            token=(env.get("ONECLAW_TOKEN") or "").strip() or None,
            api_url=(api_url or env.get("ONECLAW_API_URL") or DEFAULT_API_URL).rstrip("/"),
        )

    def check(self) -> None:
        """Fail early with a readable message, before any request goes out."""
        if not self.api_key and not self.token:
            raise ConfigError(
                "no 1Claw credentials: set ONECLAW_API_KEY (a 1ck_ personal key or an ocv_ agent key), "
                "ONECLAW_TOKEN, or pass --api-key-file")
        if self.api_key and not self.api_key.startswith(("1ck_", "ocv_")):
            raise ConfigError("ONECLAW_API_KEY should start with 1ck_ (personal) or ocv_ (agent)")


@dataclass
class Client:
    """A thin client: one JSON request per call, a cached short-lived token, and a
    request counter. 1Claw plans meter API calls, so the count is worth showing."""

    creds: Credentials
    timeout: float = 20.0
    calls: int = 0  # API requests made, so the CLI can report quota use
    _token: Optional[str] = field(default=None, repr=False)
    _token_expires: float = 0.0
    agent_vault_ids: list = field(default_factory=list)

    # ---------- transport ----------
    def _send(self, method: str, path: str, body: Any = None, token: Optional[str] = None) -> tuple[int, Any]:
        """One HTTP request. Returns (status, parsed JSON or None); raises only on network failure."""
        url = self.creds.api_url + "/v1/" + path.lstrip("/")
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        self.calls += 1
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            # error responses carry an open body too; close it or every 4xx leaks a socket
            with e:
                raw = e.read()
                status = e.code
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise OneClawError(f"cannot reach {self.creds.api_url}: {reason}", 0) from e
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = None
        return status, payload

    @staticmethod
    def _problem(status: int, payload: Any, what: str) -> OneClawError:
        # the API answers errors as RFC 7807 problem details; prefer its wording over ours
        detail = ""
        if isinstance(payload, dict):
            detail = payload.get("detail") or payload.get("title") or payload.get("error") or ""
        hints = {
            401: "the key was rejected",
            402: "your 1Claw plan quota is used up",
            403: "this key has no access (check the vault policies)",
            404: "not found",
            429: "rate limited, try again later",
        }
        msg = f"{what}: HTTP {status}"
        if detail or status in hints:
            msg += " (" + (detail or hints[status]) + ")"
        return OneClawError(msg, status)

    # ---------- auth ----------
    def token(self, force: bool = False) -> str:
        """Bearer token for API calls, exchanged from the API key and reused until close to expiry.

        Agent keys (ocv_) also tell us which vaults the agent is bound to; we keep that
        so an agent can scan without being told a vault id.
        """
        if self.creds.token and not self.creds.api_key:
            return self.creds.token
        if not force and self._token and self._token_expires > time.time() + 30:
            return self._token
        key = self.creds.api_key or ""
        if key.startswith("ocv_"):
            body = {"api_key": key}
            if self.creds.agent_id:
                body["agent_id"] = self.creds.agent_id
            status, payload = self._send("POST", "auth/agent-token", body)
        else:
            status, payload = self._send("POST", "auth/api-key-token", {"api_key": key})
        if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
            raise self._problem(status, payload, "1Claw sign-in failed")
        self._token = payload["access_token"]
        self._token_expires = time.time() + int(payload.get("expires_in") or 900)
        self.agent_vault_ids = list(payload.get("vault_ids") or [])
        return self._token

    def _call(self, method: str, path: str, what: str, body: Any = None) -> Any:
        """An authenticated call with the two retries worth doing: one after a network
        blip, and one with a fresh token after a 401 (policy changes revoke agent tokens)."""
        status, payload = 0, None
        for attempt in range(2):
            try:
                status, payload = self._send(method, path, body, self.token())
            except OneClawError as e:
                if e.status == 0 and attempt == 0:  # one retry on a network blip
                    time.sleep(0.4)
                    continue
                raise
            if status == 401 and attempt == 0 and self.creds.api_key:
                self.token(force=True)  # token revoked or expired early
                continue
            break
        if status != 200:
            raise self._problem(status, payload, what)
        return payload

    # ---------- endpoints ----------
    def list_vaults(self) -> list[dict]:
        payload = self._call("GET", "vaults", "listing vaults")
        return list((payload or {}).get("vaults") or [])

    def list_secrets(self, vault_id: str, prefix: Optional[str] = None) -> list[dict]:
        path = "vaults/" + q(vault_id) + "/secrets"
        if prefix:
            path += "?" + urllib.parse.urlencode({"prefix": prefix})
        payload = self._call("GET", path, f"listing secrets in vault {vault_id}")
        return list((payload or {}).get("secrets") or [])

    def get_secret(self, vault_id: str, secret_path: str) -> dict:
        path = "vaults/" + q(vault_id) + "/secrets/" + qpath(secret_path)
        return self._call("GET", path, f"reading {secret_path}") or {}

    def resolve_vaults(self, wanted: list[str]) -> list[dict]:
        """Vaults to work on: the ones asked for, else the agent's bound vaults, else every vault."""
        if wanted:
            return [{"id": v, "name": v} for v in wanted]
        self.token()
        if self.agent_vault_ids:
            return [{"id": v, "name": v} for v in self.agent_vault_ids]
        return self.list_vaults()


def q(segment: str) -> str:
    """Quote one URL path segment, slashes included."""
    return urllib.parse.quote(segment, safe="")


def qpath(path: str) -> str:
    """Quote a secret path segment by segment, keeping its slashes as separators."""
    return "/".join(q(p) for p in path.strip("/").split("/"))

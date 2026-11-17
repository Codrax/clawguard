"""Reading secrets out of the vault for a scan.

Kept apart from the CLI so the rules for what gets searched live in one place:
disabled versions, CMEK ciphertext and secrets the key can list but not read are
all skipped here, and counted so the user knows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .client import Client, OneClawError


@dataclass
class VaultRead:
    # (vault label, secret path, secret type, value). Values never leave this list
    # except to become needles; the CLI clears it right after.
    secrets: list = field(default_factory=list, repr=False)
    vaults: int = 0
    unreadable: int = 0


def vault_label(v: dict) -> str:
    """Name for reports. Agent tokens only give us ids, so fall back to that."""
    return v.get("name") or v["id"]


def read_secrets(client: Client, wanted: list[str], prefix: Optional[str] = None) -> VaultRead:
    result = VaultRead()
    vaults = client.resolve_vaults(wanted)
    result.vaults = len(vaults)
    for v in vaults:
        for meta in client.list_secrets(v["id"], prefix):
            if meta.get("is_disabled"):
                continue
            try:
                s = client.get_secret(v["id"], meta["path"])
            except OneClawError as e:
                # a policy can allow listing a path but not reading it; that is not an error for us
                if e.status in (403, 404):
                    result.unreadable += 1
                    continue
                raise
            # with CMEK the API returns ciphertext, which would never match anything real
            if s.get("cmek_encrypted") or not isinstance(s.get("value"), str):
                result.unreadable += 1
                continue
            typ = s.get("type") or meta.get("type") or ""
            result.secrets.append((vault_label(v), meta["path"], typ, s["value"]))
    return result

"""Vault hygiene from secret metadata alone. No secret value is read."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

# worst first; a secret gets the worst status that applies
STATUSES = ("expired", "expiring", "stale", "disabled", "ok")


@dataclass(frozen=True)
class AuditRow:
    vault: str
    path: str
    type: str
    version: int
    age_days: Optional[int]
    expires_in_days: Optional[int]
    status: str
    reason: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def parse_time(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    # Python < 3.11 only parses 3 or 6 fractional digits; servers may send up to 9
    s = re.sub(r"(\.\d{6})\d+", r"\1", s.strip().replace("Z", "+00:00"))
    s = re.sub(r"\.(\d{1,5})(?=[+-]|$)", lambda m: "." + m.group(1).ljust(6, "0"), s)
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def classify(meta: dict, vault: str, now: datetime, max_age_days: int, expiring_days: int) -> AuditRow:
    created = parse_time(meta.get("created_at"))
    expires = parse_time(meta.get("expires_at"))
    age = (now - created).days if created else None
    # whole days, truncated toward zero: 3.7 days left -> 3, expired 1.5 days ago -> -1
    left_days = int((expires - now).total_seconds() / 86400) if expires else None

    if expires and expires <= now:
        status, reason = "expired", f"expired {-left_days} day(s) ago" if left_days else "expired today"
    elif expires and expires - now <= timedelta(days=expiring_days):
        status, reason = "expiring", f"expires in {left_days} day(s)"
    elif age is not None and age > max_age_days:
        status, reason = "stale", f"current version written {age} days ago (limit {max_age_days})"
    elif meta.get("is_disabled"):
        status, reason = "disabled", "current version is disabled"
    else:
        status, reason = "ok", ""
    return AuditRow(vault, meta.get("path", "?"), meta.get("type", "?"), int(meta.get("version") or 0),
                    age, left_days, status, reason)


def audit(vault_secrets: list[tuple[str, list[dict]]], max_age_days: int = 90, expiring_days: int = 14,
          now: Optional[datetime] = None) -> list[AuditRow]:
    now = now or datetime.now(timezone.utc)
    rows = [classify(m, v, now, max_age_days, expiring_days) for v, metas in vault_secrets for m in metas]
    rows.sort(key=lambda r: (STATUSES.index(r.status), r.vault, r.path))
    return rows

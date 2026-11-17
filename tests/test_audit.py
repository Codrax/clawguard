import unittest
from datetime import datetime, timezone

from clawguard.audit import audit, parse_time

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


def meta(path, created="2026-11-01T00:00:00Z", expires=None, disabled=False, version=1):
    m = {"id": path, "path": path, "type": "api_key", "version": version, "created_at": created}
    if expires:
        m["expires_at"] = expires
    if disabled:
        m["is_disabled"] = True
    return m


class AuditTest(unittest.TestCase):
    def rows(self, *metas, **kw):
        return {r.path: r for r in audit([("app", list(metas))], now=NOW, **kw)}

    def test_statuses(self):
        r = self.rows(
            meta("fresh"),
            meta("old", created="2026-01-10T00:00:00Z"),
            meta("soon", expires="2026-11-20T12:00:00Z"),
            meta("gone", expires="2026-11-15T12:00:00Z"),
            meta("off", disabled=True),
        )
        self.assertEqual(r["fresh"].status, "ok")
        self.assertEqual(r["old"].status, "stale")
        self.assertEqual(r["old"].age_days, 311)
        self.assertEqual(r["soon"].status, "expiring")
        self.assertEqual(r["soon"].expires_in_days, 3)
        self.assertEqual(r["gone"].status, "expired")
        self.assertIn("2 day", r["gone"].reason)
        self.assertEqual(r["off"].status, "disabled")

    def test_expired_today(self):
        r = self.rows(meta("x", expires="2026-11-17T06:00:00Z"))
        self.assertEqual((r["x"].status, r["x"].reason), ("expired", "expired today"))

    def test_worst_status_wins(self):
        r = self.rows(meta("x", created="2025-01-01T00:00:00Z", expires="2026-11-01T00:00:00Z"))
        self.assertEqual(r["x"].status, "expired")

    def test_limits(self):
        r = self.rows(meta("x", created="2026-10-01T00:00:00Z"), max_age_days=30)
        self.assertEqual(r["x"].status, "stale")
        r = self.rows(meta("y", expires="2026-12-10T00:00:00Z"), expiring_days=30)
        self.assertEqual(r["y"].status, "expiring")

    def test_sorted_worst_first(self):
        rows = audit([("app", [meta("a"), meta("b", expires="2026-11-01T00:00:00Z")])], now=NOW)
        self.assertEqual([r.path for r in rows], ["b", "a"])

    def test_missing_dates(self):
        r = self.rows({"path": "bare", "type": "generic", "version": 2})
        self.assertEqual((r["bare"].status, r["bare"].age_days), ("ok", None))

    def test_parse_time(self):
        self.assertEqual(parse_time("2026-11-17T12:00:00Z"), NOW)
        self.assertEqual(parse_time("2026-11-17T12:00:00"), NOW)
        self.assertEqual(parse_time("2026-11-17T12:00:00.123456789Z").microsecond, 123456)
        self.assertEqual(parse_time("2026-11-17T12:00:00.5+00:00").microsecond, 500000)
        self.assertIsNone(parse_time("not a date"))
        self.assertIsNone(parse_time(None))


if __name__ == "__main__":
    unittest.main()

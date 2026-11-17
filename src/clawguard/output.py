"""Text, JSON, Markdown and SARIF output. Nothing here ever receives a secret value."""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from typing import TextIO

from . import __version__
from .audit import AuditRow
from .scan import Finding

RULE_ID = "CLAWGUARD001"


def use_color(stream: TextIO) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


class Style:
    def __init__(self, on: bool):
        self.on = on

    def _w(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def red(self, s): return self._w("31", s)
    def yellow(self, s): return self._w("33", s)
    def green(self, s): return self._w("32", s)
    def dim(self, s): return self._w("2", s)
    def bold(self, s): return self._w("1", s)


# ---------- scan ----------
def where(f: Finding) -> str:
    loc = f"{f.file}:{f.line}"
    if f.source == "history":
        loc += f" @ {f.commit or '?'}"
    elif f.source == "staged":
        loc += " (staged)"
    return loc


def scan_text(findings: list[Finding], out: TextIO = sys.stdout) -> None:
    st = Style(use_color(out))
    if not findings:
        out.write(st.green("No vault secrets found.") + "\n")
        return
    width = min(60, max(len(where(f)) for f in findings))
    for f in findings:
        enc = "" if f.variant == "raw" else st.dim(f" ({f.variant})")
        out.write(f"{st.red('LEAK')}  {where(f).ljust(width)}  {st.bold(f.secret)}{enc}\n")
    n = len({f.secret for f in findings})
    out.write("\n" + st.red(f"{len(findings)} finding(s), {n} distinct secret(s).") + " "
              + "Rotate them in 1Claw, then remove them from the files"
              + (" and from git history." if any(f.source == "history" for f in findings) else ".") + "\n")


def scan_json(findings: list[Finding], out: TextIO = sys.stdout) -> None:
    json.dump({"tool": "clawguard", "version": __version__, "findings": [f.to_dict() for f in findings]},
              out, indent=2)
    out.write("\n")


def scan_sarif(findings: list[Finding], out: TextIO = sys.stdout) -> None:
    results = []
    for f in findings:
        msg = f"The value of 1Claw secret '{f.secret}' appears here"
        if f.variant != "raw":
            msg += f" ({f.variant}-encoded)"
        if f.source == "history":
            msg += f", in git history (first added in commit {f.commit or 'unknown'})"
        results.append({
            "ruleId": RULE_ID,
            "level": "error",
            "message": {"text": msg + ". Rotate the secret in 1Claw."},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                "region": {"startLine": f.line}}}],
            "partialFingerprints": {"clawguard/v1": f"{f.secret}:{f.file}:{f.source}"},
        })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "clawguard",
                "version": __version__,
                "rules": [{
                    "id": RULE_ID,
                    "name": "VaultSecretOutsideVault",
                    "shortDescription": {"text": "A secret stored in a 1Claw vault appears in the repository"},
                    "fullDescription": {"text": "clawguard compared this file against the exact values in your "
                                                "1Claw vault. A match means the secret is exposed to anyone "
                                                "who can read the repository."},
                    "help": {"text": "Rotate the secret in 1Claw (store a new version and revoke the old "
                                     "credential at its provider), then remove it from the file."},
                    "defaultConfiguration": {"level": "error"},
                    "properties": {"tags": ["security", "secrets"]},
                }],
            }},
            "results": results,
        }],
    }
    json.dump(doc, out, indent=2)
    out.write("\n")


# ---------- audit ----------
def audit_text(rows: list[AuditRow], out: TextIO = sys.stdout, show_ok: bool = False) -> None:
    st = Style(use_color(out))
    color = {"expired": st.red, "expiring": st.yellow, "stale": st.yellow, "disabled": st.dim, "ok": st.green}
    shown = [r for r in rows if show_ok or r.status != "ok"]
    if shown:
        pw = max(len(r.path) for r in shown)
        for r in shown:
            out.write(f"{color[r.status](r.status.upper().ljust(8))}  {r.path.ljust(pw)}  "
                      f"{st.dim('v' + str(r.version))}  {r.reason}\n")
        out.write("\n")
    c = Counter(r.status for r in rows)
    parts = [f"{c[s]} {s}" for s in ("expired", "expiring", "stale", "disabled", "ok") if c[s]]
    out.write(f"{len(rows)} secret(s): " + (", ".join(parts) or "none") + "\n")


def audit_json(rows: list[AuditRow], out: TextIO = sys.stdout) -> None:
    json.dump({"tool": "clawguard", "version": __version__, "secrets": [r.to_dict() for r in rows]}, out, indent=2)
    out.write("\n")


def audit_markdown(rows: list[AuditRow], out: TextIO = sys.stdout) -> None:
    icon = {"expired": "🔴", "expiring": "🟠", "stale": "🟡", "disabled": "⚪", "ok": "🟢"}
    c = Counter(r.status for r in rows)
    out.write("## 1Claw vault audit\n\n")
    out.write(" · ".join(f"{icon[s]} {c[s]} {s}" for s in icon if c[s]) + "\n\n")
    out.write("| Status | Secret | Vault | Version | Age (days) | Note |\n|---|---|---|---|---|---|\n")
    for r in rows:
        age = "" if r.age_days is None else str(r.age_days)
        out.write(f"| {icon[r.status]} {r.status} | `{r.path}` | `{r.vault}` | v{r.version} | {age} | {r.reason} |\n")

"""clawguard command line."""
from __future__ import annotations

import argparse
import os
import sys
from contextlib import contextmanager
from typing import Optional

from . import __version__, output
from .audit import STATUSES, audit
from .client import Client, ConfigError, Credentials, OneClawError
from .scan import (DEFAULT_MAX_BYTES, DEFAULT_MIN_LENGTH, Stats, build_needles, scan_history, scan_staged,
                   scan_worktree)

EXIT_OK, EXIT_FOUND, EXIT_CONFIG, EXIT_API = 0, 1, 2, 3


def log(args, msg: str) -> None:
    if not getattr(args, "quiet", False):
        sys.stderr.write(msg + "\n")


@contextmanager
def out_stream(path: Optional[str]):
    if not path or path == "-":
        yield sys.stdout
        return
    with open(path, "w", encoding="utf-8") as f:
        yield f


def make_client(args) -> Client:
    creds = Credentials.from_env(api_key_file=args.api_key_file, api_url=args.api_url)
    creds.check()
    return Client(creds)


def wanted_vaults(args) -> list[str]:
    vs = list(args.vault or [])
    if not vs and os.environ.get("ONECLAW_VAULT_ID"):
        vs = [v.strip() for v in os.environ["ONECLAW_VAULT_ID"].split(",") if v.strip()]
    return vs


def vault_label(v: dict) -> str:
    return v.get("name") or v["id"]


# ---------- scan ----------
def fetch_values(client: Client, args) -> list[tuple[str, str, str, str]]:
    secrets = []
    vaults = client.resolve_vaults(wanted_vaults(args))
    skipped = 0
    for v in vaults:
        for meta in client.list_secrets(v["id"], args.prefix):
            if meta.get("is_disabled"):
                continue
            try:
                s = client.get_secret(v["id"], meta["path"])
            except OneClawError as e:
                if e.status in (403, 404):  # listed but not readable by this key
                    skipped += 1
                    continue
                raise
            if s.get("cmek_encrypted") or not isinstance(s.get("value"), str):
                skipped += 1
                continue
            secrets.append((vault_label(v), meta["path"], s.get("type") or meta.get("type") or "", s["value"]))
    note = f", {skipped} not readable" if skipped else ""
    log(args, f"clawguard: read {len(secrets)} secret(s) from {len(vaults)} vault(s){note} "
              f"in {client.calls} API call(s)")
    return secrets


def cmd_scan(args) -> int:
    client = make_client(args)
    values = fetch_values(client, args)
    needles, short = build_needles(values, args.min_length, encodings=not args.no_encodings)
    values.clear()
    if short:
        log(args, f"clawguard: {short} value(s) shorter than {args.min_length} characters not searched")
    if not needles:
        log(args, "clawguard: nothing to search for")
    root = os.getcwd()
    stats = Stats()
    if args.staged:
        findings = scan_staged(root, needles, args.max_bytes, args.exclude, stats)
    else:
        findings = scan_worktree(root, args.paths, needles, args.max_bytes, args.exclude, stats)
        if args.history:
            findings += scan_history(root, needles, args.max_bytes, args.exclude, stats)
    needles.clear()
    extra = f", {stats.blobs} history blob(s)" if args.history else ""
    log(args, f"clawguard: scanned {stats.files} file(s){extra}")

    with out_stream(args.output) as out:
        {"text": output.scan_text, "json": output.scan_json, "sarif": output.scan_sarif}[args.format](findings, out)
    if args.output and args.format != "text":
        log(args, f"clawguard: {len(findings)} finding(s) written to {args.output}")
    return EXIT_FOUND if findings else EXIT_OK


# ---------- audit ----------
def cmd_audit(args) -> int:
    client = make_client(args)
    vaults = client.resolve_vaults(wanted_vaults(args))
    data = [(vault_label(v), client.list_secrets(v["id"], args.prefix)) for v in vaults]
    rows = audit(data, args.max_age, args.expiring)
    fail_on = {s.strip() for s in args.fail_on.split(",") if s.strip()}
    bad = sorted(fail_on - set(STATUSES) - {"none"})
    if bad:
        raise ConfigError(f"--fail-on: unknown status {', '.join(bad)} (use {', '.join(STATUSES[:-1])} or none)")
    with out_stream(args.output) as out:
        if args.format == "json":
            output.audit_json(rows, out)
        elif args.format == "markdown":
            output.audit_markdown(rows, out)
        else:
            output.audit_text(rows, out, show_ok=args.all)
    log(args, f"clawguard: {len(rows)} secret(s) in {len(vaults)} vault(s), {client.calls} API call(s), "
              "no values read")
    return EXIT_FOUND if any(r.status in fail_on for r in rows) else EXIT_OK


# ---------- vaults ----------
def cmd_vaults(args) -> int:
    client = make_client(args)
    vaults = client.list_vaults()
    if args.format == "json":
        import json
        json.dump(vaults, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for v in vaults:
            sys.stdout.write(f"{v.get('id', '?')}  {v.get('name', '')}\n")
        if not vaults:
            log(args, "clawguard: no vaults visible to this key")
    return EXIT_OK


# ---------- parser ----------
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("1Claw connection")
    g.add_argument("--api-key-file", metavar="FILE",
                   help="read the 1Claw key from FILE instead of ONECLAW_API_KEY")
    g.add_argument("--api-url", metavar="URL", help="API base URL (default https://api.1claw.co, "
                                                    "or ONECLAW_API_URL)")
    g.add_argument("-q", "--quiet", action="store_true", help="no progress messages on stderr")

    pick = argparse.ArgumentParser(add_help=False)
    pick.add_argument("-v", "--vault", action="append", metavar="ID",
                      help="vault id, repeatable (default: ONECLAW_VAULT_ID, the agent's vaults, or all)")
    pick.add_argument("--prefix", metavar="PATH", help="only secrets under this path, e.g. prod/")

    p = argparse.ArgumentParser(
        prog="clawguard",
        description="Find your 1Claw vault secrets where they should not be, and keep the vault tidy.",
        epilog="Exit codes: 0 clean, 1 findings, 2 configuration error, 3 1Claw API error.")
    p.add_argument("--version", action="version", version=f"clawguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    s = sub.add_parser("scan", parents=[common, pick], help="search files and git history for vault secrets",
                       description="Read the secrets in your vault (kept in memory only) and search for "
                                   "their exact values, plus base64 and URL-encoded forms.")
    s.add_argument("paths", nargs="*", help="files or folders to scan (default: the current folder)")
    s.add_argument("--staged", action="store_true", help="scan only staged changes (for pre-commit hooks)")
    s.add_argument("--history", action="store_true", help="also scan every blob in git history")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    s.add_argument("--exclude", action="append", metavar="GLOB", help="skip matching files, repeatable")
    s.add_argument("--min-length", type=int, default=DEFAULT_MIN_LENGTH, metavar="N",
                   help=f"ignore secret values shorter than N characters (default {DEFAULT_MIN_LENGTH})")
    s.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, metavar="N",
                   help="skip files larger than N bytes (default 5 MiB)")
    s.add_argument("--no-encodings", action="store_true", help="match only the raw value, not base64/URL forms")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("audit", parents=[common, pick], help="report expired, expiring and stale secrets",
                       description="Check secret metadata against expiry and age limits. Reads no values, "
                                   "so it only needs list access.")
    a.add_argument("--max-age", type=int, default=90, metavar="DAYS",
                   help="flag secrets whose current version is older than DAYS (default 90)")
    a.add_argument("--expiring", type=int, default=14, metavar="DAYS",
                   help="flag secrets that expire within DAYS (default 14)")
    a.add_argument("--fail-on", default="expired", metavar="LIST",
                   help="statuses that make the exit code 1, comma separated: expired, expiring, stale, "
                        "disabled, or none (default expired)")
    a.add_argument("--all", action="store_true", help="also list healthy secrets")
    a.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    a.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    a.set_defaults(func=cmd_audit)

    v = sub.add_parser("vaults", parents=[common], help="list the vaults this key can see")
    v.add_argument("-f", "--format", choices=["text", "json"], default="text")
    v.set_defaults(func=cmd_vaults)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as e:
        sys.stderr.write(f"clawguard: {e}\n")
        return EXIT_CONFIG
    except RuntimeError as e:
        sys.stderr.write(f"clawguard: {e}\n")
        return EXIT_CONFIG
    except OneClawError as e:
        sys.stderr.write(f"clawguard: {e}\n")
        return EXIT_API
    except KeyboardInterrupt:
        return 130

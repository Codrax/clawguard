# Changelog

## Unreleased

- Close HTTP error responses instead of leaking a socket per 4xx.
- Progress messages no longer print above a piped report.
- Internal: shared skip rules for all scan sources, vault reading moved to `vault.py`.
- Tests for every output format; ruff lint in CI.

## 0.1.0

- `clawguard scan`: search the working tree, staged changes (`--staged`) or all of git history (`--history`) for the exact values stored in a 1Claw vault, including base64, base64url and URL-encoded forms. Text, JSON and SARIF output.
- `clawguard audit`: report expired, expiring, stale and disabled secrets from metadata only.
- `clawguard vaults`: list the vaults a key can see.
- `ocv_` agent keys, `1ck_` personal keys or a ready `ONECLAW_TOKEN`.
- `.clawguardignore`, `--exclude` and inline `clawguard:allow`.
- pre-commit hook and composite GitHub Action.

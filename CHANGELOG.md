# Changelog

## 0.1.0

- `clawguard scan`: search the working tree, staged changes (`--staged`) or all of git history (`--history`) for the exact values stored in a 1Claw vault, including base64, base64url and URL-encoded forms. Text, JSON and SARIF output.
- `clawguard audit`: report expired, expiring, stale and disabled secrets from metadata only.
- `clawguard vaults`: list the vaults a key can see.
- `ocv_` agent keys, `1ck_` personal keys or a ready `ONECLAW_TOKEN`.
- `.clawguardignore`, `--exclude` and inline `clawguard:allow`.
- pre-commit hook and composite GitHub Action.

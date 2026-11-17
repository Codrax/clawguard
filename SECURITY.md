# Security

clawguard reads secrets from your vault so it can search for them. That makes its own
behaviour worth being precise about.

## What it does with secret values

- Fetches them over HTTPS from the API URL you configure (`https://api.1claw.co` by default).
- Keeps them in process memory as bytes, only for the duration of the scan.
- Never prints, logs, caches or writes them. Reports (text, JSON, SARIF) contain the vault path, file and line.
- `clawguard audit` never requests a value at all.

## Recommended setup

Give clawguard its own 1Claw agent with a **read-only** policy on just the paths you want checked,
and pass the key through `ONECLAW_API_KEY` or `--api-key-file`. In CI, store it as an encrypted
repository secret.

## Reporting a vulnerability

Please don't open a public issue for a security problem. Use GitHub's
[private vulnerability reporting](https://github.com/Codrax/clawguard/security/advisories/new)
instead. You'll get a reply within a few days.

Problems with 1Claw itself should go to 1Claw, not here.

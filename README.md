# clawguard

**Find your 1Claw vault secrets where they should not be.**

Most secret scanners guess. They match regexes for things that *look like* API keys, so they
miss the keys that don't follow a pattern and flag a pile of test strings that do.

clawguard doesn't guess. It signs in to your [1Claw](https://1claw.co) vault, reads the secrets you
actually store there (in memory only), and searches your working tree, your staged changes or
your whole git history for those exact values, including their base64 and URL-encoded forms.
Every hit is a real secret in a place it shouldn't be.

```console
$ clawguard scan --history
clawguard: read 5 secret(s) from 1 vault(s) in 7 API call(s)
clawguard: scanned 5 file(s), 3 history blob(s)
LEAK  docker-compose.override.yml:5  db/postgres-password
LEAK  src/settings.py:1              prod/env#SENTRY_DSN
LEAK  config/dev.yml:2 @ 43b5bda     github/deploy-token (base64)

3 finding(s), 3 distinct secret(s). Rotate them in 1Claw, then remove them from the files and from git history.
```

It also checks the vault itself:

```console
$ clawguard audit
EXPIRED   github/deploy-token  v3  expired 2 day(s) ago
EXPIRING  partners/acme-api    v1  expires in 4 day(s)
STALE     stripe/secret-key    v1  current version written 211 days ago (limit 90)

5 secret(s): 1 expired, 1 expiring, 1 stale, 2 ok
```

`audit` uses metadata only and never reads a secret value.

> clawguard is an independent open-source tool built on the public 1Claw Vault API.
> It is not made or endorsed by 1Claw.

## Why

- **No false positives.** It matches values you stored, not patterns.
- **Catches what regex scanners miss:** internal tokens, database passwords, webhook secrets, anything in your vault.
- **History mode.** A key deleted in the last commit is still in `git log`. `--history` checks every blob on every branch and names the commit that first added it.
- **Pre-commit mode.** `--staged` checks exactly what you're about to commit.
- **CI-ready.** Exit codes, JSON, and SARIF output for GitHub code scanning.
- **Zero dependencies.** Pure Python 3.9+ standard library, under 1,000 lines. Small enough to read before you hand it a key.

## Install

```bash
pip install git+https://github.com/Codrax/clawguard
```

Or from a clone:

```bash
pip install .
```

## Set up

Create a key in the 1Claw dashboard and export it:

```bash
export ONECLAW_API_KEY=ocv_...        # an agent key (recommended) or a 1ck_ personal key
export ONECLAW_VAULT_ID=<vault-uuid>  # optional; see "Which vaults" below
```

**Use a dedicated agent key with read-only access.** `scan` needs read access to the secrets
it checks. `audit` only needs to list them. An agent with a read-only policy on the paths you
care about is the least you can give it. clawguard never writes to the vault.

| Variable | Meaning |
|---|---|
| `ONECLAW_API_KEY` | `ocv_` agent key or `1ck_` personal key (also read from `ONECLAW_AGENT_API_KEY`) |
| `ONECLAW_AGENT_ID` | agent id, only needed if your key doesn't resolve on its own |
| `ONECLAW_TOKEN` | a ready JWT instead of a key, e.g. from `1claw login` |
| `ONECLAW_VAULT_ID` | vault id(s), comma separated |
| `ONECLAW_API_URL` | API base URL, default `https://api.1claw.co` |

Prefer `--api-key-file path` over putting a key on the command line, where it shows up in `ps`
and shell history.

### Which vaults

1. `--vault ID` (repeatable), or `ONECLAW_VAULT_ID`
2. otherwise, for an agent key, the vaults the agent is bound to
3. otherwise, every vault the key can list

`clawguard vaults` lists what your key can see.

## Usage

### scan

```bash
clawguard scan                      # working tree (git-tracked + untracked, honouring .gitignore)
clawguard scan src/ config/         # only these paths
clawguard scan --staged             # only what is staged (pre-commit)
clawguard scan --history            # working tree + every blob in git history
clawguard scan --prefix prod/       # only secrets under prod/ in the vault
clawguard scan -f sarif -o clawguard.sarif
```

| Option | |
|---|---|
| `--staged` | scan the staged version of added/changed files |
| `--history` | also scan all reachable blobs; hits name the first commit containing them |
| `-f text\|json\|sarif` | output format |
| `-o FILE` | write the report to a file |
| `--exclude GLOB` | skip files, repeatable |
| `--min-length N` | ignore vault values shorter than N characters (default 8) |
| `--no-encodings` | match the raw value only, not base64 / base64url / URL-encoded |
| `--max-bytes N` | skip files larger than N bytes (default 5 MiB) |

Secrets of type `env` (a whole `.env` file stored as one secret) are split into lines, and
each value is searched on its own. Hits are reported as `path#KEY`.

Not searched: values shorter than `--min-length`, disabled versions, CMEK-encrypted secrets
(the API returns ciphertext), and secrets the key can list but not read. The summary line says
how many were skipped.

### audit

```bash
clawguard audit                         # fails (exit 1) if anything is expired
clawguard audit --max-age 30 --expiring 7
clawguard audit --fail-on expired,expiring,stale
clawguard audit -f markdown >> "$GITHUB_STEP_SUMMARY"
```

| Status | When |
|---|---|
| `expired` | `expires_at` has passed |
| `expiring` | expires within `--expiring` days (default 14) |
| `stale` | the current version is older than `--max-age` days (default 90) |
| `disabled` | the current version is disabled |
| `ok` | none of the above (shown with `--all`) |

Age is measured from the `created_at` the API reports for the current version.

### Allowing a match

- One line: put `clawguard:allow` anywhere on it (e.g. in a comment).
- Files or folders: list globs in `.clawguardignore` at the repo root.

```gitignore
# .clawguardignore
tests/fixtures/
*.lock
```

### Exit codes

| Code | |
|---|---|
| 0 | clean |
| 1 | `scan` found secrets, or `audit` hit a `--fail-on` status |
| 2 | configuration or usage error |
| 3 | 1Claw API error (bad key, no access, quota, network) |

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Codrax/clawguard
    rev: v0.1.0
    hooks:
      - id: clawguard
```

The hook runs `clawguard scan --staged` and needs `ONECLAW_API_KEY` in your environment.

## GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0            # needed for history
- uses: Codrax/clawguard@v0.1.0
  with:
    api-key: ${{ secrets.ONECLAW_API_KEY }}
    vault: ${{ vars.ONECLAW_VAULT_ID }}
    history: true
```

See [examples/github-workflow.yml](examples/github-workflow.yml) for a full workflow that also
uploads SARIF to code scanning and runs a weekly `audit`.

## API usage and quotas

`scan` reads every secret it checks, so a run costs about one API call per secret, plus one
for sign-in and one per vault for listing. 1Claw's free tier includes 100 API calls a month,
so on that tier, narrow runs with `--prefix` or `--vault` and keep scheduled scans infrequent.
`audit` costs one call per vault plus sign-in.

## Security notes

- Secret values stay in process memory, are compared as bytes and dropped after the scan. They are never printed, logged, cached or written to a report. Reports name the vault path only.
- No third-party dependencies, no telemetry. The only network traffic is to the API URL you configure.
- Tokens from the key exchange are short-lived and kept in memory only.
- Finding a secret means it's exposed. **Rotate it first**, then clean up the file or history. Deleting the line doesn't un-leak it.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
```

The tests run against an in-process fake of the 1Claw API (`tests/fake_api.py`) shaped after
the public OpenAPI spec, plus throwaway git repositories. No account or network is needed.

## License

MIT

# Contributing

Issues and pull requests are welcome. A few things make them easier to merge.

## Setup

```bash
git clone https://github.com/Codrax/clawguard
cd clawguard
python -m venv .venv && . .venv/bin/activate
pip install -e . ruff
```

## Before you open a PR

```bash
ruff check .
python -m unittest discover -s tests -v
```

The tests need git on your PATH and nothing else: they run against a fake 1Claw API
(`tests/fake_api.py`) and throwaway repositories in a temp folder. No account, no network.

If you change how the API is called, update `tests/fake_api.py` to match the
[public OpenAPI spec](https://www.npmjs.com/package/@1claw/openapi-spec), not the other way round.

## Ground rules

- **No dependencies.** clawguard gets handed a vault key; the less code it pulls in, the easier it is to trust.
  The standard library is enough.
- **Never print a secret.** Not in errors, not in debug output, not in a test failure message. Findings name the
  vault path only. If you add a code path that touches values, add a test that checks they don't leak.
- **Python 3.9+.** Keep `from __future__ import annotations` at the top of modules and `Optional[...]` in runtime
  positions.
- One change per PR, with a line in `CHANGELOG.md` under "Unreleased".

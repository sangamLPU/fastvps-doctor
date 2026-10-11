# Contributing

Thanks for considering a contribution. FastVPS Doctor is an independent project and is not maintained or endorsed by FastVPS.gr.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src/fastvps_doctor
```

## Contribution expectations

- Keep diagnostics read-only, offline by default, bounded, and least-privilege.
- Route every subprocess through the audited allowlist; never use `shell=True`.
- Return structured results rather than printing from diagnostic modules.
- Update the privacy allowlist for any new report field and add a test proving identifying data is excluded.
- Add deterministic rule tests for healthy and failing cases and explain evidence limitations.
- Do not add FastVPS logos, unofficial API calls, credential collection, or claims of endorsement.
- Do not claim compatibility, test success, performance improvement or support savings without evidence.


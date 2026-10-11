# Testing and quality checks

## Local checks

```bash
python -m pip install '.[dev]'
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src/fastvps_doctor
```

The unit suite uses mocks for operating-system and subprocess boundaries. It covers malformed route/resolver data, permission failures, reserved filesystem capacity, malformed pressure data, inconsistent systemd responses, report redaction, and timeout handling. It does not require a VPS. The optional Linux integration tests exercise the installed CLI and verify process-group cleanup in a disposable container/VM; they run only when `FASTVPS_DOCTOR_INTEGRATION=1` is set.

Example container invocation after building `tests/integration/Dockerfile`:

```bash
docker build -f tests/integration/Dockerfile -t fastvps-doctor-integration .
docker run --rm fastvps-doctor-integration
```

The image runs as a regular user. The GitHub Actions workflow builds and runs this disposable image separately from the cross-version unit matrix. For manual integration checks, use a disposable machine and do not mount production secrets or data into the test environment. Do not enable `FASTVPS_DOCTOR_INTEGRATION=1` on the sponsored production VPS; use the read-only manual steps in [the Linux VPS testing guide](LINUX_VPS_TESTING_GUIDE.md) instead.

## CI

GitHub Actions is configured to run unit tests, Ruff lint/format checks and mypy on Ubuntu across Python 3.11, 3.12 and 3.13, then run Linux integration checks in an Ubuntu 24.04 Docker image. This repository's current-session validation status is reported separately and should not be inferred from workflow configuration. A Windows-only local pass does not establish Linux compatibility.


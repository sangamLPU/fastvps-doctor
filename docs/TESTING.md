# Testing and quality checks

## Local checks

```bash
python -m pip install '.[dev]'
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src/fastvps_doctor
```

The unit suite uses mocks for operating-system and subprocess boundaries. It covers malformed IPv4/IPv6 route and resolver data, permission failures, root and mounted-filesystem pressure, unsupported mounts, memory/swap evidence, SSH effective-output failures, custom/masked service states, timestamped restart-loop/OOM fixtures, report redaction, and timeouts. It does not require a VPS and does not cause real failures. The optional Linux integration tests exercise the installed CLI and verify process-group cleanup in a disposable container/VM; they run only when `FASTVPS_DOCTOR_INTEGRATION=1` is set.

Example container invocation after building `tests/integration/Dockerfile`:

```bash
docker build -f tests/integration/Dockerfile -t fastvps-doctor-integration .
docker run --rm fastvps-doctor-integration
```

The Dockerfile defaults to Ubuntu 24.04; choose Debian for a manual disposable run with `--build-arg BASE_IMAGE=debian:12` or `debian:13`.

The image runs as a regular user. The GitHub Actions workflow builds and runs this disposable image separately from the cross-version unit matrix. For manual integration checks, use a disposable machine and do not mount production secrets or data into the test environment. Do not enable `FASTVPS_DOCTOR_INTEGRATION=1` on the sponsored production VPS; use the read-only manual steps in [the Linux VPS testing guide](LINUX_VPS_TESTING_GUIDE.md) instead.

## CI

GitHub Actions is configured to run unit tests, Ruff lint/format checks and mypy on Ubuntu across Python 3.11, 3.12 and 3.13, then run the disposable Linux integration smoke tests on Ubuntu 24.04, Debian 12 and Debian 13 images. Those integration tests check installed CLI output and timeout child cleanup; they do not inject the whole failure matrix into real system services. The workflow has not run and its configuration is not evidence of a passing job. On 11 October 2026, Windows 11/Python 3.13.7 passed 134 tests with two Linux-only integration tests skipped. WSL Ubuntu 26.04/Python 3.14.4 passed 136 tests with integration enabled. Linux Ruff, formatting, mypy and pip checks passed; source and wheel installations, console entry point, and real unprivileged smoke checks also passed. Coverage was 92.5% by statements and 90% branch-inclusive on Linux. Docker was unavailable, so Ubuntu 24.04/Debian containers were not run locally. The sponsored Ubuntu 24.04.5 VPS was not accessed. These results do not establish compatibility with that host or production readiness. See the [complete QA report](COMPLETE_QA_REPORT.md) and [release readiness](RELEASE_READINESS.md).


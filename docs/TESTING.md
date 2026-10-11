# Testing and quality checks

## Unit and quality checks

From an installed development environment:

```bash
python -m pip install '.[dev]'
python -m pytest -m "not integration"
python -m ruff check .
python -m ruff format --check .
python -m mypy src/fastvps_doctor
python -m pip check
uv lock --check
```

The unit suite uses deterministic inputs and mocks for systemd, journald, resource counters, route/resolver data, service failures, timeouts and sensitive text. It covers failure cases without causing real host failures.

## Opt-in Linux integration tests

Run these only inside a disposable Linux container or VM. They validate installed CLI output, process-group cleanup on timeout, a loopback HTTP response and the complete live-local website demo.

```bash
FASTVPS_DOCTOR_INTEGRATION=1 python -m pytest -m integration -q
```

The tests use an unprivileged temporary HTTP service bound to `127.0.0.1`; one test returns HTTP 503 to a `HEAD` request. The test shuts the service down after inspection. They do not access an external host or inject failures into systemd, the filesystem or the network. Never set the integration flag on the sponsored VPS.

The Dockerfile defaults to Ubuntu 24.04 and runs as a regular user. For a manual disposable image:

```bash
docker build -f tests/integration/Dockerfile -t fastvps-doctor-integration .
docker run --rm fastvps-doctor-integration
```

Choose Debian with `--build-arg BASE_IMAGE=debian:12` or `debian:13`. GitHub Actions builds separate Ubuntu 24.04, Debian 12 and Debian 13 integration images. A configured workflow is not a passing result; inspect the run after you publish.

## Results for the v0.3.0 working tree

| Environment | Result |
| --- | --- |
| Windows 11 / Python 3.13.7 | 154 passed, 4 Linux integration tests deselected; Ruff, format, mypy and `pip check` passed. |
| WSL Ubuntu 26.04 / Python 3.14.4 | 158 passed, 0 skipped in 5.24 seconds with integration enabled; Linux Ruff, format, mypy and `pip check` passed. |
| WSL packaging | Built and installed v0.3.0 from a wheel into an isolated virtual environment; entry point, JSON/Markdown report generation, JSON schema and mode `0600` report files were verified. |
| GitHub Actions | Not run; Ubuntu Python and Ubuntu/Debian integration matrices remain pending. |
| Sponsored VPS | Not accessed in this review. Your personal smoke-test observations remain user-reported. |

WSL used Ubuntu 26.04/Python 3.14.4, not Ubuntu 24.04.5 or Debian. These results do not establish behavior on the sponsored server, all supported Python versions, or production systems. No destructive failure was induced. See [the complete QA report](COMPLETE_QA_REPORT.md), [release readiness](RELEASE_READINESS.md), and [the safe Linux VPS guide](LINUX_VPS_TESTING_GUIDE.md).

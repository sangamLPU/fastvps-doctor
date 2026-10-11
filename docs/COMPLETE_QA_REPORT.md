# FastVPS Doctor v0.2 complete QA report

**Assessment date:** 11 October 2026
**Result:** Final code/test revalidation passed on WSL Ubuntu 26.04; Ubuntu 24.04.5, Debian, GitHub Actions, and the sponsored VPS remain unverified.
**No sponsored VPS, FastVPS infrastructure, or remote server was accessed. This review did not push to GitHub.**

## Source snapshot and preservation

The repository HEAD at the start of the QA work was `b8a9c310357f98218bd0df80b64320ed636af53f` on `main`. The working tree already contained 40 modified tracked files and a set of new source, tests, examples, and documentation. Those changes were preserved; no reset or discard was performed. Findings apply to the reviewed candidate snapshot, not to the original HEAD alone.

A separate copy of the working tree was used under the WSL native Linux filesystem at `$HOME/fastvps-doctor-qa-20261011`. For final release-candidate revalidation, a fresh isolated copy was created at `$HOME/fastvps-doctor-release-review-20261011`; its Python source and tests were refreshed to the final reviewed versions. Both copies excluded Git metadata and local build/cache/virtual-environment artifacts. The original Windows working tree was not used as the Linux test checkout.

## WSL availability diagnosis

The earlier QA run could not use WSL because the Codex execution context returned an access-denied error. It was not caused by a missing WSL executable or missing Linux distribution. In this run, the read-only Windows checks succeeded:

| Check | Observed |
| --- | --- |
| `wsl --list --verbose` | Ubuntu distribution present; WSL 2; initially stopped |
| `wsl --status` | Ubuntu is default; WSL 2 is default |
| `wsl --version` | WSL 2.7.11.0; kernel 6.18.33.2-2 |
| Distribution after launch | Ubuntu 26.04 LTS; Python 3.14.4; systemd is PID 1; test user is unprivileged |
| Docker | Unavailable in this environment |

No WSL setting was changed, no distribution was installed, and no system package was installed. The WSL distro lacked the venv pip bootstrap package and sudo required an interactive password. Pip was bootstrapped from PyPI into an isolated project virtual environment after hash verification. Project dependencies were installed only in isolated virtual environments.

## Test evidence and environment boundaries

The earlier Windows-only QA snapshot is retained in [QA_BASELINE_WINDOWS_132.md](QA_BASELINE_WINDOWS_132.md): 132 passed and two Linux integration tests skipped. The current expanded Windows suite has two additional regression tests and records 134 passed with the same two platform skips.

| Environment | Tests actually executed | Result |
| --- | --- | --- |
| Windows 11, CPython 3.13.7 | Full unit suite, including expanded failure/privacy regression tests | **134 passed, 2 skipped**. Skips are the opt-in Linux integration tests. |
| WSL Ubuntu 26.04, CPython 3.14.4 | Refreshed full unit and opted-in Linux integration suite from the native Linux filesystem | **136 passed, 0 skipped** in 3.49 seconds |
| WSL Ubuntu 26.04 | Final wheel build/install, generated CLI, JSON diagnosis, JSON/Markdown reports and permission checks | Passed; details below |
| GitHub Actions | Workflow configuration reviewed | Not run; no workflow result is available |
| FastVPS.gr VPS (Ubuntu 24.04.5) | No tests | Not accessed |

Linux coverage in the refreshed run was 1,849 statements with 138 missed (**92.5% statement coverage**). Branch-inclusive coverage was **90%** (640 branches, 80 partial). These percentages measure executed code paths; they do not prove the usefulness or safety of every diagnosis.

The final Linux test command was equivalent to:

~~~bash
FASTVPS_DOCTOR_INTEGRATION=1 .venv-linux-qa/bin/python -m pytest -q --basetemp /tmp/fvd-qa-tmp --cov=fastvps_doctor --cov-branch --cov-report=term-missing
~~~

Linux static and environment checks passed:

- Ruff lint and formatting check (56 Python files).
- mypy (18 source files).
- `pip check`.
- The final Linux source installation and tests ran as an unprivileged user.

The final Windows suite passed with 134 tests and two Linux-only skips. Ruff lint, formatting, mypy and `pip check` passed. Earlier repository QA also recorded a successful `uv lock --check`. The prior Bandit review found four Low findings and no Medium/High findings; pip-audit found no known vulnerabilities in that local environment but could not audit an unpublished PyPI release. Those security-tool results are supporting historical evidence, not a certification or a substitute for review of the exact release commit.

## Real Linux CLI and installation checks

The final smoke run executed 11 CLI paths: version, help, JSON diagnose, system, storage, network, services, security, web, custom systemd unit inspection, and a short incident timeline. Both report formats were generated as well.

- JSON outputs parsed with schema version 2.0.
- JSON and Markdown report files had mode `0600`.
- The test report contained none of the WSL test user's username, home-directory path, or local hostname.
- A selected `systemd-journald.service` identifier appeared in the report as `[REDACTED SERVICE]`; the literal unit identifier was absent.
- For final candidate revalidation, a Linux wheel was built from the reviewed source, installed into a fresh isolated venv, and exercised through the generated `fastvps-doctor` console entry point. The `version` command, JSON diagnosis, JSON/Markdown reports, and uninstall all worked. The diagnosis parsed as schema 2.0 and contained nine checks; generated report files were mode `0600`.
- Earlier real WSL report smoke checks confirmed no local username, home-directory path or hostname marker was present. Regression tests verify that custom unit names, including incident-analysis metadata and narrative fields, are replaced with `[REDACTED SERVICE]` in exported JSON and Markdown.
- Native Linux comparisons were made in WSL. The app's root storage and inode values were approximately 0.2% and 0.1%, versus `df`'s rounded 1% values. App memory use was 18.0% versus approximately 18.1% calculated from `/proc/meminfo`. The default-route result agreed with `ip route show default`. Differences are consistent with rounding and sampling.
- systemd reported a running system and `systemd-journald.service` loaded/active. This validates behavior in this WSL environment only.

A 1-minute incident query completed. A 30-minute journal query hit the runner's 65,536-byte output cap and was reported as incomplete; the app did not export raw journal messages. This is an observed operational limitation when journals are chatty, not evidence of complete incident coverage.

## Actual, simulated, skipped, and blocked checks

| Classification | Checks |
| --- | --- |
| Actually executed on Linux | Unit suite and opted-in Linux integration tests in WSL Ubuntu 26.04; source install; rebuilt wheel install and console entry point; real unprivileged diagnostics; systemd query; JSON/Markdown output; POSIX report permissions; report identity-marker check; storage/memory/route comparisons; short incident query |
| Simulated with mocks/fixtures | Disk and inode pressure, malformed/unsupported mounts, inaccessible files, memory/PSI/swap and OOM evidence, DNS errors/timeouts, IPv4/IPv6 route failures, missing/masked/failed services, restart loops, SSH/UFW command failures, malformed outputs, hostile report text, credential patterns, PEM private keys, and timeout cleanup edge cases |
| Skipped by design | The two opt-in integration tests on Windows; destructive failures were not injected on WSL or any live server |
| Blocked/unavailable | Docker-based Ubuntu 24.04 and Debian 12/13 local runs (Docker unavailable); GitHub Actions run (no push/dispatch); system-level WSL venv package install (sudo required interactive authentication) |
| Still requires actual target Linux testing | The sponsored Ubuntu 24.04.5 host, Ubuntu 24.04 container, Debian 12/13 containers, and live customer environments |

No full disk, inode exhaustion, resolver outage, failed production service, invalid daemon configuration, or OOM was induced on WSL or the sponsored VPS.

## Defects found and fixed

| Finding | Correction | Regression evidence |
| --- | --- | --- |
| A custom service name such as `systemd-journald.service` was incorrectly classified as a hostname, creating misleading `[HOSTNAME]` output | Custom service identifiers now export as the generic `[REDACTED SERVICE]` label | Added regression in `tests/test_services.py`; verified in WSL reports and rebuilt wheel |
| Arbitrary selected systemd unit names could remain in incident service and affected-service metadata or incident narrative fields | Incident service identifiers are now allowlisted; custom identifiers and their exact forms in incident text are replaced with `[REDACTED SERVICE]` | Regression covers `customer-private-api` in structured and narrative fields and asserts absence from JSON and Markdown; included in the 136-test Linux run |
| A platform API may return `None` for the disk partition inventory, while storage collection assumed a list | Storage now treats missing partition inventory as unavailable and preserves root metrics | Added regression in `tests/test_storage.py`; Linux tests pass |

The CI workflow also now has top-level `contents: read` permissions. Existing changes were retained.

## CI workflow review

`.github/workflows/ci.yml` has independent jobs:

- Ubuntu unit and quality jobs on Python 3.11, 3.12, and 3.13.
- A disposable container integration matrix for Ubuntu 24.04, Debian 12, and Debian 13. The image runs as an unprivileged user and covers installed CLI output plus process-group timeout cleanup.
- Workflow token permissions are limited to `contents: read`.

The workflow is configured, not executed. No GitHub dispatch or push was made. Local Docker was unavailable, so the Debian and Ubuntu 24.04 containers were not run here.

## Security and operational limits

- The command runner uses shell-free argument vectors, timeouts, output caps, and controlled executable lookup. Linux timeout/process-group behavior was exercised by the opt-in tests, but utility behavior still varies by distro and permissions.
- Four Bandit Low findings were reviewed: two literals are false positives; B404/B603 identify the centralized subprocess runner. No Medium/High Bandit finding was reported.
- The report sanitizer uses explicit metric/field allowlists and bounded pattern redaction. It is not a universal DLP scanner. Review every report before sharing.
- WSL tests do not establish the sponsored VPS's access permissions, service setup, mounts, SSH policy, log retention, or output volume.
- This is not a production-readiness or security certification and does not establish FastVPS approval, provider responsibility, or support-scope fit.

## Remaining validation

1. After the owner reviews and pushes the prepared commit, inspect and retain all GitHub Actions Ubuntu and Debian matrix results.
2. Use the final staged-file scan recorded with the commit; do not add unscanned files afterward.
3. If desired, perform the normal-user, read-only smoke checks in [the sponsored VPS guide](LINUX_VPS_TESTING_GUIDE.md). Do not run failure simulations, config validators, APT simulation, or the integration test flag on that server.
4. Ask a Linux engineer to review commands, report language, privacy assumptions, and operational value.
5. Keep compatibility claims limited to the tested WSL Ubuntu 26.04 / Python 3.14.4 environment until other platforms have actual results.

## QA conclusion

The earlier WSL access failure was an execution-context access denial. WSL is now usable, and final candidate source/tests passed on WSL Ubuntu 26.04, including Linux integration tests and an installed wheel. This supports a controlled beta candidate for engineering evaluation. The sponsored Ubuntu 24.04.5 host, Ubuntu 24.04/Debian CI containers, and GitHub Actions results remain unverified. **Do not claim production readiness or verified compatibility with the sponsored server.** See [release readiness](RELEASE_READINESS.md) and [gap analysis](GAP_ANALYSIS.md).

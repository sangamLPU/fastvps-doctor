# FastVPS Doctor QA report: v0.2 history and v0.3 validation

**Assessment date:** 11 October 2026
**Historical v0.2 result:** Final code/test revalidation passed on WSL Ubuntu 26.04; Ubuntu 24.04.5, Debian, GitHub Actions, and the sponsored VPS remained unverified.
**Current v0.3 results:** See the appended v0.3 section for the final 154-test Windows and 158-test WSL results, final wheel identity, and outstanding compatibility gaps.
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

---

# v0.3.0 Linux validation and QA

**Assessment date:** 11 October 2026
**Source:** v0.3.0 working tree (Windows checkout)
**Linux copy:** `$HOME/fastvps-doctor-v03-qa-20261011` on the WSL native filesystem
**Remote access:** No sponsored VPS, FastVPS service, or other remote server was accessed. No commit or push was made.

The v0.2 results above are retained as historical evidence. The counts below include the v0.3 scenario-report, privacy, timeout and disposable-loopback additions.

## Executed tests and quality checks

| Environment | Exact result | Notes |
| --- | --- | --- |
| Windows 11 / CPython 3.13.7 | **154 passed, 4 deselected** | `python -m pytest -q -m "not integration"`; all four opt-in Linux tests were excluded. This is not Linux evidence. |
| WSL Ubuntu 26.04 / CPython 3.14.4 | **158 passed, 0 skipped, 5.24 seconds** | Full suite with `FASTVPS_DOCTOR_INTEGRATION=1`, including installed CLI, Linux process-group timeout, a real loopback HTTP response and the live-local demo. |
| Windows and WSL source quality | **Passed** | Ruff lint, Ruff formatting check and mypy; WSL mypy checked 19 source files. |
| WSL package dependencies/lock | **Passed** | `pip check`: no broken requirements. `uv lock --check --offline`: resolved 28 packages and verified the lock. |
| GitHub Actions | **Not executed** | Workflow configuration was inspected, not dispatched. |

Four Linux integration tests consist of two pre-existing installed-CLI/process-timeout tests plus v0.3 loopback checks. The loopback tests start a temporary HTTP server on `127.0.0.1`, return a controlled 503 to a `HEAD` request, and stop the server. No external address or customer service is contacted.

## Packaging, CLI and report checks

- A fresh isolated WSL virtual environment was created. The WSL image did not provide `ensurepip`; no OS package or system setting was changed. Pip was bootstrapped from a PyPI wheel after checking its SHA-256 against PyPI JSON metadata, then dependencies were installed only into the project venv.
- The final v0.3.0 wheel was built and installed from the wheel file. It is 66,240 bytes; SHA-256 `b452ede820bd0ddf377321797719cfdbb2ed2ef4f0768e5de2634f666a7232a9`. Its generated CLI returned `FastVPS Doctor 0.3.0 (independent, unofficial contribution)`. A real storage JSON report from this exact wheel parsed and had mode `0600`.
- The generated `fastvps-doctor` console entry point returned `FastVPS Doctor 0.3.0`.
- The website-unavailable, service-crash and storage scenarios each ran real unprivileged WSL diagnostics. JSON schema 1.0 validated and Markdown rendered. New JSON/Markdown report files had POSIX mode `0600` and did not contain checked markers for the WSL username/home, loopback IP, credential assignment or private-key block.
- The selected read-only `systemd-logind.service` inspection reported `active`, `running`, `NRestarts=0`, matching a direct `systemctl show` read. Its timeline may still be incomplete due to WSL journald availability/retention.
- Root storage reported 0.3% space and 0.1% inode usage. `df -P /` and `df -Pi /` displayed 1% for both after integer rounding. This is a comparison on the WSL root filesystem only.

## v0.3 scenario performance sample

Runs used the installed wheel on WSL Ubuntu 26.04 / Python 3.14.4. Command counts wrap actual calls through `CommandRunner._invoke`. RSS includes Python and imported modules. The HTTP request is a loopback socket request, not an external command.

| Scenario/options | Time | Peak process RSS | External commands | JSON | Markdown |
| --- | ---: | ---: | ---: | ---: | ---: |
| Website unavailable; one unit, journals, port and opted-in loopback HEAD | 0.288 s | 36.7 MiB | 3 | 6,481 bytes | 4,972 bytes |
| Service crash; one unit and bounded journal | 0.209 s | 36.3 MiB | 3 | 3,386 bytes | 3,169 bytes |
| Storage; no related service | 0.006 s | 36.5 MiB | 0 | 3,375 bytes | 3,181 bytes |

The JSON byte count includes its final newline. Timeline contents may change with available journal events. The runner caps a subprocess timeout at five seconds and separately bounds cleanup. These are single WSL measurements, not performance guarantees. Optional configuration validation adds a command.

## Mocked, skipped and outstanding checks

- Synthetic tests mock systemd properties, malformed/permission-denied journal output, event correlations, service failures, high disk/inode use, read-only filesystems and secret-bearing text. These cases did not alter a real service or filesystem.
- The live local HTTP 503 tests use a disposable loopback server. They validate the local HTTP path but do not validate a public website, Nginx, DNS, TLS or provider network route.
- Four tests were deselected on Windows because they require Linux. None were skipped in the WSL full-suite run.
- Ubuntu 24.04, Debian 12 and Debian 13 integration images and the GitHub workflow remain untested until the workflow runs. Python 3.11/3.12 Linux behavior is not established by WSL Python 3.14.4.
- The user's report of a sponsored Ubuntu 24.04.5 / Python 3.12.3 smoke test is user-reported only. It is not independently confirmed by these commands.
- No full filesystem, OOM, invalid configuration, network outage or production service failure was induced. Those remain restricted to mocks or separately disposable environments. Real FastVPS support suitability, plan scope and engineering approval remain unreviewed.

## v0.3 QA conclusion

The current code passed its Windows unit/fixture checks and a separate WSL Linux suite, wheel install, live loopback example and report-permission checks. This supports a **beta candidate for engineering evaluation** only. CI images, GitHub Actions, the sponsored VPS and production conditions remain unverified. See [v0.3 release readiness](RELEASE_READINESS.md), [the gap analysis](GAP_ANALYSIS.md), [product focus](V0_3_PRODUCT_FOCUS.md), and [the limitations](LIMITATIONS.md).

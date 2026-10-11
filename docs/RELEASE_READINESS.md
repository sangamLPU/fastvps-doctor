# FastVPS Doctor v0.3.0 beta readiness

**Assessment date:** 11 October 2026
**Classification:** Beta candidate for engineering evaluation
**Production readiness:** Not established
**Official FastVPS status:** Independent and unofficial

## Decision

The current working tree is suitable for **engineering evaluation after code review**. It adds a focused three-scenario troubleshooting flow and support report while retaining the v0.2 diagnostic commands. The evidence does not establish production readiness, security certification, official FastVPS support, or compatibility with every Ubuntu/Debian installation.

No sponsored VPS, FastVPS infrastructure, or remote server was accessed. No test changed systemd configuration, stopped a service, exhausted storage, caused OOM, or changed network/security configuration. No commit or push was made.

## Verification evidence

| Environment | Result | What was exercised |
| --- | --- | --- |
| Windows 11, CPython 3.13.7 | **154 passed; 4 deselected** | Unit and fixture tests. Four Linux integration tests were excluded by the `not integration` selection. Ruff, formatting, mypy and `pip check` passed. These results do not establish Linux behavior. |
| WSL Ubuntu 26.04, CPython 3.14.4 | **158 passed; 0 skipped** | Full suite including installed CLI, process-group timeout cleanup, actual loopback HTTP probe, and complete live-local 503 demo. Linux Ruff, formatting, mypy and `pip check` passed. |
| WSL package installation | **Passed** | Built `fastvps_doctor-0.3.0-py3-none-any.whl`, installed that wheel in an isolated virtual environment, ran the generated console script and verified version 0.3.0. No system package was installed. |
| WSL reports and diagnostics | **Passed** | Website, service-crash and storage reports were generated from read-only WSL checks. JSON schema 1.0 parsed; Markdown rendered; POSIX report modes were `0600`; no checked WSL identity markers were present. |
| GitHub Actions | **Configured; not run** | Ubuntu quality matrix uses Python 3.11–3.13. Separate unprivileged integration images are `ubuntu:24.04`, `debian:12` and `debian:13`. Workflow configuration is not a passing result. |
| Sponsored FastVPS VPS | **Not independently verified** | You reported a manual smoke test on Ubuntu 24.04.5/Python 3.12.3, including installation, reports, file mode and comparisons with native utilities. You also reported incomplete SSH/UFW evidence and extra unsupported mount metrics. This review did not reproduce those observations or connect to that server. |

The WSL integration suite exercised a temporary loopback-only server which deliberately returned HTTP 503. The server was bound to `127.0.0.1` on an ephemeral port and shut down after the request. A separate read-only WSL service check reported `systemd-logind.service` active/running with `NRestarts=0`, matching `systemctl show`. The root storage reading (space 0.3%, inodes 0.1%) was directionally consistent with `df` output rounded to 1%; this comparison is specific to the WSL filesystem.

## Measured scenario cost in WSL

Each timing below is one unprivileged WSL 26.04 run using the installed v0.3.0 wheel. Peak RSS includes Python and imported dependencies. Command count wraps the real central subprocess runner; the loopback HTTP request is not an external command.

| Scenario | Elapsed | Process peak RSS | External commands | JSON bytes | Markdown bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Website unavailable, service + journal + loopback HEAD | 0.288 s | 36.7 MiB | 3 | 6,481 | 4,972 |
| Service crash, service + bounded journal | 0.209 s | 36.3 MiB | 3 | 3,386 | 3,169 |
| Storage without related service | 0.006 s | 36.5 MiB | 0 | 3,375 | 3,181 |

The maximum configured timeout for a subprocess is five seconds; `CommandRunner` also bounds process cleanup and output. These measurements are a small WSL sample, not a latency or memory guarantee for other hosts. Optional configuration validation adds one bounded command.

## Remaining validation gaps

- GitHub Actions must run after you publish the reviewed commit. Retain the workflow URL and inspect every Python and Linux image job.
- Ubuntu 24.04.5, Debian 12, Debian 13, Python 3.11/3.12 on Linux, and the sponsored server were not tested by this review. WSL Ubuntu 26.04/Python 3.14.4 is a distinct environment.
- WSL does not reproduce a VPS provider kernel, networking, cgroup policy, systemd layout, journald retention, UFW policy, or managed plan scope.
- No real Nginx/Apache/SSH syntax failure, production app route, filesystem exhaustion, inode exhaustion, OOM event, public reachability failure or real service crash was induced. Failure cases use deterministic mocks/fixtures; a disposable local 503 HTTP server was the only live scenario fault.
- Redaction is pattern-based and allowlist-based, not a universal secret scanner. Always read the entire report before sharing it.
- systemd and journal access can be incomplete for an unprivileged user. Missing or inaccessible logs do not prove that no event occurred.

## Before showing this candidate to FastVPS engineers

1. Review every change in the uncommitted diff, including the product-focus, report and limitations wording. Confirm no unrelated local files are included.
2. Run the repository publication scan on the exact files you plan to publish. Treat test strings such as `sample-secret` as synthetic fixtures; do not treat the scan as a guarantee.
3. Publish only after your own review, then inspect all GitHub Actions results for Ubuntu 24.04, Debian 12 and Debian 13. Fix failures before describing those images as tested.
4. Ask FastVPS engineers to evaluate the three workflows, support usefulness, uncertainty language, report privacy, non-root permissions, systemd/journal behavior and whether any wording implies provider responsibility.
5. If you need a sponsored-server confirmation, personally run only the normal-user read-only checks in [the Linux validation guide](LINUX_VPS_TESTING_GUIDE.md). Do not induce failure, use `sudo`, run package simulations, or make service/network/security changes there.
6. Describe the project as an independent beta candidate for engineering evaluation. Do not call it production-ready or an official/endorsed FastVPS product.

## Safe operating boundary

Use an ordinary account. The tool does not need SSH credentials, FastVPS account access or external telemetry. Do not run `--live-local` on the sponsored VPS; it starts a temporary HTTP service. Do not use the integration-test environment flag there. Review any report privately and remove details you do not intend to share.

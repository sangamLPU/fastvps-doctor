# Engineering review and master-prompt gap analysis

**Review date:** 10 October 2026  
**Reviewed version:** 0.1.0, working tree after reliability fixes  
**Host used for this review:** Windows, Python 3.13.7

This review compares the implementation with the original FastVPS Doctor master prompt. “Implemented” means code or documentation exists; it does not mean Linux compatibility, operational correctness on a live VPS, or FastVPS approval has been established.

## Readiness summary

FastVPS Doctor is an independently developed prototype with a useful read-only CLI core, conservative structured findings, local reports, and a meaningful automated unit suite. It is **not ready to be described as Linux-verified or production-ready**. The code has not yet run on Linux in this review environment. Linux integration is now configured to run inside a disposable Ubuntu 24.04 Docker image in CI, but that workflow must complete successfully before citing its result.

The fixes in this review reduce several concrete risks: OS commands no longer resolve through the user's `PATH`, Linux subprocess timeouts kill the command process group, storage pressure accounts for filesystem-reserved capacity, exported text gets common-pattern redaction, reports request owner-only POSIX permissions, and Linux-only network/web checks now skip on unsupported platforms. These code paths still need execution on Linux.

## Requirement-by-requirement status

| Master-prompt area | Current implementation | Status and remaining work |
| --- | --- | --- |
| FastVPS research and independent identity | README and proposal cite FastVPS public VPS, managed-scope, tools, FAQ and platform pages. Disclaimers say independent/unofficial; no logos, APIs or credentials. | **Implemented as research/docs.** Recheck official scope before presenting; do not imply FastVPS endorsement or a support-workflow partnership. |
| Python/tooling foundation | Python 3.11+, Typer, Rich, psutil, Pydantic, pytest, Ruff, mypy, `pyproject.toml`, wheel/sdist build and GitHub Actions. | **Implemented.** Current local checks are Windows-only. Linux CI and supported-version installation still need successful runs. |
| CLI commands and JSON | `diagnose`, `system`, `storage`, `network`, `services`, `security`, `web`, `explain`, `report`, `version`; bounded options, no-color and ASCII flags. | **Implemented with limited scope.** Progress indicators are not implemented. CLI errors and output need Linux terminal review. |
| System health | CPU sample/count, load, memory, swap, uptime, distro/kernel and memory/I/O PSI when available. | **Partial.** One brief sample only; no history or CPU PSI metric; Linux `/proc`, psutil and distro behavior need validation. |
| Storage | Root filesystem space, inodes, read-only state and mounted-filesystem count; reserved blocks now inform user-available capacity. | **Partial.** No per-mount capacity inventory or large-directory analysis. Validate `statvfs` values against `df -h` and `df -i` on each target filesystem. |
| Network | Interface/address counts, IPv4 default-route observation, resolver-file parsing, explicit one-host DNS/TCP test, selected local listener counts. | **Partial.** IPv6 routes/policy routing are absent; resolver-manager behavior varies; listener ownership can be permission-limited; no network namespace analysis. Validate on Linux. |
| Service checks | Fixed common executable/unit list, systemd active state, bounded recent journal error-word counts for failed services, selected Nginx/Apache/SSH validators. | **Partial.** Service presence is inferred from executable names and has possible MySQL/MariaDB alias ambiguity; no custom units, resource-pressure sampling, DB validators or non-systemd support. Validator side effects and output handling need Linux checks. |
| Security review | A few main-file SSH indicators, UFW status, optional generic APT upgrade simulation, selected local-port counts. | **Partial and deliberately narrow.** SSH `Include`/`Match` effective settings are not evaluated; only UFW is queried; updates are not security-advisory classified; APT simulation disables package-manager locking and may be incomplete for non-root users; firewalld/nftables and broader permissions/security features are absent. Never call it a security audit. |
| Web diagnostics | Loopback TCP handshakes for 80/443 and selected local listener counts. | **Partial.** No TLS inspection, app route/HTTP response, public reachability, reverse-proxy validation in the `web` command, or app-startup correlation. More than one socket entry is not proof of a port conflict. |
| Deterministic explanation rules | Disk/inode thresholds, low-memory vs PSI evidence, failed services, network resolver/route tests, user-requested port and limited SSH indicators. | **Partial.** Rules have tests, but false positives and threshold usefulness still need operator feedback. Port entries cannot identify a competing process reliably. |
| Support reports and privacy | JSON/Markdown, UTC timestamp, version, distribution, actual coverage, statuses, findings, next steps and optional ticket reference; field allowlists and common-pattern text redaction; no upload. | **Implemented with limits.** Reports are not a universal DLP system; review before sharing. Check completeness and file permissions on Linux. Static finding text and allowlisted metrics must remain the only exported data sources. |
| FastVPS support profile | Adds optional ticket reference, plan-scope reminder, official FAQ link and review reminder; finding scope can be guest or undetermined. | **Partial.** No infrastructure-facing rule currently exists, no ticket API is used, and classification does not decide provider responsibility. |
| Safe execution | Central fixed command methods, `shell=False`, bounded output, discarded stderr, minimal child environment and no repair operations; command lookup now ignores caller `PATH`. | **Implemented in code; Linux behavior unverified.** Process-group timeout cleanup, trusted-directory resolution, and permission behavior need CI/container execution. A timed-out DNS/TCP worker cannot be cancelled and may finish in the background. |
| Quality/testing | Unit tests, platform mocks, failure fixtures, a disposable Linux integration test and CI matrix for Python 3.11–3.13. | **Partial.** Windows run cannot verify Linux. The Linux integration job has been configured but needs an actual successful GitHub Actions run. Debian 12/13 and Ubuntu 26.04 are not in the Docker integration image. |
| Documentation | README, install/quick-start/reference/security/architecture/troubleshooting/testing/limitations/contributing docs, proposal, letter, example report, presentation outline and live-VPS guide. | **Mostly implemented.** The presentation is Markdown, not a finished slide deck or recorded demo. Commands and compatibility notes must be rechecked after Linux testing. |
| Future expansion | Historical comparisons, incident timelines, broad log correlation, backup verification, dashboard and provider integration are not present. | **Correctly deferred** by the master prompt. Do not add until the current checks have Linux evidence and operator requirements. |

## Concrete code findings fixed in this review

1. **Caller-controlled executable lookup:** `shutil.which()` previously searched the user's `PATH`, allowing an executable with an allowlisted name in a writable/current directory to be selected. Resolution now uses fixed conventional Linux system directories and ignores non-Linux hosts.
2. **Timeout cleanup:** a timed-out command previously killed only the immediate PID and could leave a child process holding the captured pipe. Linux commands now start in their own process group; timeout cleanup signals that group and returns if cleanup itself remains stuck.
3. **Filesystem capacity under-reporting:** `psutil.disk_usage().percent` does not necessarily reflect capacity available to an unprivileged account when the filesystem reserves blocks/inodes. Root capacity/inode percentages now use `statvfs` available counters; incomplete counters produce `UNKNOWN` rather than a pass.
4. **Report text and metadata:** unknown check types are not exported, report text is scrubbed for common hostname/IP/path/username/credential patterns, ticket references are restricted to identifier characters, and report files request mode `0600` on POSIX systems.
5. **False platform/state results:** Windows no longer reports Linux network/web probes as successful; route entries must be up; malformed nameserver addresses are not counted; malformed/non-finite PSI is unavailable; and a service is active only with consistent success output.
6. **Partial status and requested TCP checks:** skipped checks do not produce findings or count as diagnostic coverage. The TCP check now has a wall-clock deadline and reports timeout separately from a refused/failed connection.

These fixes are covered by unit regressions. The process-group and POSIX permission behavior require Linux execution for confirmation.

## Outstanding risks and validation tasks

- Compare root space and inode percentages with `df -h /` and `df -i /` on Ubuntu and Debian; check ext4 and any filesystem used by the VPS.
- Confirm `systemctl`, `journalctl`, `ufw`, `nginx -t`, `apache2ctl configtest`, `apachectl configtest`, `sshd -t` and APT simulation behavior using least privilege. No system should be modified.
- Confirm output caps and process-group termination with the disposable Linux integration test; inspect the process state after timeout.
- Run the installed package (not only source imports) in an unprivileged Python 3.11+ venv on the actual guest OS and at least one disposable supported Ubuntu image. Add Debian disposable validation before making Debian-specific compatibility claims.
- Compare sanitized Markdown/JSON against local identifiers and check `stat -c '%a'` reports `600` for exported files. Test Windows ACL behavior separately if Windows output is ever supported.
- Validate default network behavior with a healthy and disconnected disposable Linux VM. Do not induce route, firewall, DNS, disk, or service failures on the sponsored production VPS.
- Resolve service detection ambiguity and decide whether to expose `systemd` absence as unknown before widening supported environments.
- Ensure every report claim maps to an executed check, and preserve the explicit statement that a clean result is not proof of health/security.

## Before presenting to FastVPS.gr

1. Run all local checks listed in `docs/TESTING.md` after pulling the final changes.
2. Run the `linux-integration` GitHub Actions job and keep its result link. It exercises Ubuntu 24.04 only; it does not verify every supported release.
3. Run the [safe VPS guide](LINUX_VPS_TESTING_GUIDE.md) as a normal user on the sponsored host only after checking its OS/Python against the target matrix. Review reports locally and do not attach an unredacted report.
4. Before claiming Debian compatibility, run the package on a disposable Debian 12 and Debian 13 environment. Before claiming Ubuntu 26.04 compatibility, run the package in a disposable Ubuntu 26.04 environment.
5. Reconcile the README, proposal and presentation claims with the observed test matrix. Present the project as an independent prototype and list limitations openly.
6. Decide where the source will be reviewed (for example, a version-controlled repository) and make sure the license, exact tested commit and CI results are visible. No Git repository or release artifact publishing was performed as part of this review.
7. Ask FastVPS engineers for feedback on service names, plan scope, report usefulness and acceptable checks; do not imply adoption or support-process integration.

Until items 2–4 succeed, say **“Linux validation is pending”**, not “Ubuntu/Debian compatible” or “tested on a FastVPS VPS.”

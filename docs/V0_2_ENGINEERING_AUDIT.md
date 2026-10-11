# FastVPS Doctor v0.2 engineering audit

**Review date:** 11 October 2026
**Baseline:** `main`, clean before this review; Windows 11 / Python 3.13.7
**Baseline tests:** 60 passed, 2 opt-in Linux integration tests deselected
**Scope:** Existing Python modules, CLI, report/privacy pipeline, tests, packaging, GitHub Actions and user documentation. No VPS or other production host was accessed.

This is a code and test review, not a Linux compatibility certification. Findings below point to implementation evidence. A passing Windows test run does not establish behavior on Ubuntu or Debian.

## Executive summary

The existing prototype has good safety foundations: subprocess calls are centralized, argument vectors avoid a shell, common calls have time and output bounds, reports use metric allowlists, and tests cover several failure paths. It has no repair or upload feature. The baseline unit suite passes locally.

The main v0.2 gaps are an actual privacy defect in free-form ticket-reference handling, static rather than effective SSH configuration inspection, service detection that infers service state from executable presence, and the complete absence of the requested incident investigation workflow. Per-mount storage, IPv6 route checks, standardized incident report fields/schema versioning, meaningful automation exit codes, Debian CI and reproducible failure demonstrations are also missing.

No destructive behavior or critical vulnerability was confirmed in the reviewed code. This does not make the current prototype ready for external operational use: the privacy defect should be fixed first, and Linux behavior remains unverified in this Windows session.

## Findings

### Critical

No critical finding was confirmed.

### High

1. **Ticket-reference input can carry credential-shaped values into reports.** `src/fastvps_doctor/privacy.py:217-224` removes characters outside an identifier character set but does not reject or redact recognized credential formats. For example, token-shaped text containing only allowed letters, digits and underscores survives the transformation. `reports.py` then exports it. The existing ticket-reference tests cover punctuation and control characters but not realistic tokens (`tests/test_privacy_reports.py:214-220`). This conflicts with the stated credential-exclusion guarantee and needs a regression test and fix.

2. **SSH findings use a partial text parse, not effective sshd configuration.** `src/fastvps_doctor/checks/security.py:12-58` reads only one candidate main file, skips all settings after a `Match`, ignores `Include` files and defaults, and evaluates the first textual setting it sees. That can disagree with the effective policy used by the daemon. Findings in `src/fastvps_doctor/rules.py` explicitly describe the main file and are low confidence, but the aggregate still presents the values as security indicators. v0.2 should use bounded `sshd -T` effective output when safe and available, pass supported connection context for `Match` evaluation, and otherwise return unknown.

3. **Service inventory can misstate installed/managed service state.** `src/fastvps_doctor/checks/services.py:8-48` treats executable discovery as installation, then checks a single hard-coded unit. It cannot distinguish a missing unit from a masked unit or access restrictions, does not support aliases, templates or custom units, and can count MySQL and MariaDB separately from overlapping executable candidates. `runner.py:23-33, 147-153` constrains names safely, but exposes only `systemctl is-active`, whose result is insufficient for the requested state model. The result can therefore be incomplete or misleading even without a command-injection issue.

### Medium

4. **Incident investigation is not implemented.** There is no `incident_analysis` module or `incident` CLI command. Current service logs are queried only after a failed unit and reduced to an error-word line count (`checks/services.py:48-69`, `runner.py:152-160`). There are no journal timestamps, transitions, restart-loop evidence, OOM/pressure event classification, correlation windows, incident hypotheses, or user-provided incident context. This is a major v0.2 feature gap, not a hidden capability.

5. **Report format is not versioned and lacks incident handoff fields.** `models.py:72-90` has no schema version, incident metadata, environment/kernel summary field, timeline or dedicated handoff summary. The report currently contains diagnostic checks and generic next steps only (`reports.py:47-155`). Existing report formats should remain usable while a versioned v2 representation is added.

6. **Storage results cover only `/`.** `checks/storage.py:13-91` reports root capacity/inodes plus a count of mounted filesystems, not per-mount capacity, inode state, filesystem type, unsupported-filesystem reasons or mount-specific failures. If inode counters are unsupported, the whole root check becomes unknown, even if space usage is available.

7. **Network coverage is IPv4-centric and resolver observations are narrow.** `checks/network.py:18-37` reads `/proc/net/route`; it does not inspect IPv6 routes. Resolver diagnostics count syntactically valid nameserver lines in `/etc/resolv.conf` but do not identify systemd-resolved/resolvconf behavior or test reachability unless the user opts into DNS. DNS timeouts use a daemon thread that cannot be cancelled (`checks/network.py:124-145`), so repeated timeouts can leave background resolver calls alive.

8. **The default workflow runs config validators without a separate opt-in.** `checks/services.py:69-99` invokes `nginx -t`, Apache configtest and `sshd -t` whenever the matching executable is found. The commands are fixed and do not intentionally change configuration, but validator behavior, permissions and filesystem effects vary by service and distro. The tool’s broad “read-only” claim should not imply these commands are side-effect-free until tested on disposable Linux systems.

9. **Automated tests and CI do not cover the requested platform/scenario matrix.** The baseline contains 60 passing local unit tests and an opt-in Ubuntu 24.04 container suite. `.github/workflows/ci.yml` runs unit tests on Ubuntu across Python 3.11–3.13 but its Linux integration image is Ubuntu-only; Debian 12/13 are not exercised. Incident timelines, OOM/restart-loop fixtures, custom units, masked/missing units, unsupported filesystems, IPv6 routing and credential-shaped ticket references are not covered. The integration test confirms the installed CLI and Linux process-group timeout only.

10. **No reproducible failure demonstrations meet the v0.2 format.** `examples/simulated-report.md` is a useful synthetic report but there are no three complete reproductions with actual test output for website failure, storage pressure and a service restart loop.

### Low

11. **The CLI does not provide structured automation exit states.** `src/fastvps_doctor/cli.py` renders findings but has no documented exit-code contract distinguishing clean, finding, partial or invocation-error outcomes. This weakens support scripts and repeatable demonstrations.

12. **Support handoff data does not match the public ticket workflow.** The report accepts only an optional restricted ticket reference. It cannot capture incident start time, affected service, problem category or a brief customer description. The public FastVPS FAQ asks customers to include occurrence time, affected hostname/mailbox, exact error and actions already tried; the tool should collect a privacy-conscious subset and warn that identifying details are not automatically safe to share.

## FastVPS overlap and boundaries

FastVPS currently describes first-party public DNS/email and SSL/website checks, browser latency tests, VPS/service status and infrastructure monitoring. These are existing provider capabilities and should not be duplicated by adding public domain scans. FastVPS Doctor’s distinct scope is local guest evidence that a customer chooses to collect and review. Current code does not contact FastVPS, submit tickets or read provider-side telemetry.

Public service wording does not establish the management scope of an individual sponsored VPS. The selected plan, order and agreed operating scope must be confirmed with FastVPS; the tool must not assign provider responsibility from guest-only evidence.

Sources checked 11 October 2026: [FastVPS VPS](https://fastvps.gr/en/vps/), [Managed VPS scope](https://fastvps.gr/en/managed-vps-greece.html), [public technical tools](https://fastvps.gr/en/tools/), [FAQ and support process](https://fastvps.gr/en/faq/), and [platform overview](https://fastvps.gr/en/platform/).

## Implementation plan

1. Fix the report privacy regression first: reject or redact token/credential-like ticket references; add realistic synthetic regression cases.
2. Replace the incomplete SSH text parser with effective configuration inspection through an allowlisted, bounded `sshd -T` call; treat unavailable or context-dependent results as unknown.
3. Improve service inspection through bounded `systemctl show`/discovery calls, explicit state modeling, alias normalization and validated custom unit selection; do not infer managed state from binaries alone.
4. Add a deliberately small incident-analysis slice: user-selected service and bounded time window, structured journal input, strict size/record limits, timestamp validation, static event classification, no exported raw messages, and deterministic hypotheses only when evidence supports them.
5. Add versioned v2 report fields and a short support handoff while preserving current commands and report fields where possible. Extend allowlists before any new field can be exported.
6. Expand mocked failure fixtures and disposable Ubuntu/Debian CI where practical; keep any Linux claim limited to an image/job that actually passed.
7. Add three synthetic, test-backed demonstrations and align the README, architecture, limitations, gap analysis, proposal, presentation and letter with implemented behavior and explicit unknowns.

Do not add dashboards, remote ticket submission, auto-remediation, broad public network checks, or AI analysis in v0.2. Those do not reduce the confirmed risks and would expand trust boundaries.

## Verification boundary

The baseline command run in this session was `python -m pytest -m "not integration"` on Windows with Python 3.13.7: **60 passed, 2 deselected**. No Linux container was run from this Windows execution environment, and no sponsored VPS was accessed. All future reports must keep those facts distinct from GitHub Actions results.

## Implementation status update — 11 October 2026

The baseline findings above describe the code before the v0.2 hardening pass. The following changes have since been made and covered by unit regressions:

- **Ticket-reference export:** now accepts only a short conventional identifier; free-form values and credential-shaped references are omitted.
- **SSH effective configuration:** uses bounded `sshd -T`; connection-specific checks require the complete validated `Match` context. Missing output remains unknown.
- **Service state:** uses bounded systemd properties, distinguishes unit/binary absence and state uncertainty, handles common aliases and offers explicitly selected custom units. Config validators are opt-in.
- **Incident workflow and schema:** adds a one-unit bounded journal analysis, timestamp checks, static event classifications, cautious restart/OOM hypotheses, report schema 2.0 and support handoff fields. Raw journal messages are discarded.
- **Storage and network:** adds per-mount capacity/inodes with withheld paths, explicit incomplete state for unsupported/remote/unavailable mounts, IPv6 default-route observation, configurable local listener ports and swap corroboration with low memory.
- **Kernel journal command syntax:** a documentation check found the initial kernel query used an unsupported `journalctl --kernel` long option. It now uses the documented `_TRANSPORT=kernel` match, preserving records across boots inside the requested time window; a command-argument regression test protects this path. The systemd manual documents `-k/--dmesg` as the current-boot filter and its `_TRANSPORT=kernel` match ([journalctl manual](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)).
- **Privacy:** adds regression cases for known unlabelled token forms and PEM private-key blocks in user-entered descriptions. Pattern redaction is not universal and review remains required.
- **Operational workflow:** adds optional strict exit codes, failure-scenario fixtures, synthetic test-backed reports and an unprivileged live-VPS guide.
- **CI configuration:** adds Debian 12/13 disposable integration images alongside Ubuntu 24.04. The workflow is configuration only until it actually runs and passes.

The latest complete check set is recorded in [`docs/COMPLETE_QA_REPORT.md`](COMPLETE_QA_REPORT.md), with a formal decision in [`docs/RELEASE_READINESS.md`](RELEASE_READINESS.md). Later QA executed the working tree on WSL Ubuntu 26.04/Python 3.14.4, including Linux integration tests and an installed wheel. GitHub Actions, Ubuntu 24.04/Debian containers, and the sponsored Ubuntu 24.04.5 VPS remain unverified. Historical findings above describe the earlier audit snapshot; current status is in the newer QA report and gap analysis.

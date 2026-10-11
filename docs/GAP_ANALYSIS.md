# Engineering review and v0.2 master-prompt gap analysis

**Reviewed code version:** 0.2.0 working tree
**Windows test host:** Windows 11, Python 3.13.7
**Linux test host:** WSL Ubuntu 26.04, Python 3.14.4
**Scope boundary:** No sponsored VPS, FastVPS infrastructure, or remote server was accessed. No push was made.

“Implemented” means code and tests exist. “Linux tested” refers only to the WSL environment above. Neither label establishes production safety, FastVPS usefulness, adoption, or company approval.

## Current assessment

The reviewed candidate passed 134 Windows tests (two Linux-only tests skipped) and 136 Linux tests (including the opt-in integration tests) on WSL Ubuntu 26.04. Linux source and wheel installations, the console entry point, real unprivileged diagnostics, report output modes/permissions, systemd inspection, and selected comparisons with native Linux utilities were exercised. The WSL run does not match the sponsored server's Ubuntu 24.04.5 target.

**Release classification: BETA CANDIDATE FOR ENGINEERING EVALUATION.** The workflow is configured, but GitHub Actions has not run; no Ubuntu 24.04 or Debian container was tested locally, and the sponsored server was not accessed. This status does not mean production-ready or officially supported. See [release readiness](RELEASE_READINESS.md). An output-cap event in a longer WSL incident query was correctly reported as incomplete and remains an operational limit.

## Requirement-by-requirement status

| Master-prompt area | Current implementation and evidence | Remaining gap |
| --- | --- | --- |
| Repository review and security posture | Earlier code audit is in [V0_2_ENGINEERING_AUDIT.md](V0_2_ENGINEERING_AUDIT.md); current runner uses bounded, shell-free commands. Bandit has reviewed Low findings only. | Re-scan exact publish tree after final edits; human Linux review remains. No security certification. |
| CLI and packaging | Existing CLI plus incident workflow and optional strict exit codes. Linux source and rebuilt wheel installs passed; console script worked in WSL. | Ubuntu 24.04.5 and Debian install runs remain. GitHub integration-job evidence is pending. |
| System health and memory | CPU/load/memory/swap/PSI readings and cautious evidence rules. Real WSL reading compared with `/proc/meminfo`. | Point-in-time only; validate readings on target host and other Linux kernels. No trend history. |
| Storage | Root and bounded local mount capacity/inode/read-only checks; inaccessible and unsupported inventory stays incomplete. Nullable partition inventory is guarded and regression-tested. WSL root/inode values compared with `df`. | Compare ext4/VPS volumes on the target. No large-directory attribution and no live pressure test. |
| Network | IPv4/IPv6 route checks, resolver syntax, optional single-destination checks, and selected local listener checks. WSL default route agreed with `ip route`. | No policy routing, namespaces, provider path, or resolver-manager diagnosis. DNS helper threads cannot be forcibly cancelled after timeout. |
| Services | Bounded systemd property queries, common candidate units, custom-unit selection, and opt-in validators. WSL systemd and journald unit were observed active. Custom service names now redact to `[REDACTED SERVICE]`. | Ubuntu 24.04/Debian and target service setup are untested. Validators were not run on the sponsored server. Non-systemd managers remain limited. |
| SSH and security | Effective SSH setting inspection and limited UFW indicators; APT simulation remains optional. | No full security audit. Context-free SSH settings are not per-connection proof; UFW is not every firewall. Avoid APT simulation on the production test host. |
| Incident workflow | Bounded timestamped journal analysis with static event summaries and raw-message discard. Short WSL query ran; longer query exceeded the 65,536-byte runner cap and was marked incomplete. | Journal access, retention, truncation, and event formats vary. A WSL smoke is not a real service failure test and correlation is not causation. |
| Report v2 and privacy | Schema 2.0, metric allowlists, common-pattern redaction, exclusive output, and mode 0600. WSL JSON/Markdown reports parsed; local username, home, hostname markers absent; both file modes were 0600. | Pattern redaction is not universal DLP. Review the complete report manually; POSIX behavior on other filesystems and Windows ACLs are not certified. |
| Command safety and timeouts | Central runner, fixed argument forms, no shell, time/output bounds, and Linux process-group behavior. Linux integration tests passed in WSL. | Utility behavior and permissions vary by OS. Do not infer every command's production behavior from one distro. |
| Failure matrix | Mocks cover route/DNS failures, pressure, malformed outputs, permissions, service state, OOM/restart timelines, report secrets, and timeouts. | Destructive scenarios were not induced on WSL or VPS. Real invalid config, full filesystem, resolver outage, and service failure belong only in disposable fixtures/VMs. |
| CI and distro support | Workflow separates Ubuntu unit/quality jobs from disposable Ubuntu 24.04, Debian 12, and Debian 13 integration images; token permissions are `contents: read`. | Configuration is not a result. GitHub Actions has not run and local Docker is unavailable. These distro claims remain pending. |
| Demonstrations and support workflow | Synthetic demos are test-backed and identified as simulated. Report remains customer-controlled and provider-scope-neutral. | Obtain engineering feedback on usefulness and wording; no FastVPS review or adoption exists. |
| Sponsored VPS validation | A safe normal-user guide is available. | Not run. The user's Ubuntu 24.04.5 system was not accessed. User-run checks are optional and must remain read-only. |

## Linux validation performed

Actual Linux evidence in this review is limited to WSL Ubuntu 26.04 / Python 3.14.4:

- 136 tests passed, zero skipped, including the opt-in Linux integration tests.
- Ruff lint, Ruff formatting, mypy, and pip dependency consistency checks passed.
- Final Linux coverage was 92.5% by statements and 90% branch-inclusive.
- Linux wheel rebuilt and installed in a new venv; CLI console entry point and uninstall verified.
- Final wheel smoke ran the version command, JSON diagnosis, and JSON/Markdown report generation.
- Report files were mode 0600; tested WSL identity markers were absent.
- systemd/journald state and basic native storage, memory, and route comparisons were checked.
- 1-minute journal query completed. A 30-minute query exceeded the configured bounded output and was marked incomplete.

Windows evidence is separate: 134 passed and two Linux integration tests skipped. No Linux outcome is inferred from mocks.

## Required next steps

1. Review the proposed commit and its staged-file publication scan before pushing.
2. Push only after your own review, then run and retain GitHub Actions results for all configured jobs.
3. Resolve any Ubuntu 24.04, Debian 12, or Debian 13 CI failure before naming those as tested.
4. Optionally run only the normal-user read-only smoke checks on the sponsored VPS, following [the guide](LINUX_VPS_TESTING_GUIDE.md). Never perform destructive fault injection there.
5. Ask a Linux engineer to review command behavior, uncertainty, redaction limitations, and support workflow.
6. Keep external claims precise: tested in WSL Ubuntu 26.04, while the sponsored Ubuntu 24.04.5 and CI distro matrix remain unverified. Present this as an independent beta candidate for engineering evaluation, not a supported product.

## FastVPS scope comparison

FastVPS publicly describes infrastructure monitoring and customer-facing DNS/email, website/TLS, and latency tools. FastVPS Doctor provides optional local guest evidence and a customer-controlled support summary. A customer's order and written service agreement define support scope; the tool cannot determine responsibility. See [support use cases](FASTVPS_SUPPORT_USE_CASES.md) and [FastVPS public tools](https://fastvps.gr/en/tools/).

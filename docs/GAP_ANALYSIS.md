# FastVPS Doctor v0.3 master-prompt gap analysis

**Reviewed version:** 0.3.0 working tree
**Review date:** 11 October 2026
**Assessment:** Beta candidate for engineering evaluation; not production-ready
**Server access:** No sponsored VPS, FastVPS infrastructure or remote server was accessed.

This compares the current implementation with the v0.3 requirements summarized in [the product-focus document](V0_3_PRODUCT_FOCUS.md). “Implemented” describes code/tests present. “Verified” is limited to the environment and evidence named below. The prior v0.2 audit remains at [V0_2_ENGINEERING_AUDIT.md](V0_2_ENGINEERING_AUDIT.md); historical v0.2 QA results remain above the v0.3 section in [the complete QA report](COMPLETE_QA_REPORT.md).

## Requirement comparison

| v0.3 requirement | Current implementation | Evidence and remaining gap |
| --- | --- | --- |
| Exactly three focused support scenarios | `fastvps-doctor troubleshoot` offers website/application unavailable, service crash/restart, and disk/storage. It does not add unrelated workflow choices. | Interactive picker and explicit flags are tested on Windows; WSL full suite passed. No FastVPS engineer has assessed whether these are the most useful first scenarios. |
| Relevant, bounded checks per scenario | Website checks one selected unit, one selected port, bounded storage/resource context and bounded journal evidence; loopback `HEAD` is opt-in. Service crash checks one unit, systemd restart/exit properties, bounded service/kernel journal and a current resource snapshot. Storage checks root and bounded local mount counters, with one optional service timeline. | Unit tests assert targeted collector calls and absence of broad collectors. Real read-only WSL runs covered all three. Exact behavior can vary with systemd, journald, kernel and permissions. |
| Distinguish service state, listener, app response and public reachability | The report labels selected-unit state, local listener count, optional loopback HTTP response and public reachability as separate facts/limits. The HTTP probe sends one `HEAD /` to `127.0.0.1`, reads no body and follows no redirect. | A disposable Linux HTTP server returned 503 to the integration test. Public DNS, TLS, firewall path and external client access were not tested. |
| Restart and OOM evidence without false causation | The selected unit exposes restart count, result and available exit code/status. Timestamped service/kernel event summaries support repeated-restart and near-OOM observations; a single event is not labelled a loop. Current resources are a separate snapshot and never inserted into the historic timeline. | Mock fixtures cover multiple/single events, near-OOM correlation and incomplete journals. WSL systemd state was read-only inspected, but no restart/OOM failure was induced. Restart count has no time window; journal retention can hide records. |
| Storage diagnosis without customer-data search or causal overclaim | Root space, inode and read-only counters plus at most 16 bounded mount summaries are available. Optional selected-service errors are shown separately. No recursive walk, file-content read or deletion recommendation is made. | Tests cover high space/inode use, read-only state, unsupported and incomplete mounts. WSL root figures were compared with rounded `df` values. No real full-volume or write-failure scenario was induced. |
| Evidence traceability and calibrated wording | Reports use `OBS-*` and timestamped `EVT-*` identifiers. Conclusions use confirmed/plausible/insufficient and refer to observation/event IDs. Correlation language does not claim causation. | Unit and fixture tests assert IDs, certainty, timeline boundaries and one-event behavior. Human reviewers should still verify that wording stays useful and cautious. |
| Engineer-ready local support report | Scenario report schema 1.0 has the reported symptom, environment, checks actually run, observations, timestamped events, evidence-based explanations, investigation areas, evidence gaps and next actions. Markdown and JSON share the sanitized model. | JSON schema validation, Markdown render, wheel install and mode `0600` output were exercised in WSL. FastVPS engineers have not evaluated the report's usefulness. |
| Privacy and local-only handling | Check metrics are allowlisted; custom service names are redacted unless common; raw journal and validator output and application response bodies are excluded. Reports are exclusive-create local files and request POSIX mode `0600`. | Synthetic secret/path/host/credential tests pass; WSL reports had mode `0600` and passed selected marker checks. Redaction is pattern-based, not universal DLP. A user must manually review the full report. |
| Interactive and non-interactive command use | No-argument TTY use displays a numbered scenario picker and relevant prompts. Explicit `--scenario` use is flag-driven; required service/port values are validated. | Picker, cancellation, missing flags and explicit option paths are covered by tests. Platform-specific terminal input behavior still merits Linux operator review. |
| Safe operation | Central command runner uses fixed executables/argument forms, shell-free subprocesses, bounded output and timeouts. Troubleshoot performs no repair, install, restart, external scan, upload or automatic escalation. | WSL process-group timeout test passed. Live demo binds only to loopback and shuts down its temporary server. No privilege escalation is requested. Utility availability/permissions vary by distribution. |
| Demos, QA and performance record | Three deterministic report fixtures plus a live local HTTP 503 demo exist. Performance records elapsed time, process peak RSS, subprocess count and report size. | WSL 158 tests passed; Windows 154 passed with four Linux integrations deselected. One refreshed WSL performance sample is documented. Reproducible Debian/Ubuntu CI results are pending. |
| FastVPS-specific neutrality | Optional `--profile fastvps`, ticket-reference validation, official support link and plan-scope caveat are present. The project clearly says it is independent and unofficial. | No portal integration, credential collection, company approval, or responsibility assignment exists. Engineers must review brand/usefulness wording before presentation. |

## Test evidence boundaries

### Executed on Windows 11 / Python 3.13.7

- 154 passed; 4 Linux integration tests deselected.
- Ruff lint, Ruff formatting check and mypy passed.
- Windows tests do not establish Linux systemd, journald, `statvfs`, Linux process cleanup or loopback behavior.

### Executed on WSL Ubuntu 26.04 / Python 3.14.4

- 158 passed, zero skipped, including the opt-in integration suite.
- Linux Ruff lint, formatting, mypy and `pip check` passed; the updated lock was checked offline.
- A v0.3.0 wheel was built and installed in an isolated virtual environment; the generated command ran.
- Read-only service and storage readings were compared with `systemctl show`, `df -P` and `df -Pi` on this WSL instance.
- All three report scenarios, JSON/Markdown output and POSIX mode `0600` were exercised.
- The live integration examples ran an unprivileged loopback HTTP server that deliberately returned 503 and shut it down afterward.

### Simulated, not induced on a real host

Permission-denied and timeout outputs, missing units, high utilization, read-only filesystems, malformed/truncated journals, repeated restart events, OOM correlation, private markers and most rare failures are deterministic test fixtures/mocks. They do not prove how a given VPS kernel or daemon behaves during a real incident.

### Still unverified or blocked

- GitHub Actions is configured for Ubuntu quality jobs on Python 3.11–3.13 and integration images Ubuntu 24.04/Debian 12/Debian 13; no workflow has run.
- This review did not run Debian images or Ubuntu 24.04 locally; Docker was unavailable in the earlier WSL QA environment.
- The sponsored Ubuntu 24.04.5 VPS was not accessed. Your own smoke-test observations are recorded as user-reported, not independently verified.
- Real public reachability, Nginx/Apache/SSH configuration failure, true OOM, real service crash, capacity exhaustion and application-specific behavior remain untested.

## Overall gaps before a supported or production claim

1. Run and retain the complete GitHub Actions matrix; fix any failures before naming those images as tested.
2. Get Linux-engineer review of command semantics, output uncertainty, report safety and support workflow.
3. Use disposable Ubuntu 24.04/Debian environments for additional distro-sensitive cases. Do not inject faults into the sponsored VPS.
4. Ask FastVPS engineers whether the three scenarios and handoff report fit actual support intake and plan boundaries.
5. Continue describing the tool as an independent engineering beta. Do not claim production readiness, official endorsement, provider responsibility or universal secret removal.

## Earlier v0.2 status

The preceding v0.2 test counts and detailed engineering findings are kept in [the historical QA report](COMPLETE_QA_REPORT.md) and [v0.2 audit](V0_2_ENGINEERING_AUDIT.md); they are not replaced by v0.3 results.

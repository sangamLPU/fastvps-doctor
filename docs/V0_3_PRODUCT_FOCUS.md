# FastVPS Doctor v0.3 Product Focus

## Problem to solve

v0.2 can collect broad host snapshots and a bounded incident timeline, but a customer who needs help still has to choose commands, decide which observations matter, and assemble a useful support handoff. v0.3 should guide that customer through a small set of common incident patterns and produce a concise, private, evidence-based local report for human review.

FastVPS Doctor remains an independent, unofficial, read-only diagnostic utility. It does not determine root cause, establish provider responsibility, certify security, or replace FastVPS support.

## Initial scenarios

The command offers exactly these three workflows:

1. **Website or application unavailable** — inspect one explicitly selected systemd service, an explicitly selected local port, optionally an explicitly requested loopback HTTP response, a bounded service timeline, and narrowly relevant storage/resource observations. A successful loopback response does not establish public reachability. A running service does not prove the application is healthy.
2. **Service crash or restart** — inspect one selected systemd unit, its bounded structured journal events and available restart/result properties, kernel OOM indicators, and a current resource snapshot. Current pressure is never presented as historical evidence. A single failure event is not a restart loop.
3. **Disk or storage problem** — inspect filesystem capacity, inode availability, read-only state, and safe mount metadata; optionally inspect one related unit's bounded event history. Do not walk application data or infer that low disk space caused an unrelated write failure.

Each workflow labels observations with evidence identifiers. Findings distinguish confirmed, plausible, and insufficient evidence; every generated explanation points back to observations and lists what is unknown.

## Reuse from v0.2

- Reuse the allowlisted command runner, unit-name and time-window validation, system/resource and storage collectors, structured journal parsing, privacy sanitizers, exclusive private report writer, support-profile disclaimers, and existing diagnostic model types.
- Keep the existing `diagnose`, area commands, `incident`, and `report` behavior stable where possible.
- Build a scenario-specific orchestrator that invokes only relevant checks. A selected-unit collector must not inspect every common service.
- Extend bounded service-state properties with restart count and last exit/result details only where systemd exposes them and the result can be safely reduced to an allowlisted summary.

## Simplify or remove from this workflow

- Do not run unrelated security, network inventory, package simulation, or all-host checks from a scenario workflow.
- Do not retain or export raw journal lines, raw command output, application response bodies, arbitrary configuration contents, hostnames, IP addresses, usernames, filesystem paths, or secret values.
- Do not turn a current snapshot into a historical timeline event.
- Do not add probabilities, root-cause declarations, telemetry, remote upload, external scanning, auto-remediation, package installation, restarts, firewall changes, or SSH changes.

## Smallest feature set

- `fastvps-doctor troubleshoot` with a numbered interactive scenario picker and validated prompts; explicit flags for non-interactive use.
- Targeted evidence collection for the three scenarios, including optional loopback HTTP probing and optional supported configuration validation only when explicitly requested.
- A versioned scenario report in Markdown or JSON, generated only on local opt-in, with a review-before-sharing reminder and private file permissions.
- A concise terminal summary when no report file is requested.
- Deterministic offline demos, realistic unit tests, Linux CI coverage, and documentation of real-host validation limits.

## Explicit exclusions

No dashboards, web applications, customer account or database inspection, user enumeration, recursive customer-file search, application-specific plugins, AI/cloud analysis, automatic remediation, remote administration, provider portal integration, ticket submission, external reachability test, security certification, or claim of official FastVPS endorsement/support.

## Measurable acceptance criteria

1. Only the three named scenarios are offered; each is selectable interactively and through validated non-interactive flags.
2. A scenario runs only its documented checks. Command invocation tests prove unrelated collectors are not called.
3. Every conclusion is traceable to one or more numbered observations. Evidence confidence uses only confirmed, plausible, or insufficient; no percentages or causal certainty are emitted.
4. Current resource/storage readings do not appear as historical events. Timeline entries require valid timestamps from structured journal records. Missing/inaccessible/truncated logs are reported as unknown or incomplete, never as proof that no event occurred.
5. Website checks distinguish unit state, selected local listener, optional loopback HTTP response, and unverified public reachability.
6. Service restart wording requires multiple timestamped restart/failure observations or an available systemd restart counter; exit/result fields are reported only when available and sanitized.
7. Storage checks remain bounded to mount metadata and filesystem counters; no recursive walk, file content read, or ungrounded cause attribution occurs.
8. JSON validates against a versioned schema; Markdown and JSON use the same sanitized source model. Reports omit raw logs, server identity, IPs, paths, usernames, credentials, and arbitrary command output. New report files use restrictive permissions where supported and never overwrite existing files.
9. Tests cover invalid input, cancellation, unavailable tools, permission denial, timeouts, incomplete journals, service aliases/missing units, read-only filesystems, inode exhaustion, high utilization, and privacy-safe report output. Simulations are explicitly identified as mocks.
10. Ubuntu and Debian CI runs are isolated from the developer's Windows environment. Actual compatibility claims remain limited to systems tested directly; automated Linux CI is not a substitute for validation on a real target VPS.
11. Demo fixtures are reproducible and isolated. No demo changes the sponsored FastVPS VPS or performs destructive work on the developer's everyday WSL host.
12. Performance evidence records measured run time, peak memory, command count, maximum configured external-command timeout, and report size for each scenario; results are described as measurements on the named test environment, not universal guarantees.

## Release boundary

v0.3 is a beta engineering evaluation candidate. Before any product or production claim, the team must review the code and reports, run Linux checks on disposable Ubuntu and Debian systems, and have FastVPS engineers assess support scope, operational safety, usefulness, privacy, and wording. The sponsored VPS observations in the request are user-reported only and are not independently verified by this review.

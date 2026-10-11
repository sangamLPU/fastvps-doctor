# Security and privacy

## Execution behavior

- Default checks read local OS counters, selected configuration metadata, systemd state and limited firewall status. They do not require root, install packages, edit configuration, restart services, change firewall/SSH/users, kill processes or upload data.
- Subprocess calls are centralized in `runner.py`, use a fixed executable/argument form, `shell=False`, a minimal environment, trusted executable directories, explicit timeouts and bounded output. Linux timeout cleanup targets the command's process group. Linux behavior still needs a successful Linux integration run.
- Service journal summaries only run for a failed service and export an error-indicator count, not log lines. `incident --service UNIT` is a separate opt-in workflow: it reads bounded timestamped service and kernel journal records, classifies fixed event types and discards raw messages. Journal permission and retention limitations are reported as incomplete evidence.
- `services --validate-config` is opt-in and invokes bounded Nginx, Apache or SSH validators. Inspect the OS-specific output privately; the report includes only a pass/fail-or-inconclusive state, not validator text.
- DNS and TCP checks run only after the user names one host and (for TCP) one port. They do not scan a range or accept a URL. `network --listen-port` inspects local sockets only.
- `--full` runs an APT simulation using local cached metadata. It does not refresh package indexes or install/upgrade packages, but simulation disables package-manager locking; avoid concurrent package operations. It is not a security-advisory audit.
- There is no telemetry, FastVPS account integration, automatic ticket submission, AI API, automatic repair or external report upload.

## Report data minimization

JSON and Markdown reports use an explicit check/metric allowlist before findings are generated or rendered. Raw logs and configuration contents are never included. Mount paths are omitted; address values are omitted; customer descriptions are scrubbed for common hostname, IP, username, path, credential assignment, known token and PEM private-key patterns. Ticket references are accepted only as short conventional identifiers. Findings use static templates and bounded evidence summaries.

Redaction is defense in depth, not a universal secret detector. Unlabelled or proprietary credentials may evade pattern matching. Review every report locally, including JSON metadata, before sharing. Reports are not sent anywhere by the application.

The report writer creates a new file exclusively and requests `0600` on POSIX. Windows ACL behavior is not covered by this mode request. Check actual file permissions on the Linux filesystem before sharing.

## Evidence and certainty

- `no_major_findings` is not proof of health, security or root cause.
- High memory or swap use alone is not classified as confirmed pressure. PSI is stronger evidence; high swap only corroborates when available memory is low.
- Route checks cover Linux IPv4/IPv6 default routes but not policy routing or network namespaces.
- `sshd -T` exposes effective configuration for the provided context. When connection-specific `Match` context is omitted, those values might not describe a particular login.
- An inactive UFW status does not prove that no firewall exists. The security command is not a security audit.
- Provider responsibility remains undetermined unless a human checks the purchased plan and provider-side evidence.

## Vulnerability reports

Review every proposed command or data field for side effects, privilege, time/output bounds and privacy impact. Do not allow journal content, filenames or other external input to become executable instructions. Report project security concerns through the repository's private reporting channel if one is configured.

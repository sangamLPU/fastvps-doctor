# Command reference

Diagnostic commands are read-only. `report --output` creates a new local report file and refuses to overwrite an existing one. `--json` is available on diagnostic area commands; it prints a sanitized structured report. The global `--no-color` and `--ascii` flags work before the command name.

| Command | Purpose |
| --- | --- |
| `fastvps-doctor --help` | List available commands and options. |
| `fastvps-doctor diagnose` | Run available local diagnostics and explain matched rules. |
| `fastvps-doctor diagnose --full` | Also simulate APT upgrades using cached metadata; no package changes occur, but APT simulation does not lock package state and its count is not security-specific. Avoid while package tools are running. |
| `fastvps-doctor diagnose --profile fastvps` | Add support-scope reminders and official-resource guidance. |
| `fastvps-doctor diagnose --json` | Print a sanitized structured report. |
| `fastvps-doctor system [--json]` | CPU sample, load, memory, swap, uptime and OS/kernel details. |
| `fastvps-doctor diagnose --strict-exit-codes` | Return 1 when findings exist, 3 for incomplete/uncertain checks, otherwise 0. |
| `fastvps-doctor storage [--json]` | Root and bounded local mounted-filesystem capacity, inode and read-only observations. |
| `fastvps-doctor network [--json]` | Local interfaces, IPv4/IPv6 default routes, resolver and selected local listeners. |
| `fastvps-doctor network --listen-port PORT` | Inspect an additional local listener port; repeat the option for more ports. |
| `fastvps-doctor network --show-addresses` | Explicitly show local IPv4/IPv6 addresses in human output; JSON reports and support reports still exclude them. |
| `fastvps-doctor network --resolve HOST` | Resolve exactly one hostname entered by the user, with a three-second limit. The report omits the hostname. |
| `fastvps-doctor network --connect-host HOST --connect-port PORT` | Attempt one TCP connection to one user-entered destination with a two-second wall-clock limit. |
| `fastvps-doctor services [--json]` | Inspect selected common systemd service state; missing binaries do not imply a running service. |
| `fastvps-doctor services --unit UNIT` | Inspect an explicitly selected custom systemd unit; repeat at most five times. |
| `fastvps-doctor services --validate-config` | Opt in to bounded Nginx/Apache/SSH configuration validators. |
| `fastvps-doctor security [--json]` | Review selected SSH settings and UFW status; this is not a full security audit. |
| `fastvps-doctor security --full` | Simulate package upgrades from cached APT data without locking package state. Results are not security-specific; avoid while package tools are running. |
| `fastvps-doctor web [--json]` | Check loopback TCP reachability for ports 80/443 and listener counts. |
| `fastvps-doctor web --port PORT` | Also inspect one explicitly named local application port. |
| `fastvps-doctor explain` | Explain rule evidence and limitations. |
| `fastvps-doctor incident --service UNIT --since 2h` | Classify timestamped journal metadata for one unit in a 1-minute to 24-hour window; raw logs are discarded. |
| `fastvps-doctor troubleshoot` | In an interactive terminal, show a numbered picker and offer detected relevant application services, manual entry, or “I'm not sure.” |
| Interactive service prompt: option `1` | Choose from detected application services only; SSH and Docker are not generic suggestions. |
| Interactive service prompt: option `2` | Enter one application service name; identifiers are validated before use. |
| Interactive service prompt: option `3` or Enter | Continue without a service name; service-specific health, logs, restart history and configuration remain unknown. |
| `fastvps-doctor troubleshoot --scenario website-unavailable --service UNIT --port PORT` | Inspect one explicitly selected systemd unit, one local listener port, bounded service/kernel events, root storage and a current resource snapshot. |
| Interactive website diagnosis when the service is unknown | Check local listeners on ports 80 and 443, Nginx/Apache installation and unit-state indicators, storage and current resources. No match does not confirm a website outage. |
| `fastvps-doctor troubleshoot --scenario website-unavailable --service UNIT --port PORT --probe-http` | Opt in to one HTTP `HEAD /` request to `127.0.0.1`; no body is read and public reachability is not tested. |
| `fastvps-doctor troubleshoot --scenario service-crash --service UNIT --since 2h` | Inspect one explicitly selected unit, bounded timestamped service/kernel journal evidence and a current resource snapshot. |
| Interactive service-crash with no unit | Collect general resource and storage snapshots only; no per-service logs or restart conclusions are available. |
| `fastvps-doctor troubleshoot --scenario storage` | Inspect root and bounded local mount space, inode and read-only counters. |
| `fastvps-doctor troubleshoot --scenario storage --service UNIT --since 2h` | Also inspect one explicitly selected service and its bounded journal window. |
| `fastvps-doctor troubleshoot ... --validate-config` | Opt in to a supported Nginx/Apache/SSH syntax validator for the selected service; raw validator output is discarded. |
| `fastvps-doctor troubleshoot ... --format json|markdown --output FILE` | Create a version 1 local scenario report; refuses to overwrite an existing path. |
| `fastvps-doctor report --format json|markdown` | Generate a version 2 general support report for review. |
| `fastvps-doctor report --strict-exit-codes` | Return 1 when findings exist, 3 for incomplete/uncertain checks, otherwise 0. |
| `fastvps-doctor report --output FILE` | Create a new local file; refuses to overwrite an existing path. |
| `fastvps-doctor version` | Display version and independent-contribution status. |

For non-interactive use, `--scenario` is required and service/port values must be supplied explicitly when that workflow needs them. Valid scenarios are `website-unavailable`, `service-crash` and `storage`. With no output file, the command prints a concise terminal summary; `--format json` prints the complete JSON report to stdout. Reports include observation IDs and timestamped event IDs so explanations can refer back to evidence. Certainty uses confirmed, plausible or insufficient; no probability or root-cause declaration is produced.

`--ticket-reference` accepts a conventional ticket identifier such as `FV-1234` or a numeric ID. Free-form text, credential-shaped strings and values outside this format are omitted. Reports exclude allowlisted identities, local addresses, mount paths, raw logs and configuration contents. Common credential formats and PEM private-key blocks in customer-entered description text are redacted, but the implementation is not a universal secret scanner; review every export before sharing it.

Report files are created exclusively and request owner-only permissions on POSIX systems. Review the report before sharing it. Checks skipped on unsupported platforms are omitted from the reported diagnostic coverage.


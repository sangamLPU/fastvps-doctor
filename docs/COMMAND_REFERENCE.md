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
| `fastvps-doctor report --format json|markdown` | Generate a version 2 local support report for review. |
| `fastvps-doctor report --strict-exit-codes` | Return 1 when findings exist, 3 for incomplete/uncertain checks, otherwise 0. |
| `fastvps-doctor report --output FILE` | Create a new local file; refuses to overwrite an existing path. |
| `fastvps-doctor version` | Display version and independent-contribution status. |

`--ticket-reference` accepts a conventional ticket identifier such as `FV-1234` or a numeric ID. Free-form text, credential-shaped strings and values outside this format are omitted. Reports exclude allowlisted identities, local addresses, mount paths, raw logs and configuration contents. Common credential formats and PEM private-key blocks in customer-entered description text are redacted, but the implementation is not a universal secret scanner; review every export before sharing it.

Report files are created exclusively and request owner-only permissions on POSIX systems. Review the report before sharing it. Checks skipped on unsupported platforms are omitted from the reported diagnostic coverage.


# Command reference

Diagnostic commands are read-only. `report --output` creates a new local report file and refuses to overwrite an existing one. `--json` is available on diagnostic area commands; it prints a sanitized structured report. The global `--no-color` and `--ascii` flags work before the command name.

| Command | Purpose |
| --- | --- |
| `fastvps-doctor --help` | List available commands and options. |
| `fastvps-doctor diagnose` | Run the available diagnostic set and explain matched rules. |
| `fastvps-doctor diagnose --full` | Also simulate APT upgrades using cached metadata; no package changes occur, but APT simulation does not lock package state and its count is not security-specific. Avoid while package tools are running. |
| `fastvps-doctor diagnose --profile fastvps` | Add support-scope reminders and official-resource guidance. |
| `fastvps-doctor diagnose --json` | Print a sanitized structured report. |
| `fastvps-doctor system [--json]` | CPU sample, load, memory, swap, uptime and OS/kernel details. |
| `fastvps-doctor storage [--json]` | Root filesystem space, inodes and read-only flag. |
| `fastvps-doctor network [--json]` | Local interfaces, address counts, route, resolver and selected local listeners. |
| `fastvps-doctor network --show-addresses` | Explicitly show local IPv4/IPv6 addresses in human output; JSON reports and support reports still exclude them. |
| `fastvps-doctor network --resolve HOST` | Resolve exactly one hostname entered by the user, with a three-second limit. The report omits the hostname. |
| `fastvps-doctor network --connect-host HOST --connect-port PORT` | Attempt one TCP connection to one user-entered destination with a two-second wall-clock limit. |
| `fastvps-doctor services [--json]` | Detect selected common service executables, inspect systemd state and use safe validators where available. |
| `fastvps-doctor security [--json]` | Review selected SSH settings and UFW status; this is not a full security audit. |
| `fastvps-doctor security --full` | Simulate package upgrades from cached APT data without locking package state. Results are not security-specific; avoid while package tools are running. |
| `fastvps-doctor web [--json]` | Check loopback TCP reachability for ports 80/443 and listener counts. |
| `fastvps-doctor web --port PORT` | Also inspect one explicitly named local application port. |
| `fastvps-doctor explain` | Explain rule evidence and limitations. |
| `fastvps-doctor report --format json|markdown` | Generate a local support report for review. |
| `fastvps-doctor report --output FILE` | Create a new local file; refuses to overwrite an existing path. |
| `fastvps-doctor version` | Display version and independent-contribution status. |

`--ticket-reference` accepts an optional user-entered identifier, restricted to letters, numbers, dots, underscores and hyphens, up to 80 characters. Reports do not include hostname, IP address, username, filesystem paths, credentials, raw logs or raw configuration contents by default. The ticket reference is intentionally included when supplied.

Report files are created exclusively and request owner-only permissions on POSIX systems. Review the report before sharing it. Checks skipped on unsupported platforms are omitted from the reported diagnostic coverage.


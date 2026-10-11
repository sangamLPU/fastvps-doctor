# Security and privacy

## Execution behavior

- Checks read operating-system counters, a few bounded system configuration indicators and (only for a detected failed service) up to 40 recent journal lines within one hour.
- Subprocesses go only through `runner.py`, which has a fixed executable and argument form per operation, resolves utilities only from conventional administrator-managed Linux directories (not the caller's `PATH`), uses `shell=False`, a minimal environment, short timeouts and an output cap.
- On Linux, subprocesses start in their own process group so timeout cleanup can terminate helper processes too. If the kernel does not reap a killed process promptly, the command returns an inconclusive timeout rather than waiting forever.
- Journal output is capped at 8 KiB and three seconds, scanned only for generic error words, and immediately discarded; only a count can enter the report. Permission failures are reported as unavailable.
- The normal run does not recursively enumerate directories, install packages, edit files, change firewall/SSH/users, kill processes, reboot, or require root.
- Optional DNS and TCP tests run only when the user explicitly supplies one hostname and, for TCP, one port. They do not scan a range or arbitrary URL.
- `--full` may run a read-only APT simulation against cached metadata. It does not refresh package indexes or install/upgrade packages, but APT simulation disables package-manager locking; do not run it while another package operation is active. Non-root APT simulations can omit configuration data the user cannot read, and the result is not security-specific.
- Debian's [APT `apt-get` reference](https://manpages.debian.org/bookworm/apt/apt-get.8) documents the disabled locking and possible state changes during simulation.
- No report is sent anywhere. No telemetry, account integration, secret collection, AI API or third-party hosted service is used.

## Report data minimization

The report builder applies `privacy.py` allowlists before rendering JSON or Markdown. Reports contain product/version/time, distribution name and version, summarized metrics, check statuses, rule findings and safe next steps. Default reports exclude hostnames, IP addresses, usernames, filesystem paths, environment variables, credentials, raw command output, raw logs and configuration file contents. Common identity and credential patterns in exported text are redacted as a second layer. The `network --show-addresses` option displays local addresses only in explicitly requested human-readable output; JSON and support reports omit them. User-entered ticket references are included only when explicitly provided and are restricted to identifier characters.

The report writer uses exclusive creation and requests owner-only `0600` permissions on POSIX systems. This is not a universal secret scanner or guarantee about every filesystem's ACL behavior; inspect reports and file permissions before sharing.

The SSH review parses three directives in the main configuration file and checks whether group/other write bits are set. It emits booleans only and does not follow `Include` files or `Match` blocks. Service validators' output and raw journal text are not included. Keep the generated report local until you review it; this software cannot control subsequent sharing.

## Evidence and certainty

`no_major_findings` does not mean healthy or secure. Missing optional services are not failures. A short high CPU sample does not produce a finding. High memory use is distinct from kernel memory pressure; PSI evidence is reported where available. An inactive firewall reported by UFW does not prove no firewall exists. Provider responsibility remains undetermined unless a human checks the ordered service scope and provider-side evidence.

## Reporting a vulnerability

Before adding any command or data field, review its side effects, time bound, output size, privacy implications and required privileges. Never allow log text, filenames or other external input to become instructions or shell syntax.


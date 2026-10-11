# Compatibility and limitations

## Compatibility status

The code targets Ubuntu 24.04/26.04 and Debian 12/13 with Python 3.11 or newer. The working tree was exercised on WSL Ubuntu 26.04 with Python 3.14.4, including the Linux integration tests and real unprivileged diagnostics. This is not the sponsored Ubuntu 24.04.5 server. GitHub Actions is configured for Ubuntu unit jobs on Python 3.11–3.13 and Ubuntu 24.04/Debian 12/13 disposable integration containers, but no workflow result is available and Docker was unavailable locally. Ubuntu 24.04, Debian 12/13, and the sponsored VPS remain unverified.

Windows unit checks ran on Windows 11 with Python 3.13.7; Linux-specific APIs are mocked in those Windows tests. Actual Linux tests ran separately in WSL Ubuntu 26.04/Python 3.14.4 from a native Linux filesystem working copy. The WSL system lacked the packaged pip bootstrap for its venv and sudo required interactive authentication, so no system package was installed; pip and project dependencies were isolated in project virtual environments. WSL evidence establishes behavior only for that environment.

## Functional limits in 0.2.0

- Resource readings are a point-in-time sample. Memory pressure rules use Linux PSI when available; high memory or swap use alone does not prove active workload pressure. High swap use is only a corroborating signal when available memory is also low.
- Storage checks inspect `/` plus up to 16 additional local filesystems reported by psutil. Mount paths are not exported. Remote, unsupported, symlinked, inaccessible and excess mounts are skipped or marked incomplete. The tool does not find large directories or identify which process owns space.
- Space/inode calculations use `statvfs` counters and user-available capacity, including reserved resources. Compare figures to `df -h`/`df -i` on the target filesystem; behavior still needs Linux validation.
- Route checks inspect `/proc/net/route` and `/proc/net/ipv6_route` for active default routes. They do not evaluate policy routing, custom network namespaces, VPN-specific routing or provider routing.
- Resolver checks validate the syntax/count of nameservers in `/etc/resolv.conf`; they do not test reachability unless the user explicitly requests one hostname. systemd-resolved and other resolver-manager behavior varies. A timed-out DNS worker cannot be safely cancelled and may finish in the background.
- Optional external checks contact only the explicitly supplied destination: DNS has a three-second wall-clock bound and TCP a two-second bound. There is no scan or public DNS/TLS assessment.
- Local listener inventory may be incomplete without permission. Common ports are selected by default; `network --listen-port` adds explicitly requested local ports. Multiple socket entries are not treated as a conflict.
- Service checks use systemd and fixed common service candidates, with optional explicitly selected custom units. They distinguish missing units, inactive/failed/masked/restricted and unknown state when systemd output provides that evidence. Non-systemd service managers, container internals, custom installation paths and all aliases/templates are not comprehensively covered.
- Configuration validators for Nginx, Apache and SSH run only with `services --validate-config`. They are read-only by intent, but command behavior and permission requirements still need Linux validation. Default diagnostics do not run them.
- SSH indicators use `sshd -T` effective configuration. `--ssh-*` context options are required together to evaluate connection-specific `Match` rules; without them, values represent sshd's default test context and may not describe a particular user connection. UFW is the only firewall tool queried.
- The optional APT simulation is not a security-update audit, does not refresh metadata and disables package-manager locking. Do not run it while another package operation is active; non-root visibility may be incomplete.
- Incident analysis reads bounded journal metadata for one selected systemd unit and kernel journal within a 1-minute to 24-hour window. It discards raw messages, classifies only known phrases, requires real timestamps, and reports correlations/hypotheses rather than causes. Permissions, journal retention or malformed records can make the timeline incomplete. No live service is stopped to test it.
- Reports use schema version 2.0, explicit metric allowlists, fixed finding templates and common-pattern redaction. Known credential token shapes and PEM private-key blocks in customer-entered descriptions are redacted. This is not a universal DLP scanner; inspect the complete report before sharing it. Reports remain local and are never uploaded.
- Report files refuse to overwrite an existing path and request mode `0600` on POSIX. Windows ACL behavior and every filesystem's permission semantics are not certified.
- `--strict-exit-codes` is opt-in: `0` means no findings and no warning/incomplete check, `1` means at least one finding or failed check, and `3` means no finding but one or more warning/unknown/skipped checks. Without the option, existing command success behavior is preserved. Invocation errors use the CLI's normal error code.
- There is no auto-remediation, trend history, broad log correlation, backup verification, web dashboard, telemetry, automatic upload or FastVPS API integration.

## Safe operating boundary

Run as an ordinary user. Missing permissions should remain visible as incomplete results; do not use `sudo` just to make checks pass. Do not induce disk exhaustion, stop services, break networking or change SSH/firewall state on a production VPS. Use mocks or disposable Linux containers/VMs for failure scenarios.

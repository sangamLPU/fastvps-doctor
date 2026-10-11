# Simulated FastVPS Doctor report (example only)

> **SIMULATED TEST FIXTURE — not a real server, customer, ticket, or FastVPS diagnostic.** Values below are manually selected solely to demonstrate report shape.

## Report header

- Product: FastVPS Doctor 0.1.0
- Scan timestamp (UTC): 2026-10-10T12:00:00+00:00
- Distribution: Debian 13
- Overall diagnostic status: **critical**
- Profile: fastvps
- Ticket reference: not provided

## Diagnostic coverage

- CPU, memory, swap, load, uptime and available Linux pressure indicators
- Root filesystem space, inodes and read-only state
- Local interfaces, route and resolver configuration
- Common service presence, systemd state and selected read-only validators
- Limited SSH and host-firewall indicators
- Loopback HTTP/HTTPS reachability and selected local listeners

## Support summary

One evidence-based finding needs review. Diagnostic rules do not prove root cause or assign provider responsibility.

Checks passed: system.resources, network.local, services.common.

Checks with warnings: none.

Checks failed: storage.root.

Checks unavailable: none.

## Findings

### STOR-001: Root filesystem space is critically low

- Category: storage
- Severity: **critical**
- Support scope: guest-os/application-facing
- Confidence: high
- Additional privileges may be needed for investigation: no

The root filesystem is close to full, which can prevent services from writing data or starting.

Evidence:

- Root filesystem usage is 96.0% (critical threshold 90%).

Possible causes:

- Application logs or uploads grew
- Backups or temporary files accumulated
- The filesystem is undersized for current workload

Recommended next steps:

- Review `df -h` and identify the affected mount.
- Inspect likely directories with a bounded, read-only command such as `du -xhd1 /var`.
- Remove data only after confirming its owner and retention requirements.

## Privacy and limitations

This simulated example contains no real hostname, IP, username, path, credential, log or configuration data. A real report should be reviewed before sharing. Diagnostic coverage is limited and does not establish root cause, provider responsibility or overall security.


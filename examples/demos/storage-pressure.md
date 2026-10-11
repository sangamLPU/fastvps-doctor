# FastVPS Doctor support report

> Independently developed and unofficial. Review this report before sharing.

## Report header

- Product: FastVPS Doctor 0.2.0
- Report schema: 2.0
- Scan timestamp (UTC): 2026-10-11T12:00:00+00:00
- Distribution: Ubuntu 24.04 synthetic
- Overall diagnostic status: **critical**
- Profile: fastvps

## Environment summary

- Kernel: demo-kernel-0.0
- Relevant systemd services: not detected
- Checks needing review: none recorded

## Diagnostic coverage

- Linux distribution and kernel identifiers
- Root filesystem space, inodes and read-only state
- Bounded capacity and inode indicators for local mounted filesystems

## Support summary

1 evidence-based finding(s) need review. Diagnostic rules do not prove root cause or assign provider responsibility.

### Checks passed

- `system.identity`
- `storage.root`

### Checks with warnings

- None reported

### Checks failed

- `storage.mounts`

### Checks unavailable

- None reported

## Findings

### STOR-005: A mounted filesystem is critically low on available capacity

- Category: storage
- Severity: **critical**
- Support scope: guest-os/application-facing
- Confidence: high
- Additional privileges may be needed for investigation: no

A local mounted filesystem exceeded its configured capacity threshold; its mount path is omitted from the report.

Evidence:
- Local mount entry 1 (ext4) reports 92.0% use.

Possible causes:
- Application data, logs, caches or backups grew
- The mounted volume is undersized for current workload

Recommended next steps:
- Use `df -hT` locally to identify the mount entry and compare its growth over time.
- Inspect the owning application before changing or deleting data.

## Support handoff

- Reported problem: not provided
### Confirmed observations

- A mounted filesystem is critically low on available capacity: Local mount entry 1 (ext4) reports 92.0% use.

### Likely investigation areas

- Application data, logs, caches or backups grew
- The mounted volume is undersized for current workload

### Checks unavailable or incomplete

- None recorded

### Suggested next actions

- Use `df -hT` locally to identify the mount entry and compare its growth over time.
- Inspect the owning application before changing or deleting data.
- FastVPS support scope depends on the ordered management plan; review this report before sharing it through the official support channel.

## Further investigation

- Use `df -hT` locally to identify the mount entry and compare its growth over time.
- Inspect the owning application before changing or deleting data.
- FastVPS support scope depends on the ordered management plan; review this report before sharing it through the official support channel.

## FastVPS support context

This independent tool does not connect to FastVPS systems. Infrastructure monitoring and guest operating system/application responsibilities depend on the customer's ordered plan and agreed scope.
Review the complete report and remove anything you do not wish to share before contacting [official FastVPS support](https://fastvps.gr/en/faq/).

## Privacy and limitations

This report uses allowlisted, summarized metrics. It excludes hostnames, IP addresses, usernames, filesystem paths, credentials, raw configuration contents and raw logs by default. Diagnostic coverage is limited and does not establish root cause, provider responsibility or overall security.

# FastVPS Doctor support report

> Independently developed and unofficial. Review this report before sharing.

## Report header

- Product: FastVPS Doctor 0.2.0
- Report schema: 2.0
- Scan timestamp (UTC): 2026-10-11T12:00:00+00:00
- Distribution: Ubuntu 24.04 synthetic
- Overall diagnostic status: **attention**
- Profile: fastvps

## Environment summary

- Kernel: demo-kernel-0.0
- Relevant systemd services: nginx
- Checks needing review: none recorded

## Diagnostic coverage

- Linux distribution and kernel identifiers
- Common service/systemd state; validators run only when explicitly enabled
- Bounded, timestamped service and kernel journal event classification

## Support summary

1 evidence-based finding(s) need review. Diagnostic rules do not prove root cause or assign provider responsibility.

### Checks passed

- `system.identity`

### Checks with warnings

- None reported

### Checks failed

- `services.common`

### Checks unavailable

- None reported

## Findings

### SVC-NGIN-001: nginx is in a failed service-manager state

- Category: services
- Severity: **high**
- Support scope: guest-os/application-facing
- Confidence: high
- Additional privileges may be needed for investigation: yes

The local service manager reports a failed state for a detected service.

Evidence:
- The nginx service state is reported as failed.

Possible causes:
- A configuration error
- A missing dependency or port conflict
- A recent change or resource issue

Recommended next steps:
- Review `systemctl status nginx` and the relevant recent unit journal locally.
- Do not share raw logs without reviewing them for secrets and personal data.

## Incident timeline

- Window: 30 minutes ending at 2026-10-11T12:00:00+00:00
- Selected service: nginx
- Evidence collection complete: yes
- Note: Only timestamped, classified journal metadata is included; raw log messages are discarded.
- 2026-10-11T11:33:00+00:00 — service_restart_scheduled (nginx): The service manager scheduled an automatic restart. Another classified event was observed within five minutes; timing alone does not establish causation.
- 2026-10-11T11:36:00+00:00 — service_restart_scheduled (nginx): The service manager scheduled an automatic restart. Another classified event was observed within five minutes; timing alone does not establish causation.
- 2026-10-11T11:39:00+00:00 — service_restart_scheduled (nginx): The service manager scheduled an automatic restart. Another classified event was observed within five minutes; timing alone does not establish causation.
- 2026-10-11T11:40:00+00:00 — service_failure (nginx): The service manager recorded a failed start or process exit. Another classified event was observed within five minutes; timing alone does not establish causation.
- 2026-10-11T11:41:00+00:00 — oom_kill (kernel): A kernel journal record matched a known out-of-memory termination indicator. Another classified event was observed within five minutes; timing alone does not establish causation.

### Evidence-based hypotheses

- **High confidence:** Repeated automatic restart scheduling is consistent with a service restart loop; it does not identify the cause.
  Time interval: 2026-10-11T11:33:00+00:00 to 2026-10-11T11:39:00+00:00
  Evidence: 3 timestamped restart-scheduling records were observed for the selected service.
  Evidence: The records span 2026-10-11T11:33:00+00:00 to 2026-10-11T11:39:00+00:00.
  Alternative: A planned deployment or operator-triggered sequence can also cause repeated restarts.
  Alternative: Journal records may be incomplete or duplicated.
  Next step: Review the selected service's local unit configuration and journal around 2026-10-11T11:33:00+00:00.
  Next step: Check the application's own health and dependencies before restarting it.
- **Low confidence:** An out-of-memory indicator was recorded near a selected-service failure; this temporal correlation does not prove the OOM event caused the failure.
  Time interval: 2026-10-11T11:40:00+00:00 to 2026-10-11T11:41:00+00:00
  Evidence: A service failure was recorded at 2026-10-11T11:40:00+00:00.
  Evidence: A kernel out-of-memory indicator was recorded at 2026-10-11T11:41:00+00:00.
  Alternative: The events may be independent.
  Alternative: The service may have failed for an unrelated application or configuration reason.
  Next step: Review service and memory monitoring around both timestamps.
  Next step: Check for kernel OOM records and service resource limits before changing settings.

## Support handoff

- Reported problem: not provided
### Confirmed observations

- nginx is in a failed service-manager state: The nginx service state is reported as failed.
- 3 timestamped restart-scheduling records were observed for the selected service.
- The records span 2026-10-11T11:33:00+00:00 to 2026-10-11T11:39:00+00:00.
- A service failure was recorded at 2026-10-11T11:40:00+00:00.
- A kernel out-of-memory indicator was recorded at 2026-10-11T11:41:00+00:00.

### Likely investigation areas

- A configuration error
- A missing dependency or port conflict
- A recent change or resource issue
- Repeated automatic restart scheduling is consistent with a service restart loop; it does not identify the cause.
- An out-of-memory indicator was recorded near a selected-service failure; this temporal correlation does not prove the OOM event caused the failure.

### Checks unavailable or incomplete

- None recorded

### Suggested next actions

- Review `systemctl status nginx` and the relevant recent unit journal locally.
- Do not share raw logs without reviewing them for secrets and personal data.
- FastVPS support scope depends on the ordered management plan; review this report before sharing it through the official support channel.
- Only timestamped, classified journal metadata is included; raw log messages are discarded.
- Review the selected service's local unit configuration and journal around 2026-10-11T11:33:00+00:00.
- Check the application's own health and dependencies before restarting it.
- Review service and memory monitoring around both timestamps.
- Check for kernel OOM records and service resource limits before changing settings.

## Further investigation

- Review `systemctl status nginx` and the relevant recent unit journal locally.
- Do not share raw logs without reviewing them for secrets and personal data.
- FastVPS support scope depends on the ordered management plan; review this report before sharing it through the official support channel.
- Only timestamped, classified journal metadata is included; raw log messages are discarded.
- Review the selected service's local unit configuration and journal around 2026-10-11T11:33:00+00:00.
- Check the application's own health and dependencies before restarting it.
- Review service and memory monitoring around both timestamps.
- Check for kernel OOM records and service resource limits before changing settings.

## FastVPS support context

This independent tool does not connect to FastVPS systems. Infrastructure monitoring and guest operating system/application responsibilities depend on the customer's ordered plan and agreed scope.
Review the complete report and remove anything you do not wish to share before contacting [official FastVPS support](https://fastvps.gr/en/faq/).

## Privacy and limitations

This report uses allowlisted, summarized metrics. It excludes hostnames, IP addresses, usernames, filesystem paths, credentials, raw configuration contents and raw logs by default. Diagnostic coverage is limited and does not establish root cause, provider responsibility or overall security.

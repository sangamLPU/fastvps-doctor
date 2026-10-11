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
- Loopback HTTP/HTTPS reachability and selected local listeners

## Support summary

2 evidence-based finding(s) need review. Diagnostic rules do not prove root cause or assign provider responsibility.

### Checks passed

- `system.identity`

### Checks with warnings

- `web.local`

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
- 2 recent service-log lines matched error indicators; raw content was omitted.

Possible causes:
- A configuration error
- A missing dependency or port conflict
- A recent change or resource issue

Recommended next steps:
- Review `systemctl status nginx` and the relevant recent unit journal locally.
- Do not share raw logs without reviewing them for secrets and personal data.

### WEB-001: No local listener was found on the requested port

- Category: web
- Severity: **medium**
- Support scope: guest-os/application-facing
- Confidence: medium
- Additional privileges may be needed for investigation: no

The local socket inventory contained no listener on the port explicitly supplied by the user.

Evidence:
- No local listener was observed on port 8080.

Possible causes:
- The application is stopped
- The service is bound to a different port or network namespace
- The inventory was restricted by operating-system permissions

Recommended next steps:
- Check the service's configured bind address and port.
- Review service status before restarting anything.

## Support handoff

- Reported problem: not provided
### Confirmed observations

- nginx is in a failed service-manager state: The nginx service state is reported as failed.
- nginx is in a failed service-manager state: 2 recent service-log lines matched error indicators; raw content was omitted.
- No local listener was found on the requested port: No local listener was observed on port 8080.

### Likely investigation areas

- A configuration error
- A missing dependency or port conflict
- A recent change or resource issue
- The application is stopped
- The service is bound to a different port or network namespace
- The inventory was restricted by operating-system permissions

### Checks unavailable or incomplete

- None recorded

### Suggested next actions

- Review `systemctl status nginx` and the relevant recent unit journal locally.
- Do not share raw logs without reviewing them for secrets and personal data.
- Check the service's configured bind address and port.
- Review service status before restarting anything.
- FastVPS support scope depends on the ordered management plan; review this report before sharing it through the official support channel.

## Further investigation

- Review `systemctl status nginx` and the relevant recent unit journal locally.
- Do not share raw logs without reviewing them for secrets and personal data.
- Check the service's configured bind address and port.
- Review service status before restarting anything.
- FastVPS support scope depends on the ordered management plan; review this report before sharing it through the official support channel.

## FastVPS support context

This independent tool does not connect to FastVPS systems. Infrastructure monitoring and guest operating system/application responsibilities depend on the customer's ordered plan and agreed scope.
Review the complete report and remove anything you do not wish to share before contacting [official FastVPS support](https://fastvps.gr/en/faq/).

## Privacy and limitations

This report uses allowlisted, summarized metrics. It excludes hostnames, IP addresses, usernames, filesystem paths, credentials, raw configuration contents and raw logs by default. Diagnostic coverage is limited and does not establish root cause, provider responsibility or overall security.

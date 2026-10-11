# FastVPS Doctor — engineering demonstration package

**Independent, unofficial project; not endorsed or adopted by FastVPS.gr.** All demo data is synthetic.

## Slide 1 — Why I built it

FastVPS supported my VPS as a student. I built FastVPS Doctor as a practical contribution: a small local tool to help VPS customers collect selected guest-OS evidence and prepare a support summary they can review themselves.

## Slide 2 — Respect the existing service boundary

FastVPS publicly describes VPS infrastructure monitoring and customer-facing tools for DNS/email, TLS/website checks and latency. FastVPS Doctor focuses on selected evidence inside the customer's Linux guest. It does not duplicate the public checkers, connect to provider telemetry or determine which plan covers an incident. Public descriptions are not confirmation of the exact scope of an individual order.

Sources checked 11 October 2026: [VPS](https://fastvps.gr/en/vps/), [managed VPS](https://fastvps.gr/en/managed-vps-greece.html), [public tools](https://fastvps.gr/en/tools/), [FAQ](https://fastvps.gr/en/faq/) and [platform](https://fastvps.gr/en/platform/).

## Slide 3 — Customer support workflow

1. A customer notices an availability, performance or storage problem.
2. They run local, bounded diagnostics as a normal user.
3. The report separates evidence, uncertainty and checks that could not run.
4. The customer reviews and chooses whether to share the local report through the existing support channel.

No ticket API, automatic upload, telemetry, repair action or provider-side diagnosis is included.

## Slide 4 — Current engineering scope

- CPU, memory, swap, load, uptime and Linux PSI indicators.
- Root and bounded local-mount space/inode/read-only observations; mount paths are omitted.
- IPv4/IPv6 default-route observations, resolver syntax, opt-in single-destination DNS/TCP and user-selected local listener ports.
- Systemd state for selected common and explicitly selected custom units.
- Effective SSH configuration with optional connection-specific `Match` context; limited UFW indicator.
- Opt-in Nginx/Apache/SSH configuration validators.
- `incident` command: bounded timestamped service/kernel journal classification, restart-loop/OOM hypotheses and no exported raw messages.
- Version 2.0 JSON/Markdown report with explicit metric allowlists and conservative redaction.

## Slide 5 — Three reproducible demonstrations

The scenarios below are built from deterministic unit fixtures on the development host, not from a live Linux system:

- [Website unavailable](docs/DEMOS.md#demo-a--website-unavailable): failed Nginx state and no listener on a selected local port.
- [Storage pressure](docs/DEMOS.md#demo-b--storage-pressure): synthetic mounted-filesystem use at 92%, without exposing its path.
- [Restart loop](docs/DEMOS.md#demo-c--service-restart-loop): timestamped service restarts, a failure and nearby synthetic OOM evidence; timing is not treated as cause.

Each includes a reproducible test command, actual test output and a full sanitized synthetic report.

## Slide 6 — Security and privacy boundaries

- Ordinary-user design, no automatic privilege escalation or remediation.
- Fixed command forms, no shell, bounded process time/output/journal inputs.
- Raw logs and config contents are discarded; customer text is scrubbed for common identities and known token/private-key formats.
- Reports are stored locally and are never uploaded. POSIX report writes request mode `0600`.
- Redaction is not a universal guarantee; customers must inspect exports before sharing.

## Slide 7 — Current verification evidence

The current review passed 136 tests with no skips in WSL Ubuntu 26.04 / Python 3.14.4, including opt-in Linux integration tests. Ruff lint, formatting, mypy and dependency consistency checks also passed there. A wheel was built and installed into an isolated Linux virtual environment; its generated CLI ran diagnosis and JSON/Markdown report smoke checks, and report files had mode `0600`. Windows 11 / Python 3.13.7 passed 134 tests with two Linux-only tests skipped. These results apply to the environments actually exercised.

GitHub Actions is configured to run unit/quality jobs on Python 3.11–3.13 and integration tests in Ubuntu 24.04, Debian 12 and Debian 13 containers, but those jobs have not run. The sponsored Ubuntu 24.04.5 VPS has not been tested. Do not present the project as validated on those targets, production-ready, or FastVPS-supported.

## Slide 8 — Known limits

- These are point-in-time heuristics and do not establish root cause or overall server security.
- Policy routing, custom namespaces, non-systemd managers, every service alias/template and full resolver-manager behavior are not covered. Ubuntu 24.04.5 and Debian behavior remain unverified despite the WSL Ubuntu 26.04 test result.
- There is no trend history, broad log search, backup verification, TLS inspection, public scan, dashboard, provider integration or automation repair.
- Journal access and local listener data may be incomplete for an ordinary account.

## Slide 9 — Feedback requested

Ask FastVPS engineers which guest signals, service names and report fields would be useful; what privacy or support-plan caveats need revision; which distro/service matrix should be prioritized; and whether any check overlaps with an existing first-party support tool. This is a request for review, not an adoption proposal.

## Demonstration setup

Use a disposable Linux image for integration checks and the committed synthetic fixtures for failure examples. Never stop services, fill a filesystem, break networking or generate resource pressure on the sponsored production VPS. See [testing](docs/TESTING.md) and the [safe VPS guide](docs/LINUX_VPS_TESTING_GUIDE.md).

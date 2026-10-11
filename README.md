# FastVPS Doctor

**Diagnose smarter. Resolve faster. Built with appreciation for FastVPS.gr.**

FastVPS Doctor is an independent, unofficial Linux command-line utility for collecting local guest-OS evidence and preparing privacy-conscious support reports. It runs checks on the VPS itself, explains a small set of findings with deterministic rules, and leaves the report on the user's machine for review.

> This project is not an official FastVPS product and is not endorsed by FastVPS.gr. It uses no FastVPS logo, customer portal, account credentials, support API, cloud AI, or telemetry.

## Why this complements FastVPS

As reviewed on 11 October 2026, FastVPS describes infrastructure monitoring for VPS plans and public tools for DNS/email, TLS/website checks and browser latency. FastVPS Doctor focuses on local guest evidence—filesystem and inode pressure, service-manager state, IPv4/IPv6 default routes, limited SSH indicators and bounded incident timelines. It does not duplicate public domain checks, inspect provider telemetry or decide responsibility for an incident.

Sources: [VPS service](https://fastvps.gr/en/vps/), [Managed VPS scope](https://fastvps.gr/en/managed-vps-greece.html), [public technical tools](https://fastvps.gr/en/tools/), [FAQ and support process](https://fastvps.gr/en/faq/), [platform monitoring overview](https://fastvps.gr/en/platform/).

## Current status

Version 0.2.0 is a **beta candidate for engineering evaluation**. It includes local resource checks, bounded local filesystem/inode inspection, IPv4/IPv6 default-route observations, explicitly selected listener ports, systemd service-state checks, effective SSH configuration, opt-in Nginx/Apache/SSH validators, deterministic findings and versioned JSON/Markdown support reports. The `incident` command classifies bounded timestamped journal metadata for one selected systemd unit; raw log messages are discarded. Validation on WSL Ubuntu 26.04 / Python 3.14.4 passed all 136 tests (including Linux integration tests), Ruff lint/format, mypy and dependency consistency checks; a built wheel, CLI, JSON/Markdown report output and POSIX report permissions were also exercised. Windows 11 / Python 3.13.7 passed 134 tests with two Linux-only tests skipped. GitHub Actions is configured for Ubuntu 24.04, Debian 12 and Debian 13 integration images, but has not run. The sponsored Ubuntu 24.04.5 VPS has not been tested, so compatibility with that host and those CI images is unverified. This is not a production-readiness claim or an official/endorsed FastVPS product. See [release readiness](docs/RELEASE_READINESS.md), [limitations](docs/LIMITATIONS.md), the [complete QA report](docs/COMPLETE_QA_REPORT.md), and the [Linux test guide](docs/LINUX_VPS_TESTING_GUIDE.md) before use.

## Quick start

Requires Python 3.11 or newer. For Ubuntu/Debian, use a virtual environment so installation does not modify system Python packages:

```bash
sudo apt install python3-venv python3-pip
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
fastvps-doctor --help
fastvps-doctor diagnose
```

General diagnostics are read-only and do not require root. Python dependencies are installed during setup; routine checks work offline. See the [installation guide](docs/INSTALLATION.md), [quick start](docs/QUICKSTART.md), and [command reference](docs/COMMAND_REFERENCE.md).

## Example commands

```bash
fastvps-doctor diagnose
fastvps-doctor diagnose --profile fastvps --ticket-reference FV-1234
fastvps-doctor system --json
fastvps-doctor network --resolve example.org
fastvps-doctor network --connect-host example.org --connect-port 443
fastvps-doctor network --listen-port 3000
fastvps-doctor incident --service nginx --since 2h --format markdown --output incident-report.md
fastvps-doctor web --port 3000
fastvps-doctor report --format markdown --profile fastvps --strict-exit-codes --output support-report.md
fastvps-doctor report --format json
fastvps-doctor explain
```

The optional DNS and TCP commands contact only the one destination explicitly supplied by the user. Listener checks inspect the current machine only. No network scanning or report upload occurs. Config validators run only with `services --validate-config`; the APT simulation is opt-in with `--full`. Report files refuse to overwrite existing paths and request owner-only permissions on POSIX systems; review every export before sharing it. Common secret formats and private-key blocks in customer-entered descriptions are redacted, but this is not a universal secret scanner.

## Documentation

- [Architecture proposal and implementation phases](docs/ARCHITECTURE.md)
- [Installation](docs/INSTALLATION.md)
- [Quick start](docs/QUICKSTART.md)
- [Command reference](docs/COMMAND_REFERENCE.md)
- [Security and privacy](docs/SECURITY_AND_PRIVACY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Testing](docs/TESTING.md)
- [Safe Linux VPS testing guide](docs/LINUX_VPS_TESTING_GUIDE.md)
- [Engineering review and master-prompt gap analysis](docs/GAP_ANALYSIS.md)
- [Support use cases and scope boundaries](docs/FASTVPS_SUPPORT_USE_CASES.md)
- [Synthetic demonstration scenarios](docs/DEMOS.md)
- [v0.2 engineering audit](docs/V0_2_ENGINEERING_AUDIT.md)
- [Compatibility and limitations](docs/LIMITATIONS.md)
- [Contributing](CONTRIBUTING.md)
- [FastVPS contribution proposal](FASTVPS_CONTRIBUTION_PROPOSAL.md)
- [Demonstration package](PRESENTATION.md)
- [Appreciation letter](LETTER_TO_FASTVPS.md)
- [Simulated report example](examples/simulated-report.md)

## Design principles

- Read-only by default; no automatic repair, package installation, firewall or SSH changes, reboot, telemetry, or upload.
- Structured check results are shared by the terminal UI and report generators.
- Reports use explicit metric allowlists; raw logs and configuration contents are not collected.
- Missing optional services do not count as errors. High memory use alone, swap use alone and a high CPU sample alone do not create confirmed pressure findings.
- Findings explain evidence, likely causes, confidence, limitations and safe next steps without claiming a root cause.

## License and dedication

MIT licensed. Product naming is an independent project label; the FastVPS name is used only to explain the intended audience and is not a claim of endorsement.

Developed with appreciation for FastVPS.gr and their support of student developers.


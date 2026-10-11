# FastVPS Doctor

**Diagnose smarter. Resolve faster. Built with appreciation for FastVPS.gr.**

FastVPS Doctor is an independent, unofficial Linux command-line utility for collecting local guest-OS evidence and preparing privacy-conscious support reports. It runs checks on the VPS itself, explains a small set of findings with deterministic rules, and leaves the report on the user's machine for review.

> This project is not an official FastVPS product and is not endorsed by FastVPS.gr. It uses no FastVPS logo, customer portal, account credentials, support API, cloud AI, or telemetry.

## Why this complements FastVPS

As reviewed on 10 October 2026, FastVPS describes 24/7 infrastructure monitoring for VPS plans, including self-managed plans. Its public tools cover DNS/email records, TLS and public website checks, and browser latency. The self-managed VPS scope assigns operating system, updates, security, applications and data management to the customer; managed operating work depends on the agreed configuration. FastVPS Doctor focuses on evidence inside the Linux guest—filesystem pressure, service-manager state, local resolver setup, limited SSH indicators—and on a report a customer can inspect before sharing. It does not duplicate public domain checkers or decide who is responsible for an incident.

Sources: [VPS service](https://fastvps.gr/en/vps/), [Managed VPS scope](https://fastvps.gr/en/managed-vps-greece.html), [public technical tools](https://fastvps.gr/en/tools/), [FAQ and support process](https://fastvps.gr/en/faq/), [platform monitoring overview](https://fastvps.gr/en/platform/).

## Current status

Version 0.1.0 is an early, working CLI foundation. It includes local system and root-filesystem checks, local network configuration indicators, explicit single-destination DNS/TCP checks, common service status and selected configuration validation, limited SSH/UFW indicators, local web port checks, deterministic rules, JSON/Markdown reports and an optional FastVPS support profile. Check [limitations](docs/LIMITATIONS.md) before using it on a production server.

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
fastvps-doctor web --port 3000
fastvps-doctor report --format markdown --profile fastvps --output support-report.md
fastvps-doctor report --format json
fastvps-doctor explain
```

The optional DNS and TCP commands contact only the one destination explicitly supplied by the user. No network scanning or report upload occurs. Report files refuse to overwrite existing paths and request owner-only permissions on POSIX systems; review every export before sharing it.

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
- Missing optional services do not count as errors. High memory use alone and a high CPU sample alone do not create incident findings.
- Findings explain evidence, likely causes, confidence, limitations and safe next steps without claiming a root cause.

## License and dedication

MIT licensed. Product naming is an independent project label; the FastVPS name is used only to explain the intended audience and is not a claim of endorsement.

Developed with appreciation for FastVPS.gr and their support of student developers.


# Safe Linux testing guide for the sponsored VPS

This guide runs the current v0.3 diagnostics on your own FastVPS.gr VPS without changing services, packages, firewall rules, SSH settings or application data. It is a smoke test of read-only behavior, not a way to simulate a failed production service.

The tool's Linux integration tests deliberately create a child process to verify timeout cleanup. Run those only in the disposable Docker/VM environment described in [Testing](TESTING.md), never on the sponsored VPS.

Do not use the `--live-local` demo on the sponsored VPS; that demo intentionally starts a temporary HTTP server. Use the CLI commands below instead.

## Before starting

- Confirm you are connected to the VPS you own and that your plan permits local diagnostic commands.
- Choose a quiet period and keep your normal SSH session open. Do not run the tool with `sudo` or as `root`.
- Use a trusted copy of the reviewed source checkout. Put it in a new directory under your home directory; do not copy it over an existing application directory.
- Do not run service stop/restart commands, `apt update`/`upgrade`, firewall or SSH changes, `dd`, recursive disk scans, or any `FASTVPS_DOCTOR_INTEGRATION=1` command during this live check.
- If a step asks for a system package installation or elevated privilege, stop and ask before changing the server.

## 1. Check the environment

In your SSH terminal, run:

```bash
id -un
python3 --version
cat /etc/os-release
```

The project was exercised in WSL Ubuntu 26.04 with Python 3.14.4, but this review did not access your sponsored Ubuntu 24.04.5 VPS. You reported separately that you personally smoke-tested that host using Python 3.12.3; those observations were not independently verified here. Ubuntu 24.04 and Debian 12/13 CI jobs are configured but have no recorded run yet. This guide is an optional user-run smoke check, not a request for credentials or remote access. Keep OS/account details private; do not paste them publicly.

If Python is older than 3.11, the virtual-environment module is unavailable, or the OS is outside the target, stop. Do not install packages or replace system Python as part of this review.

## 2. Prepare an isolated environment

Transfer or check out the reviewed source into a new path such as `$HOME/fastvps-doctor-review`. Then, from that project directory:

```bash
umask 077
python3 -m venv "$HOME/.venvs/fastvps-doctor-review"
. "$HOME/.venvs/fastvps-doctor-review/bin/activate"
python -m pip install .
fastvps-doctor version
fastvps-doctor --help
```

This installs Python dependencies into the dedicated virtual environment and may download them from the configured Python package index. It does not install operating-system packages or a background service. If the venv creation or dependency installation fails, stop and record the error; do not retry with `sudo` or system-site-package options.

If either example directory already exists, choose a new review-specific name rather than reusing or replacing it.

## 3. Run the read-only checks

Start with one full diagnostic snapshot, then inspect individual areas only if you need to understand a result:

```bash
fastvps-doctor diagnose --profile fastvps
fastvps-doctor system
fastvps-doctor storage
fastvps-doctor network
fastvps-doctor services
fastvps-doctor security
fastvps-doctor web
```

These commands inspect local counters and configuration and query selected systemd state. They do not require root. Configuration validators do **not** run by default. A skipped or unknown check is an availability limitation; do not use elevated privileges just to make it pass. `security` uses effective SSH defaults and limited UFW status; it is not a security certification.

To inspect one application port on this VPS without contacting an external system, add an explicitly selected local listener check:

```bash
fastvps-doctor network --listen-port 3000
```

If you have a specific service failure and want available journal metadata, optionally run a bounded incident report for that unit:

```bash
fastvps-doctor incident --service nginx --since 2h --format markdown \
  --output "$HOME/fastvps-doctor-incident.md"
```

Use a service unit that actually exists on the VPS. Journal access may be denied to a normal account; that should remain an incomplete result. Raw log messages are discarded. Do not run configuration validators or `--full` as part of the first live smoke test.

The v0.3 focused workflows can be checked with known service/port values. Use a unit and port that actually match your application. These scenarios are read-only; the optional `--probe-http` sends a single HTTP `HEAD /` to `127.0.0.1` and does not read a response body or test public access:

```bash
fastvps-doctor troubleshoot --scenario storage --profile fastvps
fastvps-doctor troubleshoot --scenario service-crash --service nginx --since 30m --profile fastvps
fastvps-doctor troubleshoot --scenario website-unavailable --service nginx --port 80 --probe-http --profile fastvps
```

If you do not know the service unit or expected port, do not guess; omit the focused check and record that the value is unknown. Custom service names may be redacted in an exported report. Journal access may remain incomplete for an ordinary account.

For this first production-host smoke test, do not use `--full`: it runs an APT simulation without package-manager locking, so a concurrent package operation could change state while it runs, and the count is not security-specific. Do not supply a network destination unless you have a specific host and port you intend to test. The optional DNS/TCP checks contact only the one destination you enter, but are unnecessary for verifying local command behavior.

## 4. Save and review private reports

Choose filenames that do not already exist. The report command refuses to overwrite files and requests owner-only file permissions on POSIX systems:

```bash
fastvps-doctor report --format markdown --profile fastvps \
  --output "$HOME/fastvps-doctor-review.md"
fastvps-doctor report --format json --profile fastvps \
  --output "$HOME/fastvps-doctor-review.json"
stat -c '%a %n' "$HOME/fastvps-doctor-review.md" "$HOME/fastvps-doctor-review.json"
less "$HOME/fastvps-doctor-review.md"
```

Check that each report says **independent and unofficial**, lists the checks that actually ran, and contains no hostnames, IP addresses, usernames, filesystem paths, raw logs, credentials or unexpected private details. General reports use schema 2.0; focused scenario reports use schema 1.0. The tool uses metric allowlists and common-pattern text redaction, including known token patterns and PEM private-key blocks, but this is not a universal secret scanner. Review the complete files before sharing them with anyone. Do not attach raw command output or config/log files.

If `stat` does not show mode `600`, keep the report private and do not share it until you understand the file permissions on that filesystem.

## 5. What this live test does not prove

This smoke test does not simulate disk exhaustion, inode exhaustion, a failed daemon, a firewall block, a resolver outage or a read-only root filesystem. Do not create those conditions on a production VPS. Those scenarios belong in unit fixtures and the disposable Linux integration image. It also does not prove performance, uptime, overall security, or whether an issue is within FastVPS infrastructure responsibility.

## 6. Record the result safely

For your review notes, record the OS release, Python version, command exit codes, skipped/unknown checks and any finding IDs. Avoid sending the full report until you have reviewed and redacted it yourself. If you request FastVPS feedback, describe the tool as an independent prototype and ask which checks are appropriate for the scope of your sponsored plan.

The tool does not install an agent or create system services/configuration. The venv and report files remain in the home-directory paths you chose. Keep or remove those specific review artifacts only after confirming their paths; no system cleanup is needed.

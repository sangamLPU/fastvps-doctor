# Safe Linux testing guide for the sponsored VPS

This guide runs the current diagnostics on your own FastVPS.gr VPS without changing services, packages, firewall rules, SSH settings or application data. It is a smoke test of read-only behavior, not a way to simulate a failed production service.

The tool's Linux integration tests deliberately create a child process to verify timeout cleanup. Run those only in the disposable Docker/VM environment described in [Testing](TESTING.md), never on the sponsored VPS.

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

The supported target is Ubuntu 24.04/26.04 or Debian 12/13 with Python 3.11 or newer. These are targets, not yet a statement that every release has passed on a VPS. Keep the output private; do not paste it publicly because system and account details can identify your host.

If Python is older than 3.11, the virtual-environment module is unavailable, or the OS is outside the target, stop. Do not install packages or replace system Python as part of this review.

## 2. Prepare an isolated environment

Transfer or check out the reviewed source into a new path such as `$HOME/fastvps-doctor-review`. Then, from that project directory:

```bash
umask 077
python3 -m venv "$HOME/.venvs/fastvps-doctor-review"
. "$HOME/.venvs/fastvps-doctor-review/bin/activate"
python -m pip install .
fastvps-doctor --version
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

These commands inspect local counters and configuration, query selected service state, and run bounded read-only validators when matching tools are found. They do not require root. A skipped or unknown check is an availability limitation; do not use elevated privileges just to make it pass. `security` is a narrow indicator check, not a security certification.

For this first production-host smoke test, do not use `--full`: it runs an APT simulation without package-manager locking, so a concurrent package operation could change state while it runs, and the count is not security-specific. Do not supply a network destination unless you have a specific host and port you intend to test. The optional DNS/TCP checks contact only the one destination you enter, but are unnecessary for verifying local command behavior.

## 4. Save and review private reports

Choose filenames that do not already exist. The report command refuses to overwrite files and requests owner-only file permissions on POSIX systems:

```bash
fastvps-doctor report --format markdown --profile fastvps \
  --output "$HOME/fastvps-doctor-review.md"
fastvps-doctor report --format json \
  --output "$HOME/fastvps-doctor-review.json"
stat -c '%a %n' "$HOME/fastvps-doctor-review.md" "$HOME/fastvps-doctor-review.json"
less "$HOME/fastvps-doctor-review.md"
```

Check that the report says **independent and unofficial**, lists the checks that actually ran, and contains no hostnames, IP addresses, usernames, filesystem paths, raw logs, credentials or unexpected private details. The tool uses metric allowlists and common-pattern text redaction, but that is not a universal secret scanner. Review the complete files before sharing them with anyone. Do not attach raw command output or config/log files.

If `stat` does not show mode `600`, keep the report private and do not share it until you understand the file permissions on that filesystem.

## 5. What this live test does not prove

This smoke test does not simulate disk exhaustion, inode exhaustion, a failed daemon, a firewall block, a resolver outage or a read-only root filesystem. Do not create those conditions on a production VPS. Those scenarios belong in unit fixtures and the disposable Linux integration image. It also does not prove performance, uptime, overall security, or whether an issue is within FastVPS infrastructure responsibility.

## 6. Record the result safely

For your review notes, record the OS release, Python version, command exit codes, skipped/unknown checks and any finding IDs. Avoid sending the full report until you have reviewed and redacted it yourself. If you request FastVPS feedback, describe the tool as an independent prototype and ask which checks are appropriate for the scope of your sponsored plan.

The tool does not install an agent or create system services/configuration. The venv and report files remain in the home-directory paths you chose. Keep or remove those specific review artifacts only after confirming their paths; no system cleanup is needed.

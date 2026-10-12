# Quick start

## 1. Collect a local snapshot

```bash
fastvps-doctor diagnose
```

Review the checks and any rule-based findings. A high CPU sample or memory utilization by itself is not a confirmed incident. A skipped check means the tool could not safely or portably inspect it; it is not a pass.

## 2. Focus on one area

```bash
fastvps-doctor storage
fastvps-doctor services
fastvps-doctor network
fastvps-doctor network --listen-port 3000
fastvps-doctor services --unit my-app.service
fastvps-doctor web --port 3000
```

`web --port` asks the tool to inspect that one local port. It does not scan remote systems. `network --resolve example.org` and `network --connect-host example.org --connect-port 443` run one explicitly requested DNS lookup or TCP connection.

## 3. Make a support report

```bash
fastvps-doctor report --format markdown --profile fastvps --output support-report.md
```

The output path must not already exist. Open and review the file locally before attaching it to a ticket. The FastVPS profile adds context, not an integration or responsibility decision. Management scope depends on the customer's plan and written service scope. Official support options are documented in the [FastVPS FAQ](https://fastvps.gr/en/faq/).

For a bounded timeline for one systemd service, run `fastvps-doctor incident --service nginx --since 2h`. It reads available timestamped journal metadata, discards raw messages, and reports event classifications without asserting why an event happened. Denied journal access or missing timestamps make the result incomplete. `services --validate-config` is a separate opt-in for selected Nginx/Apache/SSH validators.

## Focused troubleshooting

Run `fastvps-doctor troubleshoot` for a numbered prompt, or choose one of the three v0.3 scenarios explicitly:

```bash
fastvps-doctor troubleshoot --scenario website-unavailable --service nginx --port 8080
fastvps-doctor troubleshoot --scenario service-crash --service app-worker --since 1h --format markdown --output crash-report.md
fastvps-doctor troubleshoot --scenario storage --format json --output storage-report.json
```

In the interactive flow, FastVPS Doctor asks which application or background service is affected and offers three choices: select a detected relevant application service, enter its name, or choose “I'm not sure.” Detected suggestions are limited to common application services; SSH and Docker are not offered as generic suggestions. Pressing Enter at the choice prompt means “I'm not sure.” A blank manual name also continues without a service. For a website problem with no known service, it checks local listeners on ports 80 and 443, common Nginx/Apache installation and service-state indicators, storage, and current resource usage. It does not make external network requests. The report states that the affected application's service state, logs, restart history, configuration, and relationship to a local listener cannot be determined without its service name. “No common web service detected” is not confirmation of a website outage. Non-interactive website and service-crash commands continue to require `--service`.

Website checks inspect the explicitly selected systemd unit and port alongside bounded local context. `--probe-http` is optional and sends one `HEAD /` request to `127.0.0.1`; it does not check public DNS, TLS, firewall paths or external reachability. `--validate-config` is also opt-in and works only for the supported Nginx, Apache and SSH syntax validators. The service-crash scenario inspects one selected unit and its bounded journal window. Storage does not search files or suggest deleting them. Scenario reports use schema 1.0, omit raw logs and response bodies, and remain local for manual review.

## 4. Ask what the rules mean

```bash
fastvps-doctor explain
fastvps-doctor --help
fastvps-doctor diagnose --json
```

JSON is useful for inspection or later tooling; it still contains only allowlisted report fields. Never attach raw logs or configuration files without manually reviewing them.

## Configure thresholds

Create `~/.config/fastvps-doctor/config.toml` to adjust deterministic rule thresholds. The configuration is read only; invalid settings fall back to defaults.

```toml
[thresholds]
disk_warning_percent = 80
disk_critical_percent = 90
inode_warning_percent = 80
inode_critical_percent = 90
low_available_memory_percent = 10
memory_psi_warning_percent = 10
swap_warning_percent = 80
```


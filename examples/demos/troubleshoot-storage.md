> DEMONSTRATION ONLY — synthetic fixture, not FastVPS customer or server data.

# FastVPS Doctor focused support handoff

> Independent and unofficial. This report is a diagnostic aid, not a root-cause finding or provider decision.
> Review and redact this report before sharing it.

## Report header

- Version: 0.3.0
- Report schema: 1.0
- Scenario: storage
- Snapshot time (UTC): 2026-10-11T12:00:00+00:00
- Environment: Ubuntu 24.04 \(synthetic fixture\); kernel 6.8.0-demo
- Service label: postgresql
- Selected local port: not applicable
- Profile: fastvps
- Ticket reference: `DEMO-001`

## Reported symptom

\[DEMO FIXTURE\] Application reported a storage write issue.

## Checks actually run

### `storage.root` — WARNING

Collected root filesystem capacity and inode utilization.

- `inode_usage_percent`: `99.2`
- `mounted_filesystem_count`: `2`
- `readonly`: `False`
- `total_gb`: `75.0`
- `usage_percent`: `97.0`
- `used_gb`: `72.75`

### `storage.mounts` — WARNING

Collected bounded capacity indicators for local mounted filesystems.

- `inspected_mount_count`: `1`
- `mount_0_filesystem_type`: `ext4`
- `mount_0_inode_usage_percent`: `99.2`
- `mount_0_readonly`: `False`
- `mount_0_state`: `ok`
- `mount_0_usage_percent`: `97.0`
- `mount_count`: `1`

### `troubleshoot.service` — WARNING

Queried one optional selected storage\-related service.

- `service_restart_count`: `0`
- `service_state`: `active`
- `service_unit_found`: `True`

## Confirmed observations

- **OBS-001** (filesystem): Root filesystem utilization: 97.0%; inode utilization: 99.2%; read\-only: false.
- **OBS-002** (filesystem): One local mounted filesystem was inspected; its path is withheld.
- **OBS-003** (snapshot): The selected service was active at snapshot time.

## Timestamped event timeline

- **EVT-001** 2026-10-11T11:58:00+00:00 — service_error: A journal record for the selected service had error\-level priority.

## Evidence-based explanations

- **Confirmed** (OBS-001): The root filesystem snapshot reported space utilization of 97.0% and inode utilization of 99.2%; this does not prove the cause of any individual write failure.
- **Confirmed** (EVT-001): One timestamped selected\-service error record was available; its timing does not establish a connection to storage conditions.

## Areas for further investigation

- Synthetic evidence illustrates the structure of a human support handoff; it is not a root\-cause determination.

## Evidence gaps and limits

- No customer files or file contents were searched.
- Capacity indicators do not establish why a write failed.
- This is synthetic fixture evidence, not a live VPS diagnosis.

## Suggested next actions

- Compare space and inode usage with the filesystem used by the failing application.
- Ask an administrator to review relevant application errors; do not delete files based only on this report.

## Privacy and limitations

The export contains allowlisted summaries only; raw logs, command output, host identity, addresses, paths, usernames, credentials and application response bodies are excluded. A loopback response does not establish public reachability. Correlation and current snapshots do not prove causation. Missing or restricted logs are incomplete evidence.

## FastVPS support context

This is an independent, unofficial tool and does not connect to FastVPS systems. Support scope depends on the customer's ordered plan. Review the report before contacting [official FastVPS support](https://fastvps.gr/en/faq/).

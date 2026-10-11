# FastVPS support use cases and scope boundaries

FastVPS Doctor is an independent project created as a personal contribution to FastVPS.gr. It is not an official FastVPS product, is not endorsed or adopted by the company, and does not connect to provider systems.

## Publicly described FastVPS capabilities

Public pages reviewed 11 October 2026 describe VPS plans and infrastructure monitoring, managed-service scope, customer-facing DNS/email and website/TLS tools, latency checks and a support/FAQ process. See [VPS](https://fastvps.gr/en/vps/), [managed VPS](https://fastvps.gr/en/managed-vps-greece.html), [public tools](https://fastvps.gr/en/tools/), [FAQ](https://fastvps.gr/en/faq/) and [platform overview](https://fastvps.gr/en/platform/).

These public descriptions do not reveal provider-side incident data or establish the contracted support scope for any specific customer. The customer’s order and agreed management terms still govern that question.

## Three customer-facing scenarios

| Scenario | FastVPS publicly described overlap | FastVPS Doctor's current guest-side evidence | What remains unknown / feedback to request |
| --- | --- | --- | --- |
| **Website unavailable** | FastVPS offers public website/TLS checks and VPS monitoring. | Checks selected systemd web-service state and a user-selected local listening port; a customer can compare this with a separate public reachability result. | Which guest signals help support separate an application bind failure from DNS, reverse proxy, firewall or provider-side reachability? Which web services/ports are common in customer plans? |
| **Disk or inode pressure** | FastVPS describes VPS monitoring; the public pages do not establish a customer-facing filesystem/inode diagnostic. | Reads root plus up to 16 local mount capacity/inode/read-only counters, includes reserved-space effects, hides mount paths in reports and suggests non-destructive `df` review. | Are inode exhaustion or non-root data volumes common support cases? Should an export include a mount index/filesystem type, or is that unnecessary? |
| **Repeated service failure** | Provider monitoring can identify VPS-level availability conditions; plan scope affects OS/application operations. | For one selected systemd unit, reads a bounded timestamped journal window, classifies restart/failure and known kernel OOM/memory-pressure phrases, and discards raw messages. The report labels correlation and uncertainty. | Which services and journal signals are useful? What access limits and privacy requirements should be documented? What information should a customer gather before support? |

## Capabilities that require engineering feedback

- Whether report check IDs and support handoff structure match real triage workflows.
- Which service/unit names, systemd aliases and distro versions deserve priority.
- Whether bounded incident timelines are useful, and which journal fields must be excluded.
- Whether the report should expose mount filesystem type/index, local listener counts or other summarized signals.
- How to describe customer versus provider responsibility without overstepping plan-specific scope.
- Whether any check duplicates a first-party tool or generates noise for FastVPS support.

## Explicit boundaries

- FastVPS Doctor sees only guest data available to the local account. It cannot inspect hypervisor state, provider monitoring, network switches, storage backends, support tickets or the customer's order.
- It performs no public-domain scan, no TLS certificate assessment, no account login, no ticket submission, no upload and no auto-remediation.
- A timestamped guest event is not proof of root cause. Coincident service and OOM events are reported as a correlation, not causation.
- A clean report is not proof of health or security. All exports require human review, and common-pattern redaction is not a universal secret detector.

The intended contribution is a modest customer-side evidence-gathering aid. Whether it is useful, compatible with support policy or worth further investment is for FastVPS engineers to evaluate.

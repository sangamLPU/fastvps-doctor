# FastVPS Doctor: independent contribution proposal

**Status:** early-stage, independent and unofficial project. This proposal is for discussion and review; it is not a request to deploy the code or integrate it with FastVPS systems.

## Why I started it

FastVPS supported my VPS as a student. I wanted to respond with a practical technical contribution: a small local diagnostic tool that helps a VPS customer gather guest-operating-system evidence and describe an issue clearly before contacting support.

## Customer problem

“My website is down” can describe a service that did not start, a full filesystem, a resolver problem, a local port issue, or a condition outside the guest. Beginners may not know which observations are useful, and raw logs or configuration files can expose private information. FastVPS Doctor aims to collect a modest set of useful signals, explain what each result does and does not establish, and create a reviewable support summary.

## How it complements existing services

FastVPS publicly describes 24/7 infrastructure monitoring and offers DNS/email, SSL/website and latency checks. The proposed tool focuses on local guest evidence: filesystem/inode pressure, Linux resource indicators, selected service-manager state, limited SSH/resolver checks and local loopback reachability. It intentionally does not recreate public DNS or SSL checkers, inspect FastVPS infrastructure, upload data, or decide whether a finding falls under a customer's support plan.

Official pages reviewed on 10 October 2026: [VPS](https://fastvps.gr/en/vps/), [managed VPS](https://fastvps.gr/en/managed-vps-greece.html), [public tools](https://fastvps.gr/en/tools/), [FAQ/support process](https://fastvps.gr/en/faq/), and [platform overview](https://fastvps.gr/en/platform/).

## Possible use

1. A VPS customer runs a local check after noticing a problem.
2. The tool reports observed evidence, skipped checks and cautious next steps.
3. The customer reviews a local JSON or Markdown report and removes anything they do not want to share.
4. If useful, the customer attaches the sanitized report to the existing support channel and includes the correct service/ticket context.

Support engineers could potentially use the consistent check IDs and summary to orient a conversation. That is a hypothesis for feedback, not a measured efficiency or cost saving.

## Current technical limitations

- The project is at version 0.1.0 and has not yet been integration-tested on Linux in this development environment.
- Checks cover only a subset of Linux services and may not detect custom units, namespaces, or nonstandard installation paths.
- Reports are point-in-time observations, not root-cause analysis or provider-side telemetry.
- The security checklist is deliberately narrow. The tool does not collect logs, verify backups, inspect public TLS, or guarantee that a service is healthy.
- Compatibility is a target matrix, not an assertion that every listed distribution has passed acceptance testing.

## Feedback requested

- Which guest-level signals are actually useful in initial customer support triage?
- Which report fields should be removed, renamed, or made optional?
- Are the descriptions and responsibility caveats technically accurate for distinct managed and self-managed scopes?
- What maximum report size, format and retention expectations would be acceptable?
- Which distribution/service versions should receive integration testing first?
- Are there existing first-party tools or support workflows that make any proposed check redundant?

## What official adoption would require

Possible adoption would need explicit agreement from FastVPS, technical and security review, distribution/service test coverage, privacy and data-retention review, branding and name approval, a named maintenance owner, support documentation, a change/release process, compatibility commitments, and a clear policy for customer-generated report attachments. Any official API or portal integration would require documented authorization and a separate security design. Nothing in this project assumes or enables such integration.

## Project identity

FastVPS Doctor is an independently developed open-source contribution. It does not imply FastVPS endorsement, use protected logos, collect account credentials, or contact FastVPS automatically.


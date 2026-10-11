# FastVPS Doctor: independent contribution proposal

**Status:** early-stage, independent and unofficial project. This proposal is for discussion and review; it is not a request to deploy the code or integrate it with FastVPS systems.

## Why I started it

FastVPS supported my VPS as a student. I wanted to respond with a practical technical contribution: a small local diagnostic tool that helps a VPS customer gather guest-operating-system evidence and describe an issue clearly before contacting support.

## Customer problem

“My website is down” can describe a service that did not start, a full filesystem, a resolver problem, a local port issue, or a condition outside the guest. Beginners may not know which observations are useful, and raw logs or configuration files can expose private information. FastVPS Doctor aims to collect a modest set of useful signals, explain what each result does and does not establish, and create a reviewable support summary.

## How it complements existing services

FastVPS publicly describes 24/7 infrastructure monitoring and offers DNS/email, SSL/website and latency checks. The proposed tool focuses on local guest evidence: filesystem/inode pressure, Linux resource indicators, selected service-manager state, limited SSH/resolver checks and local loopback reachability. It intentionally does not recreate public DNS or SSL checkers, inspect FastVPS infrastructure, upload data, or decide whether a finding falls under a customer's support plan.

Official pages reviewed on 11 October 2026: [VPS](https://fastvps.gr/en/vps/), [managed VPS](https://fastvps.gr/en/managed-vps-greece.html), [public tools](https://fastvps.gr/en/tools/), [FAQ/support process](https://fastvps.gr/en/faq/), and [platform overview](https://fastvps.gr/en/platform/).

## Possible use

1. A VPS customer runs a local check after noticing a problem.
2. The tool reports observed evidence, skipped checks and cautious next steps.
3. The customer reviews a local JSON or Markdown report and removes anything they do not want to share.
4. If useful, the customer attaches the sanitized report to the existing support channel and includes the correct service/ticket context.

Support engineers could potentially use the consistent check IDs and summary to orient a conversation. That is a hypothesis for feedback, not a measured efficiency or cost saving.

## Current technical limitations

- Version 0.2.0 is a beta candidate for engineering evaluation. The current evidence is 136 passing tests and quality checks in WSL Ubuntu 26.04 / Python 3.14.4, plus 134 Windows tests with two Linux-only skips. The configured Ubuntu 24.04, Debian 12 and Debian 13 GitHub Actions jobs have not run; the sponsored Ubuntu 24.04.5 VPS has not been accessed.
- Checks cover a subset of Linux services and may not detect all aliases/templates, namespaces or nonstandard installation paths.
- Incident output is timestamped event classification and cautious hypotheses, not root-cause analysis or provider-side telemetry.
- The security checklist is deliberately narrow. It does not verify backups, inspect public TLS, or guarantee that a service is healthy.
- WSL Ubuntu 26.04 passed the recorded test suite, but that result does not establish compatibility across Ubuntu 26.04 installations, Ubuntu 24.04.5, Debian or the sponsored VPS. Compatibility remains unverified for the configured CI images until those jobs actually pass.

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


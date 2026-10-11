# Compatibility and limitations

## Compatibility target

The initial target is Ubuntu LTS and Debian stable with Python 3.11+. Official release pages checked 10 October 2026 identify Ubuntu 26.04 LTS as current, Ubuntu 24.04 LTS as a prior supported LTS, and Debian 13 (Trixie) as current stable. Debian 12 remains in LTS but is now oldstable. The intended validation matrix is Ubuntu 24.04/26.04 and Debian 12/13. Ubuntu 22.04 uses Python 3.10 by default and therefore needs a separately managed Python 3.11+ interpreter.

This is a compatibility target, not a claim of successful testing on every OS release. This implementation environment is Windows; live Linux package, service-manager, filesystem and network integration has not yet been executed here.

Sources: [Ubuntu release cycle](https://ubuntu.com/about/release-cycle), [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/), [Debian releases](https://www.debian.org/releases/index.en.html).

## Functional limits in 0.1.0

- Resource checks sample the current host once; no historical baseline or trend analysis exists.
- Capacity and inode figures focus on the root filesystem, not every mounted volume.
- Local listener inventory uses psutil and may be incomplete without privileges.
- Root capacity and inode percentages account for blocks available to an ordinary user, including filesystem-reserved capacity; filesystem-specific behavior still needs Linux validation.
- Default route detection inspects the active IPv4 route entry; IPv6 routes and policy routing are not diagnosed.
- Resolver checks validate the address syntax of nameservers in `/etc/resolv.conf`; they do not validate resolver reachability unless the user requests a DNS test. Individual local IP addresses are displayed only with `network --show-addresses` and are not included in support reports.
- Only an explicitly named hostname/port receives an external DNS/TCP test (three-second DNS and two-second wall-clock TCP limits). A timed-out DNS/TCP worker may finish later in the background because system resolver/connect calls cannot be cancelled safely. Public DNS/SSL checking is intentionally left to existing first-party tools.
- Service detection uses fixed common executable/unit names. Custom services and containers are not comprehensively inspected. Only a failed detected service triggers a bounded, summarized recent-journal error count; raw logs are not exported.
- Executable lookup is limited to conventional administrator-managed Linux directories and intentionally ignores a caller-supplied `PATH`; non-Linux hosts report Linux-only command checks as skipped.
- Validators cover Nginx, Apache and SSH when detected. They may need privileges or may fail for reasons unrelated to invalid configuration; diagnostic output is intentionally withheld.
- Security checks are narrow indicators, not a compliance or vulnerability audit. UFW is the only firewall status provider queried. Optional APT simulation reads cached metadata without package-manager locking, so concurrent changes may distort results; non-root visibility may be incomplete. Its package count is generic and not security-specific; distribution security-repository advisories are not classified yet.
- Web checks make loopback TCP handshakes only; they do not inspect application routes, TLS certificates, reverse-proxy headers or public reachability.
- Report fields use explicit allowlists and common-pattern text redaction. This is data minimization, not a general-purpose secret scanner; users must still review every export before sharing.
- Report files request mode `0600` on POSIX systems and refuse to overwrite an existing path. Effective permissions can still depend on platform/filesystem behavior and should be checked on Linux.
- No auto-remediation, trend history, log correlation, backup verification, web dashboard or provider API integration is implemented.


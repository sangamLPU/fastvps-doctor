"""Explainable, deterministic rules derived only from structured checks."""

from __future__ import annotations

from fastvps_doctor.config import Thresholds
from fastvps_doctor.models import (
    DiagnosticCheck,
    Finding,
    Severity,
    SupportScope,
)


def analyze(checks: list[DiagnosticCheck], thresholds: Thresholds | None = None) -> list[Finding]:
    settings = thresholds or Thresholds()
    by_id = {check.check_id: check for check in checks}
    findings: list[Finding] = []

    storage = by_id.get("storage.root")
    if storage:
        usage = storage.metrics.get("usage_percent")
        if isinstance(usage, (int, float)):
            if usage >= settings.disk_critical_percent:
                findings.append(
                    Finding(
                        finding_id="STOR-001",
                        category="storage",
                        severity=Severity.CRITICAL,
                        title="Root filesystem space is critically low",
                        description="The root filesystem is close to full, which can prevent services from writing data or starting.",
                        evidence=[
                            f"Root filesystem usage is {usage:.1f}% (critical threshold {settings.disk_critical_percent:.0f}%)."
                        ],
                        possible_causes=[
                            "Application logs or uploads grew",
                            "Backups or temporary files accumulated",
                            "The filesystem is undersized for current workload",
                        ],
                        next_steps=[
                            "Review `df -h` and identify the affected mount.",
                            "Inspect likely directories with a bounded, read-only command such as `du -xhd1 /var`.",
                            "Remove data only after confirming its owner and retention requirements.",
                        ],
                        confidence="high",
                        support_scope=SupportScope.GUEST,
                    )
                )
            elif usage >= settings.disk_warning_percent:
                findings.append(
                    Finding(
                        finding_id="STOR-002",
                        category="storage",
                        severity=Severity.MEDIUM,
                        title="Root filesystem usage is elevated",
                        description="Filesystem capacity is high enough to monitor before writes begin to fail.",
                        evidence=[
                            f"Root filesystem usage is {usage:.1f}% (warning threshold {settings.disk_warning_percent:.0f}%)."
                        ],
                        possible_causes=[
                            "Normal growth",
                            "Logs, uploads, caches or backups using more space",
                        ],
                        next_steps=[
                            "Review `df -h` and track capacity over time.",
                            "Inspect large directories before deciding whether anything can be removed.",
                        ],
                        confidence="high",
                        support_scope=SupportScope.GUEST,
                    )
                )

        inodes = storage.metrics.get("inode_usage_percent")
        if isinstance(inodes, (int, float)):
            threshold = (
                settings.inode_critical_percent
                if inodes >= settings.inode_critical_percent
                else settings.inode_warning_percent
            )
            if inodes >= settings.inode_warning_percent:
                critical = inodes >= settings.inode_critical_percent
                findings.append(
                    Finding(
                        finding_id="STOR-003",
                        category="storage",
                        severity=Severity.HIGH if critical else Severity.MEDIUM,
                        title="Root filesystem inode usage is high",
                        description="A filesystem can run out of file entries even when it still has free bytes.",
                        evidence=[
                            f"Root filesystem inode usage is {inodes:.1f}% (threshold {threshold:.0f}%)."
                        ],
                        possible_causes=[
                            "A very large number of small files",
                            "Application sessions, caches or mail spools",
                        ],
                        next_steps=[
                            "Review inode usage with `df -i`.",
                            "Identify the responsible application before changing or deleting files.",
                        ],
                        confidence="high",
                        support_scope=SupportScope.GUEST,
                    )
                )
        if storage.metrics.get("readonly") is True:
            findings.append(
                Finding(
                    finding_id="STOR-004",
                    category="storage",
                    severity=Severity.HIGH,
                    title="Root filesystem is mounted read-only",
                    description="The operating system reports that the root filesystem is read-only; normal writes may fail.",
                    evidence=["The root filesystem mount has the read-only flag."],
                    possible_causes=[
                        "Filesystem error recovery",
                        "An intentional maintenance mount",
                        "An underlying storage or boot issue",
                    ],
                    next_steps=[
                        "Check kernel and filesystem events through your normal administrative process.",
                        "Avoid remounting or repairing until the cause and recovery plan are understood.",
                    ],
                    confidence="high",
                    requires_privileges=True,
                    support_scope=SupportScope.UNKNOWN,
                )
            )

    system = by_id.get("system.resources")
    if system:
        memory_percent = system.metrics.get("memory_percent")
        psi = system.metrics.get("memory_psi_some_avg10")
        available_mb = system.metrics.get("memory_available_mb")
        if (
            isinstance(memory_percent, (int, float))
            and memory_percent >= 100 - settings.low_available_memory_percent
        ):
            pressure_confirmed = (
                isinstance(psi, (int, float)) and psi >= settings.memory_psi_warning_percent
            )
            findings.append(
                Finding(
                    finding_id="SYS-001",
                    category="system",
                    severity=Severity.HIGH if pressure_confirmed else Severity.LOW,
                    title="Memory pressure indicators observed"
                    if pressure_confirmed
                    else "Available memory is low; pressure is unconfirmed",
                    description=(
                        "Low available memory is accompanied by Linux memory pressure evidence."
                        if pressure_confirmed
                        else "Memory use is high, but this sample alone does not prove that workloads are blocked or unhealthy."
                    ),
                    evidence=[
                        f"Memory utilization is {memory_percent:.1f}%.",
                        f"Available memory is {available_mb} MiB."
                        if isinstance(available_mb, int)
                        else "Available memory could not be measured.",
                        f"Linux memory PSI some avg10 is {psi:.1f}%"
                        if isinstance(psi, (int, float))
                        else "Linux memory PSI was unavailable; pressure could not be confirmed.",
                    ],
                    possible_causes=[
                        "Workload demand exceeds available memory",
                        "A workload has a temporary or sustained memory spike",
                        "A cache-heavy workload uses memory that the kernel may reclaim",
                    ],
                    next_steps=[
                        "Compare `free -h` with application behavior and recent time-series data.",
                        "Inspect service memory use before restarting or changing limits.",
                    ],
                    confidence="medium" if pressure_confirmed else "low",
                    support_scope=SupportScope.GUEST,
                )
            )

    services = by_id.get("services.common")
    if services:
        for service in (
            "nginx",
            "apache",
            "ssh",
            "docker",
            "mysql",
            "mariadb",
            "postgresql",
            "redis",
        ):
            if services.metrics.get(f"{service}_state") == "failed":
                evidence = [f"The {service} service state is reported as failed."]
                recent_errors = services.metrics.get(f"{service}_recent_error_count")
                if isinstance(recent_errors, int) and recent_errors > 0:
                    qualifier = (
                        "At least "
                        if services.metrics.get(f"{service}_recent_logs_truncated") is True
                        else ""
                    )
                    evidence.append(
                        f"{qualifier}{recent_errors} recent service-log lines matched error indicators; raw content was omitted."
                    )
                findings.append(
                    Finding(
                        finding_id=f"SVC-{service.upper()[:4]}-001",
                        category="services",
                        severity=Severity.HIGH,
                        title=f"{service} is in a failed service-manager state",
                        description="The local service manager reports a failed state for a detected service.",
                        evidence=evidence,
                        possible_causes=[
                            "A configuration error",
                            "A missing dependency or port conflict",
                            "A recent change or resource issue",
                        ],
                        next_steps=[
                            f"Review `systemctl status {service}` and the relevant recent unit journal locally.",
                            "Do not share raw logs without reviewing them for secrets and personal data.",
                        ],
                        confidence="high",
                        requires_privileges=True,
                        support_scope=SupportScope.GUEST,
                    )
                )
            if services.metrics.get(f"{service}_config_validation") == "failed_or_inconclusive":
                findings.append(
                    Finding(
                        finding_id=f"SVC-{service.upper()[:4]}-002",
                        category="services",
                        severity=Severity.MEDIUM,
                        title=f"{service} configuration validation did not pass",
                        description="A read-only validation command returned a non-zero status; the result may reflect configuration problems or access limitations.",
                        evidence=[
                            f"The {service} validator returned a non-zero status; its output was intentionally not included."
                        ],
                        possible_causes=[
                            "Invalid configuration",
                            "A required file is unreadable",
                            "An environment-specific validation limitation",
                        ],
                        next_steps=[
                            f"Run the documented local validator for {service} and review its output privately."
                        ],
                        confidence="low",
                        support_scope=SupportScope.GUEST,
                    )
                )

    network = by_id.get("network.local")
    if network:
        if network.metrics.get("default_route_present") is False:
            findings.append(
                Finding(
                    finding_id="NET-001",
                    category="network",
                    severity=Severity.MEDIUM,
                    title="No IPv4 default route was observed",
                    description="The local route table did not show an IPv4 default route; IPv6 routes and custom network setups are not covered by this check.",
                    evidence=["No default route was present in the local IPv4 route table."],
                    possible_causes=[
                        "Guest network configuration issue",
                        "A network namespace or policy-routing setup",
                        "A transient or IPv6-only configuration",
                    ],
                    next_steps=[
                        "Review `ip route` and compare with the network configuration expected for this VPS.",
                        "Ask the provider to check infrastructure routing if guest configuration looks correct.",
                    ],
                    confidence="medium",
                    support_scope=SupportScope.UNKNOWN,
                )
            )
        if (
            network.metrics.get("resolver_readable") is True
            and network.metrics.get("resolver_nameserver_count") == 0
        ):
            findings.append(
                Finding(
                    finding_id="NET-002",
                    category="network",
                    severity=Severity.MEDIUM,
                    title="No DNS nameserver is configured in the local resolver file",
                    description="The resolver configuration that this check could read contains no nameserver entry.",
                    evidence=[
                        "No nameserver line was present in the local resolver configuration."
                    ],
                    possible_causes=[
                        "Resolver configuration is incomplete",
                        "A local resolver manager populates settings dynamically",
                        "The host uses a nonstandard resolver setup",
                    ],
                    next_steps=[
                        "Check `resolvectl status` or the resolver manager used by this system.",
                        "Compare with the network settings supplied for the VPS.",
                    ],
                    confidence="medium",
                    support_scope=SupportScope.UNKNOWN,
                )
            )
        if (
            network.metrics.get("dns_test_requested") is True
            and network.metrics.get("dns_test_succeeded") is False
        ):
            findings.append(
                Finding(
                    finding_id="NET-003",
                    category="network",
                    severity=Severity.MEDIUM,
                    title="The explicitly requested hostname did not resolve",
                    description="A local resolver lookup failed for the hostname supplied to this command. The hostname is omitted from the report.",
                    evidence=[
                        "The requested lookup returned no address records or an operating-system resolution error."
                    ],
                    possible_causes=[
                        "A typo or missing DNS record",
                        "Local resolver configuration or reachability",
                        "A temporary DNS failure",
                    ],
                    next_steps=[
                        "Check the hostname spelling and query it again later.",
                        "Compare with the local resolver status before testing application connectivity.",
                    ],
                    confidence="medium",
                    support_scope=SupportScope.UNKNOWN,
                )
            )
        if (
            network.metrics.get("dns_test_requested") is True
            and network.metrics.get("dns_test_timed_out") is True
        ):
            findings.append(
                Finding(
                    finding_id="NET-005",
                    category="network",
                    severity=Severity.LOW,
                    title="The explicitly requested DNS lookup timed out",
                    description="The local resolver did not return within the diagnostic time limit; the hostname is omitted and resolution is inconclusive.",
                    evidence=["The requested resolver lookup exceeded the three-second limit."],
                    possible_causes=[
                        "A slow or unreachable local/upstream resolver",
                        "Transient network delay",
                        "Resolver retry behavior",
                    ],
                    next_steps=[
                        "Retry once and compare with the resolver manager status.",
                        "If the delay persists, investigate local routing and resolver health.",
                    ],
                    confidence="low",
                    support_scope=SupportScope.UNKNOWN,
                )
            )
        if (
            network.metrics.get("tcp_test_requested") is True
            and network.metrics.get("tcp_test_succeeded") is False
        ):
            findings.append(
                Finding(
                    finding_id="NET-004",
                    category="network",
                    severity=Severity.MEDIUM,
                    title="The explicitly requested TCP connection failed",
                    description="A single connection attempt to the destination supplied by the user did not complete. The destination is omitted from the report.",
                    evidence=["The local TCP connect attempt failed or timed out."],
                    possible_causes=[
                        "No service is listening at the destination",
                        "A firewall or route blocks the connection",
                        "The destination is temporarily unavailable",
                    ],
                    next_steps=[
                        "Verify the destination and port with its owner.",
                        "Compare local routing and service status before changing firewall rules.",
                    ],
                    confidence="low",
                    support_scope=SupportScope.UNKNOWN,
                )
            )
        if (
            network.metrics.get("tcp_test_requested") is True
            and network.metrics.get("tcp_test_timed_out") is True
        ):
            findings.append(
                Finding(
                    finding_id="NET-006",
                    category="network",
                    severity=Severity.LOW,
                    title="The explicitly requested TCP connection timed out",
                    description="The local TCP check did not finish within its two-second diagnostic time limit. The destination is omitted and the result is inconclusive.",
                    evidence=["The requested connection exceeded the two-second wall-clock limit."],
                    possible_causes=[
                        "A slow or unreachable DNS resolver",
                        "A route, firewall or upstream delay",
                        "A destination that is not responding",
                    ],
                    next_steps=[
                        "Retry once and verify the destination and port with their owner.",
                        "Compare with local resolver and route status before changing firewall rules.",
                    ],
                    confidence="low",
                    support_scope=SupportScope.UNKNOWN,
                )
            )

    web = by_id.get("web.local")
    if web and web.metrics.get("required_port_supplied") is True:
        port = web.metrics.get("required_port")
        listeners = web.metrics.get(f"port_{port}_listeners") if isinstance(port, int) else None
        if listeners == 0:
            findings.append(
                Finding(
                    finding_id="WEB-001",
                    category="web",
                    severity=Severity.MEDIUM,
                    title="No local listener was found on the requested port",
                    description="The local socket inventory contained no listener on the port explicitly supplied by the user.",
                    evidence=[f"No local listener was observed on port {port}."],
                    possible_causes=[
                        "The application is stopped",
                        "The service is bound to a different port or network namespace",
                        "The inventory was restricted by operating-system permissions",
                    ],
                    next_steps=[
                        "Check the service's configured bind address and port.",
                        "Review service status before restarting anything.",
                    ],
                    confidence="medium",
                    support_scope=SupportScope.GUEST,
                )
            )
        elif isinstance(listeners, int) and listeners > 1:
            findings.append(
                Finding(
                    finding_id="WEB-002",
                    category="web",
                    severity=Severity.LOW,
                    title="Multiple local listeners share the requested port",
                    description="Multiple socket entries were observed on the requested port. This can be intentional with socket reuse and is not proof of a conflict.",
                    evidence=[
                        f"The local inventory observed {listeners} listening socket entries on port {port}."
                    ],
                    possible_causes=[
                        "Multiple workers using socket reuse",
                        "Several services competing for a bind",
                        "Duplicate inventory entries",
                    ],
                    next_steps=[
                        "Review local process ownership with `ss -ltnp` and confirm the intended service design."
                    ],
                    confidence="low",
                    support_scope=SupportScope.GUEST,
                )
            )

    security = by_id.get("security.local")
    if security and security.metrics.get("ssh_password_login_disabled") is False:
        findings.append(
            Finding(
                finding_id="SEC-001",
                category="security",
                severity=Severity.LOW,
                title="SSH password authentication appears enabled",
                description="The main SSH configuration file indicates password authentication is enabled. Included files and Match-specific rules were not evaluated.",
                evidence=["The main SSH configuration has `PasswordAuthentication yes`."],
                possible_causes=[
                    "An intentional access policy",
                    "A default or legacy SSH configuration",
                ],
                next_steps=[
                    "Review the effective SSH configuration with an administrator before changing access methods.",
                    "Keep a tested alternate login path before any SSH policy change.",
                ],
                confidence="low",
                requires_privileges=True,
                support_scope=SupportScope.GUEST,
            )
        )
    if security and security.metrics.get("ssh_root_login_restricted") is False:
        findings.append(
            Finding(
                finding_id="SEC-002",
                category="security",
                severity=Severity.LOW,
                title="SSH root login appears permitted",
                description="The main SSH configuration file allows root login. Included files and Match-specific rules were not evaluated.",
                evidence=["The main SSH configuration has `PermitRootLogin yes`."],
                possible_causes=[
                    "An intentional administrator access policy",
                    "A default or legacy configuration",
                ],
                next_steps=[
                    "Review the effective SSH configuration with an administrator before changing access methods.",
                    "Keep a tested alternate login path before any SSH policy change.",
                ],
                confidence="low",
                requires_privileges=True,
                support_scope=SupportScope.GUEST,
            )
        )
    if security and security.metrics.get("ssh_config_permissions_safe") is False:
        findings.append(
            Finding(
                finding_id="SEC-003",
                category="security",
                severity=Severity.MEDIUM,
                title="SSH main configuration is group- or world-writable",
                description="The main SSH configuration file has group or other write permission bits set.",
                evidence=[
                    "The main SSH configuration mode contains group or world write permission bits."
                ],
                possible_causes=[
                    "An overly broad local permission setting",
                    "A configuration-management policy",
                ],
                next_steps=[
                    "Have an administrator review the file ownership and access policy.",
                    "Do not change permissions until the effective SSH configuration and access path are understood.",
                ],
                confidence="medium",
                requires_privileges=True,
                support_scope=SupportScope.GUEST,
            )
        )
    return findings


def rule_catalog() -> list[tuple[str, str]]:
    return [
        (
            "Storage capacity",
            "Compares root filesystem space and inode use to configured warning and critical thresholds.",
        ),
        (
            "Memory pressure",
            "Requires low available memory and checks Linux PSI evidence; high memory use alone is not a confirmed incident.",
        ),
        (
            "Service failure",
            "Reports systemd failed states and read-only configuration validator failures for detected services.",
        ),
        (
            "Local network",
            "Separates default route and resolver configuration observations from an explicitly requested DNS or TCP test.",
        ),
        (
            "Port bind observation",
            "Only evaluates a port explicitly supplied by the user; multiple socket entries are treated as uncertain evidence.",
        ),
        (
            "SSH configuration",
            "Reviews a small allowlisted set of settings from the main SSH configuration file only.",
        ),
    ]

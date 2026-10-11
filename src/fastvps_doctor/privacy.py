"""Explicit report allowlists and defensive local data minimization."""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any

from fastvps_doctor.models import DiagnosticCheck, Finding

CHECK_FIELDS: dict[str, set[str]] = {
    "system.resources": {
        "cpu_count",
        "cpu_sample_percent",
        "load_1m",
        "load_5m",
        "load_15m",
        "memory_percent",
        "memory_available_mb",
        "swap_percent",
        "uptime_seconds",
        "memory_psi_some_avg10",
        "io_psi_some_avg10",
    },
    "system.identity": {"distribution", "kernel_release", "python_supported"},
    "storage.root": {
        "usage_percent",
        "used_gb",
        "total_gb",
        "inode_usage_percent",
        "readonly",
        "mounted_filesystem_count",
    },
    "network.local": {
        "interface_count",
        "interfaces_up",
        "local_ipv4_address_count",
        "local_ipv6_address_count",
        "default_route_present",
        "resolver_readable",
        "resolver_nameserver_count",
        "dns_test_requested",
        "dns_test_succeeded",
        "dns_test_timed_out",
        "dns_answer_count",
        "tcp_test_requested",
        "tcp_test_succeeded",
        "tcp_test_timed_out",
    },
    "network.listeners": set(),
    "services.common": {"installed_count", "failed_count"},
    "security.local": {
        "ssh_root_login_restricted",
        "ssh_password_login_disabled",
        "ssh_public_key_authentication_enabled",
        "ssh_config_permissions_safe",
        "firewall_state",
        "update_simulation_requested",
        "package_upgrade_count",
    },
    "web.local": {
        "http_80_reachable",
        "https_443_reachable",
        "required_port_supplied",
        "required_port",
    },
}
SERVICE_NAMES = {"nginx", "apache", "ssh", "docker", "mysql", "mariadb", "postgresql", "redis"}
SAFE_STATES = {
    "active",
    "inactive",
    "failed",
    "activating",
    "deactivating",
    "unknown",
    "timeout",
    "unavailable",
    "passed",
    "failed_or_inconclusive",
}
SAFE_FIREWALL_STATES = {"active", "inactive", "unknown", "timeout", "unavailable"}
CHECK_CATEGORIES = {
    "system.resources": "system",
    "system.identity": "system",
    "storage.root": "storage",
    "network.local": "network",
    "network.listeners": "network",
    "services.common": "services",
    "security.local": "security",
    "web.local": "web",
}
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|"
    r"authorization|credential|private[_-]?key)\b(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_SECRET = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_URI_CREDENTIALS = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/\s@]*)?@")
_HOST_ASSIGNMENT = re.compile(r"(?i)\b(hostname|host)\s*[:=]\s*[^\s,;]+")
_USER_ASSIGNMENT = re.compile(r"(?i)\b(username|user|login)\s*[:=]\s*[^\s,;]+")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_DOMAIN = re.compile(
    r"(?i)(?<![\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])"
)
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_IPV6 = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.%]+(?![0-9a-f:])", re.I)
_UNIX_PATH = re.compile(r"(?<![\w:])/(?:[^\s,;)}\]]+)")
_WINDOWS_PATH = re.compile(r"(?i)\b[A-Z]:\\[^\s,;)}\]]+")


def _safe_metric_value(key: str, value: Any) -> str | int | float | bool | None | object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 1_000_000_000:
            return _DROP
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > 1_000_000_000:
            return _DROP
        return value
    if not isinstance(value, str):
        return _DROP
    if key == "distribution":
        return _clean_text(re.sub(r"[^A-Za-z0-9 ._-]", "", value), 80)
    if key == "kernel_release":
        return _clean_text(re.sub(r"[^A-Za-z0-9.+_-]", "", value), 64)
    if key == "firewall_state":
        return value if value in SAFE_FIREWALL_STATES else _DROP
    if key.endswith("_state") or key.endswith("_config_validation"):
        return value if value in SAFE_STATES else _DROP
    return _DROP


class _Drop:
    pass


_DROP = _Drop()


def sanitize_checks(checks: list[DiagnosticCheck]) -> list[DiagnosticCheck]:
    result: list[DiagnosticCheck] = []
    for check in checks:
        category = CHECK_CATEGORIES.get(check.check_id)
        if category is None:
            # New check types must be explicitly reviewed and added to the export allowlist.
            continue
        allowed = set(CHECK_FIELDS.get(check.check_id, set()))
        if check.check_id in {"network.listeners", "web.local"}:
            allowed.update(key for key in check.metrics if re.fullmatch(r"port_\d+_listeners", key))
        elif check.check_id == "services.common":
            for name in SERVICE_NAMES:
                allowed.update(
                    {
                        f"{name}_installed",
                        f"{name}_state",
                        f"{name}_config_validation",
                        f"{name}_recent_error_count",
                        f"{name}_recent_logs_truncated",
                    }
                )
        metrics: dict[str, str | int | float | bool | None] = {}
        for key in allowed & set(check.metrics):
            value = _safe_metric_value(key, check.metrics[key])
            if value is not _DROP:
                metrics[key] = value  # type: ignore[assignment]
        result.append(
            DiagnosticCheck(
                check_id=check.check_id[:64],
                category=category,
                status=check.status,
                summary=_clean_text(check.summary, 240),
                metrics=metrics,
                note=_clean_text(check.note, 240) if check.note else None,
            )
        )
    return result


def sanitize_findings(findings: list[Finding]) -> list[Finding]:
    # Findings are generated from fixed rule templates. This caps text and removes controls
    # defensively in case a future rule accidentally includes machine or command output.
    clean: list[Finding] = []
    for item in findings:
        clean.append(
            Finding(
                finding_id=(
                    item.finding_id
                    if re.fullmatch(
                        r"(?:STOR|SYS|SVC-[A-Z]{1,4}|NET|WEB|SEC)-\d{3}", item.finding_id
                    )
                    else "GEN-000"
                ),
                category=(
                    item.category
                    if item.category
                    in {"system", "storage", "network", "services", "security", "web"}
                    else "unknown"
                ),
                severity=item.severity,
                title=_clean_text(item.title, 120),
                description=_clean_text(item.description, 500),
                evidence=[_clean_text(text, 240) for text in item.evidence[:8]],
                possible_causes=[_clean_text(text, 200) for text in item.possible_causes[:8]],
                next_steps=[_clean_text(text, 240) for text in item.next_steps[:8]],
                confidence=item.confidence
                if item.confidence in {"low", "medium", "high"}
                else "low",
                requires_privileges=item.requires_privileges,
                support_scope=item.support_scope,
            )
        )
    return clean


def sanitize_ticket_reference(value: str | None) -> str | None:
    if value is None:
        return None
    # A ticket identifier is not free-form text. Restrict it to common ID characters
    # so Markdown, paths, addresses, and pasted credentials cannot enter the report.
    result = re.sub(r"[^A-Za-z0-9._-]", "", _clean_text(value, 120))[:80]
    return result or None


def sanitize_distribution(value: str) -> str:
    return _clean_text(value, 80)


def _clean_text(value: str, limit: int) -> str:
    text = "".join(char for char in value if char.isprintable())[:limit]
    text = _URI_CREDENTIALS.sub(r"\1[REDACTED]@", text)
    text = _BEARER_SECRET.sub(lambda match: f"{match.group(1)} [REDACTED]", text)
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _HOST_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _USER_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _EMAIL.sub("[EMAIL]", text)
    text = _IPV4.sub(_redact_ip, text)
    text = _IPV6.sub(_redact_ip, text)
    text = _DOMAIN.sub("[HOSTNAME]", text)
    text = _WINDOWS_PATH.sub("[PATH]", text)
    text = _UNIX_PATH.sub("[PATH]", text)
    return text[:limit]


def _redact_ip(match: re.Match[str]) -> str:
    candidate = match.group(0).rstrip(".,;)]}")
    suffix = match.group(0)[len(candidate) :]
    try:
        ipaddress.ip_address(candidate.split("%", maxsplit=1)[0])
    except ValueError:
        return match.group(0)
    return f"[IP]{suffix}"

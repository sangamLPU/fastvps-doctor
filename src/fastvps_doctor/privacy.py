"""Explicit report allowlists and defensive local data minimization."""

from __future__ import annotations

import ipaddress
import math
import re
from datetime import UTC, datetime
from typing import Any

from fastvps_doctor.models import (
    DiagnosticCheck,
    Finding,
    IncidentAnalysis,
    IncidentEvent,
    IncidentHypothesis,
    IncidentInformation,
    SupportHandoff,
)

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
    "storage.mounts": {"mount_count", "inspected_mount_count", "mount_inventory_truncated"},
    "network.local": {
        "interface_count",
        "interfaces_up",
        "local_ipv4_address_count",
        "local_ipv6_address_count",
        "default_route_present",
        "ipv6_default_route_present",
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
    "services.common": {
        "installed_count",
        "failed_count",
        "unit_count",
        "custom_unit_count",
    },
    "security.local": {
        "ssh_root_login_restricted",
        "ssh_password_login_disabled",
        "ssh_public_key_authentication_enabled",
        "ssh_config_permissions_safe",
        "ssh_effective_config_available",
        "ssh_connection_context_supplied",
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
    "reloading",
    "not_installed",
    "unit_not_found",
    "masked",
    "permission_restricted",
    "alias",
    "unknown",
    "timeout",
    "unavailable",
    "passed",
    "failed_or_inconclusive",
    "ok",
    "partial",
    "unsupported_filesystem",
    "remote_skipped",
}
SAFE_FIREWALL_STATES = {"active", "inactive", "unknown", "timeout", "unavailable"}
SAFE_SERVICE_NAMES = {
    "apache",
    "apache2",
    "docker",
    "httpd",
    "kernel",
    "mariadb",
    "mysql",
    "nginx",
    "postgresql",
    "redis",
    "redis-server",
    "ssh",
    "sshd",
}
SAFE_FILESYSTEM_TYPES = {
    "btrfs",
    "ext2",
    "ext3",
    "ext4",
    "exfat",
    "f2fs",
    "fat",
    "jfs",
    "ntfs",
    "overlay",
    "tmpfs",
    "vfat",
    "xfs",
    "zfs",
    "unsupported",
}
CHECK_CATEGORIES = {
    "system.resources": "system",
    "system.identity": "system",
    "storage.root": "storage",
    "network.local": "network",
    "network.listeners": "network",
    "storage.mounts": "storage",
    "services.common": "services",
    "security.local": "security",
    "web.local": "web",
}
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])((?:[A-Za-z0-9]+[_-])*"
    r"(?:password|passwd|pwd|token|secret(?:[\s_-]?key)?|api[\s_-]?key|"
    r"access[\s_-]?key|authorization|credential|private[\s_-]?key)"
    r"(?:[_-][A-Za-z0-9]+)*)"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_SECRET = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_PRIVATE_KEY_BLOCK = re.compile(
    r"(?is)-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z0-9 ]* )?PRIVATE KEY(?: BLOCK)?-----|$)"
)
_KNOWN_CREDENTIAL_TOKEN = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|"
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b"
)
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
_SENSITIVE_TICKET_REFERENCE = re.compile(
    r"(?i)(?:\b(?:password|passwd|token|secret|credential|authorization|bearer|"
    r"private[\s_-]?key|api[\s_-]?key)\b|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,})\b)"
)
_TICKET_REFERENCE = re.compile(r"(?:[A-Za-z][A-Za-z0-9_.]{0,15}-[A-Za-z0-9]{1,20}|[0-9]{1,20})")


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
    if re.fullmatch(r"custom_unit_\d+_name", key):
        # Custom unit names are intentionally withheld, but sending them through
        # generic hostname redaction mislabels ordinary names such as
        # "systemd-journald.service" as hostnames. Keep privacy while making the
        # reason for omission accurate and explicit.
        return "[REDACTED SERVICE]"
    if key == "firewall_state":
        return value if value in SAFE_FIREWALL_STATES else _DROP
    if key.endswith("_filesystem_type"):
        return value if value in SAFE_FILESYSTEM_TYPES else _DROP
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
        elif check.check_id == "storage.mounts":
            allowed.update(
                key
                for key in check.metrics
                if re.fullmatch(
                    r"mount_\d+_(?:filesystem_type|state|usage_percent|inode_usage_percent|readonly|used_gb|total_gb)",
                    key,
                )
            )
        elif check.check_id == "services.common":
            for name in SERVICE_NAMES:
                allowed.update(
                    {
                        f"{name}_installed",
                        f"{name}_unit_found",
                        f"{name}_state",
                        f"{name}_config_validation",
                        f"{name}_recent_error_count",
                        f"{name}_recent_logs_truncated",
                    }
                )
            for key in check.metrics:
                if re.fullmatch(
                    r"custom_unit_\d+_(?:name|state|unit_found|recent_error_count|recent_logs_truncated)",
                    key,
                ):
                    allowed.add(key)
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
    # Keep this field narrower than free-form text. Stripping punctuation can turn
    # pasted credentials into identifier-looking text (for example, "token=...").
    # Common support/ticket IDs are a short prefix plus an ID, or a numeric ID.
    if _SENSITIVE_TICKET_REFERENCE.search(value):
        return None
    candidate = _clean_text(value, 120).strip()
    if len(candidate) > 80 or not _TICKET_REFERENCE.fullmatch(candidate):
        return None
    return candidate


def sanitize_distribution(value: str) -> str:
    return _clean_text(value, 80)


def sanitize_incident_information(
    information: IncidentInformation | None,
) -> IncidentInformation | None:
    if information is None:
        return None
    start_time = _utc_if_aware(information.start_time_utc)
    affected_service = (
        _clean_service_unit(information.affected_service) if information.affected_service else None
    )
    description = _clean_text(information.description, 500) if information.description else None
    return IncidentInformation(
        start_time_utc=start_time,
        affected_service=affected_service or None,
        problem_category=information.problem_category,
        description=description or None,
    )


def sanitize_incident_analysis(analysis: IncidentAnalysis | None) -> IncidentAnalysis | None:
    if analysis is None:
        return None
    safe_service = _clean_service_unit(analysis.service)
    events = [
        IncidentEvent(
            timestamp_utc=timestamp,
            classification=event.classification,
            component=_clean_service_unit(event.component),
            evidence_summary=_sanitize_incident_text(event.evidence_summary, 240, analysis.service),
            correlation_explanation=(
                _sanitize_incident_text(event.correlation_explanation, 240, analysis.service)
                if event.correlation_explanation
                else None
            ),
        )
        for event in analysis.events[:100]
        if (timestamp := _utc_if_aware(event.timestamp_utc)) is not None
    ]
    hypotheses = [
        IncidentHypothesis(
            statement=_sanitize_incident_text(item.statement, 300, analysis.service),
            start_time_utc=start_time,
            end_time_utc=end_time,
            evidence=[
                _sanitize_incident_text(text, 240, analysis.service) for text in item.evidence[:8]
            ],
            confidence=item.confidence if item.confidence in {"low", "medium", "high"} else "low",
            alternatives=[
                _sanitize_incident_text(text, 200, analysis.service)
                for text in item.alternatives[:8]
            ],
            next_steps=[
                _sanitize_incident_text(text, 240, analysis.service) for text in item.next_steps[:8]
            ],
        )
        for item in analysis.hypotheses[:20]
        if (start_time := _utc_if_aware(item.start_time_utc)) is not None
        and (end_time := _utc_if_aware(item.end_time_utc)) is not None
        and start_time <= end_time
    ]
    sources = [
        value
        for value in analysis.unavailable_sources
        if value in {"service_journal", "kernel_journal"}
    ]
    return IncidentAnalysis(
        service=safe_service,
        window_seconds=min(max(analysis.window_seconds, 60), 86400),
        generated_at_utc=_utc_if_aware(analysis.generated_at_utc) or datetime.now(UTC),
        complete=analysis.complete,
        unavailable_sources=sources,
        events=events,
        hypotheses=hypotheses,
        note=(
            _sanitize_incident_text(analysis.note, 300, analysis.service) if analysis.note else None
        ),
    )


def sanitize_handoff(handoff: SupportHandoff) -> SupportHandoff:
    valid_unavailable = set(CHECK_CATEGORIES) | {
        "Incident source: service_journal",
        "Incident source: kernel_journal",
    }
    return SupportHandoff(
        reported_problem=_clean_text(handoff.reported_problem, 500)
        if handoff.reported_problem
        else None,
        confirmed_observations=[
            _clean_text(value, 240) for value in handoff.confirmed_observations[:12]
        ],
        investigation_areas=[_clean_text(value, 200) for value in handoff.investigation_areas[:12]],
        unavailable_checks=[
            value for value in handoff.unavailable_checks[:16] if value in valid_unavailable
        ],
        next_actions=[_clean_text(value, 240) for value in handoff.next_actions[:16]],
    )


def _clean_service_unit(value: str) -> str:
    suffix = ".service"
    name = value[: -len(suffix)] if value.endswith(suffix) else value
    if name.lower() in SAFE_SERVICE_NAMES:
        canonical = name.lower()
        return f"{canonical}{suffix}" if value.endswith(suffix) else canonical
    return "[REDACTED SERVICE]"


def _sanitize_incident_text(value: str, limit: int, service: str) -> str:
    if _clean_service_unit(service) == "[REDACTED SERVICE]":
        variants = {service, f"{service}.service"}
        for variant in sorted(variants, key=len, reverse=True):
            if variant:
                value = re.sub(
                    rf"(?<![A-Za-z0-9_@-]){re.escape(variant)}(?![A-Za-z0-9_@-])",
                    "[REDACTED SERVICE]",
                    value,
                    flags=re.IGNORECASE,
                )
    return _clean_text(value, limit)


def _utc_if_aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is None or value.utcoffset() is None:
        return None
    return value.astimezone(UTC)


def _clean_text(value: str, limit: int) -> str:
    text = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", value)
    text = _URI_CREDENTIALS.sub(r"\1[REDACTED]@", text)
    text = _BEARER_SECRET.sub(lambda match: f"{match.group(1)} [REDACTED]", text)
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _KNOWN_CREDENTIAL_TOKEN.sub("[REDACTED TOKEN]", text)
    text = _HOST_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _USER_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _EMAIL.sub("[EMAIL]", text)
    text = _IPV4.sub(_redact_ip, text)
    text = _IPV6.sub(_redact_ip, text)
    text = _DOMAIN.sub("[HOSTNAME]", text)
    text = _WINDOWS_PATH.sub("[PATH]", text)
    text = _UNIX_PATH.sub("[PATH]", text)
    return "".join(char for char in text if char.isprintable())[:limit]


def _redact_ip(match: re.Match[str]) -> str:
    candidate = match.group(0).rstrip(".,;)]}")
    suffix = match.group(0)[len(candidate) :]
    try:
        ipaddress.ip_address(candidate.split("%", maxsplit=1)[0])
    except ValueError:
        return match.group(0)
    return f"[IP]{suffix}"

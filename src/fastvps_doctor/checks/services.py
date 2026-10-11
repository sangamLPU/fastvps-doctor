"""Presence and read-only active/configuration checks for common services."""

from __future__ import annotations

from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.runner import CommandRunner, find_executable

SERVICE_DEFINITIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "nginx": ("nginx", ("nginx",)),
    "apache": ("apache2", ("apache2ctl", "apachectl", "httpd")),
    "ssh": ("ssh", ("sshd",)),
    "docker": ("docker", ("docker",)),
    "mysql": ("mysql", ("mysqld", "mariadbd", "mysqld_safe")),
    "mariadb": ("mariadb", ("mariadbd", "mariadb")),
    "postgresql": ("postgresql", ("postgres",)),
    "redis": ("redis-server", ("redis-server",)),
}


def collect_services(runner: CommandRunner | None = None) -> list[DiagnosticCheck]:
    command_runner = runner or CommandRunner()
    metrics: dict[str, str | int | float | bool | None] = {"installed_count": 0, "failed_count": 0}
    installed = 0
    failed = 0
    uncertain = 0

    for name, (unit, candidates) in SERVICE_DEFINITIONS.items():
        executable = next(
            (item for candidate in candidates if (item := find_executable(candidate))), None
        )
        metrics[f"{name}_installed"] = executable is not None
        if executable is None:
            continue
        installed += 1
        active_result = command_runner.service_active(unit)
        raw_state = active_result.stdout.strip().lower()
        if not active_result.available:
            state = "unavailable"
        elif active_result.timed_out:
            state = "timeout"
        elif active_result.returncode is None:
            state = "unknown"
        elif active_result.returncode == 0 and raw_state == "active":
            state = "active"
        elif raw_state in {"inactive", "failed", "activating", "deactivating"}:
            state = raw_state
        else:
            # Never infer a healthy state from malformed output or an inconsistent code.
            state = "unknown"
        metrics[f"{name}_state"] = state
        failed += int(state == "failed")
        uncertain += int(state in {"unknown", "timeout", "unavailable"})
        if state == "failed":
            log_result = command_runner.recent_service_logs(unit)
            if log_result.available and not log_result.timed_out and log_result.returncode == 0:
                error_indicators = sum(
                    1
                    for line in log_result.stdout.splitlines()
                    if any(
                        token in line.lower()
                        for token in ("error", "failed", "failure", "fatal", "critical")
                    )
                )
                metrics[f"{name}_recent_error_count"] = min(error_indicators, 40)
                metrics[f"{name}_recent_logs_truncated"] = log_result.truncated
            else:
                metrics[f"{name}_recent_error_count"] = None

        if name == "nginx":
            validation = command_runner.validate_nginx()
            metrics["nginx_config_validation"] = _validation_state(validation)
        elif name == "apache":
            validator = next(
                (
                    item
                    for item in candidates
                    if item in {"apache2ctl", "apachectl"} and find_executable(item)
                ),
                None,
            )
            if validator:
                metrics["apache_config_validation"] = _validation_state(
                    command_runner.validate_apache(validator)
                )
        elif name == "ssh":
            metrics["ssh_config_validation"] = _validation_state(command_runner.validate_ssh())

    metrics["installed_count"] = installed
    metrics["failed_count"] = failed
    if installed == 0:
        status = CheckStatus.SKIPPED
        summary = "No monitored service executable was found; this is not an error."
        note = "Installations using custom paths or service names may not be detected."
    elif failed:
        status = CheckStatus.WARNING
        summary = "At least one detected service reports a failed state."
        note = "Inactive services can be intentional. A failed systemd state is stronger evidence than inactivity."
    elif uncertain:
        status = CheckStatus.UNKNOWN
        summary = "One or more detected service states could not be determined."
        note = "The service manager may be unavailable or access may be restricted."
    elif any(
        value == "failed_or_inconclusive"
        for key, value in metrics.items()
        if key.endswith("_config_validation")
    ):
        status = CheckStatus.WARNING
        summary = "A selected read-only service validator did not pass."
        note = "A non-zero validator can reflect a configuration issue or an access limitation."
    else:
        status = CheckStatus.PASS
        summary = "Inspected detected common service executables and their service-manager state."
        note = "Only failed services trigger bounded log summaries; custom units and non-systemd hosts may be missed."
    return [
        DiagnosticCheck(
            check_id="services.common",
            category="services",
            status=status,
            summary=summary,
            metrics=metrics,
            note=note,
        )
    ]


def _validation_state(result: object) -> str:
    available = getattr(result, "available", False)
    timed_out = getattr(result, "timed_out", False)
    returncode = getattr(result, "returncode", None)
    if not available:
        return "unavailable"
    if timed_out:
        return "timeout"
    if returncode == 0:
        return "passed"
    return "failed_or_inconclusive"

"""Bounded systemd discovery and optional read-only configuration checks."""

from __future__ import annotations

from collections.abc import Sequence

from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.runner import CommandResult, CommandRunner, find_executable, safe_systemd_unit

SERVICE_DEFINITIONS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "nginx": (("nginx.service",), ("nginx",)),
    "apache": (("apache2.service", "httpd.service"), ("apache2ctl", "apachectl", "httpd")),
    "ssh": (("ssh.service", "sshd.service"), ("sshd",)),
    "docker": (("docker.service",), ("docker",)),
    "mysql": (("mysql.service",), ("mysqld", "mysqld_safe")),
    "mariadb": (("mariadb.service",), ("mariadbd", "mariadb")),
    "postgresql": (("postgresql.service",), ("postgres",)),
    "redis": (("redis-server.service", "redis.service"), ("redis-server",)),
}

UNCERTAIN_STATES = {
    "unknown",
    "timeout",
    "unavailable",
    "permission_restricted",
    "unit_not_found",
}
PRESENT_STATES = {
    "active",
    "inactive",
    "failed",
    "masked",
    "activating",
    "deactivating",
    "reloading",
}


def collect_services(
    runner: CommandRunner | None = None,
    *,
    custom_units: Sequence[str] = (),
    validate_config: bool = False,
) -> list[DiagnosticCheck]:
    """Inspect known services and explicitly selected units without running repairs.

    Executable presence is kept as supporting evidence only. A service is considered
    managed when systemd reports a loaded unit; a binary alone never implies active.
    Configuration validators are opt-in because their file-access behavior varies by
    daemon and distribution.
    """
    command_runner = runner or CommandRunner()
    if len(custom_units) > 5:
        raise ValueError("Select no more than five custom systemd units.")
    metrics: dict[str, str | int | float | bool | None] = {
        "installed_count": 0,
        "failed_count": 0,
        "unit_count": 0,
        "custom_unit_count": 0,
    }
    installed_count = 0
    failed_count = 0
    unit_count = 0
    uncertain = 0
    seen_unit_ids: set[str] = set()

    for name, (units, executables) in SERVICE_DEFINITIONS.items():
        executable_present = any(find_executable(candidate) for candidate in executables)
        selected_state = "unit_not_found"
        selected_unit: str | None = None
        for candidate in units:
            result = command_runner.systemd_unit_show(candidate)
            state, properties = _unit_state(result)
            if state != "unit_not_found":
                selected_state = state
                selected_unit = properties.get("Id") or candidate
                break

        if selected_state == "unit_not_found":
            selected_state = "unit_not_found" if executable_present else "not_installed"
        elif selected_unit:
            canonical_id = selected_unit.casefold()
            # mysql.service can be an alias for mariadb.service and vice versa.
            if (
                (name == "mysql" and canonical_id == "mariadb.service")
                or (name == "mariadb" and canonical_id == "mysql.service")
            ) or canonical_id in seen_unit_ids:
                selected_state = "alias"
            else:
                seen_unit_ids.add(canonical_id)
                if selected_state in PRESENT_STATES:
                    unit_count += 1

        is_present = executable_present or selected_state in PRESENT_STATES | {"alias"}
        metrics[f"{name}_installed"] = is_present
        metrics[f"{name}_unit_found"] = selected_state in PRESENT_STATES | {"alias"}
        metrics[f"{name}_state"] = selected_state
        installed_count += int(is_present)
        failed_count += int(selected_state == "failed")
        uncertain += int(selected_state in UNCERTAIN_STATES)

        if selected_state == "failed" and selected_unit:
            logs = command_runner.recent_service_logs(selected_unit)
            if (
                logs.available
                and not logs.timed_out
                and not logs.truncated
                and logs.returncode == 0
            ):
                metrics[f"{name}_recent_error_count"] = min(
                    _count_error_indicators(logs.stdout), 40
                )
                metrics[f"{name}_recent_logs_truncated"] = logs.truncated
            else:
                metrics[f"{name}_recent_error_count"] = None

        if validate_config and executable_present:
            validation = _run_validator(command_runner, name, executables)
            if validation is not None:
                metrics[f"{name}_config_validation"] = _validation_state(validation)

    custom_names: list[str] = []
    for index, requested_unit in enumerate(custom_units[:5]):
        unit = safe_systemd_unit(requested_unit)
        if unit in custom_names:
            continue
        custom_names.append(unit)
        state, properties = _unit_state(command_runner.systemd_unit_show(unit))
        canonical_id = properties.get("Id", unit).casefold()
        if state in PRESENT_STATES and canonical_id in seen_unit_ids:
            state = "alias"
        elif state in PRESENT_STATES:
            seen_unit_ids.add(canonical_id)
            unit_count += 1
        metrics[f"custom_unit_{index}_name"] = unit
        metrics[f"custom_unit_{index}_state"] = state
        metrics[f"custom_unit_{index}_unit_found"] = state in PRESENT_STATES | {"alias"}
        if state == "failed":
            failed_count += 1
            logs = command_runner.recent_service_logs(unit)
            if (
                logs.available
                and not logs.timed_out
                and not logs.truncated
                and logs.returncode == 0
            ):
                metrics[f"custom_unit_{index}_recent_error_count"] = min(
                    _count_error_indicators(logs.stdout), 40
                )
                metrics[f"custom_unit_{index}_recent_logs_truncated"] = logs.truncated
            else:
                metrics[f"custom_unit_{index}_recent_error_count"] = None
        uncertain += int(state in UNCERTAIN_STATES)

    metrics["installed_count"] = installed_count
    metrics["failed_count"] = failed_count
    metrics["unit_count"] = unit_count
    metrics["custom_unit_count"] = len(custom_names)

    validators_failed = any(
        value == "failed_or_inconclusive"
        for key, value in metrics.items()
        if key.endswith("_config_validation")
    )
    if installed_count == 0 and not custom_names and not uncertain:
        status = CheckStatus.SKIPPED
        summary = "No monitored service executable or systemd unit was found; this is not an error."
        note = "Custom paths and non-systemd service managers may not be detected."
    elif uncertain:
        status = CheckStatus.UNKNOWN
        summary = "One or more detected service states could not be determined."
        note = "The service manager may be unavailable or access may be restricted."
    elif failed_count or validators_failed:
        status = CheckStatus.WARNING
        summary = "At least one detected service is failed or a requested validator did not pass."
        note = "Inactive and masked services can be intentional; review the reported unit state."
    else:
        status = CheckStatus.PASS
        summary = "Inspected selected systemd unit states for detected common services."
        note = "Executable presence is not proof that a service is installed or active."
    if custom_names:
        note = (
            note + " " if note else ""
        ) + "Custom units were queried only because they were explicitly selected."
    if not validate_config:
        note = (note + " " if note else "") + "Configuration validators are opt-in."

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


def _unit_state(result: CommandResult) -> tuple[str, dict[str, str]]:
    if result.error == "permission_denied":
        return "permission_restricted", {}
    if not result.available:
        return "unavailable", {}
    if result.timed_out:
        return "timeout", {}
    if result.truncated or result.returncode != 0:
        return "unknown", {}
    properties = _parse_properties(result.stdout)
    load_state = properties.get("LoadState", "").lower()
    if load_state == "not-found":
        return "unit_not_found", properties
    if load_state in {"masked", "masked-runtime"} or properties.get(
        "UnitFileState", ""
    ).lower() in {
        "masked",
        "masked-runtime",
    }:
        return "masked", properties
    active_state = properties.get("ActiveState", "").lower()
    if active_state in {"active", "inactive", "failed", "activating", "deactivating", "reloading"}:
        if active_state == "active" and properties.get("SubState") in {"failed", "dead"}:
            return "unknown", properties
        return active_state, properties
    return "unknown", properties


def _parse_properties(stdout: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "Result",
            "NRestarts",
        }:
            properties[key] = value.strip()
    return properties


def _count_error_indicators(log_text: str) -> int:
    return sum(
        1
        for line in log_text.splitlines()
        if any(
            token in line.lower() for token in ("error", "failed", "failure", "fatal", "critical")
        )
    )


def _run_validator(
    runner: CommandRunner, name: str, executables: tuple[str, ...]
) -> CommandResult | None:
    if name == "nginx" and find_executable("nginx"):
        return runner.validate_nginx()
    if name == "apache":
        executable = next(
            (
                candidate
                for candidate in executables
                if candidate in {"apache2ctl", "apachectl"} and find_executable(candidate)
            ),
            None,
        )
        if executable:
            return runner.validate_apache(executable)
    if name == "ssh" and find_executable("sshd"):
        return runner.validate_ssh()
    return None


def _validation_state(result: CommandResult) -> str:
    if not result.available:
        return "unavailable"
    if result.timed_out:
        return "timeout"
    if result.truncated:
        return "failed_or_inconclusive"
    if result.returncode == 0:
        return "passed"
    return "failed_or_inconclusive"

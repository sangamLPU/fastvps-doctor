"""Read-only, deliberately limited security configuration indicators."""

from __future__ import annotations

from pathlib import Path

from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.runner import CommandRunner

SSHContext = tuple[str, str, str, str, int]
SSH_INDICATORS = {"permitrootlogin", "passwordauthentication", "pubkeyauthentication"}


def _ssh_indicators(
    runner: CommandRunner, context: SSHContext | None = None
) -> tuple[bool | None, bool | None, bool | None, bool | None, bool]:
    """Read effective sshd values, or return unknown when sshd cannot establish them."""
    config = next(
        (
            path
            for path in (Path("/etc/ssh/sshd_config"), Path("/usr/local/etc/ssh/sshd_config"))
            if path.is_file()
        ),
        None,
    )
    if config is None:
        config_permissions_safe = None
    else:
        try:
            permissions = config.stat()
            config_permissions_safe = not bool(permissions.st_mode & 0o022)
        except OSError:
            config_permissions_safe = None

    result = runner.effective_ssh_config(context)
    if not result.available or result.timed_out or result.truncated or result.returncode != 0:
        return None, None, None, config_permissions_safe, False

    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in SSH_INDICATORS:
            values[parts[0].lower()] = parts[1].strip().lower()
    available = SSH_INDICATORS.issubset(values)
    if not available:
        return None, None, None, config_permissions_safe, False

    root_setting = values["permitrootlogin"]
    password_setting = values["passwordauthentication"]
    pubkey_setting = values["pubkeyauthentication"]
    root_login_restricted = (
        root_setting in {"no", "prohibit-password", "without-password", "forced-commands-only"}
        if root_setting
        in {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}
        else None
    )
    password_login_disabled = (
        password_setting == "no" if password_setting in {"yes", "no"} else None
    )
    public_key_enabled = pubkey_setting == "yes" if pubkey_setting in {"yes", "no"} else None
    return (
        root_login_restricted,
        password_login_disabled,
        public_key_enabled,
        config_permissions_safe,
        True,
    )


def collect_security(
    runner: CommandRunner | None = None,
    include_update_simulation: bool = False,
    ssh_context: SSHContext | None = None,
) -> list[DiagnosticCheck]:
    command_runner = runner or CommandRunner()
    (
        root_restricted,
        passwords_disabled,
        pubkey_enabled,
        ssh_permissions_safe,
        ssh_effective_available,
    ) = _ssh_indicators(command_runner, ssh_context)

    firewall = command_runner.firewall_status()
    firewall_text = firewall.stdout.strip().lower()
    if not firewall.available:
        firewall_state = "unavailable"
    elif firewall.timed_out:
        firewall_state = "timeout"
    elif firewall.truncated or firewall.returncode != 0:
        firewall_state = "unknown"
    elif "status: active" in firewall_text:
        firewall_state = "active"
    elif "status: inactive" in firewall_text:
        firewall_state = "inactive"
    else:
        firewall_state = "unknown"

    metrics: dict[str, str | int | float | bool | None] = {
        "ssh_root_login_restricted": root_restricted,
        "ssh_password_login_disabled": passwords_disabled,
        "ssh_public_key_authentication_enabled": pubkey_enabled,
        "ssh_config_permissions_safe": ssh_permissions_safe,
        "ssh_effective_config_available": ssh_effective_available,
        "ssh_connection_context_supplied": ssh_context is not None,
        "firewall_state": firewall_state,
        "update_simulation_requested": include_update_simulation,
        "package_upgrade_count": None,
    }
    update_simulation_available = False
    if include_update_simulation:
        # This uses locally cached APT metadata; it never refreshes indices or applies changes.
        update_result = command_runner.simulate_package_upgrades()
        if (
            update_result.available
            and not update_result.timed_out
            and not update_result.truncated
            and update_result.returncode == 0
        ):
            package_count = sum(
                1 for line in update_result.stdout.splitlines() if line.startswith("Inst ")
            )
            metrics["package_upgrade_count"] = package_count
            update_simulation_available = True

    firewall_known = firewall_state in {"active", "inactive"}
    requested_checks_complete = (
        firewall_known
        and ssh_effective_available
        and (not include_update_simulation or update_simulation_available)
    )
    any_evidence = (
        firewall_state != "unavailable"
        or ssh_effective_available
        or ssh_permissions_safe is not None
        or root_restricted is not None
        or passwords_disabled is not None
        or pubkey_enabled is not None
    )
    if requested_checks_complete:
        status = CheckStatus.PASS
    elif not any_evidence:
        status = CheckStatus.SKIPPED
    else:
        status = CheckStatus.UNKNOWN

    notes = [
        "Firewall providers other than UFW are not inspected.",
        (
            "SSH values apply only to the supplied connection context."
            if ssh_context
            else "sshd -T reports effective global defaults; Match-specific policy may differ by connection."
        ),
        "No configuration is changed.",
    ]
    if include_update_simulation:
        notes.append(
            "The optional APT simulation uses cached state without package-manager locking; "
            "concurrent package changes may make its generic count incomplete, and it is not security-specific."
        )
    return [
        DiagnosticCheck(
            check_id="security.local",
            category="security",
            status=status,
            summary="Collected limited effective SSH and host-firewall indicators; this is not a complete security audit.",
            metrics=metrics,
            note=" ".join(notes),
        )
    ]

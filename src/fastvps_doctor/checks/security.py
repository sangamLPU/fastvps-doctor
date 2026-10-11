"""Read-only, deliberately limited security configuration indicators."""

from __future__ import annotations

import re
from pathlib import Path

from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.runner import CommandRunner


def _ssh_indicators() -> tuple[bool | None, bool | None, bool | None, bool | None]:
    candidates = (Path("/etc/ssh/sshd_config"), Path("/usr/local/etc/ssh/sshd_config"))
    config = next((path for path in candidates if path.is_file()), None)
    if config is None:
        return None, None, None, None
    values: dict[str, str] = {}
    inside_match = False
    try:
        with config.open("r", encoding="utf-8", errors="ignore") as stream:
            content = stream.read(65536)
    except OSError:
        return None, None, None, None
    try:
        permissions = config.stat()
        config_permissions_safe: bool | None = not bool(permissions.st_mode & 0o022)
    except OSError:
        config_permissions_safe = None
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = re.split(r"\s+", line.strip(), maxsplit=1)
        if len(parts) != 2:
            continue
        directive, value = parts[0].lower(), parts[1].split()[0].lower()
        if directive == "match":
            inside_match = True
        if inside_match or directive == "include":
            continue
        if directive in {"permitrootlogin", "passwordauthentication", "pubkeyauthentication"}:
            values.setdefault(directive, value)

    root_setting = values.get("permitrootlogin")
    password_setting = values.get("passwordauthentication")
    pubkey_setting = values.get("pubkeyauthentication")
    root_login_restricted = (
        root_setting in {"no", "prohibit-password", "without-password", "forced-commands-only"}
        if root_setting
        else None
    )
    password_login_disabled = password_setting == "no" if password_setting else None
    public_key_enabled = pubkey_setting == "yes" if pubkey_setting else None
    return (
        root_login_restricted,
        password_login_disabled,
        public_key_enabled,
        config_permissions_safe,
    )


def collect_security(
    runner: CommandRunner | None = None, include_update_simulation: bool = False
) -> list[DiagnosticCheck]:
    command_runner = runner or CommandRunner()
    root_restricted, passwords_disabled, pubkey_enabled, ssh_permissions_safe = _ssh_indicators()

    firewall = command_runner.firewall_status()
    firewall_text = firewall.stdout.strip().lower()
    if not firewall.available:
        firewall_state = "unavailable"
    elif firewall.timed_out:
        firewall_state = "timeout"
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
        else:
            metrics["package_upgrade_count"] = None

    known_indicators = (
        any(
            value is not None
            for value in (root_restricted, passwords_disabled, pubkey_enabled, ssh_permissions_safe)
        )
        or update_simulation_available
    )
    requested_checks_complete = firewall_state in {"active", "inactive"} and (
        not include_update_simulation or update_simulation_available
    )
    if requested_checks_complete:
        status = CheckStatus.PASS
    elif not known_indicators and firewall_state == "unavailable":
        status = CheckStatus.SKIPPED
    else:
        # Some SSH evidence may still be available, but the aggregate security check
        # remains partial when the only firewall provider cannot be inspected.
        status = CheckStatus.UNKNOWN
    note = "Firewall providers other than UFW are not inspected. No configuration is changed."
    if include_update_simulation:
        note += (
            " The optional APT simulation uses cached state without package-manager locking; "
            "concurrent package changes may make its generic count incomplete, and it is not security-specific."
        )
    return [
        DiagnosticCheck(
            check_id="security.local",
            category="security",
            status=status,
            summary="Collected limited SSH and host-firewall indicators; this is not a complete security audit.",
            metrics=metrics,
            note=note,
        )
    ]

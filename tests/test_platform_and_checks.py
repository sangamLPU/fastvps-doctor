import sys

import psutil

from fastvps_doctor.checks import network as network_module
from fastvps_doctor.checks import services as services_module
from fastvps_doctor.checks import storage as storage_module
from fastvps_doctor.checks import system as system_module
from fastvps_doctor.models import CheckStatus
from fastvps_doctor.platform import is_supported_distribution, linux_distribution
from fastvps_doctor.runner import CommandResult


def test_unsupported_platform_is_explicitly_skipped(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert linux_distribution() == "Unsupported platform"
    storage_check = storage_module.collect_storage()[0]
    assert storage_check.status == CheckStatus.SKIPPED
    identity_check = system_module.collect_system()[1]
    assert identity_check.status == CheckStatus.SKIPPED


def test_only_initial_ubuntu_debian_version_targets_are_supported() -> None:
    assert is_supported_distribution({"ID": "ubuntu", "VERSION_ID": "24.04"})
    assert is_supported_distribution({"ID": "debian", "VERSION_ID": "13"})
    assert not is_supported_distribution({"ID": "fedora", "VERSION_ID": "43"})
    assert not is_supported_distribution({"ID": "ubuntu", "VERSION_ID": "22.04"})


def test_permission_limited_listener_inventory_is_skipped(monkeypatch) -> None:
    monkeypatch.setattr(network_module.sys, "platform", "linux")

    def denied(*_: object, **__: object) -> None:
        raise psutil.AccessDenied(pid=123)

    monkeypatch.setattr(network_module.psutil, "net_connections", denied)
    check = network_module.collect_listeners()
    assert check.status == CheckStatus.SKIPPED
    assert "not permit" in (check.note or "")


class MalformedServiceRunner:
    def service_active(self, unit: str) -> CommandResult:
        return CommandResult(available=True, returncode=3, stdout="unexpected output")

    def recent_service_logs(self, unit: str) -> CommandResult:
        raise AssertionError("Logs are read only for failed services.")

    def validate_nginx(self) -> CommandResult:
        return CommandResult(available=True, returncode=0)


def test_unrecognized_service_manager_output_is_not_called_failed(monkeypatch) -> None:
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda executable: "/usr/sbin/nginx" if executable == "nginx" else None,
    )
    check = services_module.collect_services(runner=MalformedServiceRunner())[0]
    assert check.metrics["nginx_state"] == "unknown"
    assert check.metrics["failed_count"] == 0

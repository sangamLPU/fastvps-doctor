import sys
from types import SimpleNamespace

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
    system_checks = system_module.collect_system()
    assert system_checks[0].status == CheckStatus.SKIPPED
    identity_check = system_checks[1]
    assert identity_check.status == CheckStatus.SKIPPED


def test_only_initial_ubuntu_debian_version_targets_are_supported() -> None:
    assert is_supported_distribution({"ID": "ubuntu", "VERSION_ID": "24.04"})
    assert is_supported_distribution({"ID": "debian", "VERSION_ID": "13"})
    assert not is_supported_distribution({"ID": "fedora", "VERSION_ID": "43"})
    assert not is_supported_distribution({"ID": "ubuntu", "VERSION_ID": "22.04"})


def test_os_release_metadata_is_sanitized_and_read_failures_are_unknown(monkeypatch) -> None:
    import fastvps_doctor.platform as platform_module

    monkeypatch.setattr(platform_module.sys, "platform", "linux")
    monkeypatch.setattr(
        platform_module.std_platform,
        "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "24.04", "NAME": "Ubuntu <private>"},
    )
    assert linux_distribution() == "ubuntu 24.04"
    assert platform_module.linux_distribution_supported() is True

    monkeypatch.setattr(
        platform_module.std_platform,
        "freedesktop_os_release",
        lambda: (_ for _ in ()).throw(OSError("private os-release path")),
    )
    assert linux_distribution() == "Linux distribution could not be identified"
    assert platform_module.linux_distribution_supported() is None


def test_system_check_survives_unavailable_linux_load_average(monkeypatch) -> None:
    monkeypatch.setattr(system_module.sys, "platform", "linux")
    monkeypatch.setattr(system_module.psutil, "cpu_percent", lambda **_: 8.0)
    monkeypatch.setattr(system_module.psutil, "cpu_count", lambda **_: 4)
    monkeypatch.setattr(
        system_module.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(percent=32.0, available=4 * 1024 * 1024 * 1024),
    )
    monkeypatch.setattr(
        system_module.psutil,
        "swap_memory",
        lambda: SimpleNamespace(percent=0.0),
    )
    monkeypatch.setattr(system_module.psutil, "boot_time", lambda: 1.0)
    monkeypatch.setattr(system_module, "linux_distribution", lambda: "Ubuntu 24.04")
    monkeypatch.setattr(system_module, "linux_distribution_supported", lambda: True)

    def unavailable_load_average():
        raise RuntimeError("performance counters are unavailable")

    monkeypatch.setattr(system_module.psutil, "getloadavg", unavailable_load_average)
    resources = system_module.collect_system()[0]

    assert resources.status == CheckStatus.PASS
    assert resources.metrics["load_1m"] is None
    assert "Load-average counters were unavailable" in (resources.note or "")


def test_system_check_marks_core_counter_failures_unknown_without_error_details(
    monkeypatch,
) -> None:
    monkeypatch.setattr(system_module.sys, "platform", "linux")
    monkeypatch.setattr(
        system_module.psutil,
        "cpu_percent",
        lambda **_: (_ for _ in ()).throw(RuntimeError("private cpu counter")),
    )
    monkeypatch.setattr(system_module.psutil, "cpu_count", lambda **_: None)
    monkeypatch.setattr(
        system_module.psutil,
        "virtual_memory",
        lambda: (_ for _ in ()).throw(psutil.AccessDenied(pid=1)),
    )
    monkeypatch.setattr(
        system_module.psutil,
        "swap_memory",
        lambda: (_ for _ in ()).throw(OSError("private swap path")),
    )
    monkeypatch.setattr(
        system_module.psutil,
        "getloadavg",
        lambda: (_ for _ in ()).throw(RuntimeError("private load counter")),
    )
    monkeypatch.setattr(
        system_module.psutil,
        "boot_time",
        lambda: (_ for _ in ()).throw(OSError("private boot metadata")),
    )
    monkeypatch.setattr(system_module, "linux_distribution", lambda: "Linux")
    monkeypatch.setattr(system_module, "linux_distribution_supported", lambda: None)

    resources = system_module.collect_system()[0]
    assert resources.status == CheckStatus.UNKNOWN
    assert resources.metrics["cpu_sample_percent"] is None
    assert resources.metrics["memory_percent"] is None
    assert resources.metrics["swap_percent"] is None
    assert resources.metrics["load_1m"] is None
    assert resources.metrics["uptime_seconds"] is None
    assert "private" not in (resources.note or "")


def test_permission_limited_listener_inventory_is_skipped(monkeypatch) -> None:
    monkeypatch.setattr(network_module.sys, "platform", "linux")

    def denied(*_: object, **__: object) -> None:
        raise psutil.AccessDenied(pid=123)

    monkeypatch.setattr(network_module.psutil, "net_connections", denied)
    check = network_module.collect_listeners()
    assert check.status == CheckStatus.SKIPPED
    assert "not permit" in (check.note or "")


class MalformedServiceRunner:
    def systemd_unit_show(self, unit: str) -> CommandResult:
        return CommandResult(available=True, returncode=0, stdout="unexpected output")

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

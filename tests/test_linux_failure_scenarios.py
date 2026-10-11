"""Deterministic fixtures for Linux-specific failure paths; no live host mutation."""

from __future__ import annotations

from io import BytesIO
from types import SimpleNamespace

import psutil

from fastvps_doctor.checks import network as network_module
from fastvps_doctor.checks import security as security_module
from fastvps_doctor.checks import storage as storage_module
from fastvps_doctor.checks import system as system_module
from fastvps_doctor.checks import web as web_module
from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.reports import build_report
from fastvps_doctor.rules import analyze
from fastvps_doctor.runner import CommandResult


class FakeLinuxPath:
    files: dict[str, bytes] = {}

    def __init__(self, path: str) -> None:
        self.path = path

    def open(self, *_: object, **__: object) -> BytesIO:
        return BytesIO(self.files[self.path])


def _network_files(resolv_conf: bytes = b"nameserver 127.0.0.53\n") -> dict[str, bytes]:
    return {
        "/proc/net/route": (
            b"Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
            b"eth0 00000000 0100000A 0003 0 0 100 00000000\n"
        ),
        "/proc/net/ipv6_route": (
            b"00000000000000000000000000000000 00 "
            b"00000000000000000000000000000000 00 "
            b"00000000000000000000000000000000 00000064 00000000 00000000 00000001 eth0\n"
        ),
        "/etc/resolv.conf": resolv_conf,
    }


def _patch_network_host(monkeypatch, resolv_conf: bytes = b"nameserver 127.0.0.53\n") -> None:
    monkeypatch.setattr(network_module.sys, "platform", "linux")
    FakeLinuxPath.files = _network_files(resolv_conf)
    monkeypatch.setattr(network_module, "Path", FakeLinuxPath)
    monkeypatch.setattr(
        network_module.psutil,
        "net_if_stats",
        lambda: {"eth0": SimpleNamespace(isup=True)},
    )
    monkeypatch.setattr(network_module.psutil, "net_if_addrs", lambda: {"eth0": []})


def test_default_route_requires_up_flag_and_ignores_malformed_rows(monkeypatch) -> None:
    monkeypatch.setattr(network_module.sys, "platform", "linux")
    FakeLinuxPath.files = {
        "/proc/net/route": (
            b"Iface Destination Gateway Flags\n"
            b"eth0 00000000 0100000A 0000\n"
            b"eth0 00000000 0100000A 0201\n"
            b"eth0 00000000 0100000A nope\n"
        )
    }
    monkeypatch.setattr(network_module, "Path", FakeLinuxPath)
    assert network_module._has_default_route() is False

    FakeLinuxPath.files["/proc/net/route"] += b"eth0 00000000 0100000A 0001\n"
    assert network_module._has_default_route() is True


def test_route_and_resolver_permission_errors_are_inconclusive(monkeypatch) -> None:
    monkeypatch.setattr(network_module.sys, "platform", "linux")

    class DeniedPath:
        def __init__(self, _: str) -> None:
            pass

        def open(self, *_: object, **__: object):
            raise PermissionError("private path")

    monkeypatch.setattr(network_module, "Path", DeniedPath)
    monkeypatch.setattr(
        network_module.psutil,
        "net_if_stats",
        lambda: {"eth0": SimpleNamespace(isup=True)},
    )
    monkeypatch.setattr(network_module.psutil, "net_if_addrs", lambda: {"eth0": []})

    assert network_module._has_default_route() is None
    assert network_module._has_ipv6_default_route() is None
    check = network_module.collect_network()[0]
    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["resolver_readable"] is False
    assert "private path" not in (check.note or "")

    monkeypatch.setattr(
        network_module.psutil,
        "net_if_stats",
        lambda: (_ for _ in ()).throw(psutil.AccessDenied(pid=1)),
    )
    unavailable_interfaces = network_module.collect_network()[0]
    assert unavailable_interfaces.status == CheckStatus.UNKNOWN
    assert unavailable_interfaces.metrics["interface_count"] == 0


def test_successful_explicit_network_probes_and_listener_inventory(monkeypatch) -> None:
    _patch_network_host(monkeypatch)
    monkeypatch.setattr(
        network_module.psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [
                SimpleNamespace(family=network_module.socket.AF_INET, address="192.0.2.10"),
                SimpleNamespace(family=network_module.socket.AF_INET6, address="2001:db8::10%eth0"),
                SimpleNamespace(family=17, address="link-layer"),
            ]
        },
    )
    monkeypatch.setattr(network_module.socket, "getaddrinfo", lambda *_args, **_kwargs: [1, 2])

    class ConnectedSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: ConnectedSocket(),
    )
    check = network_module.collect_network(
        resolve="node.example",
        connect=("node.example", 443),
        include_addresses=True,
    )[0]
    assert check.status == CheckStatus.PASS
    assert check.metrics["dns_test_succeeded"] is True
    assert check.metrics["dns_answer_count"] == 2
    assert check.metrics["tcp_test_succeeded"] is True
    assert check.metrics["address_0"] == "eth0 IPv4 192.0.2.10"
    assert check.metrics["address_1"] == "eth0 IPv6 2001:db8::10"

    monkeypatch.setattr(
        network_module.psutil,
        "net_connections",
        lambda **_: [
            SimpleNamespace(
                status=psutil.CONN_LISTEN,
                laddr=SimpleNamespace(port=8080),
            ),
            SimpleNamespace(
                status="ESTABLISHED",
                laddr=SimpleNamespace(port=8080),
            ),
        ],
    )
    listeners = network_module.collect_listeners({8080})
    assert listeners.status == CheckStatus.PASS
    assert listeners.metrics["port_8080_listeners"] == 1


def test_listener_ports_are_validated_before_socket_inspection() -> None:
    import pytest

    for ports in ({0}, {65536}, {True}):
        with pytest.raises(ValueError, match="integers"):
            network_module.collect_listeners(ports)


def test_ipv6_default_route_requires_up_flag_and_ignores_reject_routes(monkeypatch) -> None:
    monkeypatch.setattr(network_module.sys, "platform", "linux")
    route = "0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32 + " 00000064 00000000 00000000 "
    FakeLinuxPath.files = {
        "/proc/net/ipv6_route": (
            (route + "00000000 eth0\n").encode()
            + (route + "00000201 eth0\n").encode()
            + (route + "notflags eth0\n").encode()
        )
    }
    monkeypatch.setattr(network_module, "Path", FakeLinuxPath)
    assert network_module._has_ipv6_default_route() is False

    FakeLinuxPath.files["/proc/net/ipv6_route"] += (route + "00000001 eth0\n").encode()
    assert network_module._has_ipv6_default_route() is True


def test_ipv6_only_default_route_is_not_reported_missing(monkeypatch) -> None:
    _patch_network_host(monkeypatch)
    FakeLinuxPath.files["/proc/net/route"] = b"Iface Destination Gateway Flags\n"
    check = network_module.collect_network()[0]
    assert check.metrics["default_route_present"] is False
    assert check.metrics["ipv6_default_route_present"] is True
    assert check.status == CheckStatus.PASS
    assert not any(item.finding_id == "NET-001" for item in analyze([check]))


def test_malformed_resolver_entries_are_not_counted(monkeypatch) -> None:
    _patch_network_host(
        monkeypatch,
        b"# no resolver\nnameserver not-an-ip\nnameserver\tgarbage # ignored\n",
    )
    check = network_module.collect_network()[0]
    assert check.metrics["resolver_readable"] is True
    assert check.metrics["resolver_nameserver_count"] == 0
    assert check.status == CheckStatus.WARNING
    assert analyze([check])[0].finding_id == "NET-002"


def test_explicit_dns_failure_is_reported_without_exporting_hostname(monkeypatch) -> None:
    _patch_network_host(monkeypatch)

    def fail_lookup(*_: object, **__: object) -> None:
        raise OSError("resolver detail containing private.example")

    monkeypatch.setattr(network_module.socket, "getaddrinfo", fail_lookup)
    check = network_module.collect_network(resolve="private.example")[0]
    assert check.metrics["dns_test_requested"] is True
    assert check.metrics["dns_test_succeeded"] is False
    report = build_report([check])
    assert [finding.finding_id for finding in report.findings] == ["NET-003"]
    assert "private.example" not in report.json_document()


def test_dns_timeout_is_inconclusive_not_a_resolution_failure(monkeypatch) -> None:
    _patch_network_host(monkeypatch)

    class StuckThread:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def start(self) -> None:
            pass

        def join(self, timeout: float | None = None) -> None:
            assert timeout == 3.0

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(network_module, "Thread", StuckThread)
    check = network_module.collect_network(resolve="slow.example")[0]
    assert check.metrics["dns_test_succeeded"] is None
    assert check.metrics["dns_test_timed_out"] is True
    report = build_report([check])
    assert [finding.finding_id for finding in report.findings] == ["NET-005"]


def test_explicit_tcp_failure_is_distinct_from_timeout(monkeypatch) -> None:
    _patch_network_host(monkeypatch)

    def refused(*_: object, **__: object) -> None:
        raise ConnectionRefusedError("private destination detail")

    monkeypatch.setattr(network_module.socket, "create_connection", refused)
    check = network_module.collect_network(connect=("service.example", 443))[0]
    assert check.metrics["tcp_test_succeeded"] is False
    assert check.metrics["tcp_test_timed_out"] is False
    assert [finding.finding_id for finding in analyze([check])] == ["NET-004"]


def test_tcp_probe_has_a_wall_clock_timeout(monkeypatch) -> None:
    _patch_network_host(monkeypatch)

    class StuckThread:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def start(self) -> None:
            pass

        def join(self, timeout: float | None = None) -> None:
            assert timeout == 2.0

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(network_module, "Thread", StuckThread)
    check = network_module.collect_network(connect=("slow.example", 443))[0]
    assert check.metrics["tcp_test_succeeded"] is None
    assert check.metrics["tcp_test_timed_out"] is True
    assert [finding.finding_id for finding in analyze([check])] == ["NET-006"]


def test_reserved_filesystem_blocks_count_toward_user_pressure(monkeypatch) -> None:
    monkeypatch.setattr(storage_module.sys, "platform", "linux")
    monkeypatch.setattr(
        storage_module.psutil,
        "disk_usage",
        lambda _: SimpleNamespace(used=8 * 1024**3, total=10 * 1024**3, percent=80.0),
    )
    stats = SimpleNamespace(
        f_blocks=1000,
        f_bfree=200,
        f_bavail=100,
        f_frsize=1024**2,
        f_bsize=1024**2,
        f_files=1000,
        f_ffree=100,
        f_favail=50,
        f_flag=1,
    )
    monkeypatch.setattr(storage_module.os, "statvfs", lambda _: stats, raising=False)
    monkeypatch.setattr(
        storage_module.psutil,
        "disk_partitions",
        lambda **_: (_ for _ in ()).throw(psutil.AccessDenied(pid=1)),
    )

    check = storage_module.collect_storage()[0]
    assert check.status == CheckStatus.PASS
    assert check.metrics["usage_percent"] == 88.9
    assert check.metrics["inode_usage_percent"] == 94.7
    assert check.metrics["readonly"] is True
    assert [item.finding_id for item in analyze([check])] == [
        "STOR-002",
        "STOR-003",
        "STOR-004",
    ]


def test_storage_permission_denial_preserves_known_capacity_but_marks_partial(monkeypatch) -> None:
    monkeypatch.setattr(storage_module.sys, "platform", "linux")
    monkeypatch.setattr(
        storage_module.psutil,
        "disk_usage",
        lambda _: SimpleNamespace(used=8, total=10, percent=80.0),
    )

    def denied(_: str) -> None:
        raise PermissionError("private mount path")

    monkeypatch.setattr(storage_module.os, "statvfs", denied, raising=False)
    monkeypatch.setattr(storage_module.psutil, "disk_partitions", lambda **_: [])
    check = storage_module.collect_storage()[0]
    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["used_gb"] is not None
    assert check.metrics["usage_percent"] is None
    assert "private mount path" not in (check.note or "")


def test_malformed_or_out_of_range_psi_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(system_module.sys, "platform", "linux")

    class FakePressurePath:
        content = b""

        def __init__(self, _: str) -> None:
            pass

        def open(self, *_: object, **__: object) -> BytesIO:
            return BytesIO(self.content)

    monkeypatch.setattr(system_module, "Path", FakePressurePath)
    for value in ("nan", "inf", "-1", "101", "bad"):
        FakePressurePath.content = f"some avg10={value} avg60=0.0 avg300=0.0 total=1\n".encode()
        assert system_module._pressure_avg10("memory") is None


def test_security_aggregate_is_partial_when_firewall_cannot_be_read(monkeypatch) -> None:
    monkeypatch.setattr(
        security_module,
        "_ssh_indicators",
        lambda *_: (True, False, True, True, True),
    )

    class MissingFirewall:
        def firewall_status(self):
            return CommandResult(available=False)

    check = security_module.collect_security(runner=MissingFirewall())[0]
    assert check.metrics["ssh_password_login_disabled"] is False
    assert check.metrics["firewall_state"] == "unavailable"
    assert check.status == CheckStatus.UNKNOWN


def test_ssh_permission_metadata_and_successful_apt_simulation_are_reported(monkeypatch) -> None:
    class ConfigPath:
        def __init__(self, path: str) -> None:
            self.path = path

        def is_file(self) -> bool:
            return self.path == "/etc/ssh/sshd_config"

        def stat(self):
            return SimpleNamespace(st_mode=0o100600)

    monkeypatch.setattr(security_module, "Path", ConfigPath)

    class CompleteSecurityRunner:
        def effective_ssh_config(self, context=None):
            return CommandResult(
                available=True,
                returncode=0,
                stdout=(
                    "permitrootlogin without-password\n"
                    "passwordauthentication no\n"
                    "pubkeyauthentication yes\n"
                ),
            )

        def firewall_status(self):
            return CommandResult(available=True, returncode=0, stdout="Status: inactive\n")

        def simulate_package_upgrades(self):
            return CommandResult(
                available=True,
                returncode=0,
                stdout="Inst nginx [1] (2 Debian:stable)\nInst openssl [3] (4 Debian:stable)\n",
            )

    check = security_module.collect_security(
        runner=CompleteSecurityRunner(), include_update_simulation=True
    )[0]
    assert check.status == CheckStatus.PASS
    assert check.metrics["ssh_config_permissions_safe"] is True
    assert check.metrics["ssh_root_login_restricted"] is True
    assert check.metrics["ssh_password_login_disabled"] is True
    assert check.metrics["ssh_public_key_authentication_enabled"] is True
    assert check.metrics["firewall_state"] == "inactive"
    assert check.metrics["package_upgrade_count"] == 2


def test_known_ssh_permission_finding_is_preserved_when_other_security_checks_are_unavailable(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        security_module,
        "_ssh_indicators",
        lambda *_: (None, None, None, False, False),
    )

    class MissingFirewall:
        def firewall_status(self):
            return CommandResult(available=False)

    check = security_module.collect_security(runner=MissingFirewall())[0]
    assert check.status == CheckStatus.UNKNOWN
    assert [item.finding_id for item in analyze([check])] == ["SEC-003"]


def test_failed_ufw_command_cannot_be_parsed_as_a_known_state(monkeypatch) -> None:
    monkeypatch.setattr(
        security_module,
        "_ssh_indicators",
        lambda *_: (None, None, None, None, False),
    )

    class FailedUfw:
        def firewall_status(self):
            return CommandResult(available=True, returncode=1, stdout="Status: active\n")

    check = security_module.collect_security(runner=FailedUfw())[0]
    assert check.metrics["firewall_state"] == "unknown"
    assert check.status == CheckStatus.UNKNOWN


def test_requested_apt_simulation_failure_does_not_look_complete(monkeypatch) -> None:
    monkeypatch.setattr(
        security_module,
        "_ssh_indicators",
        lambda *_: (None, None, None, None, False),
    )

    class MissingAptSimulation:
        def firewall_status(self):
            return CommandResult(available=True, returncode=0, stdout="Status: active\n")

        def simulate_package_upgrades(self):
            return CommandResult(available=False)

    check = security_module.collect_security(
        runner=MissingAptSimulation(), include_update_simulation=True
    )[0]
    assert check.metrics["firewall_state"] == "active"
    assert check.metrics["package_upgrade_count"] is None
    assert check.status == CheckStatus.UNKNOWN
    assert "without package-manager locking" in (check.note or "")


def test_ssh_indicators_use_effective_output_and_optional_match_context() -> None:
    context = ("alice", "client.example", "192.0.2.10", "192.0.2.20", 22)

    class EffectiveSshRunner:
        seen_context = None

        def effective_ssh_config(self, supplied_context):
            self.seen_context = supplied_context
            return CommandResult(
                available=True,
                returncode=0,
                stdout=(
                    "permitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\n"
                ),
            )

    runner = EffectiveSshRunner()
    values = security_module._ssh_indicators(runner, context)
    assert values[:3] == (True, True, True)
    assert values[4] is True
    assert runner.seen_context == context


def test_unavailable_effective_sshd_output_returns_unknown_indicators() -> None:
    class MissingSshd:
        def effective_ssh_config(self, supplied_context):
            return CommandResult(available=False)

    values = security_module._ssh_indicators(MissingSshd())
    assert values[:3] == (None, None, None)
    assert values[4] is False


def test_known_firewall_does_not_make_unknown_ssh_look_complete(monkeypatch) -> None:
    monkeypatch.setattr(
        security_module,
        "_ssh_indicators",
        lambda *_: (None, None, None, None, False),
    )

    class ActiveFirewall:
        def firewall_status(self):
            return CommandResult(available=True, returncode=0, stdout="Status: active\n")

    check = security_module.collect_security(runner=ActiveFirewall())[0]
    assert check.metrics["firewall_state"] == "active"
    assert check.status == CheckStatus.UNKNOWN


def test_non_linux_network_and_web_checks_skip_without_socket_probes(monkeypatch) -> None:
    monkeypatch.setattr(network_module.sys, "platform", "win32")
    monkeypatch.setattr(
        network_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected DNS lookup")),
    )
    network = network_module.collect_network(resolve="example.org")[0]
    listeners = network_module.collect_listeners()
    web = web_module.collect_web(required_port=3000)[0]
    assert network.status == listeners.status == web.status == CheckStatus.SKIPPED
    assert network.metrics["dns_test_succeeded"] is None
    assert web.metrics["port_3000_listeners"] is None


def test_web_check_keeps_successful_loopback_evidence_when_listener_inventory_is_denied(
    monkeypatch,
) -> None:
    monkeypatch.setattr(web_module.sys, "platform", "linux")
    monkeypatch.setattr(web_module, "_loopback_reachable", lambda port: port == 80)
    monkeypatch.setattr(
        web_module,
        "collect_listeners",
        lambda _ports: DiagnosticCheck(
            check_id="network.listeners",
            category="network",
            status=CheckStatus.SKIPPED,
            summary="restricted",
            metrics={"port_80_listeners": None},
        ),
    )

    check = web_module.collect_web(required_port=3000)[0]

    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["http_80_reachable"] is True
    assert "listener inventory was unavailable" in (check.note or "")

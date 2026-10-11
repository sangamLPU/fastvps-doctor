from __future__ import annotations

from fastvps_doctor.checks import services as services_module
from fastvps_doctor.checks.services import collect_services
from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.reports import build_report, render_markdown
from fastvps_doctor.runner import CommandResult


def _unit(load: str, active: str = "inactive", *, unit_id: str = "") -> CommandResult:
    return CommandResult(
        available=True,
        returncode=0,
        stdout=(
            f"Id={unit_id}\nLoadState={load}\nActiveState={active}\n"
            "SubState=running\nUnitFileState=enabled\nResult=success\nNRestarts=0\n"
        ),
    )


class FixtureRunner:
    def __init__(self, results: dict[str, CommandResult]) -> None:
        self.results = results
        self.queried: list[str] = []
        self.validator_calls = 0

    def systemd_unit_show(self, unit: str) -> CommandResult:
        self.queried.append(unit)
        return self.results.get(unit, _unit("not-found"))

    def recent_service_logs(self, unit: str) -> CommandResult:
        return CommandResult(
            available=True,
            returncode=0,
            stdout="error: connection failed\nfatal: token=very-private\n",
        )

    def validate_nginx(self) -> CommandResult:
        self.validator_calls += 1
        return CommandResult(available=True, returncode=0)

    def validate_apache(self, executable: str) -> CommandResult:
        self.validator_calls += 1
        return CommandResult(available=True, returncode=0)

    def validate_ssh(self) -> CommandResult:
        self.validator_calls += 1
        return CommandResult(available=True, returncode=0)


def test_failed_service_logs_are_summarized_without_exporting_contents(monkeypatch) -> None:
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda name: "/usr/sbin/nginx" if name == "nginx" else None,
    )
    runner = FixtureRunner({"nginx.service": _unit("loaded", "failed", unit_id="nginx.service")})
    check = collect_services(runner=runner)[0]
    assert check.status == CheckStatus.WARNING
    assert check.metrics["nginx_state"] == "failed"
    assert check.metrics["nginx_recent_error_count"] == 2
    markdown = render_markdown(build_report([check]))
    assert "service-log lines matched error indicators" in markdown
    assert "very-private" not in markdown
    assert "connection failed" not in markdown


def test_service_detection_distinguishes_unit_states_and_binary_only(monkeypatch) -> None:
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda name: "/usr/sbin/apache2ctl" if name == "apache2ctl" else None,
    )
    runner = FixtureRunner(
        {
            "nginx.service": _unit("loaded", "active", unit_id="nginx.service"),
            "apache2.service": _unit("not-found"),
            "httpd.service": _unit("not-found"),
            "ssh.service": _unit("masked", "inactive", unit_id="ssh.service"),
        }
    )
    check = collect_services(runner=runner)[0]
    assert check.metrics["nginx_state"] == "active"
    assert check.metrics["apache_state"] == "unit_not_found"
    assert check.metrics["apache_installed"] is True
    assert check.metrics["ssh_state"] == "masked"
    assert check.metrics["docker_state"] == "not_installed"
    assert check.status == CheckStatus.UNKNOWN


def test_systemd_unavailable_is_unknown_not_no_services(monkeypatch) -> None:
    monkeypatch.setattr(services_module, "find_executable", lambda _: None)
    runner = FixtureRunner(
        {
            unit: CommandResult(available=False)
            for units, _executables in services_module.SERVICE_DEFINITIONS.values()
            for unit in units
        }
    )
    check = collect_services(runner=runner)[0]
    assert check.status == CheckStatus.UNKNOWN


def test_permission_denied_systemctl_result_is_reported_as_restricted(monkeypatch) -> None:
    from fastvps_doctor.checks.services import _unit_state

    denied = CommandResult(available=True, returncode=126, error="permission_denied")
    state, properties = _unit_state(denied)
    assert state == "permission_restricted"
    assert properties == {}

    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda name: "/usr/sbin/nginx" if name == "nginx" else None,
    )
    check = collect_services(runner=FixtureRunner({"nginx.service": denied}))[0]
    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["nginx_state"] == "permission_restricted"


def test_missing_systemd_units_and_executables_are_skipped(monkeypatch) -> None:
    monkeypatch.setattr(services_module, "find_executable", lambda _: None)
    check = collect_services(runner=FixtureRunner({}))[0]
    assert check.status == CheckStatus.SKIPPED
    assert check.metrics["nginx_state"] == "not_installed"


def test_aliases_do_not_double_count_systemd_units(monkeypatch) -> None:
    monkeypatch.setattr(services_module, "find_executable", lambda _: None)
    shared = _unit("loaded", "active", unit_id="mariadb.service")
    check = collect_services(
        runner=FixtureRunner({"mysql.service": shared, "mariadb.service": shared})
    )[0]
    assert check.metrics["mysql_state"] == "alias"
    assert check.metrics["mariadb_state"] == "active"
    assert check.metrics["unit_count"] == 1


def test_custom_unit_is_validated_and_failed_state_generates_finding(monkeypatch) -> None:
    monkeypatch.setattr(services_module, "find_executable", lambda _: None)
    runner = FixtureRunner(
        {"worker@1.service": _unit("loaded", "failed", unit_id="worker@1.service")}
    )
    check = collect_services(runner=runner, custom_units=["worker@1"])[0]
    report = build_report([check])
    assert check.metrics["custom_unit_0_state"] == "failed"
    assert any(item.finding_id == "SVC-CUST-001" for item in report.findings)
    try:
        collect_services(runner=runner, custom_units=["--help;id"])
    except ValueError:
        pass
    else:
        raise AssertionError("Unsafe unit selection was accepted.")


def test_config_validators_are_opt_in(monkeypatch) -> None:
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda name: "/usr/sbin/nginx" if name == "nginx" else None,
    )
    runner = FixtureRunner({"nginx.service": _unit("loaded", "active", unit_id="nginx.service")})
    collect_services(runner=runner)
    assert runner.validator_calls == 0
    collect_services(runner=runner, validate_config=True)
    assert runner.validator_calls == 1


def test_opt_in_validators_cover_nginx_apache_and_ssh(monkeypatch) -> None:
    executables = {"nginx", "apache2ctl", "sshd"}
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda name: f"/usr/sbin/{name}" if name in executables else None,
    )
    runner = FixtureRunner(
        {
            "nginx.service": _unit("loaded", "active", unit_id="nginx.service"),
            "apache2.service": _unit("loaded", "active", unit_id="apache2.service"),
            "ssh.service": _unit("loaded", "active", unit_id="ssh.service"),
        }
    )

    check = collect_services(runner=runner, validate_config=True)[0]

    assert runner.validator_calls == 3
    assert check.metrics["nginx_config_validation"] == "passed"
    assert check.metrics["apache_config_validation"] == "passed"
    assert check.metrics["ssh_config_validation"] == "passed"


def test_failed_opt_in_validator_is_conservative_and_custom_unit_limit_is_enforced(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda name: "/usr/sbin/nginx" if name == "nginx" else None,
    )

    class FailedValidator(FixtureRunner):
        def validate_nginx(self) -> CommandResult:
            return CommandResult(available=True, returncode=1, stdout="private config path")

    runner = FailedValidator({"nginx.service": _unit("loaded", "active", unit_id="nginx.service")})
    check = collect_services(runner=runner, validate_config=True)[0]
    assert check.metrics["nginx_config_validation"] == "failed_or_inconclusive"
    assert check.status == CheckStatus.WARNING
    assert "private config path" not in str(check.metrics)
    try:
        collect_services(runner=runner, custom_units=["a", "b", "c", "d", "e", "f"])
    except ValueError as error:
        assert "five" in str(error)
    else:
        raise AssertionError("More than five custom units were accepted.")


def test_custom_service_metric_is_exported_only_when_selected() -> None:
    selected = DiagnosticCheck(
        check_id="services.common",
        category="services",
        status=CheckStatus.WARNING,
        summary="selected custom unit",
        metrics={
            "custom_unit_count": 1,
            "custom_unit_0_name": "customer-private-worker.service",
            "custom_unit_0_state": "failed",
            "custom_unit_0_unit_found": True,
        },
    )
    document = build_report([selected]).json_document()
    assert "custom_unit_0_state" in document
    assert "customer-private-worker" not in document


def test_custom_service_name_redaction_does_not_label_it_as_a_hostname() -> None:
    selected = DiagnosticCheck(
        check_id="services.common",
        category="services",
        status=CheckStatus.PASS,
        summary="selected custom unit",
        metrics={
            "custom_unit_count": 1,
            "custom_unit_0_name": "systemd-journald.service",
            "custom_unit_0_state": "active",
            "custom_unit_0_unit_found": True,
        },
    )

    document = build_report([selected]).json_document()

    assert '"custom_unit_0_name": "[REDACTED SERVICE]"' in document
    assert "systemd-journald.service" not in document
    assert "[HOSTNAME]" not in document

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
import typer
from typer.testing import CliRunner

import fastvps_doctor.cli as cli_module
import fastvps_doctor.troubleshoot as troubleshoot_module
from fastvps_doctor.cli import app
from fastvps_doctor.models import (
    CheckStatus,
    DiagnosticCheck,
    IncidentAnalysis,
    IncidentEvent,
    IncidentEventType,
    TroubleshootScenario,
)
from fastvps_doctor.privacy import sanitize_checks
from fastvps_doctor.runner import CommandResult
from fastvps_doctor.troubleshoot import (
    build_troubleshoot_report,
    collect_common_web_services,
    collect_loopback_http_head,
    collect_selected_service,
    discover_relevant_services,
    render_troubleshoot_markdown,
)


class PropertyRunner:
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        self.units: list[str] = []

    def systemd_unit_show(self, unit: str) -> CommandResult:
        self.units.append(unit)
        return self.result


def _check(check_id: str, metrics: dict[str, object] | None = None) -> DiagnosticCheck:
    return DiagnosticCheck(
        check_id=check_id,
        category=check_id.split(".", maxsplit=1)[0],
        status=CheckStatus.PASS,
        summary=f"{check_id} fixture",
        metrics=metrics or {},  # type: ignore[arg-type]
    )


def _fake_incident(service: str = "nginx") -> IncidentAnalysis:
    at = datetime.now(UTC) - timedelta(minutes=2)
    return IncidentAnalysis(
        service=service,
        window_seconds=7200,
        complete=True,
        events=[
            IncidentEvent(
                timestamp_utc=at,
                classification=IncidentEventType.SERVICE_FAILURE,
                component=service,
                evidence_summary="The service manager recorded a failed start or process exit.",
            )
        ],
    )


def test_selected_service_queries_only_one_unit_and_captures_allowlisted_properties() -> None:
    runner = PropertyRunner(
        CommandResult(
            available=True,
            returncode=0,
            stdout=(
                "Id=worker@green.service\nLoadState=loaded\nActiveState=failed\n"
                "SubState=failed\nResult=exit-code\nNRestarts=4\n"
                "ExecMainCode=1\nExecMainStatus=9\nPrivateThing=secret-value\n"
            ),
        )
    )

    check = collect_selected_service("worker@green", runner)  # type: ignore[arg-type]

    assert runner.units == ["worker@green.service"]
    assert check.status == CheckStatus.WARNING
    assert check.metrics["service_state"] == "failed"
    assert check.metrics["service_restart_count"] == 4
    assert check.metrics["service_result"] == "exit-code"
    assert check.metrics["service_exec_main_status"] == 9
    assert "worker@green" not in check.model_dump_json()
    assert "secret-value" not in check.model_dump_json()


def test_blank_service_choice_goes_to_unknown_without_repeating_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    monkeypatch.setattr(
        cli_module.typer,
        "prompt",
        lambda label, **_kwargs: prompts.append(label) or "",
    )

    assert cli_module._prompt_unit() is None
    assert prompts == ["Enter 1, 2 or 3"]


def test_unknown_service_option_continues_without_a_fabricated_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    monkeypatch.setattr(cli_module.typer, "prompt", lambda *_args, **_kwargs: "3")

    assert cli_module._prompt_unit() is None


def test_detected_service_selection_excludes_unrelated_running_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "discover_relevant_services",
        lambda _scenario: ([("nginx", "nginx.service", "inactive")], True),
    )
    answers = iter(["1", "1"])
    monkeypatch.setattr(cli_module.typer, "prompt", lambda *_args, **_kwargs: next(answers))

    assert cli_module._prompt_unit() == "nginx.service"


def test_no_relevant_units_offers_unknown_without_suggesting_other_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output: list[str] = []
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    monkeypatch.setattr(cli_module.typer, "echo", output.append)
    monkeypatch.setattr(cli_module.typer, "prompt", lambda *_args, **_kwargs: "1")

    assert cli_module._prompt_unit() is None
    assert any("No relevant application service unit" in line for line in output)
    assert not any("ssh" in line.lower() or "docker" in line.lower() for line in output)


def test_unavailable_systemd_is_described_as_incomplete_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output: list[str] = []
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], False))
    monkeypatch.setattr(cli_module.typer, "echo", output.append)
    monkeypatch.setattr(cli_module.typer, "prompt", lambda *_args, **_kwargs: "3")

    assert cli_module._prompt_unit() is None
    assert any("unavailable or incomplete" in line for line in output)


def test_manual_service_name_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    answers = iter(["2", "myapp.service"])
    monkeypatch.setattr(cli_module.typer, "prompt", lambda *_args, **_kwargs: next(answers))

    assert cli_module._prompt_unit() == "myapp.service"


@pytest.mark.parametrize("choice", ["../ssh", "-x", "bad name", "service;id"])
def test_manual_service_name_rejects_invalid_identifier(
    monkeypatch: pytest.MonkeyPatch, choice: str
) -> None:
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    answers = iter(["2", choice])
    monkeypatch.setattr(cli_module.typer, "prompt", lambda *_args, **_kwargs: next(answers))

    with pytest.raises(typer.BadParameter, match="valid systemd unit"):
        cli_module._prompt_unit()


def test_blank_manual_service_name_means_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    answers = iter(["2", ""])
    monkeypatch.setattr(cli_module.typer, "prompt", lambda *_args, **_kwargs: next(answers))

    assert cli_module._prompt_unit() is None


@pytest.mark.parametrize("exception", [KeyboardInterrupt, EOFError])
def test_service_prompt_cancellation_is_graceful(
    monkeypatch: pytest.MonkeyPatch, exception: type[BaseException]
) -> None:
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))

    def cancel(*_args, **_kwargs) -> str:
        raise exception

    monkeypatch.setattr(cli_module.typer, "prompt", cancel)
    with pytest.raises(typer.Abort):
        cli_module._prompt_unit()


def test_common_web_service_inventory_distinguishes_absence_from_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")
    monkeypatch.setattr(troubleshoot_module, "find_executable", lambda _name: None)

    class UnitRunner:
        def __init__(self, result: CommandResult) -> None:
            self.result = result

        def systemd_unit_show(self, _unit: str) -> CommandResult:
            return self.result

    absent = collect_common_web_services(
        UnitRunner(CommandResult(available=True, returncode=0, stdout="LoadState=not-found\n"))  # type: ignore[arg-type]
    )
    assert absent.status == CheckStatus.PASS
    assert absent.metrics["nginx_installed"] is False
    assert absent.metrics["apache2_installed"] is False

    unavailable = collect_common_web_services(
        UnitRunner(CommandResult(available=False))  # type: ignore[arg-type]
    )
    assert unavailable.status == CheckStatus.UNKNOWN
    assert unavailable.metrics["nginx_installed"] is None
    assert unavailable.metrics["nginx_state"] == "unavailable"


def test_relevant_service_discovery_handles_absence_unavailability_and_known_units(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")
    monkeypatch.setattr(troubleshoot_module, "find_executable", lambda _name: False)
    absent = CommandResult(available=True, returncode=0, stdout="LoadState=not-found\n")

    class UnitRunner:
        def __init__(self, results: dict[str, CommandResult]) -> None:
            self.results = results
            self.calls: list[str] = []

        def systemd_unit_show(self, unit: str) -> CommandResult:
            self.calls.append(unit)
            return self.results.get(unit, absent)

    empty_runner = UnitRunner({})
    candidates, complete = discover_relevant_services(
        TroubleshootScenario.WEBSITE_UNAVAILABLE,
        empty_runner,  # type: ignore[arg-type]
    )
    assert candidates == []
    assert complete is True
    assert not any("ssh" in unit or "docker" in unit for unit in empty_runner.calls)

    unavailable_runner = UnitRunner({"nginx.service": CommandResult(available=False)})
    candidates, complete = discover_relevant_services(
        TroubleshootScenario.WEBSITE_UNAVAILABLE,
        unavailable_runner,  # type: ignore[arg-type]
    )
    assert candidates == []
    assert complete is False
    assert unavailable_runner.calls == ["nginx.service"]

    active_runner = UnitRunner(
        {
            "nginx.service": CommandResult(
                available=True,
                returncode=0,
                stdout="LoadState=loaded\nActiveState=active\n",
            )
        }
    )
    candidates, complete = discover_relevant_services(
        TroubleshootScenario.WEBSITE_UNAVAILABLE,
        active_runner,  # type: ignore[arg-type]
    )
    assert candidates == [("nginx", "nginx.service", "active")]
    assert complete is True


def test_web_service_inventory_report_does_not_export_raw_unit_output(monkeypatch) -> None:
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")
    monkeypatch.setattr(troubleshoot_module, "find_executable", lambda _name: False)

    class PrivateRunner:
        def systemd_unit_show(self, _unit: str) -> CommandResult:
            return CommandResult(
                available=True,
                returncode=0,
                stdout="LoadState=loaded\nActiveState=active\nCustom=secret.example.com\n",
            )

    check = collect_common_web_services(PrivateRunner())  # type: ignore[arg-type]
    clean = sanitize_checks([check])[0]
    serialized = clean.model_dump_json()
    assert "secret.example.com" not in serialized
    assert "Custom" not in serialized
    assert clean.metrics["nginx_state"] == "active"


def test_unknown_website_generated_reports_keep_web_inventory_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")
    monkeypatch.setattr(troubleshoot_module, "find_executable", lambda _name: False)

    class PrivateRunner:
        def systemd_unit_show(self, _unit: str) -> CommandResult:
            return CommandResult(
                available=True,
                returncode=0,
                stdout=(
                    "LoadState=not-found\nHost=private-vps.example.test\nPassword=hidden-value\n"
                ),
            )

    monkeypatch.setattr(
        troubleshoot_module,
        "collect_common_web_services",
        lambda: collect_common_web_services(PrivateRunner()),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(troubleshoot_module, "collect_storage", lambda: [_check("storage.root")])
    monkeypatch.setattr(troubleshoot_module, "collect_system", lambda: [_check("system.resources")])
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_listeners",
        lambda _ports: _check(
            "network.listeners", {"port_80_listeners": 0, "port_443_listeners": 0}
        ),
    )

    report = build_troubleshoot_report(TroubleshootScenario.WEBSITE_UNAVAILABLE)
    json_report = report.json_document()
    markdown_report = render_troubleshoot_markdown(report)

    for private_value in ("private-vps.example.test", "hidden-value", "Password"):
        assert private_value not in json_report
        assert private_value not in markdown_report
    assert "nginx_state" in json_report
    assert "No common Nginx or Apache" in markdown_report


def test_unknown_web_service_inventory_stays_unknown_in_report(monkeypatch) -> None:
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")
    monkeypatch.setattr(troubleshoot_module, "find_executable", lambda _name: False)

    class UnavailableRunner:
        def systemd_unit_show(self, _unit: str) -> CommandResult:
            return CommandResult(available=False)

    monkeypatch.setattr(
        troubleshoot_module,
        "collect_common_web_services",
        lambda: collect_common_web_services(UnavailableRunner()),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(troubleshoot_module, "collect_storage", lambda: [_check("storage.root")])
    monkeypatch.setattr(troubleshoot_module, "collect_system", lambda: [_check("system.resources")])
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_listeners",
        lambda _ports: _check(
            "network.listeners", {"port_80_listeners": None, "port_443_listeners": None}
        ),
    )

    report = build_troubleshoot_report(TroubleshootScenario.WEBSITE_UNAVAILABLE)
    web_check = next(item for item in report.checks if item.check_id == "troubleshoot.web_services")

    assert web_check.status == CheckStatus.UNKNOWN
    assert web_check.metrics["nginx_installed"] is None
    assert any(item.certainty.value == "insufficient" for item in report.conclusions)
    assert not any("No common Nginx or Apache" in item.statement for item in report.conclusions)


@pytest.mark.parametrize(
    ("result", "expected_state", "expected_status"),
    [
        (CommandResult(available=False), "unavailable", CheckStatus.UNKNOWN),
        (
            CommandResult(available=True, error="permission_denied"),
            "permission_restricted",
            CheckStatus.UNKNOWN,
        ),
        (
            CommandResult(available=True, timed_out=True),
            "timeout",
            CheckStatus.UNKNOWN,
        ),
        (
            CommandResult(available=True, returncode=0, stdout="LoadState=not-found\n"),
            "unit_not_found",
            CheckStatus.WARNING,
        ),
    ],
)
def test_selected_service_reports_missing_permissions_and_timeouts(
    result, expected_state, expected_status
) -> None:
    check = collect_selected_service("worker", PropertyRunner(result))  # type: ignore[arg-type]
    assert check.metrics["service_state"] == expected_state
    assert check.status == expected_status


def test_website_scenario_runs_only_relevant_collectors(monkeypatch) -> None:
    calls: list[str] = []
    selected = _check(
        "troubleshoot.service",
        {"service_state": "active", "service_unit_found": True, "service_restart_count": 0},
    )
    root = _check(
        "storage.root", {"usage_percent": 42.0, "inode_usage_percent": 31.0, "readonly": False}
    )
    mounts = _check("storage.mounts", {"mount_count": 0, "inspected_mount_count": 0})
    resources = _check("system.resources", {"memory_percent": 42.0, "cpu_sample_percent": 5.0})
    listener = _check("network.listeners", {"port_8080_listeners": 0})
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_selected_service",
        lambda unit: calls.append(f"service:{unit}") or selected,
    )
    monkeypatch.setattr(
        troubleshoot_module, "collect_storage", lambda: calls.append("storage") or [root, mounts]
    )
    monkeypatch.setattr(
        troubleshoot_module, "collect_system", lambda: calls.append("system") or [resources]
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_listeners",
        lambda ports: calls.append(f"listeners:{sorted(ports)}") or listener,
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "analyze_incident",
        lambda unit, since: calls.append(f"journal:{unit}:{since}") or _fake_incident(unit),
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_loopback_http_head",
        lambda port: calls.append(f"http:{port}") or _check("troubleshoot.http"),
    )

    report = build_troubleshoot_report(
        TroubleshootScenario.WEBSITE_UNAVAILABLE,
        service="nginx",
        port=8080,
        probe_http=True,
    )

    assert calls == [
        "service:nginx",
        "storage",
        "system",
        "listeners:[8080]",
        "http:8080",
        "journal:nginx:2h",
    ]
    assert {check.check_id for check in report.checks} == {
        "troubleshoot.service",
        "storage.root",
        "storage.mounts",
        "system.resources",
        "network.listeners",
        "troubleshoot.http",
    }
    assert report.scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
    assert any("no listener on port 8080" in item.statement for item in report.conclusions)


def test_loopback_probe_uses_head_and_never_reads_response_body(monkeypatch) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")

    class Response:
        status = 503

        def close(self) -> None:
            calls.append(("response.close",))

        def read(self, *_args, **_kwargs):  # pragma: no cover - must never be called
            raise AssertionError("response body must not be read")

    class Connection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            calls.append(("connect", host, port, timeout))

        def request(self, method: str, target: str, headers: dict[str, str]) -> None:
            calls.append(("request", method, target, headers))

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            calls.append(("connection.close",))

    monkeypatch.setattr(troubleshoot_module.http.client, "HTTPConnection", Connection)
    check = collect_loopback_http_head(9000)

    assert check.metrics["http_probe_state"] == "response_5xx"
    assert check.metrics["http_status_code"] == 503
    assert calls[0][:3] == ("connect", "127.0.0.1", 9000)
    assert calls[1][1:3] == ("HEAD", "/")


def test_informational_http_response_does_not_count_as_a_successful_probe(monkeypatch) -> None:
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")

    class Response:
        status = 101

        def close(self) -> None:
            pass

    class Connection:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def request(self, *_args, **_kwargs) -> None:
            pass

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            pass

    monkeypatch.setattr(troubleshoot_module.http.client, "HTTPConnection", Connection)
    check = collect_loopback_http_head(8080)

    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["http_probe_state"] == "response_1xx"
    assert check.metrics["http_status_code"] == 101
    assert sanitize_checks([check])[0].metrics["http_probe_state"] == "response_1xx"


def test_loopback_probe_timeout_is_unknown_and_safe(monkeypatch) -> None:
    monkeypatch.setattr(troubleshoot_module.sys, "platform", "linux")

    class Connection:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def request(self, *_args, **_kwargs) -> None:
            raise TimeoutError("synthetic private host data")

        def close(self) -> None:
            pass

    monkeypatch.setattr(troubleshoot_module.http.client, "HTTPConnection", Connection)
    check = collect_loopback_http_head(8080)
    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["http_probe_state"] == "timeout"
    assert "synthetic private host data" not in check.model_dump_json()


def test_report_redacts_custom_unit_and_sensitive_free_text(monkeypatch) -> None:
    custom = _check(
        "troubleshoot.service",
        {
            "service_unit_found": True,
            "service_state": "failed",
            "service_restart_count": 3,
            "service_result": "token=do-not-export",
        },
    )
    root = _check("storage.root", {"usage_percent": 99.0, "readonly": False})
    mounts = _check("storage.mounts", {"mount_count": 0})
    resources = _check("system.resources", {"memory_percent": 80.0})
    listeners = _check("network.listeners", {"port_8080_listeners": 0})
    monkeypatch.setattr(troubleshoot_module, "collect_selected_service", lambda _unit: custom)
    monkeypatch.setattr(troubleshoot_module, "collect_storage", lambda: [root, mounts])
    monkeypatch.setattr(troubleshoot_module, "collect_system", lambda: [resources])
    monkeypatch.setattr(troubleshoot_module, "collect_listeners", lambda _ports: listeners)
    monkeypatch.setattr(
        troubleshoot_module, "analyze_incident", lambda unit, _since: _fake_incident(unit)
    )
    monkeypatch.setattr(
        troubleshoot_module, "collect_loopback_http_head", lambda _port: _check("troubleshoot.http")
    )

    report = build_troubleshoot_report(
        TroubleshootScenario.WEBSITE_UNAVAILABLE,
        service="customer-private-api",
        port=8080,
        probe_http=True,
        description=(
            "token=sample-secret host=prod.example.test user=account-hammer-937 "
            "10.20.30.40 /srv/customer/data api_key=private-key-value "
            "[private link](https://leak.example.test/path)"
        ),
        ticket_reference="FV-1042",
        profile="fastvps",
    )
    document = report.json_document()
    markdown = render_troubleshoot_markdown(report)

    for private_value in (
        "customer-private-api",
        "sample-secret",
        "prod.example.test",
        "account-hammer-937",
        "10.20.30.40",
        "/srv/customer/data",
        "private-key-value",
        "do-not-export",
    ):
        assert private_value not in document
        assert private_value not in markdown
    assert report.service_label == "[REDACTED SERVICE]"
    assert report.ticket_reference == "FV-1042"
    assert "Review and redact this report" in markdown
    assert r"\[private link\]\(" in markdown
    assert r"\[private link\](https://" not in markdown


def test_noninteractive_command_requires_scenario_and_accepts_explicit_choice(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_is_interactive", lambda: False)
    result = CliRunner().invoke(app, ["troubleshoot"])
    assert result.exit_code != 0
    plain_output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.output)
    assert "--scenario is required" in plain_output

    observed: dict[str, object] = {}

    def build(scenario, **kwargs):
        observed["scenario"] = scenario
        observed.update(kwargs)
        return build_troubleshoot_report(
            TroubleshootScenario.STORAGE,
            description="sanitized mock output",
        )

    monkeypatch.setattr(cli_module, "build_troubleshoot_report", build)
    result = CliRunner().invoke(
        app,
        ["troubleshoot", "--scenario", "storage", "--description", "disk issue"],
    )
    assert result.exit_code == 0, result.output
    assert observed["scenario"] == TroubleshootScenario.STORAGE
    assert "Scenario: storage" in result.output


def test_noninteractive_output_file_is_versioned_and_never_overwritten(
    monkeypatch, tmp_path
) -> None:
    from examples.troubleshoot_demos import build_fixture_report

    report = build_fixture_report(TroubleshootScenario.STORAGE)
    monkeypatch.setattr(cli_module, "build_troubleshoot_report", lambda *_args, **_kwargs: report)
    destination = tmp_path / "scenario-report.json"
    args = [
        "troubleshoot",
        "--scenario",
        "storage",
        "--profile",
        "fastvps",
        "--format",
        "json",
        "--output",
        str(destination),
    ]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0, first.output
    saved = destination.read_text(encoding="utf-8")
    parsed = type(report).model_validate_json(saved)
    assert parsed.schema_version == "1.0"
    assert parsed.version == "0.3.0"

    second = CliRunner().invoke(app, args)
    assert second.exit_code != 0
    assert "already exists" in second.output
    assert destination.read_text(encoding="utf-8") == saved


def test_interactive_scenario_picker_and_cancel_do_not_write_report(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_is_interactive", lambda: True)
    completed = CliRunner().invoke(app, ["troubleshoot"], input="3\nn\n\nn\n")
    assert completed.exit_code == 0, completed.output
    assert "Choose the problem" in completed.output
    assert "Scenario: storage" in completed.output
    assert "Created local report" not in completed.output

    cancelled = CliRunner().invoke(app, ["troubleshoot"], input="")
    assert cancelled.exit_code != 0
    assert "Aborted" in cancelled.output
    assert "Created local report" not in cancelled.output


def test_interactive_unknown_service_continues_without_reprompting(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_is_interactive", lambda: True)
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], False))
    monkeypatch.setattr(
        cli_module,
        "build_troubleshoot_report",
        lambda scenario, **kwargs: captured.update(scenario=scenario, **kwargs) or object(),
    )
    monkeypatch.setattr(cli_module, "_emit_troubleshoot_report", lambda *_args: None)

    result = CliRunner().invoke(app, ["troubleshoot"], input="2\n\n\nn\n")

    assert result.exit_code == 0, result.output
    assert result.output.count("Which application or background service is having trouble?") == 1
    assert captured["scenario"] == TroubleshootScenario.SERVICE_CRASH
    assert captured["service"] is None
    assert "cannot assess the affected application's service state" in result.output


def test_interactive_unknown_website_needs_no_port_or_external_probe(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_is_interactive", lambda: True)
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    monkeypatch.setattr(
        cli_module,
        "build_troubleshoot_report",
        lambda scenario, **kwargs: captured.update(scenario=scenario, **kwargs) or object(),
    )
    monkeypatch.setattr(cli_module, "_emit_troubleshoot_report", lambda *_args: None)

    result = CliRunner().invoke(app, ["troubleshoot"], input="1\n3\n\nn\n")

    assert result.exit_code == 0, result.output
    assert "local application port" not in result.output
    assert "HEAD request" not in result.output
    assert captured["scenario"] == TroubleshootScenario.WEBSITE_UNAVAILABLE
    assert captured["service"] is None
    assert captured["port"] is None
    assert captured["probe_http"] is False


def test_ctrl_c_at_service_prompt_aborts_without_traceback(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli_module, "_is_interactive", lambda: True)
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], False))
    prompt_count = 0

    def cancel_on_unit_prompt(*_args, **_kwargs) -> str:
        nonlocal prompt_count
        prompt_count += 1
        if prompt_count == 1:
            return "2"
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module.typer, "prompt", cancel_on_unit_prompt)

    destination = tmp_path / "cancelled-report.md"
    result = CliRunner().invoke(app, ["troubleshoot", "--output", str(destination)])

    assert result.exit_code != 0
    assert "Aborted" in result.output
    assert "Traceback" not in result.output
    assert "Created local report" not in result.output
    assert not destination.exists()


def test_eof_at_service_prompt_aborts_without_report_or_traceback(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli_module, "_is_interactive", lambda: True)
    monkeypatch.setattr(cli_module, "discover_relevant_services", lambda _scenario: ([], True))
    monkeypatch.setattr(
        cli_module,
        "build_troubleshoot_report",
        lambda *_args, **_kwargs: pytest.fail("report must not be built after EOF"),
    )
    destination = tmp_path / "eof-report.md"

    result = CliRunner().invoke(
        app,
        ["troubleshoot", "--output", str(destination)],
        input="1\n",
    )

    assert result.exit_code != 0
    assert "Aborted" in result.output
    assert "Traceback" not in result.output
    assert "Created local report" not in result.output
    assert not destination.exists()


def test_noninteractive_service_specific_scenario_still_requires_service(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_is_interactive", lambda: False)

    result = CliRunner().invoke(
        app, ["troubleshoot", "--scenario", "service-crash", "--format", "json"]
    )

    assert result.exit_code != 0
    plain_output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.output)
    assert "--service is required for this scenario." in plain_output


def test_noninteractive_website_accepts_explicit_service_and_port(monkeypatch) -> None:
    from examples.troubleshoot_demos import build_fixture_report

    monkeypatch.setattr(cli_module, "_is_interactive", lambda: False)
    captured: dict[str, object] = {}

    def build(scenario, **kwargs):
        captured["scenario"] = scenario
        captured.update(kwargs)
        return build_fixture_report(TroubleshootScenario.WEBSITE_UNAVAILABLE)

    monkeypatch.setattr(cli_module, "build_troubleshoot_report", build)
    result = CliRunner().invoke(
        app,
        [
            "troubleshoot",
            "--scenario",
            "website-unavailable",
            "--service",
            "myapp.service",
            "--port",
            "8080",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["scenario"] == TroubleshootScenario.WEBSITE_UNAVAILABLE
    assert captured["service"] == "myapp.service"
    assert captured["port"] == 8080


def test_website_unknown_service_collects_only_general_read_only_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = _check("storage.root", {"usage_percent": 70.0})
    resources = _check("system.resources", {"memory_percent": 20.0})
    web_services = _check(
        "troubleshoot.web_services",
        {
            "nginx_installed": False,
            "nginx_unit_found": False,
            "nginx_state": "not_installed",
            "apache2_installed": False,
            "apache2_unit_found": False,
            "apache2_state": "not_installed",
        },
    )
    listeners = _check("network.listeners", {"port_80_listeners": 0, "port_443_listeners": 0})
    calls: list[str] = []
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_common_web_services",
        lambda: calls.append("web_services") or web_services,
    )
    monkeypatch.setattr(
        troubleshoot_module, "collect_storage", lambda: calls.append("storage") or [storage]
    )
    monkeypatch.setattr(
        troubleshoot_module, "collect_system", lambda: calls.append("system") or [resources]
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_listeners",
        lambda ports: calls.append(f"listeners:{sorted(ports)}") or listeners,
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_selected_service",
        lambda _unit: pytest.fail("unknown service must not be queried"),
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "analyze_incident",
        lambda *_args: pytest.fail("unknown service must not trigger service journals"),
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_selected_config_validation",
        lambda _unit: pytest.fail("unknown service must not trigger config validation"),
    )

    report = build_troubleshoot_report(TroubleshootScenario.WEBSITE_UNAVAILABLE, service=None)

    assert calls == ["web_services", "storage", "system", "listeners:[80, 443]"]
    assert {check.check_id for check in report.checks} == {
        "troubleshoot.web_services",
        "storage.root",
        "system.resources",
        "network.listeners",
    }
    assert report.service_label is None
    assert report.timeline == []
    assert any("does not confirm a website outage" in item.statement for item in report.conclusions)
    assert any("No common Nginx or Apache" in item.statement for item in report.conclusions)
    assert all(item.certainty.value != "plausible" for item in report.conclusions)
    assert any("No systemd unit was selected" in gap for gap in report.evidence_gaps)


def test_service_crash_unknown_service_collects_general_evidence_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = _check("storage.root", {"usage_percent": 65.0})
    resources = _check("system.resources", {"memory_percent": 30.0})
    calls: list[str] = []
    monkeypatch.setattr(
        troubleshoot_module, "collect_storage", lambda: calls.append("storage") or [storage]
    )
    monkeypatch.setattr(
        troubleshoot_module, "collect_system", lambda: calls.append("system") or [resources]
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_selected_service",
        lambda _unit: pytest.fail("unknown service must not be queried"),
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "analyze_incident",
        lambda *_args: pytest.fail("unknown service must not trigger service journals"),
    )

    report = build_troubleshoot_report(TroubleshootScenario.SERVICE_CRASH)

    assert calls == ["system", "storage"]
    assert {check.check_id for check in report.checks} == {"system.resources", "storage.root"}
    assert report.timeline == []
    assert any(
        "cannot confirm whether a particular service" in item.statement
        for item in report.conclusions
    )
    assert any("No systemd unit was selected" in gap for gap in report.evidence_gaps)


def test_json_and_markdown_reports_are_built_from_same_sanitized_scenario_model(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_storage",
        lambda: [
            _check(
                "storage.root",
                {"usage_percent": 98.1, "inode_usage_percent": 97.0, "readonly": False},
            ),
            _check("storage.mounts", {"mount_count": 0}),
        ],
    )
    report = build_troubleshoot_report(TroubleshootScenario.STORAGE)
    from_json = type(report).model_validate_json(report.json_document())
    markdown = render_troubleshoot_markdown(from_json)
    assert from_json.scenario == TroubleshootScenario.STORAGE
    assert "98.1%" in markdown
    assert "do not prove the cause" in markdown


def test_service_crash_repeated_events_and_nearby_oom_are_cautious(monkeypatch) -> None:
    at = datetime.now(UTC) - timedelta(minutes=4)
    events = [
        IncidentEvent(
            timestamp_utc=at + timedelta(seconds=index * 30),
            classification=IncidentEventType.SERVICE_RESTART_SCHEDULED,
            component="api-worker",
            evidence_summary="The service manager scheduled an automatic restart.",
        )
        for index in range(2)
    ]
    events += [
        IncidentEvent(
            timestamp_utc=at + timedelta(seconds=45),
            classification=IncidentEventType.SERVICE_FAILURE,
            component="api-worker",
            evidence_summary="The service manager recorded a failed start or process exit.",
        ),
        IncidentEvent(
            timestamp_utc=at + timedelta(seconds=50),
            classification=IncidentEventType.OOM_KILL,
            component="kernel",
            evidence_summary="A kernel journal record matched an out-of-memory termination indicator.",
        ),
    ]
    service = _check(
        "troubleshoot.service",
        {
            "service_unit_found": True,
            "service_state": "failed",
            "service_restart_count": 5,
            "service_result": "exit-code",
            "service_exec_main_status": 137,
        },
    )
    resources = _check("system.resources", {"memory_percent": 25.0, "cpu_sample_percent": 5.0})
    calls: list[str] = []
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_selected_service",
        lambda unit: calls.append(f"service:{unit}") or service,
    )
    monkeypatch.setattr(
        troubleshoot_module, "collect_system", lambda: calls.append("system") or [resources]
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "analyze_incident",
        lambda unit, _since: (
            calls.append(f"journal:{unit}")
            or IncidentAnalysis(service=unit, window_seconds=7200, complete=True, events=events)
        ),
    )

    report = build_troubleshoot_report(
        TroubleshootScenario.SERVICE_CRASH, service="api-worker", since="2h"
    )
    report_json = report.json_document()

    assert calls == ["service:api-worker", "system", "journal:api-worker"]
    assert {check.check_id for check in report.checks} == {
        "troubleshoot.service",
        "system.resources",
    }
    assert any(
        item.certainty.value == "plausible"
        and "consistent with repeated restarts" in item.statement
        for item in report.conclusions
    )
    oom = next(item for item in report.conclusions if "out-of-memory" in item.statement)
    assert oom.certainty.value == "plausible"
    assert len(oom.evidence_ids) == 2
    assert "does not prove causation" in oom.statement
    assert "api-worker" not in report_json
    assert "memory 25.0%" in report.observations[1].summary


def test_single_restart_event_is_not_described_as_a_restart_loop(monkeypatch) -> None:
    service = _check(
        "troubleshoot.service",
        {"service_unit_found": True, "service_state": "failed", "service_restart_count": 1},
    )
    resources = _check("system.resources", {"memory_percent": 99.0})
    monkeypatch.setattr(troubleshoot_module, "collect_selected_service", lambda _unit: service)
    monkeypatch.setattr(troubleshoot_module, "collect_system", lambda: [resources])
    monkeypatch.setattr(
        troubleshoot_module,
        "analyze_incident",
        lambda unit, _since: IncidentAnalysis(
            service=unit,
            window_seconds=7200,
            complete=True,
            events=[
                IncidentEvent(
                    timestamp_utc=datetime.now(UTC) - timedelta(minutes=1),
                    classification=IncidentEventType.SERVICE_RESTART_SCHEDULED,
                    component=unit,
                    evidence_summary="The service manager scheduled an automatic restart.",
                )
            ],
        ),
    )

    report = build_troubleshoot_report(TroubleshootScenario.SERVICE_CRASH, service="worker")

    assert not any(
        "consistent with repeated restarts" in item.statement for item in report.conclusions
    )
    assert any("restart counter of 1" in item.statement for item in report.conclusions)
    assert all("historical" not in item.summary.lower() for item in report.observations)


def test_storage_scenario_keeps_capacity_inode_and_service_errors_separate(monkeypatch) -> None:
    root = _check(
        "storage.root",
        {"usage_percent": 99.5, "inode_usage_percent": 100.0, "readonly": True},
    )
    mounts = _check("storage.mounts", {"mount_count": 1, "inspected_mount_count": 1})
    service = _check(
        "troubleshoot.service", {"service_state": "active", "service_unit_found": True}
    )
    event = IncidentEvent(
        timestamp_utc=datetime.now(UTC) - timedelta(minutes=1),
        classification=IncidentEventType.SERVICE_ERROR,
        component="postgresql",
        evidence_summary="A journal record for the selected service had error-level priority.",
    )
    calls: list[str] = []
    monkeypatch.setattr(troubleshoot_module, "collect_storage", lambda: [root, mounts])
    monkeypatch.setattr(
        troubleshoot_module,
        "collect_selected_service",
        lambda unit: calls.append(f"service:{unit}") or service,
    )
    monkeypatch.setattr(
        troubleshoot_module,
        "analyze_incident",
        lambda unit, _since: (
            calls.append(f"journal:{unit}")
            or IncidentAnalysis(service=unit, window_seconds=7200, complete=True, events=[event])
        ),
    )

    report = build_troubleshoot_report(TroubleshootScenario.STORAGE, service="postgresql")

    assert calls == ["service:postgresql", "journal:postgresql"]
    assert {check.check_id for check in report.checks} == {
        "storage.root",
        "storage.mounts",
        "troubleshoot.service",
    }
    assert any("read-only state was true" in item.statement for item in report.conclusions)
    assert any(
        "does not establish a connection to storage" in item.statement
        for item in report.conclusions
    )


@pytest.mark.integration
@pytest.mark.skipif(
    not troubleshoot_module.sys.platform.startswith("linux"),
    reason="Requires Linux loopback networking.",
)
def test_loopback_http_probe_uses_a_disposable_real_local_server() -> None:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self) -> None:
            self.send_response(503)
            self.end_headers()

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        check = collect_loopback_http_head(server.server_port, timeout=0.5)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=1)

    assert check.metrics["http_probe_state"] == "response_5xx"
    assert check.metrics["http_status_code"] == 503

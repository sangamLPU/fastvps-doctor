from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

import fastvps_doctor.cli as cli_module
from fastvps_doctor.cli import app
from fastvps_doctor.models import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticReport,
    IncidentAnalysis,
)

runner = CliRunner()


def test_help_exposes_only_working_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "diagnose" in result.stdout
    assert "security" in result.stdout
    assert "report" in result.stdout
    assert "backup" not in result.stdout


def test_version_command_is_independent() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "FastVPS Doctor 0.2.0" in result.stdout
    assert "unofficial" in result.stdout


def test_diagnose_json_emits_sanitized_report(monkeypatch) -> None:
    monkeypatch.setattr(
        cli_module,
        "_all_checks",
        lambda **_: [
            DiagnosticCheck(
                check_id="storage.root",
                category="storage",
                status=CheckStatus.PASS,
                summary="capacity",
                metrics={"usage_percent": 96, "private_path": "/srv/user/data"},
            )
        ],
    )
    result = runner.invoke(app, ["diagnose", "--json", "--profile", "fastvps"])
    assert result.exit_code == 0
    assert "STOR-001" in result.stdout
    assert "/srv/user/data" not in result.stdout
    assert '"profile": "fastvps"' in result.stdout


def test_invalid_report_format_is_rejected(monkeypatch) -> None:
    result = runner.invoke(app, ["report", "--format", "xml"])
    assert result.exit_code != 0


def _patch_network_results(monkeypatch) -> None:
    monkeypatch.setattr(
        cli_module,
        "collect_network",
        lambda **_: [
            DiagnosticCheck(
                check_id="network.local",
                category="network",
                status=CheckStatus.PASS,
                summary="network fixture",
                metrics={
                    "interface_count": 1,
                    "address_0": "eth0 IPv4 192.0.2.25",
                },
            )
        ],
    )
    monkeypatch.setattr(
        cli_module,
        "collect_listeners",
        lambda ports=None: DiagnosticCheck(
            check_id="network.listeners",
            category="network",
            status=CheckStatus.PASS,
            summary="listener fixture",
            metrics={f"port_{port}_listeners": 1 for port in (ports or {80})},
        ),
    )


def test_opt_in_network_addresses_are_human_only_and_not_exported(monkeypatch) -> None:
    _patch_network_results(monkeypatch)
    human = runner.invoke(app, ["network", "--show-addresses"])
    assert human.exit_code == 0
    assert "192.0.2.25" in human.stdout

    result = runner.invoke(app, ["network", "--show-addresses", "--json"])
    assert result.exit_code == 0
    assert "192.0.2.25" not in result.stdout
    assert '"port_80_listeners": 1' in result.stdout


def test_network_supports_repeated_custom_listener_ports(monkeypatch) -> None:
    _patch_network_results(monkeypatch)
    result = runner.invoke(
        app, ["network", "--listen-port", "3000", "--listen-port", "8443", "--json"]
    )
    assert result.exit_code == 0
    assert '"port_3000_listeners": 1' in result.stdout
    assert '"port_8443_listeners": 1' in result.stdout
    assert "port_80_listeners" not in result.stdout


def test_strict_exit_codes_distinguish_findings_and_incomplete_checks(monkeypatch) -> None:
    finding = DiagnosticCheck(
        check_id="storage.root",
        category="storage",
        status=CheckStatus.PASS,
        summary="high use",
        metrics={"usage_percent": 95},
    )
    monkeypatch.setattr(cli_module, "_all_checks", lambda **_: [finding])
    assert runner.invoke(app, ["diagnose", "--json", "--strict-exit-codes"]).exit_code == 1

    incomplete = finding.model_copy(update={"metrics": {"usage_percent": None}})
    monkeypatch.setattr(cli_module, "_all_checks", lambda **_: [incomplete])
    assert runner.invoke(app, ["diagnose", "--json", "--strict-exit-codes"]).exit_code == 0

    incomplete = incomplete.model_copy(update={"status": CheckStatus.UNKNOWN})
    monkeypatch.setattr(cli_module, "_all_checks", lambda **_: [incomplete])
    assert runner.invoke(app, ["diagnose", "--json", "--strict-exit-codes"]).exit_code == 3


def _check(check_id: str, category: str) -> DiagnosticCheck:
    return DiagnosticCheck(
        check_id=check_id,
        category=category,
        status=CheckStatus.PASS,
        summary="CLI routing fixture",
        metrics={},
    )


def test_all_area_commands_route_options_and_emit_valid_report_json(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(cli_module, "collect_system", lambda: [_check("system.identity", "system")])
    monkeypatch.setattr(cli_module, "collect_storage", lambda: [_check("storage.root", "storage")])

    def collect_network(**kwargs):
        calls["network"] = kwargs
        return [_check("network.local", "network")]

    def collect_listeners(ports=None):
        calls["ports"] = ports
        return _check("network.listeners", "network")

    def collect_services(**kwargs):
        calls["services"] = kwargs
        return [_check("services.common", "services")]

    def collect_security(**kwargs):
        calls["security"] = kwargs
        return [_check("security.local", "security")]

    def collect_web(**kwargs):
        calls["web"] = kwargs
        return [_check("web.local", "web")]

    monkeypatch.setattr(cli_module, "collect_network", collect_network)
    monkeypatch.setattr(cli_module, "collect_listeners", collect_listeners)
    monkeypatch.setattr(cli_module, "collect_services", collect_services)
    monkeypatch.setattr(cli_module, "collect_security", collect_security)
    monkeypatch.setattr(cli_module, "collect_web", collect_web)

    invocations = [
        ["system", "--json"],
        ["storage", "--json"],
        [
            "network",
            "--resolve",
            "dns.example",
            "--connect-host",
            "api.example",
            "--connect-port",
            "443",
            "--show-addresses",
            "--listen-port",
            "3000",
            "--json",
        ],
        ["services", "--unit", "worker@1.service", "--validate-config", "--json"],
        [
            "security",
            "--full",
            "--ssh-user",
            "deploy",
            "--ssh-host",
            "host.example",
            "--ssh-address",
            "192.0.2.10",
            "--local-address",
            "192.0.2.20",
            "--local-port",
            "22",
            "--json",
        ],
        ["web", "--port", "3000", "--json"],
    ]
    expected_ids = [
        "system.identity",
        "storage.root",
        "network.local",
        "services.common",
        "security.local",
        "web.local",
    ]

    for invocation, check_id in zip(invocations, expected_ids, strict=True):
        result = runner.invoke(app, invocation)
        assert result.exit_code == 0, result.output
        report = DiagnosticReport.model_validate_json(result.stdout)
        assert check_id in {check.check_id for check in report.checks}

    assert calls["network"]["resolve"] == "dns.example"
    assert calls["network"]["connect"] == ("api.example", 443)
    assert calls["network"]["include_addresses"] is True
    assert calls["ports"] == {3000}
    assert calls["services"] == {
        "custom_units": ["worker@1.service"],
        "validate_config": True,
    }
    assert calls["security"]["include_update_simulation"] is True
    assert calls["security"]["ssh_context"] == (
        "deploy",
        "host.example",
        "192.0.2.10",
        "192.0.2.20",
        22,
    )
    assert calls["web"] == {"required_port": 3000}


def test_diagnose_routes_full_profile_ticket_json_and_strict_options(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(cli_module, "_all_checks", lambda **kwargs: calls.update(kwargs) or [])
    result = runner.invoke(
        app,
        [
            "diagnose",
            "--full",
            "--profile",
            "fastvps",
            "--ticket-reference",
            "FV-1234",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert calls["full"] is True
    report = DiagnosticReport.model_validate_json(result.stdout)
    assert report.profile == "fastvps"
    assert report.ticket_reference == "FV-1234"


def test_incident_command_routes_real_syntax_and_validates_report_schema(monkeypatch) -> None:
    calls = {}
    analysis_time = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)

    def analyze(service, since):
        calls["analysis"] = (service, since)
        return IncidentAnalysis(
            service="nginx.service",
            window_seconds=1800,
            generated_at_utc=analysis_time,
            complete=False,
            unavailable_sources=["service_journal"],
        )

    def all_checks(**kwargs):
        calls["checks"] = kwargs
        return []

    monkeypatch.setattr(cli_module, "analyze_incident", analyze)
    monkeypatch.setattr(cli_module, "_all_checks", all_checks)
    result = runner.invoke(
        app,
        [
            "incident",
            "--service",
            "nginx",
            "--since",
            "30m",
            "--format",
            "json",
            "--profile",
            "fastvps",
            "--ticket-reference",
            "FV-1234",
            "--incident-start",
            "2026-10-11T11:30:00Z",
            "--problem-category",
            "website",
            "--description",
            "Homepage unavailable",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls["analysis"] == ("nginx", "30m")
    assert calls["checks"]["custom_units"] == ()
    report = DiagnosticReport.model_validate_json(result.stdout)
    assert report.profile == "fastvps"
    assert report.ticket_reference == "FV-1234"
    assert report.incident_information is not None
    assert report.incident_information.problem_category.value == "website"
    assert report.incident_analysis is not None
    assert report.incident_analysis.window_seconds == 1800


def test_report_command_routes_incident_metadata_and_writes_exclusively(
    monkeypatch, tmp_path
) -> None:
    calls = {}
    generated = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(
        cli_module,
        "analyze_incident",
        lambda service, since: (
            calls.update(analysis=(service, since))
            or IncidentAnalysis(
                service="worker@1.service",
                window_seconds=7200,
                generated_at_utc=generated,
                complete=True,
            )
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "_all_checks",
        lambda **kwargs: calls.update(checks=kwargs) or [],
    )
    output = tmp_path / "support.json"
    result = runner.invoke(
        app,
        [
            "report",
            "--format",
            "json",
            "--output",
            str(output),
            "--profile",
            "fastvps",
            "--ticket-reference",
            "FV-1234",
            "--full",
            "--incident-service",
            "worker@1.service",
            "--since",
            "2h",
            "--incident-start",
            "2026-10-11T10:00:00+00:00",
            "--affected-service",
            "worker@1.service",
            "--problem-category",
            "application",
            "--problem-description",
            "Worker stopped responding",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls["analysis"] == ("worker@1.service", "2h")
    assert calls["checks"] == {"full": True, "custom_units": ("worker@1.service",)}
    report = DiagnosticReport.model_validate_json(output.read_text(encoding="utf-8"))
    assert report.ticket_reference == "FV-1234"
    assert report.incident_information is not None
    assert report.incident_information.affected_service == "[REDACTED SERVICE]"
    assert report.incident_analysis is not None
    assert report.incident_analysis.service == "[REDACTED SERVICE]"
    assert "worker@1.service" not in output.read_text(encoding="utf-8")

    overwrite = runner.invoke(app, ["report", "--format", "markdown", "--output", str(output)])
    assert overwrite.exit_code != 0
    assert "never overwritten" not in overwrite.output
    assert "already exists" in overwrite.output


def test_report_supports_markdown_and_hides_output_os_errors(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli_module, "_all_checks", lambda **_: [])
    markdown = runner.invoke(app, ["report", "--format", "markdown"])
    assert markdown.exit_code == 0
    assert markdown.stdout.startswith("# FastVPS Doctor support report")
    assert "## Support handoff" in markdown.stdout

    monkeypatch.setattr(
        cli_module,
        "write_exclusive",
        lambda *_: (_ for _ in ()).throw(PermissionError("private path detail")),
    )
    failed_write = runner.invoke(
        app, ["report", "--format", "markdown", "--output", str(tmp_path / "denied.md")]
    )
    assert failed_write.exit_code != 0
    assert "Could not create report (PermissionError)" in failed_write.output
    assert "private path detail" not in failed_write.output


@pytest.mark.parametrize(
    "start",
    ["not-a-timestamp", "2026-10-11T12:00:00"],
)
def test_incident_rejects_invalid_or_timezone_free_start_before_collection(
    monkeypatch, start
) -> None:
    monkeypatch.setattr(
        cli_module,
        "analyze_incident",
        lambda *_: (_ for _ in ()).throw(AssertionError("analysis must not run")),
    )
    result = runner.invoke(app, ["incident", "--service", "nginx", "--incident-start", start])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_invalid_profile_is_rejected_before_diagnostic_collection(monkeypatch) -> None:
    monkeypatch.setattr(
        cli_module,
        "_all_checks",
        lambda **_: (_ for _ in ()).throw(AssertionError("diagnostics must not run")),
    )
    result = runner.invoke(app, ["report", "--profile", "other-provider"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_explain_and_root_output_options() -> None:
    result = runner.invoke(app, ["--no-color", "--ascii", "explain"])
    assert result.exit_code == 0
    assert "Troubleshooting rules" in result.stdout
    assert "Storage capacity" in result.stdout
    assert "\x1b[" not in result.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ["network", "--connect-port", "443"],
        ["network", "--connect-host", "api.example"],
        ["network", "--connect-host", "bad;id", "--connect-port", "443"],
        ["security", "--ssh-user", "deploy"],
        ["security", "--local-port", "70000"],
        ["incident", "--service", "nginx", "--since", "25h"],
        ["incident", "--service", "nginx;id"],
        ["report", "--since", "30m"],
        ["report", "--problem-category", "unknown"],
    ],
)
def test_invalid_command_arguments_are_rejected_before_diagnostics(arguments) -> None:
    result = runner.invoke(app, arguments)
    assert result.exit_code != 0
    assert "Traceback" not in result.output

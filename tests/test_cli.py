from typer.testing import CliRunner

import fastvps_doctor.cli as cli_module
from fastvps_doctor.cli import app
from fastvps_doctor.models import CheckStatus, DiagnosticCheck

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
    assert "FastVPS Doctor 0.1.0" in result.stdout
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
        lambda: DiagnosticCheck(
            check_id="network.listeners",
            category="network",
            status=CheckStatus.PASS,
            summary="listener fixture",
            metrics={"port_80_listeners": 1},
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

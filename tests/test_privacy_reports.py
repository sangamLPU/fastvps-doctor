import json
import math
import os
import stat
from datetime import UTC
from pathlib import Path

from fastvps_doctor.models import CheckStatus, DiagnosticCheck, Finding, Severity
from fastvps_doctor.privacy import sanitize_checks, sanitize_findings, sanitize_ticket_reference
from fastvps_doctor.reports import (
    build_report,
    render_markdown,
    write_exclusive,
)


def test_allowlist_removes_identity_path_and_secrets() -> None:
    checks = [
        DiagnosticCheck(
            check_id="network.local",
            category="network",
            status=CheckStatus.PASS,
            summary="collected local evidence",
            metrics={
                "interface_count": 2,
                "hostname": "vps-customer.example",
                "public_ip": "203.0.113.5",
                "address_0": "eth0 IPv4 203.0.113.5",
                "filesystem_path": "/home/alice/app",
                "token": "dont-export",
            },
        )
    ]
    safe = sanitize_checks(checks)
    serialized = safe[0].model_dump_json()
    assert "interface_count" in serialized
    for secret in (
        "hostname",
        "203.0.113.5",
        "address_0",
        "/home/alice/app",
        "dont-export",
    ):
        assert secret not in serialized


def test_report_is_json_serializable_utc_and_excludes_unapproved_fields() -> None:
    report = build_report(
        [
            DiagnosticCheck(
                check_id="system.resources",
                category="system",
                status=CheckStatus.PASS,
                summary="collected metrics",
                metrics={"cpu_count": 4, "hostname": "private-host", "memory_percent": 42.0},
            )
        ]
    )
    payload = json.loads(report.json_document())
    assert payload["timestamp_utc"].endswith("Z")
    assert "private-host" not in report.json_document()
    assert report.timestamp_utc.tzinfo == UTC
    assert payload["support_summary"]["overview"].startswith("No major issue")


def test_markdown_contains_report_header_and_privacy_notice() -> None:
    report = build_report(
        [
            DiagnosticCheck(
                check_id="storage.root",
                category="storage",
                status=CheckStatus.PASS,
                summary="capacity",
                metrics={"usage_percent": 96.0},
            )
        ],
        profile="fastvps",
        ticket_reference="FV-42",
    )
    markdown = render_markdown(report)
    assert "Scan timestamp (UTC)" in markdown
    assert "STOR-001" in markdown
    assert "FV-42" in markdown
    assert "review this report before sharing" in markdown.lower()
    assert "https://fastvps.gr/en/faq/" in markdown


def test_partial_report_lists_only_coverage_that_was_run() -> None:
    report = build_report(
        [
            DiagnosticCheck(
                check_id="system.resources",
                category="system",
                status=CheckStatus.PASS,
                summary="resource check",
                metrics={"cpu_count": 4},
            )
        ]
    )
    assert len(report.coverage) == 1
    assert "CPU, memory" in report.coverage[0]
    assert all("filesystem" not in item.lower() for item in report.coverage)


def test_report_text_redacts_common_identity_paths_and_credentials(monkeypatch) -> None:
    import fastvps_doctor.reports as reports_module

    monkeypatch.setattr(reports_module, "linux_distribution", lambda: "vps-customer.example")
    secret_values = (
        "vps-customer.example",
        "203.0.113.25",
        "alice",
        "/home/alice/private",
        "very-secret-token",
        "sensitive@example.net",
    )
    check = DiagnosticCheck(
        check_id="system.resources",
        category="attacker-controlled-category",
        status=CheckStatus.PASS,
        summary=(
            "Hostname=vps-customer.example host=203.0.113.25 user=alice "
            "token=very-secret-token path=/home/alice/private email=sensitive@example.net"
        ),
        note="Password='hunter2' address 203.0.113.25 Authorization: Bearer opaque-bearer-token",
        metrics={"cpu_count": 4, "password": "also-secret"},
    )
    document = build_report([check]).json_document()
    for secret in secret_values + (
        "hunter2",
        "opaque-bearer-token",
        "also-secret",
        "attacker-controlled-category",
    ):
        assert secret not in document
    assert "[REDACTED]" in document
    assert "system.resources" in document


def test_finding_text_and_identifiers_are_sanitized() -> None:
    finding = Finding(
        finding_id="SECRET-HOSTNAME.EXAMPLE",
        category="/home/alice/private",
        severity=Severity.LOW,
        title="Password=hunter2 on server.example.com",
        description="Bearer abcdefghi",
        evidence=["SSH key at /home/alice/.ssh/id_rsa for user=alice"],
    )
    result = sanitize_findings([finding])[0]
    serialized = result.model_dump_json()
    for secret in (
        "SECRET-HOSTNAME",
        "alice",
        "hunter2",
        "abcdefghi",
        "server.example.com",
        "/home",
    ):
        assert secret not in serialized
    assert result.finding_id == "GEN-000"
    assert result.category == "unknown"


def test_unknown_check_types_are_not_exported() -> None:
    check = DiagnosticCheck(
        check_id="private-hostname.example",
        category="private-category",
        status=CheckStatus.PASS,
        summary="private summary",
        metrics={"cpu_count": 4},
    )
    assert sanitize_checks([check]) == []


def test_nonfinite_metrics_are_dropped_before_json_serialization() -> None:
    safe = sanitize_checks(
        [
            DiagnosticCheck(
                check_id="system.resources",
                category="system",
                status=CheckStatus.PASS,
                summary="resource summary",
                metrics={
                    "memory_psi_some_avg10": math.nan,
                    "cpu_count": 10**1000,
                },
            )
        ]
    )
    assert safe[0].metrics == {}
    assert "NaN" not in safe[0].model_dump_json()


def test_distribution_and_kernel_identifiers_do_not_publish_host_suffixes() -> None:
    report = build_report(
        [
            DiagnosticCheck(
                check_id="system.identity",
                category="system",
                status=CheckStatus.PASS,
                summary="identity",
                metrics={
                    "distribution": "debian private.example",
                    "kernel_release": "6.1-vps.private.example",
                    "python_supported": True,
                },
            )
        ]
    )
    assert "private.example" not in report.json_document()
    assert "debian" in report.json_document()


def test_ticket_reference_is_restricted_to_identifier_characters() -> None:
    assert sanitize_ticket_reference("FV-1234") == "FV-1234"
    result = sanitize_ticket_reference("FV-1234;token=secret <script>")
    assert result is not None
    assert all(char.isalnum() or char in ".-_" for char in result)
    assert "secret" not in result


def test_report_file_is_exclusive_and_private_on_posix(tmp_path: Path, monkeypatch) -> None:
    import fastvps_doctor.reports as reports_module

    destination = tmp_path / "support-report.md"
    real_open = reports_module.os.open
    requested_modes: list[int] = []

    def capture_open(path, flags, mode=0o777):
        requested_modes.append(mode)
        return real_open(path, flags, mode)

    monkeypatch.setattr(reports_module.os, "open", capture_open)
    write_exclusive(destination, "private report")
    assert requested_modes == [0o600]
    assert destination.read_text(encoding="utf-8") == "private report"
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    try:
        write_exclusive(destination, "replacement")
    except FileExistsError:
        pass
    else:
        raise AssertionError("Existing report was overwritten.")
    assert destination.read_text(encoding="utf-8") == "private report"


def test_skipped_check_does_not_create_finding_or_coverage() -> None:
    report = build_report(
        [
            DiagnosticCheck(
                check_id="storage.root",
                category="storage",
                status=CheckStatus.SKIPPED,
                summary="unavailable",
                metrics={"usage_percent": 99.0},
            )
        ]
    )
    assert report.overall_status == "partial"
    assert not report.findings
    assert not report.coverage


def test_incomplete_check_keeps_unknown_status_even_with_a_finding() -> None:
    report = build_report(
        [
            DiagnosticCheck(
                check_id="system.resources",
                category="system",
                status=CheckStatus.UNKNOWN,
                summary="partial resources",
                metrics={
                    "cpu_count": 0,
                    "memory_percent": 95.0,
                    "memory_available_mb": 100,
                    "memory_psi_some_avg10": 15.0,
                },
            )
        ]
    )
    assert report.findings[0].finding_id == "SYS-001"
    assert report.checks[0].status == CheckStatus.UNKNOWN
    assert "system.resources" in report.support_summary.unavailable_checks

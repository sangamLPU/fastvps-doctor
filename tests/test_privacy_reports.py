import json
import math
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastvps_doctor.models import (
    CheckStatus,
    DiagnosticCheck,
    Finding,
    IncidentAnalysis,
    IncidentEvent,
    IncidentEventType,
    IncidentHypothesis,
    IncidentInformation,
    ProblemCategory,
    Severity,
)
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
    assert report.distribution.startswith("debian")
    assert report.distribution != "Unsupported platform"
    assert "private.example" not in report.json_document()
    assert "debian" in report.json_document()


def test_ticket_reference_is_restricted_to_identifier_characters() -> None:
    assert sanitize_ticket_reference("FV-1234") == "FV-1234"
    assert sanitize_ticket_reference("123456789") == "123456789"
    assert sanitize_ticket_reference("FV-1234;token=secret <script>") is None


def test_ticket_reference_drops_realistic_synthetic_credentials() -> None:
    sensitive_values = (
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "github_pat_abcdefghijklmnopqrstuvwxyz0123456789",
        "xoxb-123456789012345678901234",
        "AKIA1234567890ABCDEF",
        "Authorization: Bearer abcdef0123456789",
        "Password=hunter2",
        "my-private-key",
    )
    for value in sensitive_values:
        assert sanitize_ticket_reference(value) is None


def test_report_does_not_export_credential_shaped_ticket_reference() -> None:
    report = build_report([], ticket_reference="ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert report.ticket_reference is None
    assert "ghp_" not in report.json_document()


def test_v2_report_redacts_incident_context_and_keeps_structured_timeline() -> None:
    start = datetime(2026, 10, 11, 11, 0, tzinfo=UTC)
    information = IncidentInformation(
        start_time_utc=start,
        affected_service="customer-private-api.service",
        problem_category=ProblemCategory.APPLICATION,
        description=(
            "Password=hunter2 token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 "
            "Authorization: Bearer abcdef0123456789 email=alice@example.net "
            "path=/home/alice/app host=private.customer.example IP=203.0.113.20"
        ),
    )
    analysis = IncidentAnalysis(
        service="customer-private-api",
        window_seconds=3600,
        generated_at_utc=start + timedelta(hours=1),
        complete=True,
        events=[
            IncidentEvent(
                timestamp_utc=start + timedelta(minutes=10),
                classification=IncidentEventType.SERVICE_FAILURE,
                component="private.customer.example",
                evidence_summary="Credential=private-value; service failure transition recorded.",
                correlation_explanation="token=timeline-secret",
            )
        ],
        hypotheses=[
            IncidentHypothesis(
                statement="Possible issue on private.customer.example with password=hunter2.",
                start_time_utc=start,
                end_time_utc=start + timedelta(minutes=10),
                evidence=["api key=another-secret"],
                alternatives=["user=alice at /home/alice"],
                next_steps=["Review private.customer.example locally."],
            )
        ],
        note="Raw logs were discarded.",
    )
    report = build_report(
        [],
        incident_information=information,
        incident_analysis=analysis,
    )
    document = report.json_document()
    markdown = render_markdown(report)
    for secret in (
        "hunter2",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "abcdef0123456789",
        "alice@example.net",
        "/home/alice/app",
        "private.customer.example",
        "203.0.113.20",
        "private-value",
        "timeline-secret",
        "another-secret",
    ):
        assert secret not in document
        assert secret not in markdown
    assert report.schema_version == "2.0"
    assert report.incident_information is not None
    assert report.incident_information.affected_service == "[REDACTED SERVICE]"
    assert report.incident_analysis is not None
    assert report.incident_analysis.service == "[REDACTED SERVICE]"
    assert report.incident_analysis.events[0].component == "[REDACTED SERVICE]"
    assert "customer-private-api" not in document
    assert "customer-private-api" not in markdown
    assert "incident_analysis" in document
    assert "Support handoff" in markdown
    assert "Incident timeline" in markdown


def test_report_redacts_unlabelled_tokens_and_private_key_blocks() -> None:
    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    private_key_material = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
    private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + private_key_material
        + "\n-----END OPENSSH PRIVATE KEY-----"
    )
    information = IncidentInformation(
        description=(
            f"Customer pasted {token}, a bearer JWT "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue "
            f"and this key:\n{private_key}\n"
            "DATABASE_PASSWORD=database-secret-value "
            "GITHUB_TOKEN=github-secret-value "
            "AWS_SECRET_ACCESS_KEY=aws-secret-value"
        )
    )

    report = build_report([], incident_information=information)
    document = report.json_document()
    markdown = render_markdown(report)

    for secret in (
        token,
        "eyJhbGciOiJIUzI1NiJ9",
        private_key_material,
        "database-secret-value",
        "github-secret-value",
        "aws-secret-value",
    ):
        assert secret not in document
        assert secret not in markdown
    assert "REDACTED PRIVATE KEY" in document
    assert "REDACTED TOKEN" in document


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
    assert "system.resources" in report.support_handoff.unavailable_checks
    assert "[HOSTNAME]" not in report.support_handoff.unavailable_checks


def test_handoff_keeps_known_check_ids_and_drops_untrusted_values() -> None:
    report = build_report(
        [],
        incident_analysis=IncidentAnalysis(
            service="nginx.service",
            window_seconds=3600,
            generated_at_utc=datetime.now(UTC),
            complete=False,
            unavailable_sources=["service_journal", "kernel_journal"],
        ),
    )

    assert "Incident source: service_journal" in report.support_handoff.unavailable_checks
    assert "Incident source: kernel_journal" in report.support_handoff.unavailable_checks
    assert report.incident_analysis.service == "nginx.service"
    assert "[HOSTNAME]" not in report.support_handoff.unavailable_checks

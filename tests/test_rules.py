from fastvps_doctor.config import Thresholds
from fastvps_doctor.models import CheckStatus, DiagnosticCheck, Severity
from fastvps_doctor.reports import build_report
from fastvps_doctor.rules import analyze


def check(check_id: str, metrics: dict[str, object]) -> DiagnosticCheck:
    return DiagnosticCheck(
        check_id=check_id,
        category=check_id.split(".")[0],
        status=CheckStatus.PASS,
        summary="test fixture",
        metrics=metrics,  # type: ignore[arg-type]
    )


def test_critical_disk_has_specific_finding_and_steps() -> None:
    findings = analyze([check("storage.root", {"usage_percent": 96, "inode_usage_percent": 40})])
    assert len(findings) == 1
    assert findings[0].finding_id == "STOR-001"
    assert findings[0].severity == Severity.CRITICAL
    assert "df -h" in " ".join(findings[0].next_steps)


def test_healthy_disk_does_not_create_finding() -> None:
    findings = analyze([check("storage.root", {"usage_percent": 42, "inode_usage_percent": 38})])
    assert findings == []


def test_high_cpu_sample_alone_does_not_create_incident() -> None:
    findings = analyze(
        [check("system.resources", {"cpu_sample_percent": 100, "memory_percent": 62})]
    )
    assert findings == []


def test_low_available_memory_without_psi_is_not_confirmed_pressure() -> None:
    findings = analyze(
        [
            check(
                "system.resources",
                {"memory_percent": 95, "memory_available_mb": 120, "memory_psi_some_avg10": None},
            )
        ]
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "unconfirmed" in findings[0].title
    assert findings[0].confidence == "low"


def test_memory_pressure_needs_low_memory_and_pressure_evidence() -> None:
    high_memory_only = analyze(
        [check("system.resources", {"memory_percent": 95, "memory_psi_some_avg10": 0.1})]
    )
    pressure = analyze(
        [check("system.resources", {"memory_percent": 95, "memory_psi_some_avg10": 15.0})]
    )
    assert high_memory_only[0].severity == Severity.LOW
    assert pressure[0].severity == Severity.HIGH


def test_failed_service_is_reported_but_inactive_service_is_not() -> None:
    failed = analyze([check("services.common", {"nginx_state": "failed"})])
    inactive = analyze([check("services.common", {"nginx_state": "inactive"})])
    assert len(failed) == 1 and failed[0].category == "services"
    assert inactive == []


def test_disk_thresholds_are_configurable() -> None:
    thresholds = Thresholds(disk_warning_percent=70, disk_critical_percent=85)
    findings = analyze([check("storage.root", {"usage_percent": 88})], thresholds)
    assert findings[0].severity == Severity.CRITICAL
    assert "85%" in findings[0].evidence[0]


def test_zero_memory_psi_threshold_cannot_confirm_zero_pressure() -> None:
    try:
        Thresholds(memory_psi_warning_percent=0)
    except ValueError:
        pass
    else:
        raise AssertionError("A zero PSI threshold would classify zero pressure as confirmed.")


def test_dns_rule_only_runs_after_explicit_request() -> None:
    no_request = analyze(
        [check("network.local", {"dns_test_requested": False, "dns_test_succeeded": None})]
    )
    failed_request = analyze(
        [check("network.local", {"dns_test_requested": True, "dns_test_succeeded": False})]
    )
    assert no_request == []
    assert failed_request[0].finding_id == "NET-003"
    assert "hostname is omitted" in failed_request[0].description


def test_report_summary_marks_critical_storage_as_failed() -> None:
    report = build_report(
        [
            check(
                "storage.root",
                {"usage_percent": 96, "inode_usage_percent": 30},
            )
        ]
    )
    assert report.checks[0].status == CheckStatus.FAIL
    assert report.support_summary.failed_checks == ["storage.root"]
    assert report.support_summary.passed_checks == []


def test_user_requested_port_is_preserved_for_web_rule() -> None:
    report = build_report(
        [
            check(
                "web.local",
                {
                    "required_port_supplied": True,
                    "required_port": 3000,
                    "port_3000_listeners": 0,
                },
            )
        ]
    )
    assert [finding.finding_id for finding in report.findings] == ["WEB-001"]
    assert report.checks[0].status == CheckStatus.WARNING

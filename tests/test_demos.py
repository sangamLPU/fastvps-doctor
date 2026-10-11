from examples.synthetic_demos import build_demo_report
from fastvps_doctor.models import IncidentEventType
from fastvps_doctor.reports import render_markdown


def test_website_unavailable_demo_shows_service_and_listener_evidence() -> None:
    report = build_demo_report("website-unavailable")

    assert [finding.finding_id for finding in report.findings] == [
        "SVC-NGIN-001",
        "WEB-001",
    ]
    assert "No local listener was observed on port 8080." in render_markdown(report)
    assert "/srv/" not in report.json_document()


def test_storage_pressure_demo_shows_index_without_mount_path() -> None:
    report = build_demo_report("storage-pressure")

    assert [finding.finding_id for finding in report.findings] == ["STOR-005"]
    assert "Local mount entry 1 (ext4) reports 92.0% use." in report.findings[0].evidence
    assert "/" not in report.findings[0].evidence[0]


def test_restart_loop_demo_has_real_synthetic_timestamps_and_discards_logs() -> None:
    report = build_demo_report("restart-loop")
    output = report.json_document()

    assert report.incident_analysis is not None
    assert len(report.incident_analysis.events) == 5
    assert (
        report.incident_analysis.events[0].classification
        == IncidentEventType.SERVICE_RESTART_SCHEDULED
    )
    assert any(
        "restart loop" in hypothesis.statement for hypothesis in report.incident_analysis.hypotheses
    )
    assert "Killed process 1234" not in output
    assert "timing alone does not establish causation" in output

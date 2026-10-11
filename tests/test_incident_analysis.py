from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from fastvps_doctor.incident_analysis import analyze_incident, parse_time_window
from fastvps_doctor.models import IncidentEventType
from fastvps_doctor.runner import CommandResult


def _journal_record(at: datetime, message: str, **fields: str) -> str:
    timestamp = str(int(at.timestamp() * 1_000_000))
    return json.dumps({"__REALTIME_TIMESTAMP": timestamp, "MESSAGE": message, **fields})


class JournalRunner:
    def __init__(self, service: str = "", kernel: str = "") -> None:
        self.service = CommandResult(available=True, returncode=0, stdout=service)
        self.kernel = CommandResult(available=True, returncode=0, stdout=kernel)
        self.requested_unit = ""
        self.requested_window = 0

    def recent_service_events(self, unit: str, window_seconds: int) -> CommandResult:
        self.requested_unit = unit
        self.requested_window = window_seconds
        return self.service

    def recent_kernel_events(self, window_seconds: int) -> CommandResult:
        assert window_seconds == self.requested_window
        return self.kernel


def test_parse_time_window_is_strict_and_bounded() -> None:
    assert parse_time_window("30m") == 1800
    assert parse_time_window("2h") == 7200
    assert parse_time_window("1d") == 86400
    for invalid in ("0m", "25h", "2h;id", "-2h", "5s", "1d1h"):
        with pytest.raises(ValueError):
            parse_time_window(invalid)


def test_incident_analysis_uses_only_timestamped_classified_records() -> None:
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    runner = JournalRunner(
        _journal_record(
            now - timedelta(minutes=5),
            "Main process exited, code=exited, status=1/FAILURE token=synthetic-secret",
            _PID="1",
            _COMM="systemd",
        )
    )
    analysis = analyze_incident("nginx", "2h", runner=runner, now=now)
    assert runner.requested_unit == "nginx.service"
    assert runner.requested_window == 7200
    assert len(analysis.events) == 1
    assert analysis.events[0].classification == IncidentEventType.SERVICE_FAILURE
    assert analysis.events[0].timestamp_utc == now - timedelta(minutes=5)
    assert "synthetic-secret" not in analysis.model_dump_json()
    assert analysis.hypotheses[0].confidence == "medium"


def test_restart_loop_and_oom_correlation_is_timed_and_cautious() -> None:
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    service_records = [
        _journal_record(
            now - timedelta(minutes=10 - index * 2),
            "Scheduled restart job, restart counter is at 1",
            _PID="1",
            _COMM="systemd",
        )
        for index in range(3)
    ]
    service_records.append(
        _journal_record(
            now - timedelta(minutes=5),
            "Failed with result 'exit-code'.",
            _PID="1",
            _COMM="systemd",
        )
    )
    kernel_record = _journal_record(
        now - timedelta(minutes=4), "Out of memory: Killed process 1234"
    )
    runner = JournalRunner("\n".join(service_records), kernel_record)
    analysis = analyze_incident("nginx", "30m", runner=runner, now=now)
    assert len(analysis.events) == 5
    assert any(event.classification == IncidentEventType.OOM_KILL for event in analysis.events)
    assert any(event.correlation_explanation for event in analysis.events)
    assert len(analysis.hypotheses) == 2
    assert analysis.hypotheses[0].confidence == "high"
    assert analysis.hypotheses[1].confidence == "low"
    assert "does not prove" in analysis.hypotheses[1].statement


def test_missing_or_malformed_timestamps_produce_incomplete_analysis() -> None:
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    runner = JournalRunner(json.dumps({"MESSAGE": "Started nginx.service"}), "not-json")
    analysis = analyze_incident("nginx", "2h", runner=runner, now=now)
    assert analysis.complete is False
    assert analysis.events == []
    assert analysis.hypotheses == []
    assert "No qualifying timestamped" in (analysis.note or "")


def test_unavailable_journals_are_reported_without_error_text() -> None:
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    runner = JournalRunner()
    runner.service = CommandResult(available=False, error="permission_denied")
    runner.kernel = CommandResult(available=True, returncode=0)
    analysis = analyze_incident("worker@1.service", "1h", runner=runner, now=now)
    assert analysis.complete is False
    assert analysis.unavailable_sources == ["service_journal"]
    assert analysis.service == "worker@1"
    assert "permission_denied" not in analysis.model_dump_json()


def test_out_of_window_events_are_not_included() -> None:
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    runner = JournalRunner(
        _journal_record(
            now - timedelta(hours=3), "Started nginx.service", _PID="1", _COMM="systemd"
        )
    )
    analysis = analyze_incident("nginx", "2h", runner=runner, now=now)
    assert analysis.events == []


def test_incident_parser_caps_large_journal_windows() -> None:
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    records = [
        _journal_record(
            now - timedelta(minutes=10) + timedelta(seconds=index),
            "Scheduled restart job, restart counter is at 1",
            _PID="1",
        )
        for index in range(101)
    ]
    runner = JournalRunner("\n".join(records))

    analysis = analyze_incident("nginx", "1h", runner=runner, now=now)

    assert len(analysis.events) == 100
    assert analysis.complete is False
    assert "incomplete" in (analysis.note or "")


def test_incident_parser_rejects_oversized_messages_without_exporting_them() -> None:
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
    private_marker = "oversized-private-message-marker"
    record = _journal_record(
        now - timedelta(minutes=1),
        "Main process exited " + ("x" * 8200) + private_marker,
        _PID="1",
    )
    analysis = analyze_incident("nginx", "1h", runner=JournalRunner(record), now=now)

    assert analysis.events == []
    assert analysis.complete is False
    assert private_marker not in analysis.model_dump_json()

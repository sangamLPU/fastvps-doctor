"""Deterministic, bounded incident evidence collection and correlation."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from fastvps_doctor.models import (
    IncidentAnalysis,
    IncidentEvent,
    IncidentEventType,
    IncidentHypothesis,
)
from fastvps_doctor.runner import CommandResult, CommandRunner, safe_systemd_unit

MAX_JOURNAL_RECORDS = 100
MAX_MESSAGE_LENGTH = 8192
CORRELATION_WINDOW = timedelta(minutes=5)
_TIME_WINDOW = re.compile(r"([1-9][0-9]{0,3})(m|h|d)")
_OOM_TERMS = re.compile(
    r"(?i)(?:out of memory|oom-kill|oom killer|invoked oom-killer|killed process \d+|memory cgroup out of memory)"
)
_PRESSURE_TERMS = re.compile(r"(?i)(?:memory pressure|pressure stall|memory PSI)")
_FAILURE_TERMS = (
    "failed to start",
    "main process exited",
    "control process exited",
    "failed with result",
    "start request repeated too quickly",
)


def parse_time_window(value: str) -> int:
    """Parse a bounded duration such as 30m, 2h or 1d into seconds."""
    match = _TIME_WINDOW.fullmatch(value.strip().lower())
    if not match:
        raise ValueError("Use a time window such as 30m, 2h or 1d (maximum 24h).")
    amount = int(match.group(1))
    seconds = amount * {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
    if seconds < 60 or seconds > 86400:
        raise ValueError("Incident time window must be between one minute and 24 hours.")
    return seconds


def analyze_incident(
    service: str,
    since: str = "2h",
    *,
    runner: CommandRunner | None = None,
    now: datetime | None = None,
) -> IncidentAnalysis:
    """Inspect one selected systemd unit and kernel events; never export log text."""
    unit = safe_systemd_unit(service)
    window_seconds = parse_time_window(since)
    end_time = now or datetime.now(UTC)
    if end_time.tzinfo is None or end_time.utcoffset() is None:
        raise ValueError("Incident analysis requires an aware timestamp.")
    end_time = end_time.astimezone(UTC)
    start_time = end_time - timedelta(seconds=window_seconds)
    command_runner = runner or CommandRunner(output_limit=65536)

    try:
        service_result = command_runner.recent_service_events(unit, window_seconds)
    except OSError:
        service_result = CommandResult(available=False, error="read_error")
    try:
        kernel_result = command_runner.recent_kernel_events(window_seconds)
    except OSError:
        kernel_result = CommandResult(available=False, error="read_error")

    unavailable_sources: list[str] = []
    complete = True
    if not _command_succeeded(service_result):
        unavailable_sources.append("service_journal")
        complete = False
    if not _command_succeeded(kernel_result):
        unavailable_sources.append("kernel_journal")
        complete = False

    service_events, service_parse_complete = _parse_service_events(
        service_result.stdout if _command_succeeded(service_result) else "",
        unit.removesuffix(".service"),
        start_time,
        end_time,
    )
    kernel_events, kernel_parse_complete = _parse_kernel_events(
        kernel_result.stdout if _command_succeeded(kernel_result) else "",
        start_time,
        end_time,
    )
    complete = complete and service_parse_complete and kernel_parse_complete
    events = sorted(service_events + kernel_events, key=lambda event: event.timestamp_utc)
    events = _add_correlation_notes(events)
    hypotheses = _build_hypotheses(events, unit.removesuffix(".service"))

    if not events:
        note = (
            "No qualifying timestamped events were available in this window. "
            "This does not prove that no incident occurred."
        )
    elif not complete:
        note = "Some journal evidence was unavailable or malformed; the timeline may be incomplete."
    else:
        note = "Only timestamped, classified journal metadata is included; raw log messages are discarded."

    return IncidentAnalysis(
        service=unit.removesuffix(".service"),
        window_seconds=window_seconds,
        generated_at_utc=end_time,
        complete=complete,
        unavailable_sources=unavailable_sources,
        events=events[:MAX_JOURNAL_RECORDS],
        hypotheses=hypotheses,
        note=note,
    )


def _command_succeeded(result: CommandResult) -> bool:
    return (
        result.available
        and not result.timed_out
        and not result.truncated
        and result.returncode == 0
    )


def _parse_service_events(
    output: str,
    service: str,
    start_time: datetime,
    end_time: datetime,
) -> tuple[list[IncidentEvent], bool]:
    events: list[IncidentEvent] = []
    complete = True
    for index, line in enumerate(output.splitlines()):
        if index >= MAX_JOURNAL_RECORDS:
            return events, False
        parsed = _parse_record(line, start_time, end_time)
        if parsed is None:
            if line.strip():
                complete = False
            continue
        timestamp, record = parsed
        message = record.get("MESSAGE")
        if not isinstance(message, str) or len(message) > MAX_MESSAGE_LENGTH:
            complete = False
            continue
        lowered = message.lower()
        is_manager_event = (
            record.get("_PID") == "1"
            or str(record.get("_COMM", "")).lower() == "systemd"
            or str(record.get("SYSLOG_IDENTIFIER", "")).lower() == "systemd"
        )
        event_type: IncidentEventType | None = None
        if is_manager_event and "scheduled restart job" in lowered:
            event_type = IncidentEventType.SERVICE_RESTART_SCHEDULED
        elif is_manager_event and any(term in lowered for term in _FAILURE_TERMS):
            event_type = IncidentEventType.SERVICE_FAILURE
        elif is_manager_event and lowered.startswith("started "):
            event_type = IncidentEventType.SERVICE_STARTED
        elif is_manager_event and lowered.startswith("stopped "):
            event_type = IncidentEventType.SERVICE_STOPPED
        elif str(record.get("PRIORITY", "")) in {"0", "1", "2", "3"}:
            event_type = IncidentEventType.SERVICE_ERROR
        if event_type is not None:
            events.append(_event(timestamp, event_type, service))
    return events, complete


def _parse_kernel_events(
    output: str,
    start_time: datetime,
    end_time: datetime,
) -> tuple[list[IncidentEvent], bool]:
    events: list[IncidentEvent] = []
    complete = True
    for index, line in enumerate(output.splitlines()):
        if index >= MAX_JOURNAL_RECORDS:
            return events, False
        parsed = _parse_record(line, start_time, end_time)
        if parsed is None:
            if line.strip():
                complete = False
            continue
        timestamp, record = parsed
        message = record.get("MESSAGE")
        if not isinstance(message, str) or len(message) > MAX_MESSAGE_LENGTH:
            complete = False
            continue
        if _OOM_TERMS.search(message):
            events.append(_event(timestamp, IncidentEventType.OOM_KILL, "kernel"))
        elif _PRESSURE_TERMS.search(message):
            events.append(_event(timestamp, IncidentEventType.MEMORY_PRESSURE, "kernel"))
    return events, complete


def _parse_record(
    line: str,
    start_time: datetime,
    end_time: datetime,
) -> tuple[datetime, dict[str, Any]] | None:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(record, dict):
        return None
    raw_timestamp = record.get("__REALTIME_TIMESTAMP")
    if not isinstance(raw_timestamp, str) or not raw_timestamp.isdecimal():
        return None
    try:
        timestamp = datetime.fromtimestamp(int(raw_timestamp) / 1_000_000, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    if timestamp < start_time or timestamp > end_time + timedelta(minutes=5):
        return None
    return timestamp, record


def _event(timestamp: datetime, event_type: IncidentEventType, component: str) -> IncidentEvent:
    summaries = {
        IncidentEventType.SERVICE_STARTED: "The service manager recorded a service start.",
        IncidentEventType.SERVICE_STOPPED: "The service manager recorded a service stop.",
        IncidentEventType.SERVICE_FAILURE: "The service manager recorded a failed start or process exit.",
        IncidentEventType.SERVICE_RESTART_SCHEDULED: "The service manager scheduled an automatic restart.",
        IncidentEventType.SERVICE_ERROR: "A journal record for the selected service had error-level priority.",
        IncidentEventType.OOM_KILL: "A kernel journal record matched a known out-of-memory termination indicator.",
        IncidentEventType.MEMORY_PRESSURE: "A kernel journal record matched a memory-pressure indicator.",
    }
    return IncidentEvent(
        timestamp_utc=timestamp,
        classification=event_type,
        component=component,
        evidence_summary=summaries[event_type],
    )


def _add_correlation_notes(events: list[IncidentEvent]) -> list[IncidentEvent]:
    result: list[IncidentEvent] = []
    for event in events:
        nearby = any(
            other is not event
            and abs(other.timestamp_utc - event.timestamp_utc) <= CORRELATION_WINDOW
            for other in events
        )
        result.append(
            event.model_copy(
                update={
                    "correlation_explanation": (
                        "Another classified event was observed within five minutes; timing alone does not establish causation."
                        if nearby
                        else None
                    )
                }
            )
        )
    return result


def _build_hypotheses(events: list[IncidentEvent], service: str) -> list[IncidentHypothesis]:
    hypotheses: list[IncidentHypothesis] = []
    restarts = [
        event
        for event in events
        if event.classification == IncidentEventType.SERVICE_RESTART_SCHEDULED
    ]
    failures = [
        event for event in events if event.classification == IncidentEventType.SERVICE_FAILURE
    ]
    oom_events = [event for event in events if event.classification == IncidentEventType.OOM_KILL]

    if len(restarts) >= 3:
        first, last = restarts[0], restarts[-1]
        hypotheses.append(
            IncidentHypothesis(
                statement="Repeated automatic restart scheduling is consistent with a service restart loop; it does not identify the cause.",
                start_time_utc=first.timestamp_utc,
                end_time_utc=last.timestamp_utc,
                evidence=[
                    f"{len(restarts)} timestamped restart-scheduling records were observed for the selected service.",
                    f"The records span {first.timestamp_utc.isoformat()} to {last.timestamp_utc.isoformat()}.",
                ],
                confidence="high",
                alternatives=[
                    "A planned deployment or operator-triggered sequence can also cause repeated restarts.",
                    "Journal records may be incomplete or duplicated.",
                ],
                next_steps=[
                    f"Review the selected service's local unit configuration and journal around {first.timestamp_utc.isoformat()}.",
                    "Check the application's own health and dependencies before restarting it.",
                ],
            )
        )

    correlated_pairs = [
        (failure, oom)
        for failure in failures
        for oom in oom_events
        if abs(failure.timestamp_utc - oom.timestamp_utc) <= CORRELATION_WINDOW
    ]
    if correlated_pairs:
        failure, oom = min(
            correlated_pairs,
            key=lambda pair: abs(pair[0].timestamp_utc - pair[1].timestamp_utc),
        )
        hypotheses.append(
            IncidentHypothesis(
                statement="An out-of-memory indicator was recorded near a selected-service failure; this temporal correlation does not prove the OOM event caused the failure.",
                start_time_utc=min(failure.timestamp_utc, oom.timestamp_utc),
                end_time_utc=max(failure.timestamp_utc, oom.timestamp_utc),
                evidence=[
                    f"A service failure was recorded at {failure.timestamp_utc.isoformat()}.",
                    f"A kernel out-of-memory indicator was recorded at {oom.timestamp_utc.isoformat()}.",
                ],
                confidence="low",
                alternatives=[
                    "The events may be independent.",
                    "The service may have failed for an unrelated application or configuration reason.",
                ],
                next_steps=[
                    "Review service and memory monitoring around both timestamps.",
                    "Check for kernel OOM records and service resource limits before changing settings.",
                ],
            )
        )
    elif failures:
        first, last = failures[0], failures[-1]
        hypotheses.append(
            IncidentHypothesis(
                statement="A selected-service failure transition was recorded; available evidence does not establish its root cause.",
                start_time_utc=first.timestamp_utc,
                end_time_utc=last.timestamp_utc,
                evidence=[
                    f"{len(failures)} timestamped service failure transition(s) were observed for {service}.",
                    f"The observed interval is {first.timestamp_utc.isoformat()} to {last.timestamp_utc.isoformat()}.",
                ],
                confidence="medium",
                alternatives=[
                    "A service configuration, dependency, application or resource issue may have contributed.",
                    "A planned operator action can also produce a failure transition.",
                ],
                next_steps=[
                    "Review the service journal locally around the recorded times.",
                    "Compare with deployment and application error timestamps.",
                ],
            )
        )
    return hypotheses

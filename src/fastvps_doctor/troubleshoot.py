"""Focused, read-only incident workflows and scenario support reports."""

from __future__ import annotations

import html
import http.client
import platform
import sys
from datetime import UTC, datetime

from fastvps_doctor import __version__
from fastvps_doctor.checks.network import collect_listeners
from fastvps_doctor.checks.services import PRESENT_STATES, UNCERTAIN_STATES, _unit_state
from fastvps_doctor.checks.storage import collect_storage
from fastvps_doctor.checks.system import collect_system
from fastvps_doctor.incident_analysis import analyze_incident
from fastvps_doctor.models import (
    CheckStatus,
    DiagnosticCheck,
    EvidenceCertainty,
    IncidentAnalysis,
    IncidentInformation,
    TroubleshootConclusion,
    TroubleshootObservation,
    TroubleshootReport,
    TroubleshootScenario,
    TroubleshootTimelineEvent,
)
from fastvps_doctor.platform import linux_distribution
from fastvps_doctor.privacy import (
    sanitize_incident_information,
    sanitize_troubleshoot_report,
)
from fastvps_doctor.runner import (
    CommandResult,
    CommandRunner,
    find_executable,
    safe_systemd_unit,
)


def collect_selected_service(service: str, runner: CommandRunner | None = None) -> DiagnosticCheck:
    """Read properties for exactly one user-selected systemd unit."""
    unit = safe_systemd_unit(service)
    command_runner = runner or CommandRunner()
    try:
        result = command_runner.systemd_unit_show(unit)
    except OSError:
        result = CommandResult(available=False, error="read_error")
    state, properties = _unit_state(result)
    unit_found = state in PRESENT_STATES | {"alias"}
    status = (
        CheckStatus.UNKNOWN
        if state in UNCERTAIN_STATES - {"unit_not_found"}
        else CheckStatus.PASS
        if state == "active"
        else CheckStatus.WARNING
    )
    metrics: dict[str, str | int | float | bool | None] = {
        "service_unit_found": unit_found,
        "service_state": state,
        "service_restart_count": _nonnegative_int(properties.get("NRestarts")),
        "service_result": properties.get("Result", "").lower() or None,
        "service_exec_main_code": _bounded_int(properties.get("ExecMainCode")),
        "service_exec_main_status": _bounded_int(properties.get("ExecMainStatus")),
    }
    return DiagnosticCheck(
        check_id="troubleshoot.service",
        category="services",
        status=status,
        summary="Queried the selected systemd unit state and available exit/restart properties.",
        metrics=metrics,
        note=(
            "Only the explicitly selected unit was queried. Unit names are withheld from exported reports unless they match a common service label."
        ),
    )


def collect_loopback_http_head(port: int, timeout: float = 1.0) -> DiagnosticCheck:
    """Issue a bounded HEAD request to IPv4 loopback only; never read a body."""
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if not 0 < timeout <= 3:
        raise ValueError("HTTP probe timeout must be greater than zero and at most three seconds.")
    if not sys.platform.startswith("linux"):
        return DiagnosticCheck(
            check_id="troubleshoot.http",
            category="web",
            status=CheckStatus.SKIPPED,
            summary="The loopback HTTP probe is available only on Linux.",
            metrics={"http_probe_requested": True, "http_probe_state": "unavailable"},
        )

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    status_code: int | None = None
    state = "connection_error"
    try:
        connection.request("HEAD", "/", headers={"Connection": "close"})
        response = connection.getresponse()
        status_code = response.status if 100 <= response.status <= 599 else None
        if status_code is not None:
            state = (
                "response_1xx"
                if status_code // 100 == 1
                else f"response_{status_code // 100}xx"
                if status_code // 100 in {2, 3, 4, 5}
                else "response_other"
            )
        response.close()
    except TimeoutError:
        state = "timeout"
    except http.client.HTTPException:
        state = "protocol_error"
    except OSError:
        state = "connection_error"
    finally:
        connection.close()

    check_status = (
        CheckStatus.FAIL
        if state == "response_5xx" or state == "connection_error"
        else CheckStatus.WARNING
        if state == "response_4xx"
        else CheckStatus.UNKNOWN
        if state in {"timeout", "protocol_error", "unavailable", "response_1xx"}
        else CheckStatus.PASS
    )
    return DiagnosticCheck(
        check_id="troubleshoot.http",
        category="web",
        status=check_status,
        summary="Issued one optional HTTP HEAD request to 127.0.0.1; no response body was read.",
        metrics={
            "http_probe_requested": True,
            "http_probe_state": state,
            "http_status_code": status_code,
        },
        note="This loopback-only probe does not test TLS, public reachability, DNS or application-specific routes.",
    )


def collect_selected_config_validation(
    service: str, runner: CommandRunner | None = None
) -> DiagnosticCheck:
    """Optionally run a built-in syntax validator for a supported common daemon."""
    unit = safe_systemd_unit(service)
    daemon = unit.removesuffix(".service").lower()
    command_runner = runner or CommandRunner()
    if daemon == "nginx":
        result = command_runner.validate_nginx()
    elif daemon in {"apache", "apache2", "httpd"}:
        executable = next(
            (name for name in ("apache2ctl", "apachectl") if find_executable(name)), None
        )
        result = (
            command_runner.validate_apache(executable)
            if executable
            else CommandResult(available=False)
        )
    elif daemon in {"ssh", "sshd"}:
        result = command_runner.validate_ssh()
    else:
        result = None

    state = "not_supported"
    if result is not None:
        if not result.available:
            state = "unavailable"
        elif result.timed_out:
            state = "timeout"
        elif result.truncated or result.returncode != 0:
            state = "failed_or_inconclusive"
        else:
            state = "passed"
    return DiagnosticCheck(
        check_id="troubleshoot.config",
        category="services",
        status=(
            CheckStatus.PASS
            if state == "passed"
            else CheckStatus.UNKNOWN
            if state in {"not_supported", "unavailable", "timeout"}
            else CheckStatus.WARNING
        ),
        summary="Ran the explicitly requested built-in configuration syntax check."
        if result is not None
        else "No built-in configuration validator is available for the selected service.",
        metrics={"config_state": state},
        note="Validator output is discarded because it may contain local paths or configuration details.",
    )


def build_troubleshoot_report(
    scenario: TroubleshootScenario,
    *,
    service: str | None = None,
    port: int | None = None,
    since: str = "2h",
    probe_http: bool = False,
    validate_config: bool = False,
    description: str | None = None,
    ticket_reference: str | None = None,
    profile: str | None = None,
) -> TroubleshootReport:
    """Collect only the selected scenario's bounded, read-only evidence."""
    if profile not in {None, "fastvps"}:
        raise ValueError("The only supported profile is 'fastvps'.")
    if service:
        safe_systemd_unit(service)
    selected_service: str | None = service
    if scenario == TroubleshootScenario.STORAGE and service is None and since != "2h":
        raise ValueError("--since requires a selected service in the storage scenario.")
    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        if not selected_service or port is None:
            raise ValueError("The website scenario requires --service and --port.")
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        checks = [collect_selected_service(selected_service)]
        checks.extend(collect_storage())
        checks.append(collect_system()[0])
        checks.append(collect_listeners({port}))
        if probe_http:
            checks.append(collect_loopback_http_head(port))
        if validate_config:
            checks.append(collect_selected_config_validation(selected_service))
        incident = analyze_incident(selected_service, since)
    elif scenario == TroubleshootScenario.SERVICE_CRASH:
        if not selected_service:
            raise ValueError("The service-crash scenario requires --service.")
        if port is not None or probe_http:
            raise ValueError("--port and --probe-http apply only to the website scenario.")
        checks = [collect_selected_service(selected_service), collect_system()[0]]
        if validate_config:
            checks.append(collect_selected_config_validation(selected_service))
        incident = analyze_incident(selected_service, since)
    elif scenario == TroubleshootScenario.STORAGE:
        checks = collect_storage()
        if selected_service:
            checks.insert(0, collect_selected_service(selected_service))
            incident = analyze_incident(selected_service, since)
        else:
            incident = None
        if validate_config:
            raise ValueError("--validate-config requires a selected service.")
        if probe_http or port is not None:
            raise ValueError("--port and --probe-http apply only to the website scenario.")
    else:
        raise ValueError("Select one of the three supported troubleshooting scenarios.")

    report = TroubleshootReport(
        version=__version__,
        timestamp_utc=datetime.now(UTC),
        scenario=scenario,
        distribution=linux_distribution(),
        kernel_release=platform.release() if sys.platform.startswith("linux") else None,
        reported_problem=description,
        service_label=_safe_report_service_label(selected_service),
        selected_port=port,
        loopback_http_probe_requested=probe_http,
        checks=checks,
        observations=_observations(checks, port),
        timeline=_timeline(incident),
        conclusions=_conclusions(scenario, checks, incident, port),
        investigation_areas=_investigation_areas(scenario, checks),
        evidence_gaps=_evidence_gaps(scenario, checks, incident, probe_http),
        next_actions=_next_actions(scenario),
        profile=profile,
        ticket_reference=ticket_reference,
    )
    return sanitize_troubleshoot_report(report)


def render_troubleshoot_markdown(report: TroubleshootReport) -> str:
    """Render the same sanitized model used by the JSON report."""
    lines = [
        "# FastVPS Doctor focused support handoff",
        "",
        "> Independent and unofficial. This report is a diagnostic aid, not a root-cause finding or provider decision.",
        "> Review and redact this report before sharing it.",
        "",
        "## Report header",
        "",
        f"- Version: {report.version}",
        f"- Report schema: {report.schema_version}",
        f"- Scenario: {report.scenario.value}",
        f"- Snapshot time (UTC): {report.timestamp_utc.isoformat()}",
        f"- Environment: {_markdown_text(report.distribution)}; kernel {report.kernel_release or 'not available'}",
        f"- Service label: {_markdown_text(report.service_label or 'not provided')}",
        f"- Selected local port: {report.selected_port if report.selected_port is not None else 'not applicable'}",
        f"- Profile: {report.profile or 'standard'}",
    ]
    if report.ticket_reference:
        lines.append(f"- Ticket reference: `{report.ticket_reference}`")
    if report.reported_problem:
        lines += ["", "## Reported symptom", "", _markdown_text(report.reported_problem)]

    lines += ["", "## Checks actually run", ""]
    if report.checks:
        for check in report.checks:
            lines.append(f"### `{check.check_id}` — {check.status.value.upper()}")
            lines += ["", _markdown_text(check.summary)]
            if check.metrics:
                lines.append("")
                for key, value in sorted(check.metrics.items()):
                    lines.append(f"- `{key}`: `{value if value is not None else 'unavailable'}`")
            if check.note:
                lines += ["", f"Note: {_markdown_text(check.note)}"]
            lines.append("")
    else:
        lines.append("No diagnostic checks were available.")

    lines += ["## Confirmed observations", ""]
    lines.extend(
        f"- **{item.evidence_id}** ({item.source}): {_markdown_text(item.summary)}"
        for item in report.observations
    )
    if not report.observations:
        lines.append("- No observations were collected.")

    lines += ["", "## Timestamped event timeline", ""]
    if report.timeline:
        lines.extend(
            f"- **{item.event_id}** {item.timestamp_utc.isoformat()} — {item.classification.value}: {_markdown_text(item.summary)}"
            for item in report.timeline
        )
    else:
        lines.append(
            "No qualifying timestamped events were available. This does not prove no event occurred."
        )

    lines += ["", "## Evidence-based explanations", ""]
    if report.conclusions:
        lines.extend(
            f"- **{item.certainty.value.title()}** ({', '.join(item.evidence_ids) or 'no supporting observation'}): {_markdown_text(item.statement)}"
            for item in report.conclusions
        )
    else:
        lines.append("- Insufficient evidence to describe a scenario-specific explanation.")

    for heading, values in (
        ("Areas for further investigation", report.investigation_areas),
        ("Evidence gaps and limits", report.evidence_gaps),
        ("Suggested next actions", report.next_actions),
    ):
        lines += ["", f"## {heading}", ""]
        lines.extend(f"- {_markdown_text(value)}" for value in values) if values else lines.append(
            "- None recorded."
        )

    lines += [
        "",
        "## Privacy and limitations",
        "",
        "The export contains allowlisted summaries only; raw logs, command output, host identity, addresses, paths, usernames, credentials and application response bodies are excluded. A loopback response does not establish public reachability. Correlation and current snapshots do not prove causation. Missing or restricted logs are incomplete evidence.",
        "",
    ]
    if report.profile == "fastvps":
        lines += [
            "## FastVPS support context",
            "",
            "This is an independent, unofficial tool and does not connect to FastVPS systems. Support scope depends on the customer's ordered plan. Review the report before contacting [official FastVPS support](https://fastvps.gr/en/faq/).",
            "",
        ]
    return "\n".join(lines)


def _nonnegative_int(value: str | None) -> int | None:
    parsed = _bounded_int(value)
    return parsed if parsed is not None and parsed >= 0 else None


def _bounded_int(value: str | None) -> int | None:
    if value is None or not value.isdecimal():
        return None
    parsed = int(value)
    return parsed if parsed <= 1_000_000_000 else None


def _safe_report_service_label(service: str | None) -> str | None:
    if service is None:
        return None
    sanitized = sanitize_incident_information(IncidentInformation(affected_service=service))
    return sanitized.affected_service if sanitized else None


def _observations(checks: list[DiagnosticCheck], port: int | None) -> list[TroubleshootObservation]:
    result: list[TroubleshootObservation] = []
    for index, check in enumerate(checks, start=1):
        detail = check.summary
        if check.check_id == "troubleshoot.service":
            state = check.metrics.get("service_state")
            restarts = check.metrics.get("service_restart_count")
            detail = f"Selected systemd unit state: {state or 'unavailable'}; restart count: {restarts if restarts is not None else 'unavailable'}."
        elif check.check_id == "storage.root":
            used = check.metrics.get("usage_percent")
            inodes = check.metrics.get("inode_usage_percent")
            readonly = check.metrics.get("readonly")
            detail = f"Root filesystem utilization: {used if used is not None else 'unavailable'}%; inode utilization: {inodes if inodes is not None else 'unavailable'}%; read-only: {readonly if readonly is not None else 'unknown'}."
        elif check.check_id == "system.resources":
            memory = check.metrics.get("memory_percent")
            cpu = check.metrics.get("cpu_sample_percent")
            detail = f"Current resource snapshot: memory {memory if memory is not None else 'unavailable'}%; brief CPU sample {cpu if cpu is not None else 'unavailable'}%."
        elif check.check_id == "network.listeners" and port is not None:
            count = check.metrics.get(f"port_{port}_listeners")
            detail = f"Local listener inventory for selected port: {count if count is not None else 'unavailable'} listener(s)."
        elif check.check_id == "troubleshoot.http":
            state = check.metrics.get("http_probe_state", "unavailable")
            code = check.metrics.get("http_status_code")
            detail = f"Loopback HTTP HEAD result: {state}; status code {code if code is not None else 'not available'}."
        elif check.check_id == "storage.mounts":
            detail = check.summary
        source = (
            "loopback"
            if check.check_id == "troubleshoot.http"
            else "filesystem"
            if check.check_id.startswith("storage.")
            else "snapshot"
        )
        result.append(
            TroubleshootObservation(
                evidence_id=f"OBS-{index:03d}",
                source=source,
                summary=detail,
                check_id=check.check_id,
                status=check.status,
            )
        )
    return result


def _timeline(analysis: IncidentAnalysis | None) -> list[TroubleshootTimelineEvent]:
    if analysis is None:
        return []
    return [
        TroubleshootTimelineEvent(
            event_id=f"EVT-{index:03d}",
            timestamp_utc=event.timestamp_utc,
            classification=event.classification,
            summary=event.evidence_summary,
        )
        for index, event in enumerate(analysis.events[:100], start=1)
    ]


def _conclusions(
    scenario: TroubleshootScenario,
    checks: list[DiagnosticCheck],
    analysis: IncidentAnalysis | None,
    port: int | None,
) -> list[TroubleshootConclusion]:
    by_id = {check.check_id: check for check in checks}
    observations = {item.check_id: item.evidence_id for item in _observations(checks, port)}
    conclusions: list[TroubleshootConclusion] = []
    service_check = by_id.get("troubleshoot.service")
    service_evidence = observations.get("troubleshoot.service")
    if service_check and service_evidence:
        state = service_check.metrics.get("service_state")
        if state in {"active", "inactive", "failed", "masked", "unit_not_found", "not_installed"}:
            conclusions.append(
                TroubleshootConclusion(
                    certainty=EvidenceCertainty.CONFIRMED,
                    statement=f"The selected systemd unit was reported as {state} at the snapshot time.",
                    evidence_ids=[service_evidence],
                )
            )
        else:
            conclusions.append(
                TroubleshootConclusion(
                    certainty=EvidenceCertainty.INSUFFICIENT,
                    statement="The selected service state could not be determined from available systemd evidence.",
                    evidence_ids=[service_evidence],
                )
            )

        restart_count = service_check.metrics.get("service_restart_count")
        if isinstance(restart_count, int) and restart_count > 0:
            certainty = (
                EvidenceCertainty.PLAUSIBLE if restart_count >= 3 else EvidenceCertainty.CONFIRMED
            )
            conclusions.append(
                TroubleshootConclusion(
                    certainty=certainty,
                    statement=f"systemd currently reports a restart counter of {restart_count}; this counter does not identify when the restarts occurred or why.",
                    evidence_ids=[service_evidence],
                )
            )

    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE and port is not None:
        listener_check = by_id.get("network.listeners")
        listener_evidence = observations.get("network.listeners")
        count = listener_check.metrics.get(f"port_{port}_listeners") if listener_check else None
        if listener_evidence and isinstance(count, int):
            conclusions.append(
                TroubleshootConclusion(
                    certainty=EvidenceCertainty.CONFIRMED,
                    statement=(
                        f"The local listener inventory reported no listener on port {port} at snapshot time."
                        if count == 0
                        else f"The local listener inventory reported {count} listener(s) on port {port}; this does not prove the application route or public reachability works."
                    ),
                    evidence_ids=[listener_evidence],
                )
            )
        http_check = by_id.get("troubleshoot.http")
        http_evidence = observations.get("troubleshoot.http")
        if http_check and http_evidence:
            state = http_check.metrics.get("http_probe_state")
            code = http_check.metrics.get("http_status_code")
            if isinstance(state, str) and state.startswith("response_"):
                conclusions.append(
                    TroubleshootConclusion(
                        certainty=EvidenceCertainty.CONFIRMED,
                        statement=f"A loopback HTTP HEAD request received status {code}; this does not establish public reachability or application-specific health.",
                        evidence_ids=[http_evidence],
                    )
                )
            elif state in {"connection_error", "timeout", "protocol_error"}:
                conclusions.append(
                    TroubleshootConclusion(
                        certainty=EvidenceCertainty.CONFIRMED
                        if state == "connection_error"
                        else EvidenceCertainty.INSUFFICIENT,
                        statement=f"The optional loopback HTTP HEAD probe ended with {state}; this alone does not identify a cause.",
                        evidence_ids=[http_evidence],
                    )
                )

    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE and analysis and analysis.events:
        relevant = [
            (index, event)
            for index, event in enumerate(analysis.events[:100], start=1)
            if event.classification.value
            in {"service_failure", "service_restart_scheduled", "service_error"}
        ]
        if relevant:
            conclusions.append(
                TroubleshootConclusion(
                    certainty=EvidenceCertainty.CONFIRMED,
                    statement=f"The bounded journal window contains {len(relevant)} classified service failure, restart-scheduling or error event(s); event timing does not establish the cause of the reported website problem.",
                    evidence_ids=[f"EVT-{index:03d}" for index, _event in relevant[:8]],
                )
            )
    if scenario == TroubleshootScenario.SERVICE_CRASH and analysis:
        restart_events = [
            (index, event)
            for index, event in enumerate(analysis.events[:100], start=1)
            if event.classification.value == "service_restart_scheduled"
        ]
        if len(restart_events) >= 2:
            conclusions.append(
                TroubleshootConclusion(
                    certainty=EvidenceCertainty.PLAUSIBLE,
                    statement=f"{len(restart_events)} timestamped restart-scheduling records were found in the selected window. This pattern is consistent with repeated restarts, but does not establish cause.",
                    evidence_ids=[f"EVT-{index:03d}" for index, _event in restart_events[:8]],
                )
            )
        failures = [
            (index, event)
            for index, event in enumerate(analysis.events[:100], start=1)
            if event.classification.value == "service_failure"
        ]
        oom_events = [
            (index, event)
            for index, event in enumerate(analysis.events[:100], start=1)
            if event.classification.value == "oom_kill"
        ]
        pairs = [
            (failure, oom)
            for failure in failures
            for oom in oom_events
            if abs(failure[1].timestamp_utc - oom[1].timestamp_utc).total_seconds() <= 300
        ]
        if pairs:
            failure, oom = min(
                pairs,
                key=lambda pair: abs(
                    (pair[0][1].timestamp_utc - pair[1][1].timestamp_utc).total_seconds()
                ),
            )
            conclusions.append(
                TroubleshootConclusion(
                    certainty=EvidenceCertainty.PLAUSIBLE,
                    statement="A kernel out-of-memory indicator and a selected-service failure were timestamped within five minutes; timing alone does not prove causation.",
                    evidence_ids=[f"EVT-{failure[0]:03d}", f"EVT-{oom[0]:03d}"],
                )
            )

    if scenario == TroubleshootScenario.STORAGE:
        root = by_id.get("storage.root")
        root_evidence = observations.get("storage.root")
        if root and root_evidence:
            usage = root.metrics.get("usage_percent")
            inodes = root.metrics.get("inode_usage_percent")
            readonly = root.metrics.get("readonly")
            if usage is not None or inodes is not None or readonly is not None:
                facts = []
                if usage is not None:
                    facts.append(f"space utilization was {usage}%")
                if inodes is not None:
                    facts.append(f"inode utilization was {inodes}%")
                if readonly is not None:
                    facts.append(f"read-only state was {str(readonly).lower()}")
                conclusions.append(
                    TroubleshootConclusion(
                        certainty=EvidenceCertainty.CONFIRMED,
                        statement="The root filesystem snapshot reported "
                        + ", ".join(facts)
                        + ". These counters do not prove the cause of an application write failure.",
                        evidence_ids=[root_evidence],
                    )
                )
        if analysis:
            storage_related = [
                (index, event)
                for index, event in enumerate(analysis.events[:100], start=1)
                if event.classification.value in {"service_error", "service_failure"}
            ]
            if storage_related:
                conclusions.append(
                    TroubleshootConclusion(
                        certainty=EvidenceCertainty.CONFIRMED,
                        statement=f"The selected service journal contains {len(storage_related)} timestamped error or failure event(s); this does not establish a connection to storage conditions.",
                        evidence_ids=[f"EVT-{index:03d}" for index, _event in storage_related[:8]],
                    )
                )

    if not conclusions:
        used = [value for value in observations.values() if value]
        conclusions.append(
            TroubleshootConclusion(
                certainty=EvidenceCertainty.INSUFFICIENT,
                statement="Available evidence is insufficient to identify why the reported problem occurred.",
                evidence_ids=used[:8],
            )
        )
    return conclusions


def _investigation_areas(
    scenario: TroubleshootScenario, checks: list[DiagnosticCheck]
) -> list[str]:
    areas = {
        TroubleshootScenario.WEBSITE_UNAVAILABLE: [
            "Compare the selected port and service state with the application's intended bind address and deployment configuration.",
            "If local checks respond, have an administrator separately review DNS, proxy routing and external network reachability.",
        ],
        TroubleshootScenario.SERVICE_CRASH: [
            "Review the full local journal and unit configuration around the reported incident time with an administrator.",
            "Check application dependencies and exit details; do not infer cause from the current resource snapshot.",
        ],
        TroubleshootScenario.STORAGE: [
            "Compare the bounded filesystem and inode counters with the exact filesystem used by the failing application.",
            "Review storage-related application or service errors separately; no customer files were searched.",
        ],
    }[scenario]
    if any(check.status in {CheckStatus.UNKNOWN, CheckStatus.SKIPPED} for check in checks):
        areas.append("Resolve the unavailable or incomplete checks before drawing a conclusion.")
    return areas


def _evidence_gaps(
    scenario: TroubleshootScenario,
    checks: list[DiagnosticCheck],
    analysis: IncidentAnalysis | None,
    probe_http: bool,
) -> list[str]:
    gaps = [
        "This report is a point-in-time, read-only snapshot and does not establish root cause.",
        "Public internet reachability, DNS delegation and provider network paths were not tested.",
    ]
    if analysis is not None and not analysis.complete:
        gaps.append(
            "One or more bounded journal sources were unavailable or incomplete; missing events are not proof that no event occurred."
        )
    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE and not probe_http:
        gaps.append("The optional loopback HTTP HEAD probe was not requested.")
    if scenario == TroubleshootScenario.STORAGE:
        gaps.append(
            "Storage counters do not identify which application files are large or prove why a write failed."
        )
    if any(check.status in {CheckStatus.UNKNOWN, CheckStatus.SKIPPED} for check in checks):
        gaps.append(
            "At least one check was skipped or incomplete, possibly due to permissions, platform or missing tools."
        )
    return gaps


def _next_actions(scenario: TroubleshootScenario) -> list[str]:
    actions = {
        TroubleshootScenario.WEBSITE_UNAVAILABLE: [
            "Confirm the expected service name, local listening port and application route with the site administrator.",
            "Review this sanitized report before attaching it to a support request.",
        ],
        TroubleshootScenario.SERVICE_CRASH: [
            "Have an administrator inspect full service and kernel logs around the event timestamps.",
            "Review the service's exit result and dependencies before considering any restart or configuration change.",
            "Review this sanitized report before attaching it to a support request.",
        ],
        TroubleshootScenario.STORAGE: [
            "Compare space and inode usage with read-only system tools and identify the application's actual filesystem.",
            "Ask an administrator to review relevant storage and application errors; do not delete files based only on this report.",
            "Review this sanitized report before attaching it to a support request.",
        ],
    }
    return actions[scenario]


def _markdown_text(value: str) -> str:
    flattened = " ".join(value.splitlines())
    escaped = html.escape(flattened, quote=False)
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", "!", "|"):
        escaped = escaped.replace(character, "\\" + character)
    return escaped

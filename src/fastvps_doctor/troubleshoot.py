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

APPLICATION_SERVICE_GROUPS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "nginx": (("nginx.service",), ("nginx",)),
    "apache2": (("apache2.service", "httpd.service"), ("apache2ctl", "apachectl", "httpd")),
    "mysql": (("mysql.service",), ("mysqld", "mysqld_safe")),
    "mariadb": (("mariadb.service",), ("mariadbd", "mariadb")),
    "postgresql": (("postgresql.service",), ("postgres",)),
    "redis-server": (("redis-server.service", "redis.service"), ("redis-server",)),
}
WEB_SERVICE_NAMES = ("nginx", "apache2")


def _inspect_application_service(
    name: str,
    runner: CommandRunner,
) -> tuple[str, bool | None, bool | None, str | None]:
    """Inspect one fixed, common application unit without reading its logs."""
    units, executables = APPLICATION_SERVICE_GROUPS[name]
    state = "unit_not_found"
    found_unit: str | None = None
    for unit in units:
        try:
            result = runner.systemd_unit_show(unit)
        except OSError:
            result = CommandResult(available=False, error="read_error")
        state, _properties = _unit_state(result)
        if state != "unit_not_found":
            if state in PRESENT_STATES:
                found_unit = unit
            break

    executable_present = any(find_executable(executable) for executable in executables)
    if state == "unit_not_found":
        state = "unit_not_found" if executable_present else "not_installed"
    installed: bool | None = True if found_unit or executable_present else None
    unit_found: bool | None = True if found_unit else None
    if state == "not_installed":
        installed = False
        unit_found = False
    elif state == "unit_not_found":
        unit_found = False
    elif state in UNCERTAIN_STATES:
        if not executable_present:
            installed = None
        unit_found = None
    elif state in PRESENT_STATES:
        installed = True
        unit_found = True
    return state, installed, unit_found, found_unit


def discover_relevant_services(
    scenario: TroubleshootScenario,
    runner: CommandRunner | None = None,
) -> tuple[list[tuple[str, str, str]], bool]:
    """Return fixed-name application service suggestions and discovery completeness.

    SSH and Docker are deliberately excluded: they are commonly critical host
    services and are not a sensible default suggestion for application incidents.
    """
    command_runner = runner or CommandRunner()
    names = (
        WEB_SERVICE_NAMES
        if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
        else tuple(APPLICATION_SERVICE_GROUPS)
    )
    candidates: list[tuple[str, str, str]] = []
    complete = True
    for name in names:
        state, _installed, unit_found, unit = _inspect_application_service(name, command_runner)
        if unit_found is True and unit is not None:
            candidates.append((name, unit, state))
        if state in UNCERTAIN_STATES - {"unit_not_found"}:
            complete = False
            break
    return candidates, complete


def collect_common_web_services(runner: CommandRunner | None = None) -> DiagnosticCheck:
    """Collect allowlisted Nginx/Apache installation and unit-state indicators."""
    command_runner = runner or CommandRunner()
    metrics: dict[str, str | int | float | bool | None] = {}
    uncertain = False
    if not sys.platform.startswith("linux"):
        for name in WEB_SERVICE_NAMES:
            metrics[f"{name}_installed"] = None
            metrics[f"{name}_unit_found"] = None
            metrics[f"{name}_state"] = "unavailable"
        return DiagnosticCheck(
            check_id="troubleshoot.web_services",
            category="web",
            status=CheckStatus.UNKNOWN,
            summary="Common web service inventory is available only on Linux.",
            metrics=metrics,
        )

    for index, name in enumerate(WEB_SERVICE_NAMES):
        state, installed, unit_found, _unit = _inspect_application_service(name, command_runner)
        metrics[f"{name}_installed"] = installed
        metrics[f"{name}_unit_found"] = unit_found
        metrics[f"{name}_state"] = state
        uncertain = uncertain or state in UNCERTAIN_STATES - {"unit_not_found"}
        if state in UNCERTAIN_STATES - {"unit_not_found"}:
            for remaining_name in WEB_SERVICE_NAMES[index + 1 :]:
                metrics[f"{remaining_name}_installed"] = None
                metrics[f"{remaining_name}_unit_found"] = None
                metrics[f"{remaining_name}_state"] = state
            break
    return DiagnosticCheck(
        check_id="troubleshoot.web_services",
        category="web",
        status=CheckStatus.UNKNOWN if uncertain else CheckStatus.PASS,
        summary="Read-only inventory of common Nginx and Apache executables and systemd units.",
        metrics=metrics,
        note=(
            "This checks common Nginx and Apache names only. No match does not prove a website outage or rule out another web server, proxy or container."
        ),
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
    selected_service = service or None
    if selected_service is None and since != "2h":
        raise ValueError("--since requires a selected service for service-specific event analysis.")
    if validate_config and selected_service is None:
        raise ValueError("--validate-config requires a selected service.")
    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE and probe_http and port is None:
        raise ValueError("--probe-http requires --port.")
    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        if port is None and selected_service is not None:
            raise ValueError("The website scenario requires --port.")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        checks = []
        if selected_service:
            checks.append(collect_selected_service(selected_service))
        else:
            checks.append(collect_common_web_services())
        checks.extend(collect_storage())
        checks.append(collect_system()[0])
        listener_ports = {port} if selected_service is not None and port is not None else {80, 443}
        if port is not None:
            listener_ports.add(port)
        checks.append(collect_listeners(listener_ports))
        if probe_http:
            if port is None:
                raise ValueError("--probe-http requires --port.")
            checks.append(collect_loopback_http_head(port))
        if validate_config and selected_service:
            checks.append(collect_selected_config_validation(selected_service))
        incident = analyze_incident(selected_service, since) if selected_service else None
    elif scenario == TroubleshootScenario.SERVICE_CRASH:
        if port is not None or probe_http:
            raise ValueError("--port and --probe-http apply only to the website scenario.")
        checks = []
        if selected_service:
            checks.append(collect_selected_service(selected_service))
        checks.append(collect_system()[0])
        if selected_service is None:
            checks.extend(collect_storage())
        if validate_config and selected_service:
            checks.append(collect_selected_config_validation(selected_service))
        incident = analyze_incident(selected_service, since) if selected_service else None
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
        investigation_areas=_investigation_areas(scenario, checks, incident),
        evidence_gaps=_evidence_gaps(scenario, checks, incident, probe_http),
        next_actions=_next_actions(
            scenario,
            service_selected=selected_service is not None,
            checks=checks,
            analysis=incident,
            port=port,
        ),
        profile=profile,
        ticket_reference=ticket_reference,
    )
    return sanitize_troubleshoot_report(report)


def render_troubleshoot_markdown(report: TroubleshootReport) -> str:
    """Render the same sanitized model used by the JSON report."""
    lines = [
        "# FastVPS Doctor incident handoff",
        "",
        "> Independent and unofficial. Diagnostic evidence is not a root-cause or provider-responsibility decision.",
        "> Review and redact this report before sharing it.",
        "",
        "## 1. Incident summary",
        "",
        f"- Incident type: {_scenario_label(report.scenario)}",
        f"- Customer-reported symptom: {_markdown_text(report.reported_problem or 'Not provided.')}",
        f"- Affected service: {_markdown_text(report.service_label or 'Not identified.')}",
        f"- Snapshot time (UTC): {report.timestamp_utc.isoformat()}",
        f"- Environment: {_markdown_text(report.distribution)}; kernel {_markdown_text(report.kernel_release or 'not available')}",
        f"- Overall assessment: **{_overall_assessment(report)}**",
    ]
    if report.scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        lines.append(
            f"- Expected local port: {report.selected_port if report.selected_port is not None else 'not selected'}"
        )
    if report.ticket_reference:
        lines.append(f"- Ticket reference: `{report.ticket_reference}`")

    lines += ["", "## 2. Most important observations", ""]
    summary_observations = _summary_observations(report)
    if summary_observations:
        for item in summary_observations[:3]:
            lines.append(
                f"- **{item.evidence_id} — {_observation_title(item.check_id)}:** "
                f"{_markdown_text(item.summary)} "
                f"Why it matters: {_markdown_text(_observation_relevance(report, item))} "
                f"*(`{item.source}`; `{item.check_id or 'not available'}`)*"
            )
        displayed_count = min(len(summary_observations), 3)
        additional_count = len(report.observations) - displayed_count
        if additional_count > 0:
            lines.append(
                f"{additional_count} additional observation(s) are listed in the technical appendix."
            )
    else:
        lines.append("No observations were collected.")

    lines += ["", "## 3. Likely investigation areas", ""]
    observation_ids = {item.evidence_id for item in report.observations}
    for certainty, heading in (
        (EvidenceCertainty.CONFIRMED, "Confirmed observations"),
        (EvidenceCertainty.PLAUSIBLE, "Plausible explanations"),
        (EvidenceCertainty.INSUFFICIENT, "Unknown or unverified"),
    ):
        items = [
            item
            for item in report.conclusions
            if item.certainty == certainty
            and not (
                certainty == EvidenceCertainty.CONFIRMED
                and item.evidence_ids
                and set(item.evidence_ids) <= observation_ids
            )
        ]
        lines += [f"### {heading}", ""]
        if items:
            lines.extend(_render_conclusion(item) for item in items[:3])
            if len(items) > 3:
                lines.append(f"{len(items) - 3} more item(s) appear in the technical appendix.")
        elif certainty == EvidenceCertainty.CONFIRMED:
            lines.append("No additional confirmed finding beyond the recorded observations.")
        elif certainty == EvidenceCertainty.PLAUSIBLE:
            lines.append("No evidence-supported causal explanation was identified.")
        else:
            lines.append("See the evidence gaps below.")
        lines.append("")

    lines += ["## 4. Recommended next steps", ""]
    lines.extend(
        f"{index}. {_markdown_text(value)}"
        for index, value in enumerate(report.next_actions[:3], start=1)
    )
    if not report.next_actions:
        lines.append("No next steps were generated from the available evidence.")

    lines += ["", "## 5. Evidence gaps", ""]
    if report.evidence_gaps:
        lines.extend(f"- {_markdown_text(value)}" for value in report.evidence_gaps[:4])
        if len(report.evidence_gaps) > 4:
            lines.append(
                f"{len(report.evidence_gaps) - 4} additional limitation(s) are listed in the technical appendix."
            )
    else:
        lines.append("No specific evidence gaps were recorded; review the check details below.")

    lines += ["", "## 6. Technical appendix", "", "### Report metadata", ""]
    lines += [
        f"- Product version: {report.version}",
        f"- Report schema: {report.schema_version}",
        f"- Scenario key: `{report.scenario.value}`",
        f"- Profile: {report.profile or 'standard'}",
        f"- Loopback HTTP probe requested: {str(report.loopback_http_probe_requested).lower()}",
    ]
    lines += ["", "### Complete observation register", ""]
    if report.observations:
        for item in report.observations:
            lines.append(
                f"- **{item.evidence_id}** (`{item.check_id or 'unknown check'}`, {item.status.value if item.status else 'status unavailable'}): {_markdown_text(item.summary)}"
            )
    else:
        lines.append("No observations were collected.")

    lines += ["", "### Checks and structured metrics", ""]
    if report.checks:
        for check in report.checks:
            lines.append(f"#### `{check.check_id}` — {check.status.value.upper()}")
            lines += ["", _markdown_text(check.summary)]
            if check.metrics:
                lines.append("")
                lines.extend(
                    f"- `{key}`: `{value if value is not None else 'unavailable'}`"
                    for key, value in sorted(check.metrics.items())
                )
            if check.note:
                lines += ["", f"Note: {_markdown_text(check.note)}"]
            if check.status == CheckStatus.SKIPPED:
                lines.append("Collection state: explicitly skipped.")
            lines.append("")
    else:
        lines.append("No diagnostic checks were available.")

    lines += ["### Timestamped event timeline", ""]
    if report.timeline:
        lines.extend(
            f"- **{item.event_id}** {item.timestamp_utc.isoformat()} — {item.classification.value}: {_markdown_text(item.summary)}"
            for item in report.timeline
        )
    else:
        lines.append(
            "No qualifying timestamped events were included. This does not prove that no event occurred."
        )

    lines += ["", "### Complete conclusion register", ""]
    if report.conclusions:
        lines.extend(_render_conclusion(item) for item in report.conclusions)
    else:
        lines.append("No conclusions were generated.")
    lines += ["", "### All recorded limitations", ""]
    if report.evidence_gaps:
        lines.extend(f"- {_markdown_text(value)}" for value in report.evidence_gaps)
    else:
        lines.append("No specific evidence gaps were recorded.")
    if report.investigation_areas:
        lines += ["", "### Investigation areas (not diagnoses)", ""]
        lines.extend(f"- {_markdown_text(value)}" for value in report.investigation_areas)
    if report.next_actions:
        lines += ["", "### Complete recommended-action list", ""]
        lines.extend(f"- {_markdown_text(value)}" for value in report.next_actions)

    lines += [
        "",
        "### Privacy and interpretation",
        "",
        "Exports use allowlisted, sanitized summaries and structured metrics; raw command output, journal lines, configuration contents, local paths, credentials and application response bodies are not exported. Sanitization is pattern-based and is not a universal secret scanner. Review the full report before sharing. A successful collection check does not establish application health; a loopback result does not establish public reachability; event timing does not prove causation.",
        "",
    ]
    if report.profile == "fastvps":
        lines += [
            "### FastVPS support context",
            "",
            "This is an independent, unofficial tool and does not connect to FastVPS systems. Support scope depends on the customer's ordered plan. Review the report before contacting [official FastVPS support](https://fastvps.gr/en/faq/).",
            "",
        ]
    return "\n".join(lines)


def _scenario_label(scenario: TroubleshootScenario) -> str:
    return {
        TroubleshootScenario.WEBSITE_UNAVAILABLE: "Website or application unavailable",
        TroubleshootScenario.SERVICE_CRASH: "Service crash or restart",
        TroubleshootScenario.STORAGE: "Storage or write problem",
    }[scenario]


def _overall_assessment(report: TroubleshootReport) -> str:
    checks = {check.check_id: check for check in report.checks}
    service_state = checks.get("troubleshoot.service")
    service_state_value = (
        service_state.metrics.get("service_state") if service_state is not None else None
    )
    http_check = checks.get("troubleshoot.http")
    http_code = http_check.metrics.get("http_status_code") if http_check is not None else None
    root_check = checks.get("storage.root")
    root_readonly = root_check.metrics.get("readonly") if root_check is not None else None
    expected_listener_absent = (
        report.scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
        and service_state is not None
        and report.selected_port is not None
        and checks.get("network.listeners") is not None
        and checks["network.listeners"].metrics.get(f"port_{report.selected_port}_listeners") == 0
    )
    failure_event = any(
        event.classification.value == "service_failure" for event in report.timeline
    )
    if (
        service_state_value == "failed"
        or failure_event
        or (isinstance(http_code, int) and 500 <= http_code <= 599)
    ):
        return "Evidence of a specific failure"

    if (
        any(item.certainty == EvidenceCertainty.PLAUSIBLE for item in report.conclusions)
        or any(check.status in {CheckStatus.WARNING, CheckStatus.FAIL} for check in report.checks)
        or root_readonly is True
        or expected_listener_absent
    ):
        return "Possible issue requiring investigation"

    if (
        any(item.certainty == EvidenceCertainty.INSUFFICIENT for item in report.conclusions)
        or any(
            check.status in {CheckStatus.UNKNOWN, CheckStatus.SKIPPED} for check in report.checks
        )
        or (
            report.scenario == TroubleshootScenario.SERVICE_CRASH
            and not any(
                event.classification.value == "service_failure" for event in report.timeline
            )
            and service_state_value != "failed"
        )
        or (report.scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE and http_check is None)
    ):
        return "Inconclusive / insufficient evidence"

    return "No relevant problem detected in available checks"


def _prioritized_observations(
    report: TroubleshootReport,
) -> list[TroubleshootObservation]:
    order = {
        TroubleshootScenario.WEBSITE_UNAVAILABLE: (
            "troubleshoot.service",
            "troubleshoot.http",
            "network.listeners",
            "troubleshoot.web_services",
            "storage.root",
            "storage.mounts",
            "system.resources",
        ),
        TroubleshootScenario.SERVICE_CRASH: (
            "troubleshoot.service",
            "system.resources",
            "storage.root",
            "storage.mounts",
        ),
        TroubleshootScenario.STORAGE: (
            "storage.root",
            "storage.mounts",
            "troubleshoot.service",
            "system.resources",
        ),
    }[report.scenario]
    priorities = {check_id: index for index, check_id in enumerate(order)}
    return sorted(
        report.observations,
        key=lambda item: (priorities.get(item.check_id or "", len(priorities)), item.evidence_id),
    )


def _summary_observations(report: TroubleshootReport) -> list[TroubleshootObservation]:
    """Keep redundant connection-failure and no-listener facts together in the appendix only."""
    observations = _prioritized_observations(report)
    if report.scenario != TroubleshootScenario.WEBSITE_UNAVAILABLE or report.selected_port is None:
        return observations
    checks = {check.check_id: check for check in report.checks}
    http_check = checks.get("troubleshoot.http")
    listener_check = checks.get("network.listeners")
    if (
        http_check is not None
        and http_check.metrics.get("http_probe_state") == "connection_error"
        and listener_check is not None
        and listener_check.metrics.get(f"port_{report.selected_port}_listeners") == 0
    ):
        primary_checks = {
            "troubleshoot.service",
            "network.listeners",
            "troubleshoot.web_services",
        }
        return [item for item in observations if item.check_id in primary_checks]
    return observations


def _observation_title(check_id: str | None) -> str:
    return {
        "troubleshoot.service": "Selected service state",
        "troubleshoot.http": "Local HTTP probe",
        "network.listeners": "Local listening ports",
        "troubleshoot.web_services": "Common web-server inventory",
        "storage.root": "Root filesystem capacity",
        "storage.mounts": "Additional filesystem inventory",
        "system.resources": "Current resource snapshot",
    }.get(check_id or "", "Diagnostic observation")


def _observation_relevance(report: TroubleshootReport, observation: TroubleshootObservation) -> str:
    check = next((item for item in report.checks if item.check_id == observation.check_id), None)
    metrics = check.metrics if check is not None else {}
    check_id = observation.check_id
    if check_id == "troubleshoot.service":
        state = metrics.get("service_state")
        if state == "failed":
            return "Confirms the selected unit failed; it does not identify why."
        if state == "active":
            return "Current state only; historical health and app routes remain unverified."
        if state in {"permission_restricted", "unavailable"}:
            return "Access limits leave service state and history unknown."
        return "One unit snapshot cannot establish root cause."
    if check_id == "troubleshoot.http":
        state = metrics.get("http_probe_state")
        if state == "response_5xx":
            return "The local handler returned an error; public reachability was not tested."
        if state == "connection_error":
            return "No local response on this port; the responsible component remains unknown."
        if isinstance(state, str) and state.startswith("response_"):
            return "One local HEAD response does not verify the app route or public access."
        return "The probe was incomplete; app and public health remain unknown."
    if check_id == "network.listeners":
        expected_ports = (
            [report.selected_port]
            if report.selected_port is not None
            else [80, 443]
            if report.scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
            else []
        )
        counts = [metrics.get(f"port_{port}_listeners") for port in expected_ports]
        if counts and all(count == 0 for count in counts):
            return "No listener on checked port(s); another port, proxy or container may differ."
        if any(isinstance(count, int) and count > 0 for count in counts):
            return "A listener is present; app route and public access remain unverified."
        return "Local snapshot only; remote access was not tested."
    if check_id == "troubleshoot.web_services":
        if metrics.get("nginx_installed") is False and metrics.get("apache2_installed") is False:
            return "Only common Nginx and Apache names were checked; another server may be used."
        return "This inventory covers common Nginx and Apache names only."
    if check_id == "storage.root":
        if metrics.get("readonly") is True:
            return "Can block writes, but the app may use another filesystem."
        return "Point-in-time capacity does not establish the app's write path or cause."
    if check_id == "storage.mounts":
        return "Bounded counters only; mount paths and files were not inspected."
    if check_id == "system.resources":
        return "Brief snapshot; does not show earlier pressure or cause."
    if observation.status in {CheckStatus.UNKNOWN, CheckStatus.SKIPPED}:
        return "Incomplete evidence cannot establish service health."
    return "Bounded context; does not independently establish root cause."


def _render_conclusion(item: TroubleshootConclusion) -> str:
    evidence = ", ".join(item.evidence_ids) or "no direct evidence reference"
    return f"- **{item.certainty.value.title()}** ({evidence}): {_markdown_text(item.statement)}"


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
        elif check.check_id == "network.listeners":
            if any(item.check_id == "troubleshoot.web_services" for item in checks):
                listener_ports = [80, 443] + ([port] if port not in {None, 80, 443} else [])
                details = [
                    f"port {checked_port} {check.metrics.get(f'port_{checked_port}_listeners') if check.metrics.get(f'port_{checked_port}_listeners') is not None else 'unavailable'}"
                    for checked_port in listener_ports
                ]
                detail = "Local HTTP/HTTPS listener inventory: " + "; ".join(details) + "."
            elif port is not None:
                count = check.metrics.get(f"port_{port}_listeners")
                detail = f"Local listener inventory for selected port: {count if count is not None else 'unavailable'} listener(s)."
            else:
                detail = "A local listener inventory was collected."
        elif check.check_id == "troubleshoot.web_services":
            inventory = []
            for name in WEB_SERVICE_NAMES:
                installed = check.metrics.get(f"{name}_installed")
                state = check.metrics.get(f"{name}_state")
                install_label = (
                    "detected"
                    if installed is True
                    else "not detected"
                    if installed is False
                    else "undetermined"
                )
                state_label = state if isinstance(state, str) else "undetermined"
                inventory.append(f"{name}: {install_label}; unit state {state_label}")
            detail = "Common web-service inventory: " + "; ".join(inventory) + "."
        elif check.check_id == "troubleshoot.http":
            state = check.metrics.get("http_probe_state", "unavailable")
            code = check.metrics.get("http_status_code")
            detail = f"Loopback HTTP HEAD result: {state}; status code {code if code is not None else 'not available'}."
        elif check.check_id == "storage.mounts":
            count = check.metrics.get("mount_count")
            inspected = check.metrics.get("inspected_mount_count")
            detail = (
                f"Additional local filesystems: inspected {inspected if inspected is not None else 'unavailable'}"
                f" of {count if count is not None else 'unavailable'} inventoried; paths are withheld."
            )
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
    if service_check is None and scenario in {
        TroubleshootScenario.WEBSITE_UNAVAILABLE,
        TroubleshootScenario.SERVICE_CRASH,
    }:
        statement = (
            "No application service was identified, so this report cannot link a local listener to the affected application or assess that application's service health, logs or configuration. The missing name is not evidence that the application is unhealthy, and this does not confirm a website outage."
            if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
            else "No application service was identified, so this report cannot confirm whether a particular service crashed or restarted, inspect its logs, or attribute a cause. This is insufficient evidence, not evidence that a service is unhealthy."
        )
        conclusions.append(
            TroubleshootConclusion(
                certainty=EvidenceCertainty.INSUFFICIENT,
                statement=statement,
            )
        )
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

    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        web_services = by_id.get("troubleshoot.web_services")
        web_evidence = observations.get("troubleshoot.web_services")
        if web_services is not None and web_evidence:
            installed = [
                web_services.metrics.get(f"{name}_installed") for name in WEB_SERVICE_NAMES
            ]
            if installed == [False, False]:
                conclusions.append(
                    TroubleshootConclusion(
                        certainty=EvidenceCertainty.CONFIRMED,
                        statement=(
                            "No common Nginx or Apache executable or service unit was detected. "
                            "This does not confirm a website outage and does not rule out another web server, proxy or container."
                        ),
                        evidence_ids=[web_evidence],
                    )
                )
            else:
                for name, label in (("nginx", "Nginx"), ("apache2", "Apache")):
                    unit_found = web_services.metrics.get(f"{name}_unit_found")
                    state = web_services.metrics.get(f"{name}_state")
                    installed_state = web_services.metrics.get(f"{name}_installed")
                    if unit_found is True and isinstance(state, str):
                        conclusions.append(
                            TroubleshootConclusion(
                                certainty=EvidenceCertainty.CONFIRMED,
                                statement=f"The local inventory detected a {label} service unit reported as {state}; this does not establish application or public website health.",
                                evidence_ids=[web_evidence],
                            )
                        )
                    elif installed_state is True and state == "unit_not_found":
                        conclusions.append(
                            TroubleshootConclusion(
                                certainty=EvidenceCertainty.CONFIRMED,
                                statement=f"A {label} executable was detected, but no matching systemd service unit was found; this does not establish whether it serves the reported website.",
                                evidence_ids=[web_evidence],
                            )
                        )
                    elif installed_state is None or state in UNCERTAIN_STATES:
                        conclusions.append(
                            TroubleshootConclusion(
                                certainty=EvidenceCertainty.INSUFFICIENT,
                                statement=f"The local inventory could not determine whether {label} is installed or managed by systemd.",
                                evidence_ids=[web_evidence],
                            )
                        )
                if not any(item.evidence_ids == [web_evidence] for item in conclusions):
                    conclusions.append(
                        TroubleshootConclusion(
                            certainty=EvidenceCertainty.INSUFFICIENT,
                            statement="The common web service inventory was incomplete, so it cannot establish whether Nginx or Apache is installed or managed by systemd.",
                            evidence_ids=[web_evidence],
                        )
                    )

        listener_check = by_id.get("network.listeners")
        listener_evidence = observations.get("network.listeners")
        if web_services is not None:
            ports = [80, 443]
            if port is not None and port not in ports:
                ports.append(port)
        else:
            ports = [port] if port is not None else [80, 443]
        if listener_check is not None and listener_evidence:
            for checked_port in ports:
                count = listener_check.metrics.get(f"port_{checked_port}_listeners")
                if isinstance(count, int):
                    conclusions.append(
                        TroubleshootConclusion(
                            certainty=EvidenceCertainty.CONFIRMED,
                            statement=(
                                f"The local listener inventory reported no listener on port {checked_port} at snapshot time. This does not confirm a website outage."
                                if count == 0
                                else f"The local listener inventory reported {count} listener(s) on port {checked_port}; this does not prove the application route or public reachability works."
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
    scenario: TroubleshootScenario,
    checks: list[DiagnosticCheck],
    analysis: IncidentAnalysis | None,
) -> list[str]:
    by_id = {check.check_id: check for check in checks}
    areas: list[str] = []
    service = by_id.get("troubleshoot.service")
    service_state = service.metrics.get("service_state") if service else None
    listener = by_id.get("network.listeners")

    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        if service is None:
            areas.append(
                "Identify the affected application, deployment method and expected local port before drawing service-specific conclusions."
            )
        elif service_state == "failed":
            areas.append(
                "The selected unit is currently failed; inspect its local startup journal and application exit details to determine why."
            )
        if listener is not None and any(
            value == 0
            for key, value in listener.metrics.items()
            if key.startswith("port_") and key.endswith("_listeners")
        ):
            areas.append(
                "Compare the application's intended bind address and port with the local listener inventory."
            )
        elif service is not None:
            areas.append(
                "Compare the selected unit's intended bind address and port with the observed listener state."
            )
        inventory = by_id.get("troubleshoot.web_services")
        if (
            inventory is not None
            and inventory.metrics.get("nginx_installed") is False
            and inventory.metrics.get("apache2_installed") is False
        ):
            areas.append(
                "The common Nginx and Apache names were not detected; confirm whether the application uses another proxy, web server or container."
            )
        http = by_id.get("troubleshoot.http")
        if http is not None and http.metrics.get("http_probe_state") == "response_5xx":
            areas.append(
                "A local HTTP server returned a 5xx response; inspect the relevant application route or upstream separately."
            )
    elif scenario == TroubleshootScenario.SERVICE_CRASH:
        if service is None:
            areas.append(
                "Identify the affected systemd unit or deployment manager; no service-specific history was collected."
            )
        elif analysis is not None and analysis.events:
            areas.append(
                "Compare the classified service events with the full local journal and application logs around those timestamps."
            )
        elif service_state == "failed":
            areas.append(
                "The selected unit is failed, but no qualifying event was captured; inspect its exit details and local startup journal."
            )
        else:
            areas.append(
                "Compare the report window with the application's own logs and deployment history; current service state alone cannot explain a past crash."
            )
        if analysis and any(event.classification.value == "oom_kill" for event in analysis.events):
            areas.append(
                "Review nearby kernel memory events and service records independently; timestamp proximity does not establish causation."
            )
    else:
        root = by_id.get("storage.root")
        readonly = root.metrics.get("readonly") if root else None
        if readonly is True:
            areas.append(
                "The root filesystem is reported read-only; confirm whether the affected application's write path is on that filesystem."
            )
        else:
            areas.append(
                "Identify the exact filesystem and path used by the failing application, then compare it with the bounded capacity counters."
            )
        areas.append(
            "Correlate the application error time with its own logs and any service evidence; this tool did not inspect customer files."
        )

    if any(check.status in {CheckStatus.UNKNOWN, CheckStatus.SKIPPED} for check in checks):
        areas.append(
            "Resolve the specifically listed incomplete checks if they are needed for this incident."
        )
    return list(dict.fromkeys(areas))[:4]


def _evidence_gaps(
    scenario: TroubleshootScenario,
    checks: list[DiagnosticCheck],
    analysis: IncidentAnalysis | None,
    probe_http: bool,
) -> list[str]:
    gaps: list[str] = []
    check_ids = {check.check_id for check in checks}
    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        if "troubleshoot.service" not in check_ids:
            gaps.append(
                "No systemd unit was selected: service state, restart counters, service logs and configuration were not checked; this is not evidence of a service failure."
            )
        if not probe_http:
            gaps.append(
                "The loopback HTTP probe was skipped by design because it is opt-in; no HTTP response was observed."
            )
        gaps.append(
            "No external DNS, TLS, public reachability or provider network-path checks were performed."
        )
        if "network.listeners" in check_ids and "troubleshoot.service" not in check_ids:
            gaps.append(
                "No application-specific port was selected; only the limited common HTTP/HTTPS listener ports were checked."
            )
    if scenario == TroubleshootScenario.SERVICE_CRASH and "troubleshoot.service" not in check_ids:
        gaps.append(
            "No systemd unit was selected. Service-specific health and cause therefore remain unknown."
        )
    if scenario == TroubleshootScenario.STORAGE:
        gaps.append(
            "The application write path, per-user quota and file ownership were not checked; no customer files were searched."
        )
    if analysis is not None:
        if not analysis.complete:
            if analysis.unavailable_sources:
                sources = ", ".join(
                    source.replace("_", " ") for source in analysis.unavailable_sources
                )
                gaps.append(
                    f"The bounded {sources} query was unavailable or incomplete; its precise access or tool failure reason was not retained in the export."
                )
            else:
                gaps.append(
                    "The bounded journal output was malformed or exceeded its record limit; event history may be incomplete."
                )
        elif not analysis.events:
            gaps.append(
                "No qualifying timestamped event matched the bounded journal window; unclassified or unretained events may still exist."
            )
        elif not any(event.classification.value == "service_failure" for event in analysis.events):
            gaps.append(
                "The timeline contains classified events but no confirmed service-failure transition; event timing alone cannot establish root cause."
            )
    for check in checks:
        if check.status == CheckStatus.SKIPPED:
            gaps.append(
                f"{check.check_id} was skipped: {check.summary}"
                + (f" {check.note}" if check.note else "")
            )
        elif check.status == CheckStatus.UNKNOWN:
            states = {
                str(value)
                for key, value in check.metrics.items()
                if key.endswith("_state") and isinstance(value, str)
            }
            if "permission_restricted" in states:
                reason = "Permission was denied or restricted."
            elif "timeout" in states:
                reason = "The check timed out."
            elif "unavailable" in states:
                reason = "A required local tool or service manager was unavailable."
            elif states & {"unsupported_filesystem", "remote_skipped"}:
                reason = (
                    "Unsupported or remote filesystem entries were intentionally not inspected."
                )
            elif "partial" in states:
                reason = (
                    "One or more counters or entries were unavailable, so this result is partial."
                )
            else:
                reason = "The check returned incomplete or unknown evidence."
            gaps.append(f"{check.check_id}: {reason} {check.summary}")
    return gaps


def _next_actions(
    scenario: TroubleshootScenario,
    *,
    service_selected: bool,
    checks: list[DiagnosticCheck],
    analysis: IncidentAnalysis | None,
    port: int | None,
) -> list[str]:
    by_id = {check.check_id: check for check in checks}
    service = by_id.get("troubleshoot.service")
    service_state = service.metrics.get("service_state") if service else None
    actions: list[str]
    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        if not service_selected:
            actions = [
                "Identify the affected application, its deployment method and expected local port with the site administrator; do not guess a unit name.",
                "After confirming those details, rerun the check with the exact service unit and port so its state and listener can be compared.",
                "Have an administrator review DNS, TLS, proxy routing and public reachability separately; those paths were not tested here.",
            ]
        else:
            actions = []
            if service_state == "failed":
                actions.append(
                    "Review the selected unit's local journal and exit details around the failure time; the export omits raw log messages."
                )
            if port is not None:
                actions.append(
                    f"Compare the application's intended bind address and port {port} with the observed local listener state."
                )
            if not actions:
                actions.append(
                    "Compare the selected unit and local HTTP response with the application's intended route and upstream."
                )
            actions.append(
                "Have an administrator assess public DNS, TLS and proxy reachability separately; this report only covers selected local checks."
            )
    elif scenario == TroubleshootScenario.SERVICE_CRASH:
        if not service_selected:
            actions = [
                "Identify the affected application and its systemd unit or other deployment manager with the administrator; do not substitute an unrelated service.",
                "Rerun the bounded service timeline using the confirmed unit and incident time window.",
            ]
        else:
            failure_event = (
                next(
                    (
                        event
                        for event in analysis.events
                        if event.classification.value == "service_failure"
                    ),
                    None,
                )
                if analysis is not None
                else None
            )
            review_window = (
                f" around {failure_event.timestamp_utc.isoformat()}"
                if failure_event is not None
                else " around the reported incident time"
            )
            actions = [
                "Have an administrator compare the unit's exit details with its full local journal and application logs"
                + review_window
                + ".",
                "Compare deployment and dependency changes from the same interval; event correlation alone does not prove cause.",
            ]
    else:
        actions = [
            "Identify the exact filesystem and path used by the failing application, then compare its space and inode counters with read-only tools.",
            "Have an administrator correlate the application error with quota, mount and service evidence before considering changes.",
            "Do not delete files or change mount settings based only on this snapshot.",
        ]
    actions.append("Review the sanitized report before attaching it to a support request.")
    return list(dict.fromkeys(actions))[:4]


def _markdown_text(value: str) -> str:
    flattened = " ".join(value.splitlines())
    escaped = html.escape(flattened, quote=False)
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", "!", "|"):
        escaped = escaped.replace(character, "\\" + character)
    return escaped

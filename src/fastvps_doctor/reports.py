"""Local JSON and Markdown support report generation."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from fastvps_doctor import __version__
from fastvps_doctor.config import Thresholds
from fastvps_doctor.models import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticReport,
    IncidentAnalysis,
    IncidentInformation,
    SupportHandoff,
    SupportSummary,
)
from fastvps_doctor.platform import linux_distribution
from fastvps_doctor.privacy import (
    sanitize_checks,
    sanitize_distribution,
    sanitize_findings,
    sanitize_handoff,
    sanitize_incident_analysis,
    sanitize_incident_information,
    sanitize_ticket_reference,
)
from fastvps_doctor.rules import analyze

CHECK_COVERAGE = (
    (
        {"system.resources"},
        "CPU, memory, swap, load, uptime and available Linux pressure indicators",
    ),
    ({"system.identity"}, "Linux distribution and kernel identifiers"),
    ({"storage.root"}, "Root filesystem space, inodes and read-only state"),
    ({"storage.mounts"}, "Bounded capacity and inode indicators for local mounted filesystems"),
    (
        {"network.local"},
        "Local interfaces, address counts, route and resolver indicators",
    ),
    ({"network.listeners"}, "Selected local listening-port inventory"),
    (
        {"services.common"},
        "Common service/systemd state; validators run only when explicitly enabled",
    ),
    ({"security.local"}, "Limited SSH, UFW and optional package-update indicators"),
    ({"web.local"}, "Loopback HTTP/HTTPS reachability and selected local listeners"),
)


def _finding_check_ids(finding_id: str) -> set[str]:
    if finding_id.startswith("STOR-"):
        try:
            number = int(finding_id.removeprefix("STOR-"))
        except ValueError:
            return set()
        return {"storage.root"} if number <= 4 else {"storage.mounts"}
    for prefix, check_id in (
        ("SYS-", "system.resources"),
        ("SVC-", "services.common"),
        ("NET-", "network.local"),
        ("WEB-", "web.local"),
        ("SEC-", "security.local"),
    ):
        if finding_id.startswith(prefix):
            return {check_id}
    return set()


def build_report(
    checks: list[DiagnosticCheck],
    thresholds: Thresholds | None = None,
    profile: str | None = None,
    ticket_reference: str | None = None,
    incident_information: IncidentInformation | None = None,
    incident_analysis: IncidentAnalysis | None = None,
) -> DiagnosticReport:
    safe_profile = "fastvps" if profile == "fastvps" else None
    # Apply the allowlist before any export or rule generation.
    clean_checks = sanitize_checks(checks)
    safe_incident_information = sanitize_incident_information(incident_information)
    safe_incident_analysis = sanitize_incident_analysis(incident_analysis)
    findings = sanitize_findings(
        analyze(
            [check for check in clean_checks if check.status != CheckStatus.SKIPPED], thresholds
        )
    )
    affected_check_ids = {
        check_id for finding in findings for check_id in _finding_check_ids(finding.finding_id)
    }
    failed_check_ids = {
        check_id
        for finding in findings
        if finding.severity.value in {"high", "critical"}
        for check_id in _finding_check_ids(finding.finding_id)
    }
    clean_checks = [
        check.model_copy(
            update={
                "status": CheckStatus.FAIL
                if check.check_id in failed_check_ids
                else CheckStatus.WARNING
            }
        )
        if (
            check.check_id in affected_check_ids
            and check.status not in {CheckStatus.SKIPPED, CheckStatus.UNKNOWN}
        )
        else check
        for check in clean_checks
    ]
    if any(finding.severity.value == "critical" for finding in findings):
        overall = "critical"
    elif any(finding.severity.value == "high" for finding in findings):
        overall = "attention"
    elif any(finding.severity.value in {"medium", "low"} for finding in findings):
        overall = "review"
    elif not clean_checks or any(
        check.status in {CheckStatus.SKIPPED, CheckStatus.UNKNOWN} for check in clean_checks
    ):
        overall = "partial"
    else:
        overall = "no_major_findings"

    passed = [check.check_id for check in clean_checks if check.status == CheckStatus.PASS]
    warnings = [check.check_id for check in clean_checks if check.status == CheckStatus.WARNING]
    failed = [check.check_id for check in clean_checks if check.status == CheckStatus.FAIL]
    unavailable = [
        check.check_id
        for check in clean_checks
        if check.status in {CheckStatus.SKIPPED, CheckStatus.UNKNOWN}
    ]
    further = [step for finding in findings for step in finding.next_steps]
    if unavailable:
        further.append(
            "Review checks marked unavailable; permissions, platform support or missing tools may limit coverage."
        )
    if findings:
        overview = f"{len(findings)} evidence-based finding(s) need review. Diagnostic rules do not prove root cause or assign provider responsibility."
    else:
        overview = "No major issue matched the available rules. This is a limited diagnostic snapshot, not proof that the server is healthy or secure."
    if safe_profile == "fastvps":
        further.append(
            "FastVPS support scope depends on the ordered management plan; review this report before sharing it through the official support channel."
        )

    summary = SupportSummary(
        overview=overview,
        passed_checks=passed,
        warning_checks=warnings,
        failed_checks=failed,
        unavailable_checks=unavailable,
        further_investigation=list(dict.fromkeys(further)),
    )
    identity = next((check for check in clean_checks if check.check_id == "system.identity"), None)
    distribution_value = identity.metrics.get("distribution") if identity else None
    distribution = (
        sanitize_distribution(distribution_value)
        if isinstance(distribution_value, str)
        else sanitize_distribution(linux_distribution())
    )
    kernel_release = identity.metrics.get("kernel_release") if identity else None
    if not isinstance(kernel_release, str):
        kernel_release = None
    service_check = next(
        (check for check in clean_checks if check.check_id == "services.common"), None
    )
    installed_services: list[str] = []
    if service_check:
        for name in sorted(
            {"nginx", "apache", "ssh", "docker", "mysql", "mariadb", "postgresql", "redis"}
        ):
            if (
                service_check.metrics.get(f"{name}_unit_found") is True
                and service_check.metrics.get(f"{name}_state") != "alias"
            ):
                installed_services.append(name)
        for key, metric_name in service_check.metrics.items():
            if (
                key.startswith("custom_unit_")
                and key.endswith("_name")
                and isinstance(metric_name, str)
            ):
                index = key.removeprefix("custom_unit_").removesuffix("_name")
                if service_check.metrics.get(f"custom_unit_{index}_unit_found") is True:
                    installed_services.append(metric_name)

    if safe_incident_analysis:
        further.append(
            safe_incident_analysis.note
            or "Review the bounded incident timeline; it does not prove root cause."
        )
    observations = [
        f"{finding.title}: {evidence}" for finding in findings for evidence in finding.evidence
    ]
    investigation_areas = [cause for finding in findings for cause in finding.possible_causes]
    handoff_reported_problem = None
    if safe_incident_information:
        handoff_reported_problem = safe_incident_information.description
        if handoff_reported_problem is None and safe_incident_information.problem_category:
            handoff_reported_problem = (
                f"Reported {safe_incident_information.problem_category.value} issue"
            )
    if safe_incident_analysis:
        for hypothesis in safe_incident_analysis.hypotheses:
            observations.extend(hypothesis.evidence)
            investigation_areas.append(hypothesis.statement)
            further.extend(hypothesis.next_steps)
        summary = summary.model_copy(update={"further_investigation": list(dict.fromkeys(further))})
    handoff = sanitize_handoff(
        SupportHandoff(
            reported_problem=handoff_reported_problem,
            confirmed_observations=list(dict.fromkeys(observations)),
            investigation_areas=list(dict.fromkeys(investigation_areas)),
            unavailable_checks=unavailable
            + (
                [
                    f"Incident source: {source}"
                    for source in safe_incident_analysis.unavailable_sources
                ]
                if safe_incident_analysis
                else []
            ),
            next_actions=list(dict.fromkeys(further)),
        )
    )

    coverage = [
        description
        for check_ids, description in CHECK_COVERAGE
        if any(
            check.check_id in check_ids and check.status != CheckStatus.SKIPPED
            for check in clean_checks
        )
    ]
    if safe_incident_analysis:
        coverage.append("Bounded, timestamped service and kernel journal event classification")

    return DiagnosticReport(
        version=__version__,
        distribution=distribution,
        kernel_release=kernel_release,
        installed_services=installed_services,
        coverage=coverage,
        overall_status=overall,
        checks=clean_checks,
        findings=findings,
        support_summary=summary,
        profile=safe_profile,
        ticket_reference=sanitize_ticket_reference(ticket_reference),
        incident_information=safe_incident_information,
        incident_analysis=safe_incident_analysis,
        support_handoff=handoff,
    )


def render_markdown(report: DiagnosticReport) -> str:
    lines = [
        "# FastVPS Doctor support report",
        "",
        "> Independently developed and unofficial. Review this report before sharing.",
        "",
        "## Report header",
        "",
        f"- Product: {report.product} {report.version}",
        f"- Report schema: {report.schema_version}",
        f"- Scan timestamp (UTC): {report.timestamp_utc.isoformat()}",
        f"- Distribution: {report.distribution}",
        f"- Overall diagnostic status: **{report.overall_status}**",
        f"- Profile: {report.profile or 'standard'}",
    ]
    lines += ["", "## Environment summary", ""]
    lines.append(f"- Kernel: {report.kernel_release or 'not available'}")
    lines.append(
        "- Relevant systemd services: "
        + (", ".join(report.installed_services) if report.installed_services else "not detected")
    )
    lines.append(
        "- Checks needing review: "
        + (
            ", ".join(report.support_summary.unavailable_checks)
            if report.support_summary.unavailable_checks
            else "none recorded"
        )
    )
    if report.ticket_reference:
        lines.append(
            f"- Customer-entered ticket reference: `{_markdown_inline(report.ticket_reference)}`"
        )
    if report.incident_information:
        incident = report.incident_information
        lines += ["", "## Incident information", ""]
        if incident.start_time_utc:
            lines.append(f"- Incident start (UTC): {incident.start_time_utc.isoformat()}")
        if incident.affected_service:
            lines.append(f"- Affected service: {incident.affected_service}")
        if incident.problem_category:
            lines.append(f"- Problem category: {incident.problem_category.value}")
        if incident.description:
            lines.append(f"- Customer description: {incident.description}")
    lines += ["", "## Diagnostic coverage", ""]
    lines.extend(f"- {item}" for item in report.coverage)
    lines += ["", "## Support summary", "", report.support_summary.overview, ""]
    for label, values in (
        ("Checks passed", report.support_summary.passed_checks),
        ("Checks with warnings", report.support_summary.warning_checks),
        ("Checks failed", report.support_summary.failed_checks),
        ("Checks unavailable", report.support_summary.unavailable_checks),
    ):
        lines.append(f"### {label}")
        lines.append("")
        lines.extend(f"- `{item}`" for item in values) if values else lines.append(
            "- None reported"
        )
        lines.append("")

    lines += ["## Findings", ""]
    if not report.findings:
        lines.append("No findings matched the available rules.")
        lines.append("")
    for finding in report.findings:
        lines += [
            f"### {finding.finding_id}: {finding.title}",
            "",
            f"- Category: {finding.category}",
            f"- Severity: **{finding.severity.value}**",
            f"- Support scope: {finding.support_scope.value}",
            f"- Confidence: {finding.confidence}",
            f"- Additional privileges may be needed for investigation: {'yes' if finding.requires_privileges else 'no'}",
            "",
            finding.description,
            "",
            "Evidence:",
        ]
        lines.extend(f"- {item}" for item in finding.evidence)
        lines += ["", "Possible causes:"]
        lines.extend(f"- {item}" for item in finding.possible_causes)
        lines += ["", "Recommended next steps:"]
        lines.extend(f"- {item}" for item in finding.next_steps)
        lines.append("")

    if report.incident_analysis:
        analysis = report.incident_analysis
        lines += ["## Incident timeline", ""]
        lines.append(
            f"- Window: {analysis.window_seconds // 60} minutes ending at {analysis.generated_at_utc.isoformat()}"
        )
        lines.append(f"- Selected service: {analysis.service}")
        lines.append(f"- Evidence collection complete: {'yes' if analysis.complete else 'no'}")
        if analysis.note:
            lines.append(f"- Note: {analysis.note}")
        for event in analysis.events:
            line = (
                f"- {event.timestamp_utc.isoformat()} — {event.classification.value} "
                f"({event.component}): {event.evidence_summary}"
            )
            if event.correlation_explanation:
                line += f" {event.correlation_explanation}"
            lines.append(line)
        if not analysis.events:
            lines.append("- No qualifying timestamped events were available.")
        if analysis.hypotheses:
            lines += ["", "### Evidence-based hypotheses", ""]
            for hypothesis in analysis.hypotheses:
                lines.append(
                    f"- **{hypothesis.confidence.title()} confidence:** {hypothesis.statement}"
                )
                lines.append(
                    f"  Time interval: {hypothesis.start_time_utc.isoformat()} to {hypothesis.end_time_utc.isoformat()}"
                )
                lines.extend(f"  Evidence: {item}" for item in hypothesis.evidence)
                lines.extend(f"  Alternative: {item}" for item in hypothesis.alternatives)
                lines.extend(f"  Next step: {item}" for item in hypothesis.next_steps)
        lines.append("")

    lines += ["## Support handoff", ""]
    handoff = report.support_handoff
    lines.append(f"- Reported problem: {handoff.reported_problem or 'not provided'}")
    for label, values in (
        ("Confirmed observations", handoff.confirmed_observations),
        ("Likely investigation areas", handoff.investigation_areas),
        ("Checks unavailable or incomplete", handoff.unavailable_checks),
        ("Suggested next actions", handoff.next_actions),
    ):
        lines.append(f"### {label}")
        lines.append("")
        lines.extend(f"- {item}" for item in values) if values else lines.append("- None recorded")
        lines.append("")

    lines += ["## Further investigation", ""]
    lines.extend(f"- {item}" for item in report.support_summary.further_investigation)
    if not report.support_summary.further_investigation:
        lines.append("- No additional investigation step was generated.")
    if report.profile == "fastvps":
        lines += [
            "",
            "## FastVPS support context",
            "",
            "This independent tool does not connect to FastVPS systems. Infrastructure monitoring and guest operating system/application responsibilities depend on the customer's ordered plan and agreed scope.",
            "Review the complete report and remove anything you do not wish to share before contacting [official FastVPS support](https://fastvps.gr/en/faq/).",
        ]
    lines += [
        "",
        "## Privacy and limitations",
        "",
        "This report uses allowlisted, summarized metrics. It excludes hostnames, IP addresses, usernames, filesystem paths, credentials, raw configuration contents and raw logs by default. Diagnostic coverage is limited and does not establish root cause, provider responsibility or overall security.",
        "",
    ]
    return "\n".join(lines)


def write_exclusive(path: Path, content: str) -> None:
    """Create a private report without replacing an existing file."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
    except BaseException:
        # Do not leave a partial report that could be mistaken for a complete export.
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _markdown_inline(value: str) -> str:
    return value.replace("`", "\\`").replace("[", "\\[").replace("]", "\\]")

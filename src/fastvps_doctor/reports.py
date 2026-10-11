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
    SupportSummary,
)
from fastvps_doctor.platform import linux_distribution
from fastvps_doctor.privacy import (
    sanitize_checks,
    sanitize_distribution,
    sanitize_findings,
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
    (
        {"network.local"},
        "Local interfaces, address counts, route and resolver indicators",
    ),
    ({"network.listeners"}, "Selected local listening-port inventory"),
    (
        {"services.common"},
        "Common service presence, systemd state and selected read-only validators",
    ),
    ({"security.local"}, "Limited SSH, UFW and optional package-update indicators"),
    ({"web.local"}, "Loopback HTTP/HTTPS reachability and selected local listeners"),
)


def build_report(
    checks: list[DiagnosticCheck],
    thresholds: Thresholds | None = None,
    profile: str | None = None,
    ticket_reference: str | None = None,
) -> DiagnosticReport:
    safe_profile = "fastvps" if profile == "fastvps" else None
    # Apply the allowlist before any export or rule generation.
    clean_checks = sanitize_checks(checks)
    findings = sanitize_findings(
        analyze(
            [check for check in clean_checks if check.status != CheckStatus.SKIPPED], thresholds
        )
    )
    category_check_ids = {
        "system": {"system.resources"},
        "storage": {"storage.root"},
        "network": {"network.local"},
        "services": {"services.common"},
        "security": {"security.local"},
        "web": {"web.local"},
    }
    affected_check_ids = {
        check_id
        for finding in findings
        for check_id in category_check_ids.get(finding.category, set())
    }
    failed_check_ids = {
        check_id
        for finding in findings
        if finding.severity.value in {"high", "critical"}
        for check_id in category_check_ids.get(finding.category, set())
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
    return DiagnosticReport(
        version=__version__,
        distribution=sanitize_distribution(linux_distribution()),
        coverage=[
            description
            for check_ids, description in CHECK_COVERAGE
            if any(
                check.check_id in check_ids and check.status != CheckStatus.SKIPPED
                for check in clean_checks
            )
        ],
        overall_status=overall,
        checks=clean_checks,
        findings=findings,
        support_summary=summary,
        profile=safe_profile,
        ticket_reference=sanitize_ticket_reference(ticket_reference),
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
        f"- Scan timestamp (UTC): {report.timestamp_utc.isoformat()}",
        f"- Distribution: {report.distribution}",
        f"- Overall diagnostic status: **{report.overall_status}**",
        f"- Profile: {report.profile or 'standard'}",
    ]
    if report.ticket_reference:
        lines.append(
            f"- Customer-entered ticket reference: `{_markdown_inline(report.ticket_reference)}`"
        )
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

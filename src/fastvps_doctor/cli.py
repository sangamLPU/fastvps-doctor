"""Typer command-line interface for FastVPS Doctor."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from fastvps_doctor import __version__
from fastvps_doctor.checks.network import collect_listeners, collect_network
from fastvps_doctor.checks.security import collect_security
from fastvps_doctor.checks.services import SERVICE_DEFINITIONS, collect_services
from fastvps_doctor.checks.storage import collect_storage
from fastvps_doctor.checks.system import collect_system
from fastvps_doctor.checks.web import collect_web
from fastvps_doctor.config import load_thresholds
from fastvps_doctor.incident_analysis import analyze_incident, parse_time_window
from fastvps_doctor.models import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticReport,
    IncidentInformation,
    ProblemCategory,
    TroubleshootReport,
    TroubleshootScenario,
)
from fastvps_doctor.reports import build_report, render_markdown, write_exclusive
from fastvps_doctor.rules import rule_catalog
from fastvps_doctor.runner import safe_hostname, safe_systemd_unit
from fastvps_doctor.troubleshoot import (
    build_troubleshoot_report,
    discover_relevant_services,
    render_troubleshoot_markdown,
)

app = typer.Typer(
    name="fastvps-doctor",
    help="Read-only Linux diagnostics and local support report generation.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="markdown",
)


def _console(ctx: typer.Context) -> Console:
    options = ctx.obj or {}
    return Console(no_color=options.get("no_color", False))


def _uses_ascii(ctx: typer.Context) -> bool:
    options = ctx.obj or {}
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    return options.get("ascii", False) or not encoding.startswith("utf")


def _table_box(ctx: typer.Context) -> box.Box:
    return box.ASCII if _uses_ascii(ctx) else box.SIMPLE


@app.callback()
def main(
    ctx: typer.Context,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable terminal colors.")] = False,
    ascii_output: Annotated[bool, typer.Option("--ascii", help="Use ASCII table borders.")] = False,
) -> None:
    ctx.ensure_object(dict)
    ctx.obj["no_color"] = no_color
    ctx.obj["ascii"] = ascii_output


def _all_checks(
    *,
    full: bool = False,
    resolve: str | None = None,
    connect: tuple[str, int] | None = None,
    required_port: int | None = None,
    custom_units: tuple[str, ...] = (),
) -> list[DiagnosticCheck]:
    checks: list[DiagnosticCheck] = []
    checks.extend(collect_system())
    checks.extend(collect_storage())
    checks.extend(collect_network(resolve=resolve, connect=connect))
    checks.append(collect_listeners())
    checks.extend(collect_services(custom_units=custom_units))
    checks.extend(collect_security(include_update_simulation=full))
    checks.extend(collect_web(required_port=required_port))
    return checks


def _incident_information(
    start: str | None,
    affected_service: str | None,
    category: str | None,
    description: str | None,
) -> IncidentInformation | None:
    if start is None and affected_service is None and category is None and description is None:
        return None
    start_time = None
    if start:
        try:
            start_time = datetime.fromisoformat(start.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(
                "Incident start must be an ISO 8601 timestamp with a timezone."
            ) from exc
        if start_time.tzinfo is None or start_time.utcoffset() is None:
            raise ValueError(
                "Incident start must include a timezone, for example 2026-10-11T12:00:00Z."
            )
    try:
        problem_category = ProblemCategory(category.lower()) if category else None
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ProblemCategory)
        raise ValueError(f"Problem category must be one of: {allowed}.") from exc
    return IncidentInformation(
        start_time_utc=start_time,
        affected_service=affected_service,
        problem_category=problem_category,
        description=description,
    )


def _report_content(report: DiagnosticReport, output_format: str) -> str:
    normalized_format = output_format.lower()
    if normalized_format not in {"json", "markdown", "md"}:
        raise typer.BadParameter("Choose json or markdown.")
    return report.json_document() + "\n" if normalized_format == "json" else render_markdown(report)


def _emit_report(report: DiagnosticReport, output_format: str, output: Path | None) -> None:
    content = _report_content(report, output_format)
    if output:
        try:
            write_exclusive(output, content)
        except FileExistsError:
            raise typer.BadParameter(
                "The output file already exists; choose a new path to avoid overwriting it."
            ) from None
        except OSError as exc:
            raise typer.BadParameter(f"Could not create report ({type(exc).__name__}).") from None
        typer.echo(f"Created local report: {output}")
    else:
        typer.echo(content)


def _emit_troubleshoot_report(
    report: TroubleshootReport, output_format: str, output: Path | None
) -> None:
    normalized_format = output_format.lower()
    if normalized_format not in {"json", "markdown", "md"}:
        raise typer.BadParameter("Choose json or markdown.")
    if output is None:
        if normalized_format == "json":
            typer.echo(report.json_document())
            return
        _render_troubleshoot_summary(report)
        return
    content = (
        report.json_document() + "\n"
        if normalized_format == "json"
        else render_troubleshoot_markdown(report)
    )
    try:
        write_exclusive(output, content)
    except FileExistsError:
        raise typer.BadParameter(
            "The output file already exists; choose a new path to avoid overwriting it."
        ) from None
    except OSError as exc:
        raise typer.BadParameter(f"Could not create report ({type(exc).__name__}).") from None
    typer.echo(f"Created local report: {output}")


def _render_troubleshoot_summary(report: TroubleshootReport) -> None:
    typer.echo(f"Scenario: {report.scenario.value}")
    typer.echo(f"Snapshot (UTC): {report.timestamp_utc.isoformat()}")
    typer.echo("Checks:")
    for check in report.checks:
        typer.echo(f"  {check.status.value.upper():7} {check.check_id}: {check.summary}")
    typer.echo("Observations:")
    for observation in report.observations:
        typer.echo(f"  {observation.evidence_id}: {observation.summary}")
    typer.echo("Explanations:")
    for conclusion in report.conclusions:
        evidence = ", ".join(conclusion.evidence_ids) or "no supporting observation"
        typer.echo(f"  {conclusion.certainty.value.upper()} ({evidence}): {conclusion.statement}")
    if report.evidence_gaps:
        typer.echo("Evidence limits:")
        for gap in report.evidence_gaps:
            typer.echo(f"  - {gap}")
    typer.echo("Review any generated report before sharing it.")


def _prompt_scenario() -> TroubleshootScenario:
    typer.echo("Choose the problem you want to investigate:")
    typer.echo("  1. Website or application unavailable")
    typer.echo("  2. Service crash or restart")
    typer.echo("  3. Disk or storage problem")
    choice = typer.prompt("Enter 1, 2 or 3", default="1").strip()
    scenarios = {
        "1": TroubleshootScenario.WEBSITE_UNAVAILABLE,
        "2": TroubleshootScenario.SERVICE_CRASH,
        "3": TroubleshootScenario.STORAGE,
    }
    if choice not in scenarios:
        raise typer.BadParameter("Choose 1, 2 or 3.")
    return scenarios[choice]


def _prompt_unit(
    scenario: TroubleshootScenario = TroubleshootScenario.WEBSITE_UNAVAILABLE,
) -> str | None:
    """Ask whether the user can identify the affected application service."""
    labels = {
        "nginx": "Nginx",
        "apache2": "Apache",
        "mysql": "MySQL",
        "mariadb": "MariaDB",
        "postgresql": "PostgreSQL",
        "redis-server": "Redis",
    }
    typer.echo(
        "Which application or background service is having trouble? "
        "For example, nginx, apache2, or myapp.service."
    )
    typer.echo(
        "A service is a background program. Its service name lets FastVPS Doctor check "
        "that program's state and recent events."
    )
    detected, complete = discover_relevant_services(scenario)
    if detected:
        typer.echo("Detected application service units (choose one only if it is affected):")
        for index, (name, _unit, state) in enumerate(detected, start=1):
            typer.echo(f"  {index}. {labels[name]} ({state})")
    elif complete:
        typer.echo(
            "No relevant application service unit was detected. This does not show that the application is down."
        )
    else:
        typer.echo(
            "Relevant service discovery was unavailable or incomplete; you can enter a known name or continue without one."
        )
    typer.echo("Choose one of these options:")
    typer.echo(
        "  1. Select a detected relevant service"
        if detected
        else "  1. Select a detected relevant service (none detected)"
    )
    typer.echo("  2. Enter a service name manually")
    typer.echo("  3. I'm not sure")
    try:
        choice = str(typer.prompt("Enter 1, 2 or 3", default="3")).strip()
        if choice == "1" and detected:
            typer.echo("Choose only the service that belongs to the affected application.")
            for index, (name, _unit, state) in enumerate(detected, start=1):
                typer.echo(f"  {index}. {labels[name]} ({state})")
            service_choice = str(
                typer.prompt("Enter a listed number, or press Enter for I'm not sure", default="")
            ).strip()
            if not service_choice:
                typer.echo(
                    "No service selected. The diagnosis will continue with checks that do not need a service name."
                )
                return None
            if not service_choice.isdecimal() or not 1 <= int(service_choice) <= len(detected):
                raise typer.BadParameter(
                    "Choose one of the listed service numbers, or press Enter."
                )
            return detected[int(service_choice) - 1][1]
        if choice == "2":
            service = str(
                typer.prompt(
                    "Which application or background service is having trouble? "
                    "For example, nginx, apache2, or myapp.service",
                    default="",
                    show_default=False,
                )
            ).strip()
            if not service:
                typer.echo("No service selected; continuing with checks that do not need its name.")
                return None
            try:
                safe_systemd_unit(service)
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from None
            return service
    except (KeyboardInterrupt, EOFError):
        raise typer.Abort() from None
    if choice in {"", "3"}:
        typer.echo(
            "No service selected. FastVPS Doctor will run only checks that do not need a "
            "service name; it cannot assess the affected application's service state, "
            "logs or configuration."
        )
        return None
    if choice == "1" and not detected:
        typer.echo("There is no detected service to select; continuing without a service name.")
        return None
    raise typer.BadParameter("Choose 1, 2 or 3.")


def _is_interactive() -> bool:
    return sys.stdin.isatty()


def _strict_exit_if_requested(report: DiagnosticReport, enabled: bool) -> None:
    if not enabled:
        return
    if report.findings or any(check.status == CheckStatus.FAIL for check in report.checks):
        raise typer.Exit(code=1)
    if any(
        check.status in {CheckStatus.UNKNOWN, CheckStatus.SKIPPED, CheckStatus.WARNING}
        for check in report.checks
    ):
        raise typer.Exit(code=3)


def _render_checks(ctx: typer.Context, checks: list[DiagnosticCheck], json_output: bool) -> None:
    if json_output:
        typer.echo(
            json.dumps(
                [check.model_dump(mode="json") for check in checks], indent=2, ensure_ascii=True
            )
        )
        return
    table = Table(title="Diagnostic checks", show_lines=False, box=_table_box(ctx), expand=True)
    table.add_column("Status", style="bold", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Summary", overflow="fold")
    for check in checks:
        table.add_row(check.status.value.upper(), check.check_id, check.summary)
    _console(ctx).print(table)
    for check in checks:
        visible_metrics = [
            f"{key}={value}" for key, value in check.metrics.items() if value is not None
        ]
        for start in range(0, len(visible_metrics), 4):
            detail = ", ".join(visible_metrics[start : start + 4])
            _console(ctx).print(f"  {check.check_id}: {detail}")
        if check.note:
            _console(ctx).print(f"  Note ({check.check_id}): {check.note}")


def _render_area(
    ctx: typer.Context, checks: list[DiagnosticCheck], json_output: bool
) -> DiagnosticReport:
    report_data = build_report(checks, load_thresholds())
    if json_output:
        typer.echo(report_data.json_document())
    else:
        _render_checks(ctx, report_data.checks, False)
        _print_report_findings(ctx, report_data)
    return report_data


def _validate_profile(profile: str | None) -> str | None:
    if profile is None:
        return None
    if profile != "fastvps":
        raise typer.BadParameter("The only supported profile is 'fastvps'.")
    return profile


def _print_report_findings(ctx: typer.Context, report: DiagnosticReport) -> None:
    console = _console(ctx)
    console.print(f"Overall status: [bold]{report.overall_status}[/bold]")
    console.print(report.support_summary.overview)
    if report.findings:
        table = Table(title="Rule-based findings", box=_table_box(ctx))
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("Finding")
        for item in report.findings:
            table.add_row(item.finding_id, item.severity.value.upper(), item.title)
        console.print(table)
        for item in report.findings:
            separator = "-" if _uses_ascii(ctx) else "—"
            console.print(f"[bold]{item.finding_id} {separator} {item.title}[/bold]")
            console.print(item.description)
            console.print(
                f"  Scope: {item.support_scope.value}; confidence: {item.confidence}; "
                f"additional privileges: {'yes' if item.requires_privileges else 'no'}"
            )
            for evidence in item.evidence:
                console.print(f"  Evidence: {evidence}")
            for cause in item.possible_causes:
                console.print(f"  Possible cause: {cause}")
            for step in item.next_steps:
                bullet = "-" if _uses_ascii(ctx) else "•"
                console.print(f"  {bullet} {step}")
    else:
        console.print(
            "No findings matched the available rules. This does not prove the system is healthy or secure."
        )
    if report.profile == "fastvps":
        console.print(
            "FastVPS support context: responsibility depends on the ordered management plan and agreed scope."
        )
        console.print(
            "Review the report before sharing it. Official support resources: https://fastvps.gr/en/faq/"
        )


@app.command()
def diagnose(
    ctx: typer.Context,
    full: Annotated[
        bool,
        typer.Option(
            "--full", help="Include a local cached APT upgrade simulation; no packages are changed."
        ),
    ] = False,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Add support-oriented context (fastvps).")
    ] = None,
    ticket_reference: Annotated[
        str | None,
        typer.Option("--ticket-reference", help="Optional customer-entered ticket reference."),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print a structured support report as JSON.")
    ] = False,
    strict_exit_codes: Annotated[
        bool,
        typer.Option(
            "--strict-exit-codes",
            help="Return 1 for findings or 3 for incomplete/uncertain checks.",
        ),
    ] = False,
) -> None:
    """Run available local checks and explain evidence-backed findings."""
    profile = _validate_profile(profile)
    checks = _all_checks(full=full)
    report = build_report(checks, load_thresholds(), profile, ticket_reference)
    if json_output:
        typer.echo(report.json_document())
        _strict_exit_if_requested(report, strict_exit_codes)
        return
    _render_checks(ctx, report.checks, False)
    _print_report_findings(ctx, report)
    _strict_exit_if_requested(report, strict_exit_codes)


@app.command()
def system(
    ctx: typer.Context, json_output: Annotated[bool, typer.Option("--json")] = False
) -> None:
    """Inspect CPU, memory, load, uptime and kernel indicators."""
    _render_area(ctx, collect_system(), json_output)


@app.command()
def storage(
    ctx: typer.Context, json_output: Annotated[bool, typer.Option("--json")] = False
) -> None:
    """Inspect root filesystem capacity, inodes and read-only state."""
    _render_area(ctx, collect_storage(), json_output)


@app.command()
def network(
    ctx: typer.Context,
    resolve: Annotated[
        str | None, typer.Option("--resolve", help="Resolve one hostname you explicitly specify.")
    ] = None,
    connect_host: Annotated[
        str | None,
        typer.Option("--connect-host", help="Connect once to an explicitly approved hostname."),
    ] = None,
    connect_port: Annotated[
        int | None,
        typer.Option("--connect-port", min=1, max=65535, help="Port for --connect-host."),
    ] = None,
    show_addresses: Annotated[
        bool,
        typer.Option(
            "--show-addresses",
            help="Show local IPv4/IPv6 addresses in human output only; JSON reports omit them.",
        ),
    ] = False,
    listen_port: Annotated[
        list[int] | None,
        typer.Option(
            "--listen-port",
            help="Inspect an additional local TCP/UDP listener port; repeat for several ports.",
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect local interfaces, route and resolver; optional tests require a named destination."""
    if connect_host is None and connect_port is not None:
        raise typer.BadParameter("--connect-port requires --connect-host.")
    if connect_host is not None and connect_port is None:
        raise typer.BadParameter("--connect-host requires --connect-port.")
    if listen_port and any(port < 1 or port > 65535 for port in listen_port):
        raise typer.BadParameter("Each --listen-port must be between 1 and 65535.")
    try:
        destination = None
        if connect_host is not None and connect_port is not None:
            destination = (safe_hostname(connect_host), connect_port)
        checks = collect_network(
            resolve=safe_hostname(resolve) if resolve else None,
            connect=destination,
            include_addresses=show_addresses,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    local_addresses = [
        str(value)
        for key, value in checks[0].metrics.items()
        if key.startswith("address_") and isinstance(value, str)
    ]
    checks.append(collect_listeners(set(listen_port) if listen_port else None))
    _render_area(ctx, checks, json_output)
    if show_addresses and not json_output:
        _console(ctx).print("Local addresses (not included in support reports):")
        for address in local_addresses:
            _console(ctx).print(f"  {address}")


@app.command()
def services(
    ctx: typer.Context,
    unit: Annotated[
        list[str] | None,
        typer.Option(
            "--unit",
            help="Also inspect one explicitly selected custom systemd unit; repeat up to five times.",
        ),
    ] = None,
    validate_config: Annotated[
        bool,
        typer.Option(
            "--validate-config",
            help="Run bounded daemon config validators (may require permission to read service files).",
        ),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect systemd state for common services and selected custom units."""
    try:
        checks = collect_services(custom_units=unit or (), validate_config=validate_config)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    _render_area(ctx, checks, json_output)


@app.command()
def security(
    ctx: typer.Context,
    full: Annotated[
        bool,
        typer.Option("--full", help="Simulate package upgrades using cached local APT metadata."),
    ] = False,
    ssh_user: Annotated[
        str | None, typer.Option("--ssh-user", help="Account for an optional sshd Match context.")
    ] = None,
    ssh_host: Annotated[
        str | None,
        typer.Option("--ssh-host", help="Remote host for an optional sshd Match context."),
    ] = None,
    ssh_address: Annotated[
        str | None,
        typer.Option("--ssh-address", help="Remote client IP for an sshd Match context."),
    ] = None,
    local_address: Annotated[
        str | None,
        typer.Option("--local-address", help="Server-side IP for an sshd Match context."),
    ] = None,
    local_port: Annotated[
        int | None,
        typer.Option(
            "--local-port", min=1, max=65535, help="Server-side port for an sshd Match context."
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Review effective SSH settings and limited UFW indicators."""
    context_values = (ssh_user, ssh_host, ssh_address, local_address, local_port)
    if any(value is not None for value in context_values) and any(
        value is None for value in context_values
    ):
        raise typer.BadParameter(
            "Supply all SSH Match context fields together: --ssh-user, --ssh-host, "
            "--ssh-address, --local-address and --local-port."
        )
    ssh_context = (
        (ssh_user, ssh_host, ssh_address, local_address, local_port)
        if ssh_user is not None
        and ssh_host is not None
        and ssh_address is not None
        and local_address is not None
        and local_port is not None
        else None
    )
    try:
        checks = collect_security(include_update_simulation=full, ssh_context=ssh_context)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    _render_area(ctx, checks, json_output)


@app.command()
def web(
    ctx: typer.Context,
    port: Annotated[
        int | None,
        typer.Option(
            "--port", min=1, max=65535, help="Also inspect a user-specified local application port."
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check loopback HTTP/HTTPS reachability and local web listener counts."""
    _render_area(ctx, collect_web(required_port=port), json_output)


@app.command()
def troubleshoot(
    scenario: Annotated[
        str | None,
        typer.Option(
            "--scenario",
            help="website-unavailable, service-crash or storage; omit for the interactive picker.",
        ),
    ] = None,
    service: Annotated[
        str | None, typer.Option("--service", help="One explicitly selected systemd unit.")
    ] = None,
    port: Annotated[
        int | None,
        typer.Option("--port", min=1, max=65535, help="Expected local application port."),
    ] = None,
    since: Annotated[
        str, typer.Option("--since", help="Bounded journal window such as 30m, 2h or 1d.")
    ] = "2h",
    probe_http: Annotated[
        bool | None,
        typer.Option(
            "--probe-http/--no-probe-http",
            help="Opt in to one HTTP HEAD request to 127.0.0.1 on the selected port.",
        ),
    ] = None,
    validate_config: Annotated[
        bool | None,
        typer.Option(
            "--validate-config/--no-validate-config",
            help="Opt in to a supported read-only configuration syntax check.",
        ),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", help="Brief symptom only; do not enter passwords or keys."),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format", help="Local report format when --output is supplied: markdown or json."
        ),
    ] = "markdown",
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Create a new private local report file; never overwrites."),
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Add support context (fastvps).")
    ] = None,
    ticket_reference: Annotated[
        str | None, typer.Option("--ticket-reference", help="Optional support ticket reference.")
    ] = None,
) -> None:
    """Guide one focused, read-only support diagnosis and optionally save a local report."""
    if format.lower() not in {"json", "markdown", "md"}:
        raise typer.BadParameter("Choose json or markdown.")
    if service is not None:
        service = service.strip() or None
    # An explicit scenario means explicit flag-driven use; only the no-argument
    # numbered picker enters interactive mode.
    interactive = scenario is None and _is_interactive()
    selected_scenario: TroubleshootScenario
    if scenario is None:
        if not interactive:
            raise typer.BadParameter(
                "--scenario is required in non-interactive use; choose one of the three listed values."
            )
        selected_scenario = _prompt_scenario()
    else:
        try:
            selected_scenario = TroubleshootScenario(scenario)
        except ValueError:
            allowed = ", ".join(item.value for item in TroubleshootScenario)
            raise typer.BadParameter(f"Choose one of: {allowed}.") from None

    if (
        selected_scenario
        in {
            TroubleshootScenario.WEBSITE_UNAVAILABLE,
            TroubleshootScenario.SERVICE_CRASH,
        }
        and service is None
    ):
        if not interactive:
            raise typer.BadParameter("--service is required for this scenario.")
        service = _prompt_unit(selected_scenario)
    if (
        selected_scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
        and port is None
        and service is not None
    ):
        if not interactive:
            raise typer.BadParameter("--port is required for the website scenario.")
        try:
            port = typer.prompt("Expected local application port", type=int, default=80)
        except (ValueError, TypeError) as exc:
            raise typer.BadParameter("Enter a port between 1 and 65535.") from exc
        if not 1 <= port <= 65535:
            raise typer.BadParameter("Enter a port between 1 and 65535.")
    if (
        selected_scenario == TroubleshootScenario.STORAGE
        and service is None
        and interactive
        and typer.confirm("Include one related service's bounded event timeline?", default=False)
    ):
        service = _prompt_unit(TroubleshootScenario.SERVICE_CRASH)

    if probe_http is None:
        probe_http = (
            typer.confirm(
                "Send one HTTP HEAD request to 127.0.0.1 on the selected port?", default=False
            )
            if interactive
            and selected_scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
            and port is not None
            else False
        )
    if validate_config is None:
        validate_config = (
            typer.confirm("Run a supported read-only configuration syntax check?", default=False)
            if interactive and service and selected_scenario != TroubleshootScenario.STORAGE
            else False
        )
    if description is None and interactive:
        description = (
            typer.prompt("Brief symptom (optional; do not enter credentials)", default="").strip()
            or None
        )

    if selected_scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        if port is None and service is not None:
            raise typer.BadParameter("The website scenario requires --port.")
        if probe_http and port is None:
            raise typer.BadParameter("--probe-http requires --port.")
    elif selected_scenario == TroubleshootScenario.SERVICE_CRASH:
        if port is not None or probe_http:
            raise typer.BadParameter("--port and --probe-http apply only to the website scenario.")
    elif port is not None or probe_http:
        raise typer.BadParameter("--port and --probe-http apply only to the website scenario.")
    if selected_scenario == TroubleshootScenario.STORAGE and validate_config:
        raise typer.BadParameter(
            "--validate-config requires the website or service-crash scenario."
        )
    if selected_scenario == TroubleshootScenario.STORAGE and service is None and since != "2h":
        raise typer.BadParameter("--since requires --service in the storage scenario.")
    if selected_scenario != TroubleshootScenario.STORAGE and service is None and since != "2h":
        raise typer.BadParameter("--since requires --service for service-specific event analysis.")
    if validate_config and service is None:
        raise typer.BadParameter("--validate-config requires a selected service.")

    profile = _validate_profile(profile)
    try:
        report_data = build_troubleshoot_report(
            selected_scenario,
            service=service,
            port=port,
            since=since,
            probe_http=probe_http,
            validate_config=validate_config,
            description=description,
            ticket_reference=ticket_reference,
            profile=profile,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None

    if (
        output is None
        and interactive
        and typer.confirm("Save a private local support report?", default=False)
    ):
        output = Path(typer.prompt("New report file path"))
    _emit_troubleshoot_report(report_data, format, output)


@app.command()
def incident(
    ctx: typer.Context,
    service: Annotated[
        str,
        typer.Option("--service", help="One systemd service unit to inspect, such as nginx."),
    ],
    since: Annotated[
        str,
        typer.Option(
            "--since", help="Bounded event window: for example 30m, 2h or 1d (maximum 24h)."
        ),
    ] = "2h",
    format: Annotated[
        str, typer.Option("--format", help="Report format: markdown or json.")
    ] = "markdown",
    output: Annotated[
        Path | None, typer.Option("--output", help="Create a new private local report file.")
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Add support-oriented context (fastvps).")
    ] = None,
    ticket_reference: Annotated[
        str | None, typer.Option("--ticket-reference", help="Optional support ticket ID.")
    ] = None,
    incident_start: Annotated[
        str | None,
        typer.Option(
            "--incident-start", help="Customer-reported ISO 8601 start time with timezone."
        ),
    ] = None,
    problem_category: Annotated[
        str | None,
        typer.Option(
            "--problem-category",
            help="website, application, database, email, network, performance, availability or other.",
        ),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", help="Brief customer-entered problem description."),
    ] = None,
    strict_exit_codes: Annotated[
        bool,
        typer.Option(
            "--strict-exit-codes",
            help="Return 1 for findings or 3 for incomplete/uncertain checks.",
        ),
    ] = False,
) -> None:
    """Build a bounded, timestamped incident timeline for one selected service."""
    profile = _validate_profile(profile)
    try:
        parse_time_window(since)
        selected_unit = safe_systemd_unit(service)
        common_units = {
            safe_systemd_unit(candidate)
            for candidates, _executables in SERVICE_DEFINITIONS.values()
            for candidate in candidates
        }
        custom_units = () if selected_unit in common_units else (service,)
        analysis = analyze_incident(service, since)
        information = _incident_information(
            incident_start,
            service,
            problem_category,
            description,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    checks = _all_checks(custom_units=custom_units)
    report_data = build_report(
        checks,
        load_thresholds(),
        profile,
        ticket_reference,
        incident_information=information,
        incident_analysis=analysis,
    )
    _emit_report(report_data, format, output)
    _strict_exit_if_requested(report_data, strict_exit_codes)


@app.command()
def explain(ctx: typer.Context) -> None:
    """List deterministic rules and their evidence requirements."""
    table = Table(title="Troubleshooting rules", box=_table_box(ctx))
    table.add_column("Rule")
    table.add_column("Evidence and limits", overflow="fold")
    for name, description in rule_catalog():
        table.add_row(name, description)
    _console(ctx).print(table)


@app.command()
def report(
    ctx: typer.Context,
    format: Annotated[
        str, typer.Option("--format", help="Report format: json or markdown.")
    ] = "markdown",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", help="Create a new local file; existing files are never overwritten."
        ),
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Add support-oriented context (fastvps). ")
    ] = None,
    ticket_reference: Annotated[
        str | None,
        typer.Option("--ticket-reference", help="Optional customer-entered ticket reference."),
    ] = None,
    full: Annotated[
        bool, typer.Option("--full", help="Include a local cached APT upgrade simulation.")
    ] = False,
    incident_service: Annotated[
        str | None,
        typer.Option(
            "--incident-service",
            help="Include a bounded timeline for one selected systemd service.",
        ),
    ] = None,
    since: Annotated[
        str, typer.Option("--since", help="Incident timeline window, such as 2h (maximum 24h).")
    ] = "2h",
    incident_start: Annotated[
        str | None,
        typer.Option(
            "--incident-start", help="Customer-reported ISO 8601 start time with timezone."
        ),
    ] = None,
    affected_service: Annotated[
        str | None, typer.Option("--affected-service", help="Optional affected service label.")
    ] = None,
    problem_category: Annotated[
        str | None,
        typer.Option(
            "--problem-category",
            help="website, application, database, email, network, performance, availability or other.",
        ),
    ] = None,
    problem_description: Annotated[
        str | None,
        typer.Option("--problem-description", help="Brief customer-entered problem description."),
    ] = None,
    strict_exit_codes: Annotated[
        bool,
        typer.Option(
            "--strict-exit-codes",
            help="Return 1 for findings or 3 for incomplete/uncertain checks.",
        ),
    ] = False,
) -> None:
    """Generate a local support report for review before sharing."""
    profile = _validate_profile(profile)
    try:
        if incident_service:
            parse_time_window(since)
        elif since != "2h":
            raise ValueError("--since requires --incident-service.")
        information = _incident_information(
            incident_start,
            affected_service or incident_service,
            problem_category,
            problem_description,
        )
        analysis = analyze_incident(incident_service, since) if incident_service else None
        selected_unit = safe_systemd_unit(incident_service) if incident_service else None
        common_units = {
            safe_systemd_unit(candidate)
            for candidates, _executables in SERVICE_DEFINITIONS.values()
            for candidate in candidates
        }
        custom_units = (
            (incident_service,) if incident_service and selected_unit not in common_units else ()
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    report_data = build_report(
        _all_checks(full=full, custom_units=custom_units),
        load_thresholds(),
        profile,
        ticket_reference,
        incident_information=information,
        incident_analysis=analysis,
    )
    _emit_report(report_data, format, output)
    _strict_exit_if_requested(report_data, strict_exit_codes)


@app.command()
def version() -> None:
    """Show the installed FastVPS Doctor version."""
    typer.echo(f"FastVPS Doctor {__version__} (independent, unofficial contribution)")

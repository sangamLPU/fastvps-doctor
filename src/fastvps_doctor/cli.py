"""Typer command-line interface for FastVPS Doctor."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from fastvps_doctor import __version__
from fastvps_doctor.checks.network import collect_listeners, collect_network
from fastvps_doctor.checks.security import collect_security
from fastvps_doctor.checks.services import collect_services
from fastvps_doctor.checks.storage import collect_storage
from fastvps_doctor.checks.system import collect_system
from fastvps_doctor.checks.web import collect_web
from fastvps_doctor.config import load_thresholds
from fastvps_doctor.models import DiagnosticCheck, DiagnosticReport
from fastvps_doctor.reports import build_report, render_markdown, write_exclusive
from fastvps_doctor.rules import rule_catalog
from fastvps_doctor.runner import safe_hostname

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
) -> list[DiagnosticCheck]:
    checks: list[DiagnosticCheck] = []
    checks.extend(collect_system())
    checks.extend(collect_storage())
    checks.extend(collect_network(resolve=resolve, connect=connect))
    checks.append(collect_listeners())
    checks.extend(collect_services())
    checks.extend(collect_security(include_update_simulation=full))
    checks.extend(collect_web(required_port=required_port))
    return checks


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
) -> None:
    """Run available local checks and explain evidence-backed findings."""
    profile = _validate_profile(profile)
    checks = _all_checks(full=full)
    report = build_report(checks, load_thresholds(), profile, ticket_reference)
    if json_output:
        typer.echo(report.json_document())
        return
    _render_checks(ctx, report.checks, False)
    _print_report_findings(ctx, report)


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
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect local interfaces, route and resolver; optional tests require a named destination."""
    if connect_host is None and connect_port is not None:
        raise typer.BadParameter("--connect-port requires --connect-host.")
    if connect_host is not None and connect_port is None:
        raise typer.BadParameter("--connect-host requires --connect-port.")
    destination = None
    if connect_host is not None and connect_port is not None:
        destination = (safe_hostname(connect_host), connect_port)
    checks = collect_network(
        resolve=safe_hostname(resolve) if resolve else None,
        connect=destination,
        include_addresses=show_addresses,
    )
    local_addresses = [
        str(value)
        for key, value in checks[0].metrics.items()
        if key.startswith("address_") and isinstance(value, str)
    ]
    checks.append(collect_listeners())
    _render_area(ctx, checks, json_output)
    if show_addresses and not json_output:
        _console(ctx).print("Local addresses (not included in support reports):")
        for address in local_addresses:
            _console(ctx).print(f"  {address}")


@app.command()
def services(
    ctx: typer.Context, json_output: Annotated[bool, typer.Option("--json")] = False
) -> None:
    """Inspect installed common services and safe validators where available."""
    _render_area(ctx, collect_services(), json_output)


@app.command()
def security(
    ctx: typer.Context,
    full: Annotated[
        bool,
        typer.Option("--full", help="Simulate package upgrades using cached local APT metadata."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Review a limited set of read-only SSH and UFW indicators."""
    _render_area(ctx, collect_security(include_update_simulation=full), json_output)


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
) -> None:
    """Generate a local support report for review before sharing."""
    profile = _validate_profile(profile)
    normalized_format = format.lower()
    if normalized_format not in {"json", "markdown", "md"}:
        raise typer.BadParameter("Choose json or markdown.")
    report_data = build_report(_all_checks(full=full), load_thresholds(), profile, ticket_reference)
    content = (
        report_data.json_document() + "\n"
        if normalized_format == "json"
        else render_markdown(report_data)
    )
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


@app.command()
def version() -> None:
    """Show the installed FastVPS Doctor version."""
    typer.echo(f"FastVPS Doctor {__version__} (independent, unofficial contribution)")

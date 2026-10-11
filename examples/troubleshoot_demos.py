"""Reproduce deterministic v0.3 support-report examples or a local live web check."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from secrets import token_hex
from threading import Thread

from fastvps_doctor import __version__
from fastvps_doctor.models import (
    CheckStatus,
    DiagnosticCheck,
    EvidenceCertainty,
    IncidentEvent,
    IncidentEventType,
    TroubleshootConclusion,
    TroubleshootObservation,
    TroubleshootReport,
    TroubleshootScenario,
    TroubleshootTimelineEvent,
)
from fastvps_doctor.privacy import sanitize_troubleshoot_report
from fastvps_doctor.reports import write_exclusive
from fastvps_doctor.troubleshoot import build_troubleshoot_report, render_troubleshoot_markdown

DEMO_TIME = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def build_fixture_report(scenario: TroubleshootScenario) -> TroubleshootReport:
    """Create a stable, synthetic report that contains no live system data."""
    if scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE:
        checks = [
            _check(
                "troubleshoot.service",
                "services",
                CheckStatus.WARNING,
                "Queried the selected systemd unit state and available exit/restart properties.",
                {
                    "service_unit_found": True,
                    "service_state": "failed",
                    "service_restart_count": 3,
                    "service_result": "exit-code",
                },
            ),
            _check(
                "storage.root",
                "storage",
                CheckStatus.PASS,
                "Collected root filesystem capacity and inode utilization.",
                {"usage_percent": 38.0, "inode_usage_percent": 22.0, "readonly": False},
            ),
            _check(
                "storage.mounts",
                "storage",
                CheckStatus.PASS,
                "Collected bounded local mount counters.",
                {
                    "mount_count": 1,
                    "inspected_mount_count": 1,
                    "mount_0_filesystem_type": "ext4",
                    "mount_0_usage_percent": 38.0,
                    "mount_0_inode_usage_percent": 22.0,
                    "mount_0_readonly": False,
                    "mount_0_state": "ok",
                },
            ),
            _check(
                "system.resources",
                "system",
                CheckStatus.PASS,
                "Collected a current resource snapshot.",
                {"cpu_sample_percent": 8.0, "memory_percent": 42.0, "memory_available_mb": 4600},
            ),
            _check(
                "network.listeners",
                "network",
                CheckStatus.PASS,
                "Inspected the selected local listener port.",
                {"port_8080_listeners": 0},
            ),
            _check(
                "troubleshoot.http",
                "web",
                CheckStatus.FAIL,
                "Issued one optional local HTTP HEAD request.",
                {
                    "http_probe_requested": True,
                    "http_probe_state": "connection_error",
                    "http_status_code": None,
                },
            ),
        ]
        events = [
            _event(
                DEMO_TIME - timedelta(minutes=3),
                IncidentEventType.SERVICE_FAILURE,
                "The service manager recorded a failed start or process exit.",
            )
        ]
        observations = [
            _observation(
                1,
                "snapshot",
                "Selected systemd unit state: failed; restart count: 3.",
                "troubleshoot.service",
                CheckStatus.WARNING,
            ),
            _observation(
                2,
                "filesystem",
                "Root filesystem utilization: 38.0%; inode utilization: 22.0%; read-only: false.",
                "storage.root",
                CheckStatus.PASS,
            ),
            _observation(
                3,
                "snapshot",
                "Current resource snapshot: memory 42.0%; brief CPU sample 8.0%.",
                "system.resources",
                CheckStatus.PASS,
            ),
            _observation(
                4,
                "snapshot",
                "Local listener inventory reported no listener on selected port 8080.",
                "network.listeners",
                CheckStatus.PASS,
            ),
            _observation(
                5,
                "loopback",
                "Loopback HTTP probe could not connect to selected port 8080.",
                "troubleshoot.http",
                CheckStatus.FAIL,
            ),
        ]
        conclusions = [
            TroubleshootConclusion(
                certainty=EvidenceCertainty.CONFIRMED,
                statement="The selected systemd unit was reported as failed at snapshot time.",
                evidence_ids=["OBS-001"],
            ),
            TroubleshootConclusion(
                certainty=EvidenceCertainty.CONFIRMED,
                statement="The local listener inventory reported no listener on port 8080 at snapshot time.",
                evidence_ids=["OBS-004"],
            ),
            TroubleshootConclusion(
                certainty=EvidenceCertainty.CONFIRMED,
                statement="One timestamped service failure event was recorded in the selected window; this does not identify why it failed.",
                evidence_ids=["EVT-001"],
            ),
        ]
        port = 8080
        service = "nginx"
        next_actions = [
            "Confirm the expected service and local bind port with the site administrator.",
            "Review the unit journal and application configuration before changing anything.",
        ]
        gaps = [
            "Public reachability and DNS were not tested.",
            "This is synthetic fixture evidence, not a live VPS diagnosis.",
        ]
        description = (
            "[DEMO FIXTURE] Website unavailable; no listener was found on the expected port."
        )
    elif scenario == TroubleshootScenario.SERVICE_CRASH:
        checks = [
            _check(
                "troubleshoot.service",
                "services",
                CheckStatus.WARNING,
                "Queried the selected systemd unit state and available exit/restart properties.",
                {
                    "service_unit_found": True,
                    "service_state": "failed",
                    "service_restart_count": 4,
                    "service_result": "exit-code",
                    "service_exec_main_code": 1,
                    "service_exec_main_status": 1,
                },
            ),
            _check(
                "system.resources",
                "system",
                CheckStatus.PASS,
                "Collected a current resource snapshot.",
                {"cpu_sample_percent": 4.0, "memory_percent": 34.0, "memory_available_mb": 5200},
            ),
        ]
        events = [
            _event(
                DEMO_TIME - timedelta(minutes=8),
                IncidentEventType.SERVICE_RESTART_SCHEDULED,
                "The service manager scheduled an automatic restart.",
            ),
            _event(
                DEMO_TIME - timedelta(minutes=6),
                IncidentEventType.SERVICE_FAILURE,
                "The service manager recorded a failed start or process exit.",
            ),
            _event(
                DEMO_TIME - timedelta(minutes=5),
                IncidentEventType.SERVICE_RESTART_SCHEDULED,
                "The service manager scheduled an automatic restart.",
            ),
            _event(
                DEMO_TIME - timedelta(minutes=4),
                IncidentEventType.OOM_KILL,
                "A kernel journal record matched an out-of-memory termination indicator.",
            ),
        ]
        observations = [
            _observation(
                1,
                "snapshot",
                "Selected systemd unit state: failed; current restart counter: 4; exit status: 1.",
                "troubleshoot.service",
                CheckStatus.WARNING,
            ),
            _observation(
                2,
                "snapshot",
                "Current resource snapshot: memory 34.0%; brief CPU sample 4.0%.",
                "system.resources",
                CheckStatus.PASS,
            ),
        ]
        conclusions = [
            TroubleshootConclusion(
                certainty=EvidenceCertainty.PLAUSIBLE,
                statement="Two timestamped restart-scheduling records are consistent with repeated restarts, but do not establish cause.",
                evidence_ids=["EVT-001", "EVT-003"],
            ),
            TroubleshootConclusion(
                certainty=EvidenceCertainty.PLAUSIBLE,
                statement="A service failure and kernel out-of-memory indicator were timestamped within five minutes; timing alone does not prove causation.",
                evidence_ids=["EVT-002", "EVT-004"],
            ),
        ]
        port = None
        service = "nginx"
        next_actions = [
            "Have an administrator compare the full service and kernel journals around these timestamps.",
            "Review exit details and dependencies before considering any restart or configuration change.",
        ]
        gaps = [
            "The current resource snapshot is not historical evidence.",
            "A timeline correlation does not prove the OOM event caused the service failure.",
            "This is synthetic fixture evidence, not a live VPS diagnosis.",
        ]
        description = "[DEMO FIXTURE] Service restarts were observed near an OOM event."
    else:
        checks = [
            _check(
                "storage.root",
                "storage",
                CheckStatus.WARNING,
                "Collected root filesystem capacity and inode utilization.",
                {
                    "usage_percent": 97.0,
                    "used_gb": 72.75,
                    "total_gb": 75.0,
                    "inode_usage_percent": 99.2,
                    "readonly": False,
                    "mounted_filesystem_count": 2,
                },
            ),
            _check(
                "storage.mounts",
                "storage",
                CheckStatus.WARNING,
                "Collected bounded capacity indicators for local mounted filesystems.",
                {
                    "mount_count": 1,
                    "inspected_mount_count": 1,
                    "mount_0_filesystem_type": "ext4",
                    "mount_0_usage_percent": 97.0,
                    "mount_0_inode_usage_percent": 99.2,
                    "mount_0_readonly": False,
                    "mount_0_state": "ok",
                },
            ),
            _check(
                "troubleshoot.service",
                "services",
                CheckStatus.WARNING,
                "Queried one optional selected storage-related service.",
                {"service_unit_found": True, "service_state": "active", "service_restart_count": 0},
            ),
        ]
        events = [
            _event(
                DEMO_TIME - timedelta(minutes=2),
                IncidentEventType.SERVICE_ERROR,
                "A journal record for the selected service had error-level priority.",
            )
        ]
        observations = [
            _observation(
                1,
                "filesystem",
                "Root filesystem utilization: 97.0%; inode utilization: 99.2%; read-only: false.",
                "storage.root",
                CheckStatus.WARNING,
            ),
            _observation(
                2,
                "filesystem",
                "One local mounted filesystem was inspected; its path is withheld.",
                "storage.mounts",
                CheckStatus.WARNING,
            ),
            _observation(
                3,
                "snapshot",
                "The selected service was active at snapshot time.",
                "troubleshoot.service",
                CheckStatus.WARNING,
            ),
        ]
        conclusions = [
            TroubleshootConclusion(
                certainty=EvidenceCertainty.CONFIRMED,
                statement="The root filesystem snapshot reported space utilization of 97.0% and inode utilization of 99.2%; this does not prove the cause of any individual write failure.",
                evidence_ids=["OBS-001"],
            ),
            TroubleshootConclusion(
                certainty=EvidenceCertainty.CONFIRMED,
                statement="One timestamped selected-service error record was available; its timing does not establish a connection to storage conditions.",
                evidence_ids=["EVT-001"],
            ),
        ]
        port = None
        service = "postgresql"
        next_actions = [
            "Compare space and inode usage with the filesystem used by the failing application.",
            "Ask an administrator to review relevant application errors; do not delete files based only on this report.",
        ]
        gaps = [
            "No customer files or file contents were searched.",
            "Capacity indicators do not establish why a write failed.",
            "This is synthetic fixture evidence, not a live VPS diagnosis.",
        ]
        description = "[DEMO FIXTURE] Application reported a storage write issue."

    timeline = [
        TroubleshootTimelineEvent(
            event_id=f"EVT-{index:03d}",
            timestamp_utc=event.timestamp_utc,
            classification=event.classification,
            summary=event.evidence_summary,
        )
        for index, event in enumerate(events, start=1)
    ]
    report = TroubleshootReport(
        version=__version__,
        timestamp_utc=DEMO_TIME,
        scenario=scenario,
        distribution="Ubuntu 24.04 (synthetic fixture)",
        kernel_release="6.8.0-demo",
        reported_problem=description,
        service_label=service,
        selected_port=port,
        loopback_http_probe_requested=scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE,
        checks=checks,
        observations=observations,
        timeline=timeline,
        conclusions=conclusions,
        investigation_areas=[
            "Synthetic evidence illustrates the structure of a human support handoff; it is not a root-cause determination."
        ],
        evidence_gaps=gaps,
        next_actions=next_actions,
        profile="fastvps",
        ticket_reference="DEMO-001",
    )
    return sanitize_troubleshoot_report(report)


def run_live_website_demo() -> TroubleshootReport:
    """Start a disposable loopback-only 503 service and inspect it, then stop it."""

    class BrokenDemoHandler(BaseHTTPRequestHandler):
        def do_HEAD(self) -> None:
            self.send_response(503)
            self.end_headers()

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), BrokenDemoHandler)
    server_thread = Thread(target=server.serve_forever, name="fastvps-doctor-demo", daemon=True)
    demo_unit = f"fastvps-doctor-demo-{token_hex(4)}"
    server_thread.start()
    try:
        return build_troubleshoot_report(
            TroubleshootScenario.WEBSITE_UNAVAILABLE,
            service=demo_unit,
            port=server.server_port,
            since="5m",
            probe_http=True,
            description="[LIVE LOCAL DEMO] Disposable loopback service deliberately returns HTTP 503.",
            profile="fastvps",
            ticket_reference="DEMO-LOCAL",
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=[item.value for item in TroubleshootScenario])
    parser.add_argument(
        "--live-local",
        action="store_true",
        help="For website-unavailable only, start a disposable 127.0.0.1 HTTP service that returns 503 and inspect it before stopping it.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Create a new private Markdown report; never overwrites an existing file.",
    )
    args = parser.parse_args()
    scenario = TroubleshootScenario(args.scenario)
    if args.live_local and scenario != TroubleshootScenario.WEBSITE_UNAVAILABLE:
        parser.error("--live-local applies only to website-unavailable.")
    report = run_live_website_demo() if args.live_local else build_fixture_report(scenario)
    content = (
        "> DEMONSTRATION ONLY — synthetic fixture, not FastVPS customer or server data.\n\n"
        + render_troubleshoot_markdown(report)
    )
    if args.output:
        write_exclusive(args.output, content)
        print(f"Created local report: {args.output}")
    else:
        print(content)


def _check(
    check_id: str,
    category: str,
    status: CheckStatus,
    summary: str,
    metrics: dict[str, str | int | float | bool | None],
) -> DiagnosticCheck:
    return DiagnosticCheck(
        check_id=check_id,
        category=category,
        status=status,
        summary=summary,
        metrics=metrics,
    )


def _event(at: datetime, kind: IncidentEventType, summary: str) -> IncidentEvent:
    return IncidentEvent(
        timestamp_utc=at,
        classification=kind,
        component="demo",
        evidence_summary=summary,
    )


def _observation(
    index: int,
    source: str,
    summary: str,
    check_id: str,
    status: CheckStatus,
) -> TroubleshootObservation:
    return TroubleshootObservation(
        evidence_id=f"OBS-{index:03d}",
        source=source,
        summary=summary,
        check_id=check_id,
        status=status,
    )


if __name__ == "__main__":
    main()

"""Render repeatable synthetic reports without contacting a host or changing state."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastvps_doctor.incident_analysis import analyze_incident
from fastvps_doctor.models import CheckStatus, DiagnosticCheck, DiagnosticReport
from fastvps_doctor.reports import build_report, render_markdown
from fastvps_doctor.runner import CommandResult

DEMO_END = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


class SyntheticJournalRunner:
    """Return fabricated, timestamped records for the restart-loop example only."""

    def recent_service_events(self, unit: str, window_seconds: int) -> CommandResult:
        assert unit == "nginx.service"
        assert window_seconds == 1800
        records = [
            self._record(minutes, "Scheduled restart job, restart counter is increasing.")
            for minutes in (27, 24, 21)
        ]
        records.append(self._record(20, "Main process exited, code=killed, status=9/KILL"))
        return CommandResult(available=True, returncode=0, stdout="\n".join(records))

    def recent_kernel_events(self, window_seconds: int) -> CommandResult:
        assert window_seconds == 1800
        record = self._record(19, "Out of memory: Killed process 1234 (worker)")
        return CommandResult(available=True, returncode=0, stdout=record)

    @staticmethod
    def _record(minutes_ago: int, message: str) -> str:
        timestamp = DEMO_END - timedelta(minutes=minutes_ago)
        return json.dumps(
            {
                "__REALTIME_TIMESTAMP": str(int(timestamp.timestamp() * 1_000_000)),
                "_PID": "1",
                "_COMM": "systemd",
                "MESSAGE": message,
            }
        )


def _check(
    check_id: str,
    category: str,
    metrics: dict[str, str | int | float | bool | None],
    *,
    status: CheckStatus = CheckStatus.PASS,
) -> DiagnosticCheck:
    return DiagnosticCheck(
        check_id=check_id,
        category=category,
        status=status,
        summary="Synthetic demonstration fixture.",
        metrics=metrics,
    )


def _identity() -> DiagnosticCheck:
    return _check(
        "system.identity",
        "system",
        {
            "distribution": "Ubuntu 24.04 (synthetic)",
            "kernel_release": "demo-kernel-0.0",
            "python_supported": True,
        },
    )


def build_demo_report(scenario: str) -> DiagnosticReport:
    """Build one report using the same rules, allowlists and renderers as the CLI."""
    checks = [_identity()]
    incident_analysis = None

    if scenario == "website-unavailable":
        checks.extend(
            [
                _check(
                    "services.common",
                    "services",
                    {
                        "nginx_installed": True,
                        "nginx_unit_found": True,
                        "nginx_state": "failed",
                        "nginx_recent_error_count": 2,
                        "nginx_recent_logs_truncated": False,
                    },
                    status=CheckStatus.WARNING,
                ),
                _check(
                    "web.local",
                    "web",
                    {
                        "required_port_supplied": True,
                        "required_port": 8080,
                        "port_8080_listeners": 0,
                    },
                    status=CheckStatus.WARNING,
                ),
            ]
        )
    elif scenario == "storage-pressure":
        checks.extend(
            [
                _check(
                    "storage.root",
                    "storage",
                    {
                        "usage_percent": 45.0,
                        "used_gb": 9.0,
                        "total_gb": 20.0,
                        "inode_usage_percent": 40.0,
                        "readonly": False,
                    },
                ),
                _check(
                    "storage.mounts",
                    "storage",
                    {
                        "mount_count": 1,
                        "inspected_mount_count": 1,
                        "mount_inventory_truncated": False,
                        "mount_0_filesystem_type": "ext4",
                        "mount_0_state": "ok",
                        "mount_0_usage_percent": 92.0,
                        "mount_0_inode_usage_percent": 55.0,
                        "mount_0_readonly": False,
                    },
                ),
            ]
        )
    elif scenario == "restart-loop":
        checks.append(
            _check(
                "services.common",
                "services",
                {
                    "nginx_installed": True,
                    "nginx_unit_found": True,
                    "nginx_state": "failed",
                    "nginx_recent_error_count": 0,
                    "nginx_recent_logs_truncated": False,
                },
                status=CheckStatus.WARNING,
            )
        )
        incident_analysis = analyze_incident(
            "nginx", "30m", runner=SyntheticJournalRunner(), now=DEMO_END
        )
    else:
        raise ValueError(f"Unknown synthetic scenario: {scenario}")

    return build_report(
        checks,
        profile="fastvps",
        incident_analysis=incident_analysis,
    ).model_copy(update={"timestamp_utc": DEMO_END})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "scenario",
        choices=("website-unavailable", "storage-pressure", "restart-loop"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optionally create a new UTF-8 Markdown file; an existing path is never overwritten.",
    )
    args = parser.parse_args()
    markdown = render_markdown(build_demo_report(args.scenario))
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as output_file:
            output_file.write(markdown)
            output_file.write("\n")
    else:
        print(markdown)


if __name__ == "__main__":
    main()

"""Local web-service reachability and bind observations; no external requests."""

from __future__ import annotations

import socket
import sys

from fastvps_doctor.checks.network import collect_listeners
from fastvps_doctor.models import CheckStatus, DiagnosticCheck


def _loopback_reachable(port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def collect_web(required_port: int | None = None) -> list[DiagnosticCheck]:
    watched = {80, 443}
    if required_port is not None:
        if not 1 <= required_port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        watched.add(required_port)
    if not sys.platform.startswith("linux"):
        return [
            DiagnosticCheck(
                check_id="web.local",
                category="web",
                status=CheckStatus.SKIPPED,
                summary="Linux local web-service checks are unavailable on this platform.",
                metrics={
                    "http_80_reachable": None,
                    "https_443_reachable": None,
                    "required_port_supplied": required_port is not None,
                    "required_port": required_port,
                    **{f"port_{port}_listeners": None for port in watched},
                },
                note="No local socket check was attempted because this is not Linux.",
            )
        ]
    listeners = collect_listeners(watched)
    metrics: dict[str, str | int | float | bool | None] = dict(listeners.metrics)
    metrics["http_80_reachable"] = _loopback_reachable(80)
    metrics["https_443_reachable"] = _loopback_reachable(443)
    metrics["required_port_supplied"] = required_port is not None
    metrics["required_port"] = required_port
    status = CheckStatus.PASS if listeners.status == CheckStatus.PASS else CheckStatus.UNKNOWN
    return [
        DiagnosticCheck(
            check_id="web.local",
            category="web",
            status=status,
            summary="Checked local HTTP/HTTPS TCP reachability and selected port listeners.",
            metrics=metrics,
            note=(
                "Only loopback TCP handshakes are attempted; TLS contents and application routes are not inspected."
                if status == CheckStatus.PASS
                else "Loopback handshakes ran, but listener inventory was unavailable or permission-restricted."
            ),
        )
    ]

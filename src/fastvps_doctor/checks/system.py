"""CPU, memory, kernel and operating-system observations."""

from __future__ import annotations

import math
import platform
import sys
import time
from pathlib import Path

import psutil

from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.platform import linux_distribution, linux_distribution_supported


def _pressure_avg10(resource: str) -> float | None:
    if not sys.platform.startswith("linux") or resource not in {"cpu", "memory", "io"}:
        return None
    try:
        with Path(f"/proc/pressure/{resource}").open("rb") as pressure_file:
            content = pressure_file.read(4096).decode("ascii", "ignore")
    except OSError:
        return None
    for line in content.splitlines():
        if line.startswith("some "):
            for item in line.split():
                if item.startswith("avg10="):
                    try:
                        value = float(item.partition("=")[2])
                    except ValueError:
                        return None
                    return value if math.isfinite(value) and 0 <= value <= 100 else None
    return None


def collect_system() -> list[DiagnosticCheck]:
    if not sys.platform.startswith("linux"):
        return [
            DiagnosticCheck(
                check_id="system.resources",
                category="system",
                status=CheckStatus.SKIPPED,
                summary="Linux resource checks are unavailable on this platform.",
                metrics={},
                note="No host resource counters were collected outside Linux.",
            ),
            DiagnosticCheck(
                check_id="system.identity",
                category="system",
                status=CheckStatus.SKIPPED,
                summary="Linux distribution checks are unavailable on this platform.",
                metrics={
                    "distribution": linux_distribution(),
                    "kernel_release": None,
                    "python_supported": None,
                },
            ),
        ]

    cpu_percent: float | None
    try:
        cpu_percent = float(psutil.cpu_percent(interval=0.1))
    except (OSError, psutil.Error, RuntimeError, ValueError):
        cpu_percent = None
    try:
        cpu_count = psutil.cpu_count(logical=True) or 0
    except (OSError, psutil.Error, RuntimeError, ValueError):
        cpu_count = 0
    try:
        memory = psutil.virtual_memory()
        memory_percent: float | None = round(float(memory.percent), 1)
        memory_available_mb: int | None = int(memory.available / (1024 * 1024))
    except (OSError, psutil.Error, RuntimeError, ValueError):
        memory_percent = None
        memory_available_mb = None
    try:
        swap_percent: float | None = round(float(psutil.swap_memory().percent), 1)
    except (OSError, psutil.Error, RuntimeError, ValueError):
        swap_percent = None
    load_1m: float | None
    load_5m: float | None
    load_15m: float | None
    try:
        load_1m, load_5m, load_15m = psutil.getloadavg()
    except (AttributeError, OSError, psutil.Error, RuntimeError):
        load_1m = load_5m = load_15m = None

    try:
        uptime_seconds = max(0, int(time.time() - psutil.boot_time()))
    except (OSError, psutil.Error, RuntimeError, ValueError):
        uptime_seconds = None

    metrics: dict[str, str | int | float | bool | None] = {
        "cpu_count": cpu_count,
        "cpu_sample_percent": round(cpu_percent, 1) if cpu_percent is not None else None,
        "load_1m": round(load_1m, 2) if load_1m is not None else None,
        "load_5m": round(load_5m, 2) if load_5m is not None else None,
        "load_15m": round(load_15m, 2) if load_15m is not None else None,
        "memory_percent": memory_percent,
        "memory_available_mb": memory_available_mb,
        "swap_percent": swap_percent,
        "uptime_seconds": uptime_seconds,
        "memory_psi_some_avg10": _pressure_avg10("memory"),
        "io_psi_some_avg10": _pressure_avg10("io"),
    }
    resources_available = cpu_count > 0 and cpu_percent is not None and memory_percent is not None
    distro_supported = linux_distribution_supported()
    python_supported: bool | None = (
        sys.version_info >= (3, 11) if sys.platform.startswith("linux") else None
    )
    if not sys.platform.startswith("linux"):
        identity_status = CheckStatus.SKIPPED
        identity_summary = "Linux distribution checks are unavailable on this platform."
    elif distro_supported and python_supported:
        identity_status = CheckStatus.PASS
        identity_summary = "Identified a distribution within the initial compatibility target."
    elif distro_supported is False or not python_supported:
        identity_status = CheckStatus.UNKNOWN
        identity_summary = (
            "Distribution or Python version is outside the initial compatibility target."
        )
    else:
        identity_status = CheckStatus.UNKNOWN
        identity_summary = "Linux distribution compatibility could not be determined."

    return [
        DiagnosticCheck(
            check_id="system.resources",
            category="system",
            status=CheckStatus.PASS if resources_available else CheckStatus.UNKNOWN,
            summary="Collected available CPU, memory, swap, load, uptime and pressure indicators.",
            metrics=metrics,
            note=(
                "CPU is a brief sample; a high single sample is not treated as an incident."
                if resources_available
                else "One or more core resource counters could not be read."
            )
            + (" Load-average counters were unavailable." if load_1m is None else ""),
        ),
        DiagnosticCheck(
            check_id="system.identity",
            category="system",
            status=identity_status,
            summary=identity_summary,
            metrics={
                "distribution": linux_distribution(),
                "kernel_release": (
                    "".join(c for c in platform.release() if c.isalnum() or c in ".-+")[:64]
                    if sys.platform.startswith("linux")
                    else None
                ),
                "python_supported": python_supported,
            },
        ),
    ]

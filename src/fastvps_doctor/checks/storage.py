"""Bounded filesystem capacity, inode and mount-state checks."""

from __future__ import annotations

import os
import sys

import psutil

from fastvps_doctor.models import CheckStatus, DiagnosticCheck


def collect_storage() -> list[DiagnosticCheck]:
    if not sys.platform.startswith("linux"):
        return [
            DiagnosticCheck(
                check_id="storage.root",
                category="storage",
                status=CheckStatus.SKIPPED,
                summary="Linux filesystem capacity checks are unavailable on this platform.",
                metrics={"usage_percent": None, "inode_usage_percent": None, "readonly": None},
                note="Use a supported Linux VPS to inspect filesystem and inode state.",
            )
        ]
    errors: list[str] = []
    try:
        usage = psutil.disk_usage("/")
    except (OSError, psutil.Error, RuntimeError, ValueError) as exc:
        usage = None
        errors.append(type(exc).__name__)

    statvfs_fn = getattr(os, "statvfs", None)
    try:
        if not callable(statvfs_fn):
            raise OSError("statvfs is unavailable")
        fs_stats = statvfs_fn("/")
    except (OSError, RuntimeError, ValueError) as exc:
        fs_stats = None
        errors.append(type(exc).__name__)

    try:
        mounts = psutil.disk_partitions(all=False)
        mounted_filesystem_count: int | None = len(mounts)
    except (OSError, psutil.Error, RuntimeError, ValueError):
        # Mount enumeration is supporting context; retain capacity evidence if it fails.
        mounted_filesystem_count = None

    usage_percent: float | None = None
    inode_percent: float | None = None
    readonly: bool | None = None
    if fs_stats is not None:
        block_size = int(fs_stats.f_frsize or fs_stats.f_bsize)
        blocks_used = max(0, int(fs_stats.f_blocks) - int(fs_stats.f_bfree))
        bytes_used = blocks_used * block_size
        bytes_available = max(0, int(fs_stats.f_bavail)) * block_size
        user_capacity = bytes_used + bytes_available
        if block_size > 0 and user_capacity > 0:
            # Match the useful-capacity basis used by tools such as df: reserved blocks
            # reduce what an ordinary VPS account can write, even before bytes are full.
            usage_percent = round(100 * bytes_used / user_capacity, 1)

        inode_used = max(0, int(fs_stats.f_files) - int(fs_stats.f_ffree))
        inode_available = max(0, int(fs_stats.f_favail))
        inode_capacity = inode_used + inode_available
        if inode_capacity > 0:
            inode_percent = round(100 * inode_used / inode_capacity, 1)
        readonly = bool(fs_stats.f_flag & getattr(os, "ST_RDONLY", 1))

    complete = (
        usage is not None
        and fs_stats is not None
        and usage_percent is not None
        and inode_percent is not None
        and readonly is not None
    )
    status = CheckStatus.PASS if complete else CheckStatus.UNKNOWN
    note = None
    if not complete:
        detail = errors[0] if errors else "incomplete filesystem counters"
        note = f"Root filesystem capacity or inode counters are incomplete ({detail})."

    metrics: dict[str, str | int | float | bool | None] = {
        "usage_percent": usage_percent,
        "used_gb": round(usage.used / (1024**3), 2) if usage else None,
        "total_gb": round(usage.total / (1024**3), 2) if usage else None,
        "inode_usage_percent": inode_percent,
        "readonly": readonly,
        "mounted_filesystem_count": mounted_filesystem_count,
    }
    return [
        DiagnosticCheck(
            check_id="storage.root",
            category="storage",
            status=status,
            summary="Collected root filesystem capacity and inode utilization."
            if complete
            else "Root filesystem capacity or inode utilization is incomplete.",
            metrics=metrics,
            note=note,
        )
    ]

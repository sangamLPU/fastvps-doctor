"""Bounded filesystem capacity, inode and mount-state checks."""

from __future__ import annotations

import os
import posixpath
import sys
from typing import Any

import psutil

from fastvps_doctor.models import CheckStatus, DiagnosticCheck

MAX_MOUNTS = 16
SUPPORTED_FILESYSTEMS = {
    "btrfs",
    "ext2",
    "ext3",
    "ext4",
    "exfat",
    "f2fs",
    "fat",
    "jfs",
    "ntfs",
    "overlay",
    "tmpfs",
    "vfat",
    "xfs",
    "zfs",
}
REMOTE_FILESYSTEMS = ("9p", "ceph", "cifs", "fuse.sshfs", "gluster", "nfs", "smb")


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
            ),
            DiagnosticCheck(
                check_id="storage.mounts",
                category="storage",
                status=CheckStatus.SKIPPED,
                summary="Linux mounted-filesystem checks are unavailable on this platform.",
                metrics={"mount_count": None, "inspected_mount_count": 0},
                note="Use a supported Linux VPS to inspect mounted filesystem state.",
            ),
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
        mounts: list[Any] | None = psutil.disk_partitions(all=False)
        mounted_filesystem_count: int | None = len(mounts) if mounts is not None else None
    except (OSError, psutil.Error, RuntimeError, ValueError):
        # Mount enumeration is supporting context; retain capacity evidence if it fails.
        mounted_filesystem_count = None
        mounts = None

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
    root_check = DiagnosticCheck(
        check_id="storage.root",
        category="storage",
        status=status,
        summary="Collected root filesystem capacity and inode utilization."
        if complete
        else "Root filesystem capacity or inode utilization is incomplete.",
        metrics=metrics,
        note=note,
    )
    return [
        root_check,
        _collect_mounted_filesystems(mounts),
    ]


def _collect_mounted_filesystems(
    mounts: list[Any] | None,
) -> DiagnosticCheck:
    if mounts is None:
        return DiagnosticCheck(
            check_id="storage.mounts",
            category="storage",
            status=CheckStatus.UNKNOWN,
            summary="Mounted filesystem inventory could not be read.",
            metrics={"mount_count": None, "inspected_mount_count": 0},
            note="Per-mount capacity could not be verified.",
        )

    non_root = [mount for mount in mounts if posixpath.normpath(mount.mountpoint) != "/"]
    selected = non_root[:MAX_MOUNTS]
    metrics: dict[str, str | int | float | bool | None] = {
        "mount_count": len(non_root),
        "inspected_mount_count": 0,
        "mount_inventory_truncated": len(non_root) > MAX_MOUNTS,
    }
    incomplete = len(non_root) > MAX_MOUNTS
    for index, mount in enumerate(selected):
        prefix = f"mount_{index}_"
        fs_type = mount.fstype.lower()
        metrics[f"{prefix}filesystem_type"] = (
            fs_type if fs_type in SUPPORTED_FILESYSTEMS else "unsupported"
        )
        if fs_type.startswith(REMOTE_FILESYSTEMS):
            metrics[f"{prefix}state"] = "remote_skipped"
            metrics[f"{prefix}usage_percent"] = None
            metrics[f"{prefix}inode_usage_percent"] = None
            metrics[f"{prefix}readonly"] = None
            incomplete = True
            continue
        if fs_type not in SUPPORTED_FILESYSTEMS:
            metrics[f"{prefix}state"] = "unsupported_filesystem"
            metrics[f"{prefix}usage_percent"] = None
            metrics[f"{prefix}inode_usage_percent"] = None
            metrics[f"{prefix}readonly"] = None
            incomplete = True
            continue
        mount_path = mount.mountpoint
        normalized_path = posixpath.normpath(mount_path)
        if (
            not posixpath.isabs(mount_path)
            or normalized_path != mount_path.rstrip("/")
            or posixpath.realpath(mount_path) != normalized_path
            or posixpath.islink(mount_path)
        ):
            metrics[f"{prefix}state"] = "unavailable"
            metrics[f"{prefix}usage_percent"] = None
            metrics[f"{prefix}inode_usage_percent"] = None
            metrics[f"{prefix}readonly"] = None
            incomplete = True
            continue
        try:
            usage = psutil.disk_usage(mount_path)
            statvfs_fn = getattr(os, "statvfs", None)
            if not callable(statvfs_fn):
                raise OSError("statvfs is unavailable")
            fs_stats = statvfs_fn(mount_path)
        except (OSError, psutil.Error, RuntimeError, ValueError):
            metrics[f"{prefix}state"] = "unavailable"
            metrics[f"{prefix}usage_percent"] = None
            metrics[f"{prefix}inode_usage_percent"] = None
            metrics[f"{prefix}readonly"] = None
            incomplete = True
            continue

        block_size = int(fs_stats.f_frsize or fs_stats.f_bsize)
        blocks_used = max(0, int(fs_stats.f_blocks) - int(fs_stats.f_bfree))
        bytes_used = blocks_used * block_size
        bytes_available = max(0, int(fs_stats.f_bavail)) * block_size
        user_capacity = bytes_used + bytes_available
        usage_percent = (
            round(100 * bytes_used / user_capacity, 1)
            if block_size > 0 and user_capacity > 0
            else None
        )
        inode_used = max(0, int(fs_stats.f_files) - int(fs_stats.f_ffree))
        inode_available = max(0, int(fs_stats.f_favail))
        inode_capacity = inode_used + inode_available
        inode_percent = round(100 * inode_used / inode_capacity, 1) if inode_capacity > 0 else None
        readonly = bool(fs_stats.f_flag & getattr(os, "ST_RDONLY", 1))
        complete = usage_percent is not None and inode_percent is not None and readonly is not None
        metrics[f"{prefix}state"] = "ok" if complete else "partial"
        metrics[f"{prefix}usage_percent"] = usage_percent
        metrics[f"{prefix}inode_usage_percent"] = inode_percent
        metrics[f"{prefix}readonly"] = readonly
        metrics[f"{prefix}used_gb"] = round(usage.used / (1024**3), 2)
        metrics[f"{prefix}total_gb"] = round(usage.total / (1024**3), 2)
        metrics["inspected_mount_count"] = int(metrics["inspected_mount_count"] or 0) + 1
        incomplete |= not complete

    return DiagnosticCheck(
        check_id="storage.mounts",
        category="storage",
        status=CheckStatus.UNKNOWN if incomplete else CheckStatus.PASS,
        summary="Collected bounded capacity and inode indicators for local mounted filesystems.",
        metrics=metrics,
        note=(
            "Mount paths are withheld from reports. Remote, unsupported, inaccessible or excess mounts are not inspected."
            if incomplete
            else "Mount paths are withheld from reports; use local `df -hT` and `df -i` output to map indexed metrics."
        ),
    )

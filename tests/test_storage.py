from __future__ import annotations

from types import SimpleNamespace

from fastvps_doctor.checks import storage as storage_module
from fastvps_doctor.config import Thresholds
from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.reports import build_report
from fastvps_doctor.rules import analyze


def _partition(mountpoint: str, fstype: str = "ext4") -> SimpleNamespace:
    return SimpleNamespace(mountpoint=mountpoint, fstype=fstype)


def _statvfs(
    *,
    used_blocks: int = 50,
    free_blocks: int = 50,
    available_blocks: int = 50,
    used_inodes: int = 40,
    free_inodes: int = 60,
    available_inodes: int = 60,
    readonly: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        f_blocks=used_blocks + free_blocks,
        f_bfree=free_blocks,
        f_bavail=available_blocks,
        f_frsize=1024,
        f_bsize=1024,
        f_files=used_inodes + free_inodes,
        f_ffree=free_inodes,
        f_favail=available_inodes,
        f_flag=1 if readonly else 0,
    )


def test_mount_capacity_and_inode_pressure_create_path_free_findings(monkeypatch) -> None:
    monkeypatch.setattr(
        storage_module.psutil,
        "disk_usage",
        lambda path: (
            SimpleNamespace(used=80 * 1024**3, total=100 * 1024**3)
            if path == "/srv/customer-private-data"
            else SimpleNamespace(used=50, total=100)
        ),
    )
    monkeypatch.setattr(
        storage_module.os,
        "statvfs",
        lambda path: _statvfs(
            used_blocks=90 if path == "/srv/customer-private-data" else 50,
            free_blocks=10 if path == "/srv/customer-private-data" else 50,
            available_blocks=10 if path == "/srv/customer-private-data" else 50,
            used_inodes=95 if path == "/srv/customer-private-data" else 40,
            free_inodes=5 if path == "/srv/customer-private-data" else 60,
            available_inodes=5 if path == "/srv/customer-private-data" else 60,
        ),
        raising=False,
    )

    check = storage_module._collect_mounted_filesystems([_partition("/srv/customer-private-data")])
    root_check = DiagnosticCheck(
        check_id="storage.root",
        category="storage",
        status=CheckStatus.PASS,
        summary="Root filesystem is healthy.",
        metrics={"usage_percent": 45.0, "inode_usage_percent": 40.0, "readonly": False},
    )
    report = build_report([root_check, check], Thresholds())

    assert check.status == CheckStatus.PASS
    assert check.metrics["mount_0_usage_percent"] == 90.0
    assert check.metrics["mount_0_inode_usage_percent"] == 95.0
    assert [item.finding_id for item in report.findings] == ["STOR-005", "STOR-006"]
    assert report.checks[0].status == CheckStatus.PASS
    assert report.checks[1].status == CheckStatus.FAIL
    assert "/srv/customer-private-data" not in report.json_document()
    assert "customer-private-data" not in report.json_document()


def test_remote_unsupported_symlink_and_failed_mounts_are_unknown(monkeypatch) -> None:
    queried: list[str] = []

    def should_not_query(path: str) -> SimpleNamespace:
        queried.append(path)
        raise PermissionError("mount unavailable")

    monkeypatch.setattr(storage_module.psutil, "disk_usage", should_not_query)
    monkeypatch.setattr(storage_module.os, "statvfs", should_not_query, raising=False)
    monkeypatch.setattr(storage_module.posixpath, "islink", lambda path: path == "/link")
    check = storage_module._collect_mounted_filesystems(
        [
            _partition("/remote", "nfs4"),
            _partition("/mystery", "examplefs"),
            _partition("/link", "ext4"),
            _partition("/unavailable", "ext4"),
        ]
    )

    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["mount_0_state"] == "remote_skipped"
    assert check.metrics["mount_1_state"] == "unsupported_filesystem"
    assert check.metrics["mount_2_state"] == "unavailable"
    assert check.metrics["mount_3_state"] == "unavailable"
    assert queried == ["/unavailable"]
    assert analyze([check]) == []
    report = build_report([check])
    for private_path in ("/remote", "/mystery", "/link", "/unavailable"):
        assert private_path not in report.json_document()


def test_mount_enumeration_is_bounded_and_reported_incomplete(monkeypatch) -> None:
    monkeypatch.setattr(
        storage_module.psutil,
        "disk_usage",
        lambda _path: SimpleNamespace(used=50, total=100),
    )
    monkeypatch.setattr(storage_module.os, "statvfs", lambda _path: _statvfs(), raising=False)
    mounts = [_partition(f"/data/{index}") for index in range(storage_module.MAX_MOUNTS + 2)]

    check = storage_module._collect_mounted_filesystems(mounts)

    assert check.status == CheckStatus.UNKNOWN
    assert check.metrics["mount_count"] == storage_module.MAX_MOUNTS + 2
    assert check.metrics["inspected_mount_count"] == storage_module.MAX_MOUNTS
    assert check.metrics["mount_inventory_truncated"] is True
    assert "mount_16_state" not in check.metrics


def test_none_mount_inventory_preserves_root_data_and_marks_mounts_unknown(monkeypatch) -> None:
    monkeypatch.setattr(storage_module.sys, "platform", "linux")
    monkeypatch.setattr(
        storage_module.psutil,
        "disk_usage",
        lambda _path: SimpleNamespace(used=50, total=100),
    )
    monkeypatch.setattr(storage_module.os, "statvfs", lambda _path: _statvfs(), raising=False)
    monkeypatch.setattr(storage_module.psutil, "disk_partitions", lambda **_: None)

    root, mounts = storage_module.collect_storage()

    assert root.status == CheckStatus.PASS
    assert root.metrics["mounted_filesystem_count"] is None
    assert mounts.status == CheckStatus.UNKNOWN
    assert mounts.metrics["mount_count"] is None

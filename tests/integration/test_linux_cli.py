"""Opt-in end-to-end command test for a disposable Linux container or VM."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import psutil
import pytest


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("FASTVPS_DOCTOR_INTEGRATION") != "1" or not sys.platform.startswith("linux"),
    reason="Enable only inside a disposable Linux container/VM.",
)
def test_installed_cli_emits_json_report() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "fastvps_doctor", "diagnose", "--json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    result = json.loads(completed.stdout)
    assert result["product"] == "FastVPS Doctor"
    assert result["checks"]
    assert result["timestamp_utc"].endswith("Z")


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("FASTVPS_DOCTOR_INTEGRATION") != "1" or not sys.platform.startswith("linux"),
    reason="Enable only inside a disposable Linux container/VM.",
)
def test_command_timeout_terminates_its_linux_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastvps_doctor.runner import CommandRunner

    monkeypatch.setattr(CommandRunner, "_path", staticmethod(lambda _: sys.executable))
    script = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
        "print(child.pid,flush=True); time.sleep(30)"
    )
    result = CommandRunner(timeout_seconds=0.25, output_limit=512)._invoke(
        "python", ("-c", script), 0.25
    )
    assert result.timed_out is True
    child_pid = int(result.stdout.splitlines()[0])

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            child_state = psutil.Process(child_pid).status()
        except psutil.NoSuchProcess:
            break
        if child_state == psutil.STATUS_ZOMBIE:
            break
        time.sleep(0.05)
    else:
        raise AssertionError("Timed-out command left its child process running.")

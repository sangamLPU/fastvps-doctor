from io import BytesIO
from pathlib import Path

import pytest

from fastvps_doctor.config import Thresholds, load_thresholds
from fastvps_doctor.runner import CommandRunner, safe_hostname


def test_valid_config_loads_only_threshold_section(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[thresholds]\ndisk_warning_percent = 75\ndisk_critical_percent = 92\n", encoding="utf-8"
    )
    assert load_thresholds(config).disk_warning_percent == 75
    assert load_thresholds(config).disk_critical_percent == 92


def test_malformed_config_falls_back_to_defaults(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("[thresholds\n", encoding="utf-8")
    assert load_thresholds(config) == Thresholds()


def test_hostname_validation_rejects_url_path_and_shell_text() -> None:
    assert safe_hostname("example.org.") == "example.org"
    for invalid in ("https://example.org/path", "example.org;whoami", "", "bad..name"):
        with pytest.raises(ValueError):
            safe_hostname(invalid)


def test_runner_rejects_non_allowlisted_service() -> None:
    with pytest.raises(ValueError, match="allowlist"):
        CommandRunner().service_active("customer-input")


def test_runner_searches_only_trusted_linux_directories(monkeypatch: pytest.MonkeyPatch) -> None:
    import fastvps_doctor.runner as runner_module

    seen: dict[str, str | None] = {}
    monkeypatch.setattr(runner_module.sys, "platform", "linux")

    def which(executable: str, path: str | None = None) -> str:
        seen["executable"] = executable
        seen["path"] = path
        return "/usr/bin/systemctl"

    monkeypatch.setattr(runner_module.shutil, "which", which)
    assert CommandRunner._path("systemctl") == "/usr/bin/systemctl"
    assert seen["executable"] == "systemctl"
    assert "/usr/bin" in (seen["path"] or "")
    assert "PATH" not in (seen["path"] or "")
    assert CommandRunner._path("../systemctl") is None


def test_runner_rejects_unusable_bounds() -> None:
    import math

    with pytest.raises(ValueError, match="timeout_seconds"):
        CommandRunner(timeout_seconds=0)
    with pytest.raises(ValueError, match="timeout_seconds"):
        CommandRunner(timeout_seconds=math.nan)
    with pytest.raises(ValueError, match="output_limit"):
        CommandRunner(output_limit=0)


def test_runner_calls_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    import fastvps_doctor.runner as runner_module

    monkeypatch.setattr(CommandRunner, "_path", staticmethod(lambda _: "C:/systemctl"))
    captured: dict[str, object] = {}

    class FakeProcess:
        pid = 42

        def __init__(self, *_: object, **kwargs: object) -> None:
            self.stdout = BytesIO(b"active\n")
            self.returncode = 0
            captured.update(kwargs)
            captured["args"] = _[0] if _ else None

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(runner_module.subprocess, "Popen", FakeProcess)
    result = CommandRunner().service_active("nginx")
    assert result.stdout.strip() == "active"
    assert captured["shell"] is False
    assert captured["args"] == ["C:/systemctl", "is-active", "nginx"]
    assert captured["env"]["PATH"] == runner_module.TRUSTED_EXECUTION_PATH


def test_runner_caps_captured_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    import fastvps_doctor.runner as runner_module

    monkeypatch.setattr(CommandRunner, "_path", staticmethod(lambda _: "C:/tool"))

    class FakeProcess:
        pid = 42
        returncode = 0
        stdout = BytesIO(b"123456789")

        def __init__(self, *_: object, **__: object) -> None:
            pass

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            pass

    monkeypatch.setattr(runner_module.subprocess, "Popen", FakeProcess)
    result = CommandRunner(output_limit=4)._invoke("systemctl", ("is-active", "nginx"), 1)
    assert result.stdout == "1234"
    assert result.truncated is True


def test_runner_handles_missing_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(CommandRunner, "_path", staticmethod(lambda _: None))
    result = CommandRunner().service_active("nginx")
    assert result.available is False


def test_runner_reports_permission_denial_without_raw_os_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fastvps_doctor.runner as runner_module

    monkeypatch.setattr(CommandRunner, "_path", staticmethod(lambda _: "C:/tool"))

    def denied(*_: object, **__: object) -> None:
        raise PermissionError("sensitive path detail")

    monkeypatch.setattr(runner_module.subprocess, "Popen", denied)
    result = CommandRunner().service_active("nginx")
    assert result.available is True
    assert result.error == "permission_denied"
    assert "sensitive" not in str(result)


def test_runner_terminates_a_command_at_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    import fastvps_doctor.runner as runner_module

    monkeypatch.setattr(CommandRunner, "_path", staticmethod(lambda _: "C:/tool"))

    killed_groups: list[int] = []
    monkeypatch.setattr(
        runner_module.os, "killpg", lambda pid, sig: killed_groups.append(pid), raising=False
    )

    class HangingProcess:
        pid = 42

        def __init__(self, *_: object, **__: object) -> None:
            self.stdout = BytesIO()
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            return self.returncode or -9

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(runner_module.subprocess, "Popen", HangingProcess)
    result = CommandRunner(timeout_seconds=0.1)._invoke("systemctl", ("is-active", "nginx"), 1)
    assert result.timed_out is True
    if runner_module.sys.platform.startswith("linux"):
        assert killed_groups == [42]


def test_runner_returns_if_process_cleanup_also_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    import fastvps_doctor.runner as runner_module

    monkeypatch.setattr(CommandRunner, "_path", staticmethod(lambda _: "C:/tool"))
    monkeypatch.setattr(runner_module.os, "killpg", lambda *_: None, raising=False)

    class StuckProcess:
        pid = 42
        stdout = BytesIO()

        def __init__(self, *_: object, **__: object) -> None:
            self.wait_calls = 0

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            self.wait_calls += 1
            raise runner_module.subprocess.TimeoutExpired("tool", timeout)

        def kill(self) -> None:
            pass

    monkeypatch.setattr(runner_module.subprocess, "Popen", StuckProcess)
    result = CommandRunner(timeout_seconds=0.1)._invoke("systemctl", ("is-active", "nginx"), 1)
    assert result.timed_out is True
    assert result.returncode is None


def test_thresholds_reject_critical_value_below_warning() -> None:
    with pytest.raises(ValueError):
        Thresholds(disk_warning_percent=90, disk_critical_percent=85)

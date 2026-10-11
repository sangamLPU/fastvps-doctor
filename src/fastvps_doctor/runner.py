"""Central, allowlisted, timeout-bounded subprocess access.

Diagnostics never accept an arbitrary executable or shell fragment. New commands
must be added here with a fixed executable, fixed argument shape, and validation.
"""

from __future__ import annotations

import contextlib
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

TRUSTED_EXECUTION_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ALLOWED_SERVICES = {
    "nginx",
    "apache2",
    "ssh",
    "docker",
    "mysql",
    "mariadb",
    "postgresql",
    "redis-server",
}


@dataclass(frozen=True)
class CommandResult:
    available: bool
    returncode: int | None = None
    stdout: str = ""
    timed_out: bool = False
    truncated: bool = False
    error: str | None = None


class CommandRunner:
    """Run only pre-approved read-only commands with bounded time and output."""

    def __init__(self, timeout_seconds: float = 5.0, output_limit: int = 8192) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")
        if not isinstance(output_limit, int) or isinstance(output_limit, bool) or output_limit < 1:
            raise ValueError("output_limit must be at least one byte.")
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit

    @staticmethod
    def _path(executable: str) -> str | None:
        return find_executable(executable)

    def _invoke(self, executable: str, arguments: tuple[str, ...], timeout: float) -> CommandResult:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive.")
        path = self._path(executable)
        if path is None:
            return CommandResult(available=False)
        output = bytearray()
        output_limit_reached = threading.Event()
        timed_out = False
        try:
            process = subprocess.Popen(
                [path, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                env={"PATH": TRUSTED_EXECUTION_PATH, "LANG": "C", "LC_ALL": "C"},
                # Keep Linux descendants in a private process group so timeout cleanup
                # does not leave a helper running with the captured output pipe open.
                start_new_session=sys.platform.startswith("linux"),
            )
        except PermissionError:
            return CommandResult(available=True, returncode=126, error="permission_denied")
        except OSError:
            return CommandResult(available=True, returncode=127, error="execution_error")

        def drain_stdout() -> None:
            if process.stdout is None:
                return
            read = getattr(process.stdout, "read1", process.stdout.read)
            try:
                while len(output) <= self.output_limit:
                    chunk = read(min(1024, self.output_limit + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > self.output_limit:
                        output_limit_reached.set()
                        break
            except OSError:
                return

        reader = threading.Thread(target=drain_stdout, name="fastvps-command-output", daemon=True)
        reader.start()
        effective_timeout = min(max(timeout, 0.1), self.timeout_seconds)
        started = time.monotonic()
        while process.poll() is None:
            if output_limit_reached.is_set():
                break
            if time.monotonic() - started >= effective_timeout:
                timed_out = True
                break
            time.sleep(0.02)

        if timed_out or output_limit_reached.is_set():
            try:
                if sys.platform.startswith("linux"):
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
        try:
            returncode = process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                process.kill()
            try:
                returncode = process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                # Preserve the timeout result instead of letting cleanup itself hang
                # the diagnostic command indefinitely.
                returncode = None
                timed_out = True
        reader.join(timeout=1.0)

        # stderr is deliberately discarded: it often contains paths or config details.
        text = bytes(output[: self.output_limit]).decode("utf-8", errors="replace")
        return CommandResult(
            available=True,
            returncode=returncode,
            stdout=text,
            timed_out=timed_out,
            truncated=output_limit_reached.is_set(),
        )

    def service_active(self, unit: str, timeout: float = 3.0) -> CommandResult:
        if unit not in ALLOWED_SERVICES:
            raise ValueError("Service is not on the allowlist.")
        return self._invoke("systemctl", ("is-active", unit), timeout)

    def recent_service_logs(self, unit: str) -> CommandResult:
        if unit not in ALLOWED_SERVICES:
            raise ValueError("Service is not on the allowlist.")
        return self._invoke(
            "journalctl",
            ("--no-pager", "--quiet", "-u", unit, "-n", "40", "--since=-1h", "--output=cat"),
            3.0,
        )

    def validate_nginx(self) -> CommandResult:
        return self._invoke("nginx", ("-t",), 5.0)

    def validate_apache(self, executable: str) -> CommandResult:
        if executable not in {"apache2ctl", "apachectl"}:
            raise ValueError("Apache validator is not on the allowlist.")
        return self._invoke(executable, ("configtest",), 5.0)

    def validate_ssh(self) -> CommandResult:
        return self._invoke("sshd", ("-t",), 5.0)

    def firewall_status(self) -> CommandResult:
        return self._invoke("ufw", ("status",), 3.0)

    def simulate_package_upgrades(self) -> CommandResult:
        return self._invoke("apt-get", ("-s", "-o", "Debug::NoLocking=1", "upgrade"), 12.0)


def find_executable(executable: str) -> str | None:
    """Resolve an OS utility without trusting the caller's PATH environment."""
    if not sys.platform.startswith("linux") or not re.fullmatch(r"[A-Za-z0-9_.+-]+", executable):
        return None
    return shutil.which(executable, path=TRUSTED_EXECUTION_PATH)


def safe_hostname(value: str) -> str:
    """Validate a single DNS name supplied explicitly by the user."""
    hostname = value.rstrip(".")
    if not hostname or len(hostname) > 253 or "/" in hostname or "\\" in hostname:
        raise ValueError("Enter one valid hostname without a URL path.")
    try:
        ascii_name = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Hostname is not valid internationalized DNS text.") from exc
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Enter one valid hostname without a URL path.")
    return ascii_name

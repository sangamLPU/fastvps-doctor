"""Small platform helpers that expose no machine-specific identity."""

from __future__ import annotations

import platform as std_platform
import sys

SUPPORTED_DISTRIBUTIONS = {"ubuntu": {"24.04", "26.04"}, "debian": {"12", "13"}}


def _os_release_info() -> dict[str, str]:
    if not sys.platform.startswith("linux"):
        return {}
    try:
        return std_platform.freedesktop_os_release()
    except (OSError, AttributeError):
        return {}


def is_supported_distribution(info: dict[str, str]) -> bool:
    distribution_id = info.get("ID", "").lower()
    version = info.get("VERSION_ID", "")
    return version in SUPPORTED_DISTRIBUTIONS.get(distribution_id, set())


def linux_distribution_supported() -> bool | None:
    if not sys.platform.startswith("linux"):
        return None
    info = _os_release_info()
    if not info:
        return None
    return is_supported_distribution(info)


def linux_distribution() -> str:
    info = _os_release_info()
    if not info:
        return (
            "Linux distribution could not be identified"
            if sys.platform.startswith("linux")
            else "Unsupported platform"
        )
    name = info.get("ID", "Linux").replace("_", " ").strip()
    version = info.get("VERSION_ID", "").strip()
    # Restrict to a conservative, non-identifying subset of os-release values.
    name = "".join(char for char in name if char.isalnum() or char in " .-")[:48]
    version = "".join(char for char in version if char.isalnum() or char in ".-")[:24]
    if not name:
        name = "Linux"
    return f"{name} {version}".strip()

"""Read-only local threshold configuration."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disk_warning_percent: float = Field(default=80.0, ge=1, le=99)
    disk_critical_percent: float = Field(default=90.0, ge=2, le=100)
    inode_warning_percent: float = Field(default=80.0, ge=1, le=99)
    inode_critical_percent: float = Field(default=90.0, ge=2, le=100)
    low_available_memory_percent: float = Field(default=10.0, ge=1, le=50)
    memory_psi_warning_percent: float = Field(default=10.0, gt=0, le=100)

    @model_validator(mode="after")
    def critical_thresholds_must_exceed_warning(self) -> Thresholds:
        if self.disk_critical_percent <= self.disk_warning_percent:
            raise ValueError("disk_critical_percent must exceed disk_warning_percent")
        if self.inode_critical_percent <= self.inode_warning_percent:
            raise ValueError("inode_critical_percent must exceed inode_warning_percent")
        return self


def default_config_path() -> Path:
    return Path.home() / ".config" / "fastvps-doctor" / "config.toml"


def load_thresholds(path: Path | None = None) -> Thresholds:
    """Load known threshold keys; malformed config falls back to safe defaults."""
    config_path = path or default_config_path()
    try:
        with config_path.open("rb") as config_file:
            data = tomllib.load(config_file)
        settings = data.get("thresholds", {})
        if not isinstance(settings, dict):
            return Thresholds()
        return Thresholds.model_validate(settings)
    except (OSError, tomllib.TOMLDecodeError, ValidationError):
        return Thresholds()

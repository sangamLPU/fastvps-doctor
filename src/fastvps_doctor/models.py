"""Shared result models consumed by the CLI and report renderers."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CheckStatus(StrEnum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SupportScope(StrEnum):
    INFRASTRUCTURE = "infrastructure-facing"
    GUEST = "guest-os/application-facing"
    UNKNOWN = "undetermined"


class DiagnosticCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str
    category: str
    status: CheckStatus
    summary: str
    metrics: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    note: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    possible_causes: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    requires_privileges: bool = False
    support_scope: SupportScope = SupportScope.UNKNOWN


class SupportSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overview: str
    passed_checks: list[str] = Field(default_factory=list)
    warning_checks: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    unavailable_checks: list[str] = Field(default_factory=list)
    further_investigation: list[str] = Field(default_factory=list)


class DiagnosticReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: str = "FastVPS Doctor"
    version: str
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    distribution: str = "Unknown Linux distribution"
    coverage: list[str]
    overall_status: str
    checks: list[DiagnosticCheck]
    findings: list[Finding]
    support_summary: SupportSummary
    profile: str | None = None
    ticket_reference: str | None = None

    def json_document(self) -> str:
        """Return stable, indented JSON suitable for local review and sharing."""
        return self.model_dump_json(indent=2)


def utc_now() -> datetime:
    return datetime.now(UTC)


def json_safe(value: Any) -> Any:
    """Convert nested Pydantic values to JSON-ready Python data."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value

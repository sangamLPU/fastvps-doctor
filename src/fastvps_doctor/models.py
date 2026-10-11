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


class ProblemCategory(StrEnum):
    WEBSITE = "website"
    APPLICATION = "application"
    DATABASE = "database"
    EMAIL = "email"
    NETWORK = "network"
    PERFORMANCE = "performance"
    AVAILABILITY = "availability"
    OTHER = "other"


class IncidentEventType(StrEnum):
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    SERVICE_FAILURE = "service_failure"
    SERVICE_RESTART_SCHEDULED = "service_restart_scheduled"
    SERVICE_ERROR = "service_error"
    OOM_KILL = "oom_kill"
    MEMORY_PRESSURE = "memory_pressure"


class TroubleshootScenario(StrEnum):
    WEBSITE_UNAVAILABLE = "website-unavailable"
    SERVICE_CRASH = "service-crash"
    STORAGE = "storage"


class EvidenceCertainty(StrEnum):
    CONFIRMED = "confirmed"
    PLAUSIBLE = "plausible"
    INSUFFICIENT = "insufficient"


class TroubleshootObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    source: str
    summary: str
    check_id: str | None = None
    status: CheckStatus | None = None


class TroubleshootTimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp_utc: datetime
    classification: IncidentEventType
    summary: str


class TroubleshootConclusion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    certainty: EvidenceCertainty
    statement: str
    evidence_ids: list[str] = Field(default_factory=list)


class TroubleshootReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: str = "FastVPS Doctor"
    version: str
    schema_version: str = "1.0"
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scenario: TroubleshootScenario
    distribution: str = "Unknown Linux distribution"
    kernel_release: str | None = None
    reported_problem: str | None = None
    service_label: str | None = None
    selected_port: int | None = None
    loopback_http_probe_requested: bool = False
    checks: list[DiagnosticCheck]
    observations: list[TroubleshootObservation] = Field(default_factory=list)
    timeline: list[TroubleshootTimelineEvent] = Field(default_factory=list)
    conclusions: list[TroubleshootConclusion] = Field(default_factory=list)
    investigation_areas: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    profile: str | None = None
    ticket_reference: str | None = None
    review_reminder: str = "Review and redact this report before sharing it."

    def json_document(self) -> str:
        """Return stable, indented JSON suitable for local review and sharing."""
        return self.model_dump_json(indent=2)


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


class IncidentInformation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_time_utc: datetime | None = None
    affected_service: str | None = None
    problem_category: ProblemCategory | None = None
    description: str | None = None


class IncidentEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp_utc: datetime
    classification: IncidentEventType
    component: str
    evidence_summary: str
    correlation_explanation: str | None = None


class IncidentHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str
    start_time_utc: datetime
    end_time_utc: datetime
    evidence: list[str] = Field(default_factory=list)
    confidence: str = "low"
    alternatives: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class IncidentAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str
    window_seconds: int
    generated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    complete: bool
    unavailable_sources: list[str] = Field(default_factory=list)
    events: list[IncidentEvent] = Field(default_factory=list)
    hypotheses: list[IncidentHypothesis] = Field(default_factory=list)
    note: str | None = None


class SupportHandoff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reported_problem: str | None = None
    confirmed_observations: list[str] = Field(default_factory=list)
    investigation_areas: list[str] = Field(default_factory=list)
    unavailable_checks: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)


class DiagnosticReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: str = "FastVPS Doctor"
    version: str
    schema_version: str = "2.0"
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    distribution: str = "Unknown Linux distribution"
    kernel_release: str | None = None
    installed_services: list[str] = Field(default_factory=list)
    coverage: list[str]
    overall_status: str
    checks: list[DiagnosticCheck]
    findings: list[Finding]
    support_summary: SupportSummary
    profile: str | None = None
    ticket_reference: str | None = None
    incident_information: IncidentInformation | None = None
    incident_analysis: IncidentAnalysis | None = None
    support_handoff: SupportHandoff = Field(default_factory=SupportHandoff)

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

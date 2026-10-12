from __future__ import annotations

import sys

import pytest

from examples.troubleshoot_demos import build_fixture_report, run_live_website_demo
from fastvps_doctor.models import CheckStatus, TroubleshootObservation, TroubleshootScenario
from fastvps_doctor.troubleshoot import render_troubleshoot_markdown


@pytest.mark.parametrize("scenario", list(TroubleshootScenario))
def test_scenario_demo_fixtures_are_deterministic_and_sanitized(scenario) -> None:
    first = build_fixture_report(scenario)
    second = build_fixture_report(scenario)

    assert first.json_document() == second.json_document()
    assert first.scenario == scenario
    assert "DEMO FIXTURE" in (first.reported_problem or "")
    assert "synthetic fixture" in render_troubleshoot_markdown(first).lower() or any(
        "synthetic fixture" in gap.lower() for gap in first.evidence_gaps
    )
    document = first.json_document()
    assert "/srv/" not in document
    assert "raw log" not in document.lower()


def test_markdown_leads_with_assessment_and_caps_prioritized_observations() -> None:
    report = build_fixture_report(TroubleshootScenario.WEBSITE_UNAVAILABLE)
    additional = [
        TroubleshootObservation(
            evidence_id=f"OBS-{index:03d}",
            source="snapshot",
            summary="Additional lower-priority synthetic context.",
            check_id="system.resources",
            status=CheckStatus.PASS,
        )
        for index in range(6, 9)
    ]
    report = report.model_copy(update={"observations": [*report.observations, *additional]})

    markdown = render_troubleshoot_markdown(report)
    main_observations = markdown.split("## 2. Most important observations", maxsplit=1)[1].split(
        "## 3. Likely investigation areas", maxsplit=1
    )[0]

    assert markdown.index("## 1. Incident summary") < markdown.index(
        "## 2. Most important observations"
    )
    assert "Overall assessment: **Evidence of a specific failure**" in markdown
    assert main_observations.count("- **OBS-") == 2
    assert main_observations.index("OBS-001") < main_observations.index("OBS-004")
    assert "OBS-005" not in main_observations
    assert "OBS-008" not in main_observations
    assert "OBS-008" in markdown.split("### Complete observation register", maxsplit=1)[1]
    assert "OBS-005" in markdown.split("### Complete observation register", maxsplit=1)[1]
    assert "Why it matters:" in main_observations
    assert "## 6. Technical appendix" in markdown


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Requires Linux loopback networking.",
)
def test_live_website_demo_uses_a_disposable_loopback_503_service() -> None:
    report = run_live_website_demo()

    assert report.scenario == TroubleshootScenario.WEBSITE_UNAVAILABLE
    assert report.selected_port is not None
    http_check = next(check for check in report.checks if check.check_id == "troubleshoot.http")
    assert http_check.metrics["http_probe_state"] == "response_5xx"
    assert http_check.metrics["http_status_code"] == 503
    assert any(
        "HTTP HEAD request received status 503" in item.statement for item in report.conclusions
    )

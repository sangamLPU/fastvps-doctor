from __future__ import annotations

import sys

import pytest

from examples.troubleshoot_demos import build_fixture_report, run_live_website_demo
from fastvps_doctor.models import TroubleshootScenario
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

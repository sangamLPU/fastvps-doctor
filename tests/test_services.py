from fastvps_doctor.checks import services as services_module
from fastvps_doctor.checks.services import collect_services
from fastvps_doctor.models import CheckStatus
from fastvps_doctor.reports import build_report, render_markdown
from fastvps_doctor.runner import CommandResult


class FailedNginxRunner:
    def service_active(self, unit: str) -> CommandResult:
        assert unit == "nginx"
        return CommandResult(available=True, returncode=3, stdout="failed\n")

    def recent_service_logs(self, unit: str) -> CommandResult:
        assert unit == "nginx"
        return CommandResult(
            available=True,
            returncode=0,
            stdout="error: connection failed\nfatal: token=very-private\n",
        )

    def validate_nginx(self) -> CommandResult:
        return CommandResult(available=True, returncode=0)


def test_failed_service_logs_are_summarized_without_exporting_contents(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda executable: "/usr/sbin/nginx" if executable == "nginx" else None,
    )
    check = collect_services(runner=FailedNginxRunner())[0]
    assert check.status == CheckStatus.WARNING
    assert check.metrics["nginx_recent_error_count"] == 2
    report = build_report([check])
    markdown = render_markdown(report)
    assert "service-log lines matched error indicators" in markdown
    assert "very-private" not in markdown
    assert "connection failed" not in markdown


def test_service_status_needs_consistent_success_output(monkeypatch) -> None:
    monkeypatch.setattr(
        services_module,
        "find_executable",
        lambda executable: "/usr/sbin/nginx" if executable == "nginx" else None,
    )

    class InconsistentRunner:
        def service_active(self, unit: str) -> CommandResult:
            assert unit == "nginx"
            return CommandResult(available=True, returncode=0, stdout="failed\n", timed_out=True)

        def recent_service_logs(self, unit: str) -> CommandResult:
            raise AssertionError("Timed-out status must not trigger a log read.")

        def validate_nginx(self) -> CommandResult:
            return CommandResult(available=True, returncode=0)

    check = collect_services(runner=InconsistentRunner())[0]
    assert check.metrics["nginx_state"] == "timeout"
    assert check.metrics["failed_count"] == 0

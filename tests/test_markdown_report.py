from datetime import UTC, datetime

from scanner.core.evidence import HttpEvidence
from scanner.core.finding import Finding, Severity, VulnerabilityClass
from scanner.core.identity import AuthenticatedIdentity
from scanner.core.result import HttpRequestResult
from scanner.main import ScannerRunResult
from scanner.reporting.markdown_report import (
    build_markdown_report,
    count_findings_by_class,
    escape_table_cell,
    write_markdown_report,
)


def build_result(findings: list[Finding] | None = None) -> ScannerRunResult:
    return ScannerRunResult(
        target_name="External API",
        base_url="http://testserver",
        identities={
            "regular": AuthenticatedIdentity(
                name="regular",
                email="regular@example.test",
                role="user",
                access_token="secret-token",
            )
        },
        health_status_code=200,
        openapi_status_code=200,
        openapi_title="External API",
        findings=findings or [],
    )


def build_finding() -> Finding:
    return Finding(
        title="BOLA: same_role_users_cannot_read_each_others_resources",
        vulnerability_class=VulnerabilityClass.BOLA,
        severity=Severity.HIGH,
        endpoint="/resources/{id}",
        method="GET",
        identity_name="regular",
        description="A regular user accessed another user's resource.",
        recommendation="Check resource ownership before returning the resource.",
        evidence=[
            HttpEvidence(
                observed=HttpRequestResult(
                    identity_name="regular",
                    method="GET",
                    path="/resources/1",
                    status_code=200,
                    request_json={"password": "secret-password"},
                    response_json={
                        "id": "1",
                        "owner_id": "other-subject",
                        "password_hash": "secret-hash",
                    },
                ),
                expected_status_code=403,
                description="Cross-user resource read succeeded.",
            )
        ],
    )


def build_bfla_finding() -> Finding:
    return Finding(
        title="BFLA: regular_users_cannot_open_admin_panel",
        vulnerability_class=VulnerabilityClass.BFLA,
        severity=Severity.HIGH,
        endpoint="/admin/users",
        method="GET",
        identity_name="regular",
        description="A regular user accessed an admin function.",
        recommendation="Require admin role before executing privileged functions.",
        evidence=[
            HttpEvidence(
                observed=HttpRequestResult(
                    identity_name="regular",
                    method="GET",
                    path="/admin/users",
                    status_code=200,
                    response_json=[],
                ),
                expected_status_code=403,
                description="Admin user listing succeeded.",
            )
        ],
    )


def test_escape_table_cell_keeps_markdown_tables_valid() -> None:
    assert escape_table_cell("a|b\nc") == "a\\|b c"


def test_count_findings_by_class_groups_findings_for_summary() -> None:
    result = build_result([build_finding(), build_bfla_finding()])

    assert count_findings_by_class(result) == {
        "BOLA": 1,
        "BFLA": 1,
    }


def test_build_markdown_report_includes_summary_findings_and_evidence() -> None:
    report = build_markdown_report(
        build_result([build_finding()]),
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert "# AuthZ Scanner Report" in report
    assert "- Target: `External API`" in report
    assert "- Total Findings: `1`" in report
    assert "### Findings by Class" in report
    assert "| BOLA | 1 |" in report
    assert "### Findings Table" in report
    assert "| 1 | high | BOLA | GET | `/resources/{id}` | regular |" in report
    assert "### 1. BOLA: same_role_users_cannot_read_each_others_resources" in report
    assert "- Expected Status: `403`" in report
    assert "- Observed Status: `200`" in report
    assert "- Full Evidence: `Appendix 1.1`" in report
    assert "## Evidence Appendix" in report
    assert "### Appendix 1.1" in report
    assert '"owner_id": "other-subject"' in report
    assert '"password": "[REDACTED]"' in report
    assert '"password_hash": "[REDACTED]"' in report
    assert "secret-password" not in report
    assert "secret-hash" not in report
    assert "Check resource ownership before returning the resource." in report
    assert "secret-token" not in report


def test_build_markdown_report_handles_zero_findings() -> None:
    report = build_markdown_report(
        build_result(),
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert "- Total Findings: `0`" in report
    assert "No findings were identified." in report


def test_write_markdown_report_creates_report_file(tmp_path) -> None:
    report_path = write_markdown_report(
        build_result([build_finding()]),
        output_dir=tmp_path,
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert report_path.name == "authz-scan-external-api-20260902T120000Z.md"
    assert report_path.read_text().startswith("# AuthZ Scanner Report")

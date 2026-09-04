import httpx

from scanner.core.config import (
    AuthConfig,
    BflaAttackConfig,
    BflaConfig,
    BflaTestConfig,
    BolaAttackConfig,
    BolaConfig,
    BolaResourceConfig,
    BolaTestConfig,
    IdentityConfig,
    ProfileConfig,
    PropertyAuthConfig,
    ScannerConfig,
    TargetConfig,
)
from scanner.core.identity import AuthenticatedIdentity
from scanner.main import ScannerRunResult, run_scan, write_reports


def build_config() -> ScannerConfig:
    return ScannerConfig(
        target=TargetConfig(name="external-api", base_url="http://testserver"),
        auth=AuthConfig(login_path="/session", token_field="token"),
        profile=ProfileConfig(path="/me", id_field="subject_id"),
        identities={
            "owner": IdentityConfig(
                email="owner@example.test",
                password="owner-secret",
                role="user",
            ),
            "attacker": IdentityConfig(
                email="attacker@example.test",
                password="attacker-secret",
                role="user",
            ),
            "privileged": IdentityConfig(
                email="privileged@example.test",
                password="privileged-secret",
                role="admin",
            ),
        },
        bola=BolaConfig(
            tests=[
                BolaTestConfig(
                    name="same_role_users_cannot_read_each_others_resources",
                    role="user",
                    owner_field="owner_id",
                    resource=BolaResourceConfig(
                        list_method="GET",
                        list_path="/resources",
                        id_field="id",
                    ),
                    attack=BolaAttackConfig(
                        method="GET",
                        path_template="/resources/{id}",
                    ),
                    expected_status=403,
                )
            ]
        ),
        bfla=BflaConfig(
            tests=[
                BflaTestConfig(
                    name="low_privilege_users_cannot_open_admin_panel",
                    role="user",
                    attack=BflaAttackConfig(
                        method="GET",
                        path_template="/admin/users",
                    ),
                    expected_status=403,
                )
            ]
        ),
        property_auth=PropertyAuthConfig(tests=[]),
    )


def test_run_scan_logs_in_identities_checks_api_and_runs_bola(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/session":
            return httpx.Response(200, json={"token": f"token-for-{request.url.host}"})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"info": {"title": "External API"}, "paths": {}})
        if request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "resource-owned-by-owner", "owner_id": "subject-owner"},
                ],
            )
        if request.url.path == "/resources/resource-owned-by-owner":
            return httpx.Response(403, json={"detail": "Forbidden"})
        if request.url.path == "/admin/users":
            return httpx.Response(403, json={"detail": "Forbidden"})
        return httpx.Response(404, json={})

    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(
                transport=httpx.MockTransport(handler),
                base_url=kwargs["base_url"],
                timeout=kwargs["timeout"],
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    result = run_scan(build_config())

    assert result.target_name == "external-api"
    assert result.base_url == "http://testserver"
    assert set(result.identities) == {"owner", "attacker", "privileged"}
    assert result.health_status_code == 200
    assert result.health_ok is True
    assert result.openapi_status_code == 200
    assert result.openapi_ok is True
    assert result.openapi_title == "External API"
    assert result.findings == []
    assert result.finding_count == 0


def test_write_reports_writes_json_and_markdown_when_format_is_all(tmp_path) -> None:
    scanner_result = ScannerRunResult(
        target_name="external-api",
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
        findings=[],
    )

    report_paths = write_reports(scanner_result, "all", tmp_path)

    assert len(report_paths) == 2
    assert {path.suffix for path in report_paths} == {".json", ".md"}

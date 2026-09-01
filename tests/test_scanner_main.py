import httpx

from scanner.core.config import (
    AuthConfig,
    BolaAttackConfig,
    BolaConfig,
    BolaResourceConfig,
    BolaTestConfig,
    IdentityConfig,
    ProfileConfig,
    ScannerConfig,
    TargetConfig,
)
from scanner.main import run_smoke_scan


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
    )


def test_run_smoke_scan_logs_in_identities_and_checks_health_and_openapi(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/session":
            return httpx.Response(200, json={"token": f"token-for-{request.url.host}"})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"info": {"title": "External API"}, "paths": {}})
        return httpx.Response(404, json={})

    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(
                transport=httpx.MockTransport(handler),
                base_url=kwargs["base_url"],
                timeout=kwargs["timeout"],
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    result = run_smoke_scan(build_config())

    assert result.target_name == "external-api"
    assert result.base_url == "http://testserver"
    assert set(result.identities) == {"owner", "privileged"}
    assert result.health_status_code == 200
    assert result.health_ok is True
    assert result.openapi_status_code == 200
    assert result.openapi_ok is True
    assert result.openapi_title == "External API"

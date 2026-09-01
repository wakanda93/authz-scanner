import json

import httpx
import pytest

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
from scanner.core.identity import IdentityLoginError, login_all_identities, login_identity


def build_config() -> ScannerConfig:
    return ScannerConfig(
        target=TargetConfig(name="test", base_url="http://testserver"),
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


def test_login_identity_returns_authenticated_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/session"
        return httpx.Response(200, json={"token": "token-for-owner"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    config = build_config()

    identity = login_identity(
        client=client,
        login_path=config.auth.login_path,
        token_field=config.auth.token_field,
        name="owner",
        identity=config.identities["owner"],
    )

    assert identity.name == "owner"
    assert identity.email == "owner@example.test"
    assert identity.role == "user"
    assert identity.access_token == "token-for-owner"
    assert identity.authorization_header == {"Authorization": "Bearer token-for-owner"}


def test_login_all_identities_returns_identity_map() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        token = "privileged-token" if body["email"] == "privileged@example.test" else "owner-token"
        return httpx.Response(200, json={"token": token})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")

    identities = login_all_identities(client, build_config())

    assert set(identities) == {"owner", "privileged"}
    assert identities["owner"].access_token == "owner-token"
    assert identities["privileged"].access_token == "privileged-token"


def test_login_identity_raises_when_login_fails() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(401, json={})),
        base_url="http://testserver",
    )
    config = build_config()

    with pytest.raises(IdentityLoginError, match="Login failed"):
        login_identity(
            client=client,
            login_path=config.auth.login_path,
            token_field=config.auth.token_field,
            name="owner",
            identity=config.identities["owner"],
        )


def test_login_identity_raises_when_token_field_is_missing() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
        base_url="http://testserver",
    )
    config = build_config()

    with pytest.raises(IdentityLoginError, match="did not include token field"):
        login_identity(
            client=client,
            login_path=config.auth.login_path,
            token_field=config.auth.token_field,
            name="owner",
            identity=config.identities["owner"],
        )

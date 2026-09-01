import json

import httpx
import pytest

from scanner.core.config import AuthConfig, IdentityConfig, ScannerConfig, TargetConfig
from scanner.core.identity import IdentityLoginError, login_all_identities, login_identity


def build_config() -> ScannerConfig:
    return ScannerConfig(
        target=TargetConfig(name="test", base_url="http://testserver"),
        auth=AuthConfig(login_path="/auth/login", token_field="access_token"),
        identities={
            "userA": IdentityConfig(
                email="userA@example.com",
                password="Password123!",
                role="user",
            ),
            "admin1": IdentityConfig(
                email="admin1@example.com",
                password="Password123!",
                role="admin",
            ),
        },
    )


def test_login_identity_returns_authenticated_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/auth/login"
        return httpx.Response(200, json={"access_token": "token-for-user-a"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    config = build_config()

    identity = login_identity(
        client=client,
        login_path=config.auth.login_path,
        token_field=config.auth.token_field,
        name="userA",
        identity=config.identities["userA"],
    )

    assert identity.name == "userA"
    assert identity.email == "userA@example.com"
    assert identity.role == "user"
    assert identity.access_token == "token-for-user-a"
    assert identity.authorization_header == {"Authorization": "Bearer token-for-user-a"}


def test_login_all_identities_returns_identity_map() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        token = "admin-token" if body["email"] == "admin1@example.com" else "user-token"
        return httpx.Response(200, json={"access_token": token})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")

    identities = login_all_identities(client, build_config())

    assert set(identities) == {"userA", "admin1"}
    assert identities["userA"].access_token == "user-token"
    assert identities["admin1"].access_token == "admin-token"


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
            name="userA",
            identity=config.identities["userA"],
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
            name="userA",
            identity=config.identities["userA"],
        )

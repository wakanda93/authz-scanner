from pydantic import BaseModel

from scanner.core.config import IdentityConfig, ScannerConfig


class AuthenticatedIdentity(BaseModel):
    name: str
    email: str
    role: str
    access_token: str

    @property
    def authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


class IdentityLoginError(RuntimeError):
    pass


def login_identity(
    client,
    login_path: str,
    token_field: str,
    name: str,
    identity: IdentityConfig,
) -> AuthenticatedIdentity:
    response = client.post(
        login_path,
        json={
            "email": identity.email,
            "password": identity.password,
        },
    )

    if response.status_code != 200:
        raise IdentityLoginError(
            f"Login failed for identity '{name}' with status {response.status_code}"
        )

    try:
        body = response.json()
    except ValueError as exc:
        raise IdentityLoginError(f"Login response for identity '{name}' was not valid JSON") from exc

    access_token = body.get(token_field)
    if not isinstance(access_token, str) or not access_token:
        raise IdentityLoginError(
            f"Login response for identity '{name}' did not include token field '{token_field}'"
        )

    return AuthenticatedIdentity(
        name=name,
        email=identity.email,
        role=identity.role,
        access_token=access_token,
    )


def login_all_identities(client, config: ScannerConfig) -> dict[str, AuthenticatedIdentity]:
    return {
        name: login_identity(
            client=client,
            login_path=config.auth.login_path,
            token_field=config.auth.token_field,
            name=name,
            identity=identity,
        )
        for name, identity in config.identities.items()
    }

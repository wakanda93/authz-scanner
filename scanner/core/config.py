from pathlib import Path

import yaml
from pydantic import BaseModel


class TargetConfig(BaseModel):
    name: str
    base_url: str


class AuthConfig(BaseModel):
    login_path: str
    token_field: str


class IdentityConfig(BaseModel):
    email: str
    password: str
    role: str


class ScannerConfig(BaseModel):
    target: TargetConfig
    auth: AuthConfig
    identities: dict[str, IdentityConfig]


def load_config(path: str | Path) -> ScannerConfig:
    config_path = Path(path)
    raw_config = yaml.safe_load(config_path.read_text()) or {}
    return ScannerConfig.model_validate(raw_config)

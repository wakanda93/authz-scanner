from pathlib import Path

import yaml
from typing import Any

from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    name: str
    base_url: str


class AuthConfig(BaseModel):
    login_path: str
    token_field: str


class ProfileConfig(BaseModel):
    path: str
    id_field: str


class IdentityConfig(BaseModel):
    email: str
    password: str
    role: str


class BolaResourceConfig(BaseModel):
    list_method: str
    list_path: str
    id_field: str


class BolaAttackConfig(BaseModel):
    method: str
    path_template: str
    path_params: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None


class BolaTestConfig(BaseModel):
    name: str
    role: str
    owner_field: str
    resource: BolaResourceConfig
    attack: BolaAttackConfig
    expected_status: int


class BolaConfig(BaseModel):
    tests: list[BolaTestConfig]


class ScannerConfig(BaseModel):
    target: TargetConfig
    auth: AuthConfig
    profile: ProfileConfig
    identities: dict[str, IdentityConfig]
    bola: BolaConfig


def load_config(path: str | Path) -> ScannerConfig:
    config_path = Path(path)
    raw_config = yaml.safe_load(config_path.read_text()) or {}
    return ScannerConfig.model_validate(raw_config)

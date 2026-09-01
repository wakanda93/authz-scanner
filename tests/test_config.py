from pathlib import Path

from scanner.core.config import ScannerConfig, load_config


def test_loads_vulnerable_scanner_config() -> None:
    config = load_config(Path("config/vulnerable.yaml"))

    assert isinstance(config, ScannerConfig)
    assert config.target.name == "vulnerable"
    assert config.target.base_url == "http://127.0.0.1:8001"
    assert config.auth.login_path == "/auth/login"
    assert config.auth.token_field == "access_token"
    assert set(config.identities) == {"userA", "userB", "admin1"}
    assert config.identities["userA"].email == "userA@example.com"
    assert config.identities["userA"].role == "user"


def test_loads_hardened_scanner_config() -> None:
    config = load_config(Path("config/hardened.yaml"))

    assert config.target.name == "hardened"
    assert config.target.base_url == "http://127.0.0.1:8002"
    assert config.identities["admin1"].email == "admin1@example.com"
    assert config.identities["admin1"].role == "admin"

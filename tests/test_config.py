from scanner.core.config import ScannerConfig, load_config


def test_loads_scanner_config_from_yaml(tmp_path) -> None:
    config_path = tmp_path / "scanner.yaml"
    config_path.write_text(
        """
target:
  name: external-api
  base_url: https://api.example.test

auth:
  login_path: /session
  token_field: token

identities:
  owner:
    email: owner@example.test
    password: owner-secret
    role: user
  attacker:
    email: attacker@example.test
    password: attacker-secret
    role: user
  privileged:
    email: privileged@example.test
    password: privileged-secret
    role: admin
""",
    )

    config = load_config(config_path)

    assert isinstance(config, ScannerConfig)
    assert config.target.name == "external-api"
    assert config.target.base_url == "https://api.example.test"
    assert config.auth.login_path == "/session"
    assert config.auth.token_field == "token"
    assert set(config.identities) == {"owner", "attacker", "privileged"}
    assert config.identities["owner"].email == "owner@example.test"
    assert config.identities["owner"].role == "user"
    assert config.identities["privileged"].role == "admin"


def test_loads_empty_yaml_as_invalid_config(tmp_path) -> None:
    config_path = tmp_path / "empty.yaml"
    config_path.write_text("")

    try:
        load_config(config_path)
    except ValueError as exc:
        assert "target" in str(exc)
    else:
        raise AssertionError("Expected invalid config to raise ValueError")

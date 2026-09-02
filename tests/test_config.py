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

profile:
  path: /me
  id_field: subject_id

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

bola:
  tests:
    - name: same_role_users_cannot_read_each_others_resources
      role: user
      owner_field: owner_id
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
      attack:
        method: GET
        path_template: /resources/{id}
        path_params:
          child_id: children.0.id
      expected_status: 403

bfla:
  tests:
    - name: low_privilege_users_cannot_run_privileged_action
      role: user
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
        owner_field: owner_id
      attack:
        method: POST
        path_template: /resources/{id}/privileged-action
      expected_status: 403
    - name: low_privilege_users_cannot_open_admin_panel
      role: user
      attack:
        method: GET
        path_template: /admin/users
      expected_status: 403
""",
    )

    config = load_config(config_path)

    assert isinstance(config, ScannerConfig)
    assert config.target.name == "external-api"
    assert config.target.base_url == "https://api.example.test"
    assert config.auth.login_path == "/session"
    assert config.auth.token_field == "token"
    assert config.profile.path == "/me"
    assert config.profile.id_field == "subject_id"
    assert set(config.identities) == {"owner", "attacker", "privileged"}
    assert config.identities["owner"].email == "owner@example.test"
    assert config.identities["owner"].role == "user"
    assert config.identities["privileged"].role == "admin"
    assert len(config.bola.tests) == 1
    bola_test = config.bola.tests[0]
    assert bola_test.name == "same_role_users_cannot_read_each_others_resources"
    assert bola_test.role == "user"
    assert bola_test.owner_field == "owner_id"
    assert bola_test.resource.list_method == "GET"
    assert bola_test.resource.list_path == "/resources"
    assert bola_test.resource.id_field == "id"
    assert bola_test.attack.method == "GET"
    assert bola_test.attack.path_template == "/resources/{id}"
    assert bola_test.attack.path_params == {"child_id": "children.0.id"}
    assert bola_test.expected_status == 403
    assert len(config.bfla.tests) == 2
    resource_bfla_test = config.bfla.tests[0]
    assert resource_bfla_test.name == "low_privilege_users_cannot_run_privileged_action"
    assert resource_bfla_test.role == "user"
    assert resource_bfla_test.resource is not None
    assert resource_bfla_test.resource.list_path == "/resources"
    assert resource_bfla_test.resource.owner_field == "owner_id"
    assert resource_bfla_test.attack.method == "POST"
    assert resource_bfla_test.attack.path_template == "/resources/{id}/privileged-action"
    assert resource_bfla_test.expected_status == 403
    direct_bfla_test = config.bfla.tests[1]
    assert direct_bfla_test.resource is None
    assert direct_bfla_test.attack.path_template == "/admin/users"


def test_loads_empty_yaml_as_invalid_config(tmp_path) -> None:
    config_path = tmp_path / "empty.yaml"
    config_path.write_text("")

    try:
        load_config(config_path)
    except ValueError as exc:
        assert "target" in str(exc)
    else:
        raise AssertionError("Expected invalid config to raise ValueError")

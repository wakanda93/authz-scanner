from fastapi.testclient import TestClient

from apps.hardened_api.main import app as hardened_app
from apps.vulnerable_api.main import app as vulnerable_app


SEED_PASSWORD = "Password123!"


def auth_headers(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/login",
        json={
            "email": email,
            "password": SEED_PASSWORD,
        },
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def get_current_user(client: TestClient, headers: dict[str, str]) -> dict:
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    return response.json()


def get_owned_order(client: TestClient, headers: dict[str, str]) -> dict:
    current_user = get_current_user(client, headers)
    response = client.get("/orders", headers=headers)
    assert response.status_code == 200
    for order in response.json():
        if order["owner_id"] == current_user["id"]:
            return order
    raise AssertionError("Expected at least one owned order")


def test_vulnerable_order_list_leaks_other_users_orders() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")
    current_user = get_current_user(client, headers)

    response = client.get("/orders", headers=headers)

    assert response.status_code == 200
    assert any(order["owner_id"] != current_user["id"] for order in response.json())


def test_hardened_order_list_returns_only_own_orders_for_regular_user() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")
    current_user = get_current_user(client, headers)

    response = client.get("/orders", headers=headers)

    assert response.status_code == 200
    assert response.json()
    assert all(order["owner_id"] == current_user["id"] for order in response.json())


def test_vulnerable_allows_cross_user_order_detail_access() -> None:
    client = TestClient(vulnerable_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_order = get_owned_order(client, user_a_headers)

    response = client.get(f"/orders/{user_a_order['id']}", headers=user_b_headers)

    assert response.status_code == 200
    assert response.json()["id"] == user_a_order["id"]


def test_hardened_blocks_cross_user_order_detail_access() -> None:
    client = TestClient(hardened_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_order = get_owned_order(client, user_a_headers)

    response = client.get(f"/orders/{user_a_order['id']}", headers=user_b_headers)

    assert response.status_code == 403


def test_vulnerable_allows_cross_user_nested_item_access() -> None:
    client = TestClient(vulnerable_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_order = get_owned_order(client, user_a_headers)
    item = user_a_order["items"][0]

    response = client.get(
        f"/orders/{user_a_order['id']}/items/{item['id']}",
        headers=user_b_headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == item["id"]


def test_hardened_blocks_cross_user_nested_item_access() -> None:
    client = TestClient(hardened_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_order = get_owned_order(client, user_a_headers)
    item = user_a_order["items"][0]

    response = client.get(
        f"/orders/{user_a_order['id']}/items/{item['id']}",
        headers=user_b_headers,
    )

    assert response.status_code == 403


def test_vulnerable_accepts_mass_assignment_on_order_create() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")

    response = client.post(
        "/orders",
        headers=headers,
        json={
            "status": "approved",
            "total_amount": "0.01",
            "items": [
                {
                    "product_name": "Laptop Stand",
                    "quantity": 2,
                    "unit_price": "45.00",
                }
            ],
        },
    )

    assert response.status_code == 201
    assert response.json()["status"] == "approved"
    assert response.json()["total_amount"] == "0.01"


def test_hardened_ignores_mass_assignment_fields_on_order_create() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")

    response = client.post(
        "/orders",
        headers=headers,
        json={
            "status": "approved",
            "total_amount": "0.01",
            "items": [
                {
                    "product_name": "Laptop Stand",
                    "quantity": 2,
                    "unit_price": "45.00",
                }
            ],
        },
    )

    assert response.status_code == 201
    assert response.json()["status"] == "pending"
    assert response.json()["total_amount"] == "90.00"


def test_vulnerable_allows_regular_user_to_refund_order() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")
    order = get_owned_order(client, headers)

    response = client.post(f"/orders/{order['id']}/refund", headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "refunded"


def test_hardened_blocks_regular_user_refund() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")
    order = get_owned_order(client, headers)

    response = client.post(f"/orders/{order['id']}/refund", headers=headers)

    assert response.status_code == 403

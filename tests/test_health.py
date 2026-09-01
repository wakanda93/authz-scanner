from fastapi.testclient import TestClient

from apps.hardened_api.main import app as hardened_app
from apps.vulnerable_api.main import app as vulnerable_app


def test_vulnerable_api_health() -> None:
    response = TestClient(vulnerable_app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "vulnerable_api",
    }


def test_hardened_api_health() -> None:
    response = TestClient(hardened_app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "hardened_api",
    }


def test_vulnerable_api_openapi_schema_is_available() -> None:
    response = TestClient(vulnerable_app).get("/openapi.json")

    assert response.status_code == 200
    body = response.json()
    assert body["info"]["title"] == "Vulnerable AuthZ API"
    assert "/auth/login" in body["paths"]
    assert "/orders/{order_id}" in body["paths"]


def test_hardened_api_openapi_schema_is_available() -> None:
    response = TestClient(hardened_app).get("/openapi.json")

    assert response.status_code == 200
    body = response.json()
    assert body["info"]["title"] == "Hardened AuthZ API"
    assert "/auth/login" in body["paths"]
    assert "/orders/{order_id}" in body["paths"]

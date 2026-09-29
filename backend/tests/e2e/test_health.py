from fastapi.testclient import TestClient


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["app_name"] == "VulnScan AI"


def test_response_carries_request_id_header(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert "X-Request-ID" in response.headers

import pytest
from httpx import AsyncClient


@pytest.mark.e2e
async def test_unauthenticated_request_is_rejected(api_client: AsyncClient) -> None:
    response = await api_client.get("/api/v1/knowledge/documents")
    assert response.status_code == 401


@pytest.mark.e2e
async def test_non_admin_cannot_access_knowledge_endpoints(api_client: AsyncClient) -> None:
    await api_client.post(
        "/api/v1/auth/register",
        json={"email": "regular@example.com", "password": "correct-horse-battery"},
    )
    login = await api_client.post(
        "/api/v1/auth/login",
        json={"email": "regular@example.com", "password": "correct-horse-battery"},
    )
    token = login.json()["access_token"]
    api_client.headers["Authorization"] = f"Bearer {token}"

    # The admin check must reject this before ever touching Chroma - if it
    # didn't, this test would need the chroma_store fixture too.
    response = await api_client.post("/api/v1/knowledge/ingest", json={})
    assert response.status_code == 403


@pytest.mark.e2e
async def test_admin_ingest_list_get_and_health_flow(admin_api_client: AsyncClient) -> None:
    ingest_response = await admin_api_client.post(
        "/api/v1/knowledge/ingest", json={"sources": ["CWE"]}
    )
    assert ingest_response.status_code == 200
    counts = ingest_response.json()["per_source"]["CWE"]
    assert counts["created"] >= 15
    assert counts["updated"] == 0
    assert counts["unchanged"] == 0
    total_cwe = counts["total"]

    # Re-ingesting the same source is a no-op (idempotent).
    reingest_response = await admin_api_client.post(
        "/api/v1/knowledge/ingest", json={"sources": ["CWE"]}
    )
    assert reingest_response.json()["per_source"]["CWE"]["unchanged"] == total_cwe

    list_response = await admin_api_client.get("/api/v1/knowledge/documents?source=CWE")
    assert list_response.status_code == 200
    body = list_response.json()
    assert body["total"] == total_cwe
    assert any(doc["external_id"] == "CWE-89" for doc in body["documents"])

    get_response = await admin_api_client.get("/api/v1/knowledge/documents/CWE-89")
    assert get_response.status_code == 200
    assert (
        get_response.json()["name"]
        == "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
    )

    health_response = await admin_api_client.get("/api/v1/knowledge/health")
    assert health_response.status_code == 200
    health_body = health_response.json()
    assert health_body["counts_by_source"]["CWE"] == total_cwe
    assert health_body["counts_by_source"]["OWASP"] == 0


@pytest.mark.e2e
async def test_get_unknown_document_returns_404(admin_api_client: AsyncClient) -> None:
    response = await admin_api_client.get("/api/v1/knowledge/documents/CWE-999999")
    assert response.status_code == 404

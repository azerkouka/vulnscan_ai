import pytest
from fastapi.testclient import TestClient


@pytest.mark.e2e
def test_full_register_login_me_refresh_logout_flow(api_client: TestClient) -> None:
    register_response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "flow@example.com",
            "password": "correct-horse-battery",
            "full_name": "Flow User",
        },
    )
    assert register_response.status_code == 201
    body = register_response.json()
    assert body["email"] == "flow@example.com"
    assert "hashed_password" not in body

    duplicate_response = api_client.post(
        "/api/v1/auth/register",
        json={"email": "flow@example.com", "password": "another-password"},
    )
    assert duplicate_response.status_code == 409

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": "flow@example.com", "password": "correct-horse-battery"},
    )
    assert login_response.status_code == 200
    tokens = login_response.json()
    assert tokens["token_type"] == "bearer"

    bad_login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": "flow@example.com", "password": "wrong-password"},
    )
    assert bad_login_response.status_code == 401

    me_response = api_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert me_response.status_code == 200
    assert me_response.json()["email"] == "flow@example.com"

    unauthenticated_response = api_client.get("/api/v1/auth/me")
    assert unauthenticated_response.status_code == 401

    refresh_response = api_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh_response.status_code == 200
    rotated_tokens = refresh_response.json()
    assert rotated_tokens["refresh_token"] != tokens["refresh_token"]

    # The old refresh token was consumed by rotation - reusing it is rejected
    # and, as a side effect, revokes the whole family (including the token
    # that rotation just issued).
    reuse_response = api_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert reuse_response.status_code == 401

    rotated_now_dead_response = api_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": rotated_tokens["refresh_token"]}
    )
    assert rotated_now_dead_response.status_code == 401


@pytest.mark.e2e
def test_logout_revokes_the_refresh_token(api_client: TestClient) -> None:
    api_client.post(
        "/api/v1/auth/register",
        json={"email": "logout@example.com", "password": "correct-horse-battery"},
    )
    tokens = api_client.post(
        "/api/v1/auth/login",
        json={"email": "logout@example.com", "password": "correct-horse-battery"},
    ).json()

    logout_response = api_client.post(
        "/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}
    )
    assert logout_response.status_code == 204

    refresh_after_logout = api_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh_after_logout.status_code == 401


@pytest.mark.e2e
def test_register_rejects_weak_password(api_client: TestClient) -> None:
    response = api_client.post(
        "/api/v1/auth/register", json={"email": "weak@example.com", "password": "short"}
    )
    assert response.status_code == 422

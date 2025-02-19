import pytest
from fastapi.testclient import TestClient
from main import app
from typing import Dict, Any

client = TestClient(app)

def test_login() -> None:
    response = client.post("/auth/login", data={"username": "test", "password": "test"})
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    assert response.json() == {"message": "Logged in as test"}, f"Unexpected response: {response.json()}"

def test_logout() -> None:
    response = client.post("/auth/logout")
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    assert response.json() == {"message": "Logged out successfully"}, f"Unexpected response: {response.json()}"

def test_login_invalid_credentials() -> None:
    # This will fail always because i have not implemented the password check
    response = client.post("/auth/login", data={"username": "invalid", "password": "invalid"})
    assert response.status_code == 401, f"Expected status code 401, got {response.status_code}"
    assert response.json() == {"detail": "Invalid credentials"}, f"Unexpected response: {response.json()}"

def test_logout_without_login() -> None:
    # will always fail because i have nto implemenmted this
    response = client.post("/auth/logout")
    assert response.status_code == 401, f"Expected status code 401, got {response.status_code}"
    assert response.json() == {"detail": "Not authenticated"}, f"Unexpected response: {response.json()}"
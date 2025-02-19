import pytest
from fastapi.testclient import TestClient
from main import app
from typing import Dict, Any
import re

client = TestClient(app)

def login() -> Dict[str, str]:
    response = client.post("/auth/login", data={"username": "test", "password": "test"})
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    token = response.cookies.get("token")
    assert token is not None, "Token should not be None"
    return {"Cookie": f"token={token}"}

def test_list_applications() -> None:
    headers = login()
    response = client.get("/applications/", headers=headers)
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    data = response.json()
    assert isinstance(data, list), f"Expected list, got {type(data)}"
    # assert "app1" in data, f"Expected 'app1' in response, got {data}"

def test_create_application() -> None:
    headers = login()
    file_content = "requests==2.28.1\naiohttp==3.8.4".encode("utf-8")

    response = client.post(
        "/applications/",
        headers=headers,
        data={"name": "new_app", "description": "A new application"},
        files={"file": ("requirements.txt", file_content)}
    )

    data = response.json()
    message = data.get("message")

    app_id = re.search(r'Application created - ([\w-]+)', message).group(1)
    assert app_id is not None, f"Expected app_id in response, got {data}"

    response = client.get(f"/applications/{app_id}", headers=headers)
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    data = response.json()
    assert isinstance(data, list), f"Expected list, got {type(data)}"
    assert any(app["id"] == app_id for app in data), f"Expected '{app_id}' in response, got {data}"


# def test_update_application() -> None:
#     headers = login()
#     file_content = "requests==2.28.1\naiohttp==3.8.4".encode("utf-8")
#
#     # Create a new application
#     response = client.post(
#         "/applications/",
#         headers=headers,
#         data={"name": "new_app", "description": "A new application"},
#         files={"file": ("requirements.txt", file_content)}
#     )
#
#     data = response.json()
#     message = data.get("message")
#     app_id = re.search(r'Application created - ([\w-]+)', message).group(1)
#     assert app_id is not None, f"Expected app_id in response, got {data}"
#
#     # Update the application
#     updated_file_content = "package1==1.0.0\npackage2==2.0.0".encode("utf-8")
#     response = client.put(
#         f"/applications/{app_id}",
#         headers=headers,
#         data={"name": "updated_app", "description": "Updated description"},
#         files={"file": ("requirements.txt", updated_file_content)}
#     )
#     assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
#     data = response.json()
#     assert "message" in data, f"Expected 'message' in response, got {data}"
#     assert data["message"] == "Application updated", f"Unexpected message: {data['message']}"
#
# def test_delete_application() -> None:
#     headers = login()
#     response = client.delete("/applications/app1", headers=headers)
#     assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
#     data = response.json()
#     assert "message" in data, f"Expected 'message' in response, got {data}"
#     assert data["message"] == "Application deleted successfully", f"Unexpected message: {data['message']}"
# API Reference

## Overview

This document provides a detailed reference for the Vulnerability Tracker API endpoints, including request and response formats, parameters, and example usage.

## Authentication

### Login

**Endpoint**: `POST /auth/login`

**Description**: Handle user login and generate a JWT access token.

**Request**:
- `username` (form data): The username of the user.
- `password` (form data): The password of the user.

**Response**:
- `LoginResponse`: A response model containing a login message.

**Example**:
```json
{
  "message": "Logged in as username"
}
```

### Logout

**Endpoint**: `POST /auth/logout`

**Description**: Handle user logout by deleting the JWT token cookie.

**Response**:
- `LogoutResponse`: A response model containing a logout message.

**Example**:
```json
{
  "message": "Logged out successfully"
}
```

## Applications

### List Applications

**Endpoint**: `GET /applications`

**Description**: List all applications for the current user.

**Response**:
- `List[str]`: A JSON response containing a list of application IDs.

**Example**:
```json
[
  "app_id_1",
  "app_id_2"
]
```

### Create Application

**Endpoint**: `POST /applications`

**Description**: Create a new application for the current user.

**Request**:
- `name` (form data): The name of the application.
- `description` (form data): The description of the application.
- `file` (UploadFile): The uploaded file containing dependencies.

**Response**:
- `Dict[str, str]`: A JSON response containing a message with the application ID.

**Example**:
```json
{
  "message": "Application created - app_id"
}
```

### Get Application

**Endpoint**: `GET /applications/{app_id}`

**Description**: Get details of a specific application for the current user.

**Response**:
- `List[Dict[str, Any]]`: A JSON response containing application details.

**Example**:
```json
[
  {
    "id": "app_id",
    "name": "app_name",
    "description": "app_description",
    "status": "completed",
    "vulnerabilities": 0
  }
]
```

### Get Application Dependencies

**Endpoint**: `GET /applications/{app_id}/dep`

**Description**: Get the dependencies of a specific application for the current user.

**Response**:
- `Dict[str, Dict[str, Any]]`: A JSON response containing dependencies and their vulnerabilities.

**Example**:
```json
{
  "dependency_name": {
    "version": "1.0.0",
    "vulnerabilities": []
  }
}
```

### Update Application

**Endpoint**: `PUT /applications/{app_id}`

**Description**: Update the details of a specific application for the current user.

**Request**:
- `name` (form data, optional): The new name of the application.
- `description` (form data, optional): The new description of the application.
- `file` (UploadFile, optional): The new uploaded file containing dependencies.

**Response**:
- `Dict[str, str]`: A JSON response containing a message indicating the update status.

**Example**:
```json
{
  "message": "Application updated"
}
```

### Delete Application

**Endpoint**: `DELETE /applications/{app_id}`

**Description**: Delete a specific application for the current user.

**Response**:
- `Dict[str, str]`: A JSON response containing a message indicating the deletion status.

**Example**:
```json
{
  "message": "Application deleted successfully"
}
```

## Dependencies

### List Dependencies

**Endpoint**: `GET /dependencies`

**Description**: List all dependencies for the current user.

**Response**:
- `Dict[str, Dict[str, Any]]`: A JSON response containing a dictionary of dependencies.

**Example**:
```json
{
  "dependency_name": {
    "version": {
      "vulns": [],
      "used_in": ["app_id"]
    }
  }
}
```

### Get Dependency

**Endpoint**: `GET /dependencies/{package_name}`

**Description**: Get details of a specific dependency for the current user.

**Request**:
- `version` (query parameter): The version of the package.

**Response**:
- `Dict[str, Any]`: A JSON response containing dependency details.

**Example**:
```json
{
  "description": "Package description",
  "summary": "Package summary",
  "vulns": [],
  "used_by": ["app_id"]
}
```

### Get Vulnerability

**Endpoint**: `GET /dependencies/vulns/{vuln_id}`

**Description**: Get details of a specific vulnerability.

**Response**:
- `Dict[str, Any]`: A JSON response containing vulnerability details.

**Example**:
```json
{
  "id": "vuln_id",
  "summary": "Vulnerability summary",
  "details": "Vulnerability details"
}
```

### Get Alternative Libraries

**Endpoint**: `GET /dependencies/alternate/{package_name}`

**Description**: Get alternative libraries for a specific package.

**Request**:
- `version` (query parameter): The version of the package.

**Response**:
- `Dict[str, Any]`: A JSON response containing a message with alternative libraries.

**Example**:
```json
{
  "message": "Alternative libraries for package_name version version"
}
```
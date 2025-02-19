# Vulnerability Tracker API

## Objective

Develop a Python application using FastAPI that allows users to track vulnerabilities in their Python applications' dependencies. The goal is to evaluate back-end development skills, API design, and optimization abilities. In addition to the core functionality, additional features have been implemented to showcase advanced skills relevant to the job.

## Overview

The Vulnerability Tracker API provides endpoints for:

- **User Authentication:**  
  - **Login:** Generate a JWT access token (dummy implementation for demonstration).  
  - **Logout:** Invalidate the JWT token (via cookie deletion).

- **Application Management:**  
  - **Create Application:** Users can create a new application by submitting a name, description, and a `requirements.txt` file.  
  - **List Applications:** Retrieve a list of applications for the current user, including identification of vulnerable applications.  
  - **Get Application Details/Dependencies:** Retrieve details for a specific application, including its dependencies and associated vulnerabilities.  
  - **Update Application:** Modify an existing application (e.g., update name, description, or reprocess the dependencies file).  
  - **Delete Application:** Remove an application and clean up its dependency associations.

- **Dependency Management:**  
  - **List Dependencies:** List all dependencies tracked across the user’s applications, with details on where each is used.  
  - **Get Dependency:** Retrieve detailed information about a specific dependency, including usage and associated vulnerabilities (with caching of external package info).  
  - **Get Vulnerability:** Retrieve details about a specific vulnerability (cached and rate limited).  
  - **Get Alternate Libraries (Bonus):** Leverage a free LLM with web search to suggest alternative libraries for a given package.

## Project Structure

The project layout is based on the official FastAPI template and organized as follows:

- **Root Directory:**  
  Contains `main.py`, database configuration files, and utility modules.
  
- **routers Directory:**  
  Contains specific routers for different API functionalities (e.g., auth, applications, dependencies).
  
- **core Directory:**  
  Handles security-related features (JWT token generation, authentication dependencies) and configuration variables.

## Endpoints and Functionality

### Authentication Routes (`/auth`)

#### **Login [POST]**
- **Functionality:**  
  Accepts any username and password combination (dummy verification) and creates a JWT access token containing the username. The token is stored in a temporary cookie.
- **Data Structure:**  
  Adds the user to `database.USERS` (a dictionary mapping usernames to a set of application IDs).
- **Example Response:**
  ```json
  { "message": "Logged in as test" }
  ```
- **Time Complexity:**  
  O(1) – Constant time dictionary operations.

#### **Logout [POST]**
- **Functionality:**  
  Handles user logout by deleting the JWT token cookie.
- **Data Structure:**  
  No data structure modification.
- **Time Complexity:**  
  O(1) – Constant time operation.

---

### Application Routes (`/applications`)

These endpoints handle CRUD operations on users' applications and their dependencies.

#### **List Applications [GET]**
- **Functionality:**  
  Lists all applications for the current user. It retrieves application IDs from `database.USERS` and details from `database.APPLICATIONS`.
- **Response Example:**
  ```json
  [
    {
      "id": "87da2dce-f188-44b2-bd45-6a58eb94bff0",
      "name": "Test App",
      "description": "Test Description",
      "status": "completed",
      "vulnerabilities": 31
    }
  ]
  ```
- **Time Complexity:**  
  O(n) where n is the number of applications.

#### **Create Application [POST]**
- **Functionality:**  
  Creates a new application using provided name, description, and a `requirements.txt` file. The file is processed in the background to extract dependencies and fetch associated vulnerabilities.
- **Assumptions:**  
  - The file contains only a list of package dependencies (basic validations implemented; more advanced validations can be added).
  - Only text files are accepted.
- **Response Example:**
  ```json
  { "message": "Application created - 14118d4f-2e80-41f4-8120-e78b67a622ce" }
  ```
- **Data Structures:**  
  - Adds application details to `database.APPLICATIONS`.
  - Updates `database.USERS` with the new application ID.
- **Time Complexity:**  
  O(1) for dictionary insertions; file processing is O(n) where n is the number of lines.

#### **Process File (Background Task)**
- **Functionality:**  
  Processes the uploaded `requirements.txt` file to extract dependencies, update vulnerabilities (using the OSV API), and update the global `DEPENDENCIES` database.
- **Data Structures:**  
  Uses a combination of dictionaries and sets to efficiently store package data.
- **Time Complexity:**  
  O(n) where n is the number of lines in the file.

#### **Update Application [PUT]**
- **Functionality:**  
  Updates application details (name, description, and optionally the dependencies file). It processes only new packages and disconnects unused ones.
- **Time Complexity:**  
  O(1) for simple dictionary updates; O(n) for file processing.

#### **Get Application Details [GET]**
- **Functionality:**  
  Retrieves details for a specific application ID.
- **Response Example:**
  ```json
  {
    "id": "14118d4f-2e80-41f4-8120-e78b67a622ce",
    "name": "Test App",
    "description": "Test Description",
    "status": "completed",
    "vulnerabilities": 31
  }
  ```
- **Time Complexity:**  
  O(1)

#### **Delete Application [DELETE]**
- **Functionality:**  
  Deletes an application if the user is authorized, removing it from both `database.USERS` and `database.APPLICATIONS`. It also updates dependency usage.
- **Response Example:**
  ```json
  { "message": "Application deleted successfully" }
  ```
- **Time Complexity:**  
  O(n) where n is the number of dependencies associated with the application.

#### **Get Application Dependencies [GET]**
- **Functionality:**  
  Retrieves all dependencies for a specific application, including package versions and associated vulnerabilities.
- **Response Example:**
  ```json
  {
    "requests": {
      "version": "2.31.0",
      "vulnerabilities": ["GHSA-9wx4-h78v-vm56"]
    },
    "beautifulsoup4": {
      "version": "4.12.2",
      "vulnerabilities": []
    }
  }
  ```
- **Time Complexity:**  
  O(n) where n is the number of dependencies.

---

### Dependency Routes (`/dependencies`)

These endpoints provide information aggregated across all user applications.

#### **List Dependencies [GET]**
- **Functionality:**  
  Lists all dependencies for the current user, indicating in which application(s) each dependency is used.
- **Response Example:**
  ```json
  {
    "requests": {
      "2.28.1": {
        "vulnerabilities": ["PYSEC-2023-74", "GHSA-9wx4-h78v-vm56"],
        "used_in": ["3b811c31-d6bf-49b9-acc4-8a811a280aef"]
      }
    }
  }
  ```
- **Time Complexity:**  
  O(n) where n is the number of dependencies.

#### **Get Dependency [GET]**
- **Functionality:**  
  Retrieves details of a specific dependency (e.g., vulnerabilities, usage information, and package info fetched from PyPI). Uses caching to avoid repeated API calls.
- **Response Example:**
  ```json
  {
    "vulns": ["GHSA-23j4-mw76-5v7h", "PYSEC-2024-162"],
    "used_by": ["fd05fcfc-74d3-4622-88a6-b52b5d45bc85"],
    "description": "A sample description",
    "summary": "A high-level Web Crawling and Web Scraping framework"
  }
  ```
- **Time Complexity:**  
  O(1)

#### **Get Vulnerability [GET]**
- **Functionality:**  
  Retrieves details for a specific vulnerability ID. Uses caching and rate limiting to prevent spam.
- **Time Complexity:**  
  O(1)

#### **Get Alternate Libraries [GET]** (Bonus)
- **Functionality:**  
  Uses an LLM (via the g4f library) with web search capabilities to suggest alternative libraries for a specified package version.  
- **Example Response:**
  ```json
  { "message": "Alternate libraries: alt1, alt2" }
  ```
- **Note:**  
  This endpoint is a bonus feature showcasing the use of state-of-the-art LLM technology.

---

## Data Structures and Performance

- **Users Database (`database.USERS`):**  
  A dictionary mapping usernames to a set of application IDs.  
  **Time Complexity:** O(1) for insertions and lookups.

- **Applications Database (`database.APPLICATIONS`):**  
  A dictionary mapping application IDs to their details (name, description, vulnerabilities, dependencies, status).  
  **Time Complexity:** O(1) for CRUD operations.

- **Dependencies Database (`database.DEPENDENCIES`):**  
  A nested dictionary mapping package names to versions, where each version holds a set of vulnerabilities and a set of application IDs that use it.  
  **Time Complexity:** O(1) for lookups and updates, thanks to the use of dictionaries and sets.

- **Caching:**  
  External API calls (to OSV and PyPI) are cached (with Redis) to optimize response times and avoid redundant calls.

- **Rate Limiting:**  
  Implemented to prevent abuse of endpoints that fetch external data.

---

## Additional Functionality and Enhancements

- **File Processing:**  
  The uploaded `requirements.txt` file is processed in the background. The processing function extracts package dependencies and uses batched API calls to retrieve vulnerability information, optimizing for both memory and time.

- **Advanced Error Handling & Logging:**  
  All endpoints return meaningful error messages and appropriate HTTP status codes. Logging is integrated throughout to aid debugging and performance monitoring.

- **JWT Authentication:**  
  Demonstrates the use of JWT tokens for securing endpoints, even though dummy verification is currently implemented.

- **Extensibility:**  
  The project layout (root, routers, core) makes it easy to extend the application with additional features in the future.

---

## Conclusion

This project demonstrates the creation of a robust, high-performance FastAPI application that tracks vulnerabilities in Python application dependencies. The implementation includes efficient data structures, caching, rate limiting, and clear API design. In addition to meeting the basic assignment requirements, additional functionality was implemented to showcase advanced back-end development skills.


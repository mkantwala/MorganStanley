import logging
import aiohttp
from databases import database
from core.config import settings
from redis_client import redis_client
from fastapi import HTTPException
from models import VulnerabilityResponse, PackageInfoResponse, VulnsResponse
from typing import Dict, Any

async def fetch_vulnerability(vuln_id: str) -> VulnerabilityResponse:
    """
    Fetch vulnerability details from the OSV API.

    Args:
        vuln_id (str): The ID of the vulnerability.

    Returns:
        VulnerabilityResponse: The response containing vulnerability details.
    """
    logging.info(f"Fetching vulnerability details for ID: {vuln_id}")
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://api.osv.dev/v1/vulns/{vuln_id}") as response:
            if response.status == 200:
                logging.info(f"Successfully fetched vulnerability details for ID: {vuln_id}")
                return VulnerabilityResponse(**await response.json())
            else:
                logging.error(f"Error fetching vulnerability details for ID: {vuln_id}, Status code: {response.status}")
                raise HTTPException(status_code=response.status, detail="Error fetching vulnerability details")

async def fetch_package_info(package_name: str, version: str) -> PackageInfoResponse:
    """
    Fetch package information from the PyPI API.

    Args:
        package_name (str): The name of the package.
        version (str): The version of the package.

    Returns:
        PackageInfoResponse: The response containing package information.
    """
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    logging.info(f"Fetching package info for {package_name} version {version}")

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                logging.info(f"Successfully fetched package info for {package_name} version {version}")
                return PackageInfoResponse(
                    description=data["info"].get("description", "Description not available"),
                    summary=data["info"].get("summary", "Summary not available")
                )
            else:
                logging.error(f"Error fetching package info for {package_name} version {version}, Status code: {response.status}")
                raise HTTPException(status_code=response.status, detail="Error fetching package info")

async def fetch_vulns(payload: Dict[str, Any]) -> VulnsResponse:
    """
    Fetch vulnerabilities for the given payload from the OSV API.

    Args:
        payload (Dict[str, Any]): The payload containing package queries.

    Returns:
        VulnsResponse: The response containing vulnerabilities.
    """
    logging.info("Fetching vulnerabilities for the given payload")
    async with aiohttp.ClientSession() as session:
        async with session.post("https://api.osv.dev/v1/querybatch", json=payload) as response:
            if response.status == 200:
                logging.info("Successfully fetched vulnerabilities")
                return VulnsResponse(**await response.json())
            else:
                logging.error(f"Error querying OSV API, Status code: {response.status}")
                raise HTTPException(status_code=response.status, detail="Error querying OSV API")

async def process_file(file_content: str, app_id: str, username: str) -> None:
    """
    Process the uploaded file to extract dependencies and fetch vulnerabilities.

    Args:
        file_content (str): The content of the uploaded file.
        app_id (str): The ID of the application.
        username (str): The username of the user.
    """
    logging.info(f"Processing file for app_id: {app_id}, user: {username}")

    lines = file_content.splitlines()
    queries = {}
    user = {}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "==" in line:
            parts = line.split("==", 1)
            if len(parts) < 2:
                continue  # malformed line, skip
            package_name = parts[0].strip()
            version = parts[1].strip()

            if ";" in version:
                version = version.split(";", 1)[0].strip()
            else:
                version = version.split()[0].strip()

            user[package_name] = version

            if package_name not in database.DEPENDENCIES:
                queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                database.DEPENDENCIES[package_name] = {version: {"vulns": set(), "used_by": {app_id}}}
            else:
                if version not in database.DEPENDENCIES[package_name]:
                    queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                    database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}
                else:
                    database.APPLICATIONS[app_id]["vulnerabilities"] += len(database.DEPENDENCIES[package_name][version]["vulns"])
                    database.DEPENDENCIES[package_name][version]["used_by"].add(app_id)

    payload = {"queries": list(queries.values())}
    response = await fetch_vulns(payload)

    results = response.results
    vulns_count = database.APPLICATIONS[app_id]["vulnerabilities"]
    for package_name, result in zip(queries.keys(), results):
        if result:
            vulns_count += len(result["vulns"])
            for vuln in result["vulns"]:
                database.DEPENDENCIES[package_name][user[package_name]]["vulns"].add(vuln["id"])

    database.APPLICATIONS[app_id].update({
        "vulnerabilities": vulns_count,
        "dependencies": user,
        "status": "completed"
    })

    logging.info(f"Processed file for app_id: {app_id}, user: {username}")

async def update_file(file_content: str, app_id: str, username: str) -> None:
    """
    Update the dependencies of an application based on the uploaded file.

    Args:
        file_content (str): The content of the uploaded file.
        app_id (str): The ID of the application.
        username (str): The username of the user.
    """
    logging.info(f"Updating file for app_id: {app_id}, user: {username}")

    previous_dependencies = dict(database.APPLICATIONS[app_id]["dependencies"])

    lines = file_content.splitlines()
    queries = {}
    user = {}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "==" in line:
            parts = line.split("==", 1)
            if len(parts) < 2:
                continue  # malformed line, skip
            package_name = parts[0].strip()
            version = parts[1].strip()

            if ";" in version:
                version = version.split(";", 1)[0].strip()
            else:
                version = version.split()[0].strip()

            user[package_name] = version

            if package_name in previous_dependencies:
                if version != previous_dependencies[package_name]:
                    database.APPLICATIONS[app_id]["dependencies"][package_name] = version

                    if version not in database.DEPENDENCIES[package_name]:
                        database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}
                        queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                    else:
                        database.DEPENDENCIES[package_name][version]["used_by"].add(app_id)
                        database.APPLICATIONS[app_id]["vulnerabilities"] += len(database.DEPENDENCIES[package_name][version]["vulns"])
                else:
                    del previous_dependencies[package_name]
            else:
                database.APPLICATIONS[app_id]["dependencies"][package_name] = version

                if package_name not in database.DEPENDENCIES:
                    queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                    database.DEPENDENCIES[package_name] = {version: {"vulns": set(), "used_by": {app_id}}}
                else:
                    if version not in database.DEPENDENCIES[package_name]:
                        database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}
                        queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                    else:
                        database.DEPENDENCIES[package_name][version]["used_by"].add(app_id)
                        database.APPLICATIONS[app_id]["vulnerabilities"] += len(database.DEPENDENCIES[package_name][version]["vulns"])

    payload = {"queries": list(queries.values())}
    response = await fetch_vulns(payload)

    results = response.results
    vulns_count = database.APPLICATIONS[app_id]["vulnerabilities"]

    for package_name, result in zip(queries.keys(), results):
        if result:
            vulns_count += len(result["vulns"])
            for vuln in result["vulns"]:
                database.DEPENDENCIES[package_name][user[package_name]]["vulns"].add(vuln["id"])

    for packages, versions in previous_dependencies.items():
        database.DEPENDENCIES[packages][versions]["used_by"].remove(app_id)
        vulns_count -= len(database.DEPENDENCIES[packages][versions]["vulns"])

        if not database.DEPENDENCIES[packages][versions]["used_by"]:
            del database.DEPENDENCIES[packages][versions]
            if not database.DEPENDENCIES[packages]:
                del database.DEPENDENCIES[packages]

    database.APPLICATIONS[app_id].update({
        "vulnerabilities": vulns_count,
        "dependencies": user,
        "status": "completed"
    })

    logging.info(f"Updated file for app_id: {app_id}, user: {username}")

def check_rate_limit(user: str) -> None:
    """
    Check if the user has exceeded the rate limit for requests.

    Args:
        user (str): The username of the user.

    Raises:
        HTTPException: If the rate limit is exceeded.
    """
    RATE_LIMIT_KEY = f"rate_limit:{user}"
    current_requests = redis_client.get(RATE_LIMIT_KEY)

    if current_requests and int(current_requests) >= settings.RATE_LIMIT_MAX_REQUESTS:
        logging.warning(f"Rate limit exceeded for user: {user}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    else:
        redis_client.incr(RATE_LIMIT_KEY)
        redis_client.expire(RATE_LIMIT_KEY, settings.RATE_LIMIT_WINDOW)
        logging.info(f"Rate limit check passed for user: {user}")
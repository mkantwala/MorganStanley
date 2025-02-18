import logging
import aiohttp
from databases import database
from redis_client import redis_client
from fastapi import HTTPException

async def fetch_vulnerability(vuln_id: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://api.osv.dev/v1/vulns/{vuln_id}") as response:
            if response.status == 200:
                return await response.json()
            else:
                raise HTTPException(status_code=response.status, detail="Error fetching vulnerability details")

async def fetch_package_info(package_name: str, version: str) -> tuple:
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    dependency_info = {}

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                dependency_info["description"] = data["info"].get("description", "")
                dependency_info["summary"] = data["info"].get("summary", "")

    return data["info"].get("description", "Description not available"), data["info"].get("summary", "Summary not available")

async def fetch_vulns(payload: dict) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post("https://api.osv.dev/v1/querybatch", json=payload) as response:
            if response.status != 200:
                raise Exception(f"Error querying OSV API: {response.status}")
            return await response.json()

async def process_file(file_content: str, app_id: str, username: str):

    logging.info(f"Processing file for app_id: {app_id}, user: {username}")

    lines = file_content.splitlines()
    queries = {}
    user = {}

    for line in lines:
        if "==" in line:
            package_name, version = line.split("==")
            user[package_name] = version

            if package_name not in database.DEPENDENCIES:
                queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                # dependencies.add(package_name)
                database.DEPENDENCIES[package_name] = {version: {"vulns": set(), "used_by": {app_id}}}
            else:
                if version not in database.DEPENDENCIES[package_name]:
                    queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                    database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}

                else:
                    database.APPLICATIONS[app_id]["vulnerabilities"] += len(database.DEPENDENCIES[package_name][version]["vulns"])
                    database.DEPENDENCIES[package_name][version]["used_by"].add(app_id)

    payload = {"queries": list(queries.values())}
    # async def _send_payload():
    #     async with aiohttp.ClientSession() as session:
    #         async with session.post("https://api.osv.dev/v1/querybatch", json=payload) as response:
    #             if response.status != 200:
    #                 raise Exception(f"Error querying OSV API: {response.status}")
    #             return await response.json()

    response = await fetch_vulns(payload)

    results = response.get("results", [])
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


async def update_file(file_content: str, app_id: str, username: str):

    logging.info(f"Updating file for app_id: {app_id}, user: {username}")

    previous_dependencies = dict(database.APPLICATIONS[app_id]["dependencies"])

    lines = file_content.splitlines()
    queries = {}
    user = {}

    for line in lines:

        if "==" in line:
            package_name, version = line.split("==")
            user[package_name] = version

            if package_name in previous_dependencies:
                # new version
                if version != previous_dependencies[package_name]:
                    database.APPLICATIONS[app_id]["dependencies"][package_name] = version

                    # check new version in if not present
                    if version not in database.DEPENDENCIES[package_name]:
                        database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}
                        queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"},"version": version}

                    # if present
                    else:
                        database.DEPENDENCIES[package_name][version]["used_by"].add(app_id)
                        database.APPLICATIONS[app_id]["vulnerabilities"] += len(database.DEPENDENCIES[package_name][version]["vulns"])

                # same version same dependency remove it to prevent unnecessary loops
                else:
                    del previous_dependencies[package_name]

            # new dependency
            else:
                database.APPLICATIONS[app_id]["dependencies"][package_name] = version

                # if not present in database we have to query
                if package_name not in database.DEPENDENCIES:
                    queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"},"version": version}
                    database.DEPENDENCIES[package_name] = {version: {"vulns": set(), "used_by": {app_id}}}

                # if present
                else:
                    # if version not present we have to query
                    if version not in database.DEPENDENCIES[package_name]:
                        database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}
                        queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"},"version": version}

                    # if present we have to update
                    else:
                        database.DEPENDENCIES[package_name][version]["used_by"].add(app_id)
                        database.APPLICATIONS[app_id]["vulnerabilities"] += len(database.DEPENDENCIES[package_name][version]["vulns"])


    payload = {"queries": list(queries.values())}

    # async def _send_payload():
    #     async with aiohttp.ClientSession() as session:
    #         async with session.post("https://api.osv.dev/v1/querybatch", json=payload) as response:
    #             if response.status != 200:
    #                 raise Exception(f"Error querying OSV API: {response.status}")
    #             return await response.json()

    response = await fetch_vulns(payload)

    results = response.get("results", [])
    vulns_count = database.APPLICATIONS[app_id]["vulnerabilities"]

    for package_name, result in zip(queries.keys(), results):
        if result:
            vulns_count += len(result["vulns"])
            for vuln in result["vulns"]:
                database.DEPENDENCIES[package_name][user[package_name]]["vulns"].add(vuln["id"])

    # remove remaining previous dependencies and update the database accordingly
    for packages,versions in previous_dependencies.items():
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


def check_rate_limit(user: str):
    RATE_LIMIT_KEY = "rate_limit:{user}"
    current_requests = redis_client.get(RATE_LIMIT_KEY.format(user=user))
    if current_requests and int(current_requests) >= database.RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    else:
        redis_client.incr(database.RATE_LIMIT_KEY.format(user=user))
        redis_client.expire(database.RATE_LIMIT_KEY.format(user=user), database.RATE_LIMIT_WINDOW)


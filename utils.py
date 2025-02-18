import logging
import aiohttp
from databases import database
from typing import AsyncGenerator
from collections import OrderedDict
from fastapi import UploadFile

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
    async def _send_payload():
        async with aiohttp.ClientSession() as session:
            async with session.post("https://api.osv.dev/v1/querybatch", json=payload) as response:
                if response.status != 200:
                    raise Exception(f"Error querying OSV API: {response.status}")
                return await response.json()

    response = await _send_payload()

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

    async def _send_payload():
        async with aiohttp.ClientSession() as session:
            async with session.post("https://api.osv.dev/v1/querybatch", json=payload) as response:
                if response.status != 200:
                    raise Exception(f"Error querying OSV API: {response.status}")
                return await response.json()

    response = await _send_payload()

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
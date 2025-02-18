import logging
import aiohttp
from databases import database
from typing import AsyncGenerator
from collections import OrderedDict
from fastapi import UploadFile


# async def process_file(file_content: str, app_id: str, username: str):
#     """Processes the uploaded requirements.txt file in the background."""
#     logging.info(f"Processing file for app_id: {app_id}, user: {username}")
#
#     lines = file_content.splitlines()
#     queries = []
#     user = {}
#     dependencies = []
#
#     for line in lines:
#         if "==" in line:
#             package_name, version = line.split("==")
#
#             user[package_name] = version
#
#             if package_name not in database.DEPENDENCIES:
#                 queries.append({
#                     "package": {
#                         "name": package_name,
#                         "ecosystem": "PyPI"
#                     },
#                     "version": version
#                 })
#                 dependencies.append(package_name)
#                 database.DEPENDENCIES[package_name] = {version: {"vulns": set(),"used_by":{app_id}}}
#             else:
#                 database.DEPENDENCIES[package_name][version]["used_by"].add(app_id)
#
#     payload = {"queries": queries}
#
#     async def _send_payload():
#         async with aiohttp.ClientSession() as session:
#             async with session.post("https://api.osv.dev/v1/querybatch", json=payload) as response:
#                 if response.status != 200:
#                     raise Exception(f"Error querying OSV API: {response.status}")
#                 return await response.json()
#
#     response = await _send_payload()
#
#     results = response.get("results", [])
#     vens = 0
#     for package_name,result in zip(dependencies, results):
#         if result:
#             vens += len(result["vulns"])
#             for i in result["vulns"]:
#                 database.DEPENDENCIES[package_name][user[package_name]]["vulns"].add(i["id"])
#
#     database.APPLICATIONS[app_id]["vulnerabilities"] = vens
#     database.APPLICATIONS[app_id]["dependencies"] = user
#     database.APPLICATIONS[app_id]["status"] = "completed"
#
#     logging.info(f"Processed file for app_id: {app_id}, user: {username}")

async def process_file(file_content: str, app_id: str, username: str):
    """Processes the uploaded requirements.txt file in the background."""
    logging.info(f"Processing file for app_id: {app_id}, user: {username}")

    lines = file_content.splitlines()
    queries = {}
    user = {}
    dependencies = set()

    for line in lines:
        if "==" in line:
            package_name, version = line.split("==")
            user[package_name] = version

            if package_name not in database.DEPENDENCIES:
                queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                dependencies.add(package_name)
                database.DEPENDENCIES[package_name] = {version: {"vulns": set(), "used_by": {app_id}}}
            else:
                if version not in database.DEPENDENCIES[package_name]:
                    database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}
                else:
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
    vens = 0
    for package_name, result in zip(dependencies, results):
        if result:
            vens += len(result["vulns"])
            for vuln in result["vulns"]:
                database.DEPENDENCIES[package_name][user[package_name]]["vulns"].add(vuln["id"])

    database.APPLICATIONS[app_id].update({
        "vulnerabilities": vens,
        "dependencies": user,
        "status": "completed"
    })

    logging.info(f"Processed file for app_id: {app_id}, user: {username}")


async def update_file(file_content: str, app_id: str, username: str):
    logging.info(f"Processing file for app_id: {app_id}, user: {username}")

    lines = file_content.splitlines()
    queries = {}
    user = {}
    dependencies = set()

    for line in lines:
        if "==" in line:
            package_name, version = line.split("==")
            user[package_name] = version

            if package_name not in database.DEPENDENCIES:
                queries[package_name] = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
                dependencies.add(package_name)
                database.DEPENDENCIES[package_name] = {version: {"vulns": set(), "used_by": {app_id}}}
            else:
                if version not in database.DEPENDENCIES[package_name]:
                    database.DEPENDENCIES[package_name][version] = {"vulns": set(), "used_by": {app_id}}
                else:
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
    vens = 0
    for package_name, result in zip(dependencies, results):
        if result:
            vens += len(result["vulns"])
            for vuln in result["vulns"]:
                database.DEPENDENCIES[package_name][user[package_name]]["vulns"].add(vuln["id"])

    database.APPLICATIONS[app_id].update({
        "vulnerabilities": vens,
        "dependencies": user,
        "status": "completed"
    })

    logging.info(f"Processed file for app_id: {app_id}, user: {username}")
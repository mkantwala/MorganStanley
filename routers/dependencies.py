from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse
import uuid
import time
import logging
from typing import Optional
from core.security import get_current_user, TokenData
from databases import database
import aiohttp
import redis
import json



router = APIRouter()

redis_client = redis.Redis(host='localhost', port=6379, db=0)

RATE_LIMIT_KEY = "rate_limit:{user}"
RATE_LIMIT_MAX_REQUESTS = 5
RATE_LIMIT_WINDOW = 60  # 1 minute

async def fetch_vulnerability(vuln_id: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://api.osv.dev/v1/vulns/{vuln_id}") as response:
            if response.status == 200:
                return await response.json()
            else:
                raise HTTPException(status_code=response.status, detail="Error fetching vulnerability details")

def check_rate_limit(user: str):
    current_requests = redis_client.get(RATE_LIMIT_KEY.format(user=user))
    if current_requests and int(current_requests) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    else:
        redis_client.incr(RATE_LIMIT_KEY.format(user=user))
        redis_client.expire(RATE_LIMIT_KEY.format(user=user), RATE_LIMIT_WINDOW)


logging.basicConfig(level=logging.INFO)

@router.get("/")
def list_dependencies(current_user: TokenData = Depends(get_current_user)):
    user_apps = database.USERS.get(current_user.username, set())
    user_dependencies = {}

    for app_id in user_apps:
        app = database.APPLICATIONS.get(app_id)
        if app:
            for dep, version in app["dependencies"].items():
                if dep not in user_dependencies:
                    user_dependencies[dep] = {}
                if version not in user_dependencies[dep]:
                    user_dependencies[dep][version] = {"vulns": [], "used_in": []}
                user_dependencies[dep][version]["vulns"] = list(database.DEPENDENCIES[dep][version]["vulns"])
                user_dependencies[dep][version]["used_in"].append(app_id)

    return JSONResponse(content=user_dependencies)


@router.get("/{package_name}")
async def get_dependency(package_name: str, version: str = Query(...), current_user: TokenData = Depends(get_current_user)):
    cache_key = f"{package_name}:{version}"
    cached_data = redis_client.get(cache_key)

    if cached_data:
        print("Cache hit")
        dependency_info = json.loads(cached_data)
    else:
        if package_name in database.DEPENDENCIES and version in database.DEPENDENCIES[package_name]:
            dependency_info = database.DEPENDENCIES[package_name][version].copy()

            dependency_info["vulns"] = list(dependency_info["vulns"])

            user_apps = database.USERS.get(current_user.username, set())
            dependency_info["used_by"] = [app_id for app_id in dependency_info["used_by"] if app_id in user_apps]

            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://pypi.org/pypi/{package_name}/{version}/json") as response:
                    if response.status == 200:
                        data = await response.json()
                        dependency_info["description"] = data["info"].get("description", "")
                        dependency_info["summary"] = data["info"].get("summary", "")
                    else:
                        dependency_info["description"] = "Description not available"
                        dependency_info["summary"] = "Summary not available"

            redis_client.setex(cache_key, 3600, json.dumps(dependency_info))  # Cache for 1 hour
        else:
            raise HTTPException(status_code=404, detail="Dependency not found")

    return JSONResponse(content=dependency_info)

@router.get("/{package_name}")
async def get_dependency(package_name: str, version: str = Query(...), current_user: TokenData = Depends(get_current_user)):
    cache_key = f"{package_name}:{version}"
    cached_data = redis_client.get(cache_key)

    if cached_data:
        print("Cache hit")
        dependency_info = json.loads(cached_data)
    else:
        if package_name in database.DEPENDENCIES and version in database.DEPENDENCIES[package_name]:
            dependency_info = database.DEPENDENCIES[package_name][version]

            dependency_info["vulns"] = list(dependency_info["vulns"])

            user_apps = database.USERS.get(current_user.username, set())
            dependency_info["used_by"] = [app_id for app_id in dependency_info["used_by"] if app_id in user_apps]

            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://pypi.org/pypi/{package_name}/{version}/json") as response:
                    if response.status == 200:
                        data = await response.json()
                        dependency_info["description"] = data["info"].get("description", "")
                        dependency_info["summary"] = data["info"].get("summary", "")
                    else:
                        dependency_info["description"] = "Description not available"
                        dependency_info["summary"] = "Summary not available"

            redis_client.setex(cache_key, 3600, json.dumps(dependency_info))  # Cache for 1 hour
        else:
            raise HTTPException(status_code=404, detail="Dependency not found")

    return JSONResponse(content=dependency_info)

@router.get("/vulns/{vuln_id}")
async def get_vulnerability(vuln_id: str, current_user: TokenData = Depends(get_current_user)):
    cache_key = f"vuln:{vuln_id}"
    cached_data = redis_client.get(cache_key)

    check_rate_limit(current_user.username)

    if cached_data:
        print("Cache hit")
        return JSONResponse(content=json.loads(cached_data))
    else:
        vulnerability_info = await fetch_vulnerability(vuln_id)
        redis_client.setex(cache_key, 3600, json.dumps(vulnerability_info))  # Cache for 1 hour
        return JSONResponse(content=vulnerability_info)
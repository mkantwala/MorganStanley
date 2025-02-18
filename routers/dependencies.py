from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse
import logging
from core.security import get_current_user, TokenData
from core.config import settings
from databases import database
import json
from utils import check_rate_limit,redis_client,fetch_vulnerability,fetch_package_info
from g4f.client import Client
router = APIRouter()

logging.basicConfig(level=logging.INFO)

@router.get("/")
def list_dependencies(current_user: TokenData = Depends(get_current_user)):
    user_apps = database.USERS.get(current_user.username, set())
    user_dependencies = {}

    for app_id in user_apps:
        app = database.APPLICATIONS.get(app_id)
        if app:
            for dep, version in app["dependencies"].items():
                #new dep
                if dep not in user_dependencies:
                    user_dependencies[dep] = {}

                #new version
                if version not in user_dependencies[dep]:
                    user_dependencies[dep][version] = {"vulns": [], "used_in": []}

                user_dependencies[dep][version]["vulns"] = list(database.DEPENDENCIES[dep][version]["vulns"].copy())

                user_dependencies[dep][version]["used_in"].append(app_id)

    return JSONResponse(content=user_dependencies)

@router.get("/{package_name}")
async def get_dependency(package_name: str, version: str = Query(...), current_user: TokenData = Depends(get_current_user)):

    user_apps = database.USERS.get(current_user.username, set())

    cache_key = f"cache_dep:{package_name}-{version}"
    cached_data = redis_client.get(cache_key)

    if cached_data:
        print("Cache hit")
        dependency_info = json.loads(cached_data)
        dependency_info["used_by"] = [app_id for app_id in database.DEPENDENCIES[package_name][version]["used_by"] if app_id in user_apps]

    else:
        if package_name in database.DEPENDENCIES and version in database.DEPENDENCIES[package_name]:
            dependency_info = database.DEPENDENCIES[package_name][version].copy()

            dependency_info["vulns"] = list(dependency_info["vulns"])
            dependency_info["used_by"] = [app_id for app_id in dependency_info["used_by"] if app_id in user_apps]
            dependency_info["description"], dependency_info["summary"] = await fetch_package_info(package_name, version)

            redis_client.setex(cache_key, 3600, json.dumps(dependency_info))  # Cache for 1 hour
        else:
            raise HTTPException(status_code=404, detail="Dependency not found")

    return JSONResponse(content=dependency_info)

@router.get("/vulns/{vuln_id}")
async def get_vulnerability(vuln_id: str, current_user: TokenData = Depends(get_current_user)):
    cache_key = f"cache_vuln:{vuln_id}"
    cached_data = redis_client.get(cache_key)

    #rate limit check
    check_rate_limit(current_user.username)

    if cached_data:
        print("Cache hit")
        return JSONResponse(content=json.loads(cached_data))
    else:
        vulnerability_info = await fetch_vulnerability(vuln_id)
        redis_client.setex(cache_key, settings.CACHE_EXPIRE, vulnerability_info.json())  # Cache for 1 hour
        return JSONResponse(content=vulnerability_info.dict())

@router.get("/alternate/{package_name}")
def get_alternate(package_name: str, version: str = Query(...), current_user: TokenData = Depends(get_current_user)):
    check_rate_limit("alternate:"+current_user.username)

    prompt = f"I am using the library '{package_name}' (version {version}), which is known to be vulnerable.\
    Can you provide a list of alternative libraries with brief descriptions that can serve as secure replacements? \
    Feel free to use any available search engine to gather relevant information."

    client = Client()
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        web_search=True
    )
    print(response.choices[0].message.content)
    return JSONResponse(content={"message": response.choices[0].message.content})
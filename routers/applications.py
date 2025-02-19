from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse
from core.security import get_current_user
from models import TokenData
from databases import database
import uuid
import logging
from typing import Optional, List, Dict, Any
from utils import process_file, update_file

router = APIRouter()

logging.basicConfig(level=logging.INFO)

@router.get("/", response_model=List[str])
async def list_applications(current_user: TokenData = Depends(get_current_user)) -> JSONResponse:
    try:
        apps = list(database.USERS[current_user.username])
        return JSONResponse(content=apps)
    except Exception as e:
        logging.error(f"Error listing applications: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
@router.post("/", response_model=Dict[str, str])
async def create_application(
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user),
    name: str = Form(...),
    description: str = Form(...),
    file: UploadFile = File(...),
) -> JSONResponse:
    try:
        logging.info("create_application called")
        app_id = str(uuid.uuid4())

        database.USERS[current_user.username].add(app_id)
        database.APPLICATIONS[app_id] = {
            "name": name,
            "description": description,
            "vulnerabilities": 0,
            "dependencies": {},
            "status": "processing",
        }

        file_content = await file.read()
        background_tasks.add_task(process_file, file_content.decode("utf-8"), app_id, current_user.username)

        return JSONResponse(content={"message": "Application created"})
    except Exception as e:
        logging.error(f"Error creating application: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
@router.get("/{app_id}", response_model=List[Dict[str, Any]])
async def get_application(app_id: str, current_user: TokenData = Depends(get_current_user)) -> JSONResponse:
    try:
        if app_id not in database.APPLICATIONS:
            raise HTTPException(status_code=404, detail="Application not found")

        if app_id not in database.USERS[current_user.username]:
            raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

        applications = []
        for app_id in database.USERS[current_user.username]:
            application = database.APPLICATIONS.get(app_id)
            if application:
                applications.append({
                    "id": app_id,
                    "name": application["name"],
                    "description": application["description"],
                    "status": application["status"],
                    "vulnerabilities": application["vulnerabilities"]
                })

        return JSONResponse(content=applications)
    except Exception as e:
        logging.error(f"Error fetching application {app_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{app_id}/dep", response_model=Dict[str, Dict[str, Any]])
async def get_application_dependencies(app_id: str, current_user: TokenData = Depends(get_current_user)) -> JSONResponse:
    try:
        if app_id not in database.APPLICATIONS:
            raise HTTPException(status_code=404, detail="Application not found")

        if app_id not in database.USERS[current_user.username]:
            raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

        dependencies = database.APPLICATIONS[app_id].get("dependencies", {})
        dependencies_with_vulns = {}

        for dep, version in dependencies.items():
            vulns = list(database.DEPENDENCIES[dep][version]["vulns"].copy()) if version else []
            dependencies_with_vulns[dep] = {
                "version": version,
                "vulnerabilities": vulns
            }

        return JSONResponse(content=dependencies_with_vulns)
    except Exception as e:
        logging.error(f"Error fetching dependencies for application {app_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{app_id}", response_model=Dict[str, str])
async def update_application(
    app_id: str,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user),
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
) -> JSONResponse:
    try:
        if app_id not in database.APPLICATIONS:
            raise HTTPException(status_code=404, detail="Application not found")

        if app_id not in database.USERS[current_user.username]:
            raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

        if name:
            database.APPLICATIONS[app_id]["name"] = name
        if description:
            database.APPLICATIONS[app_id]["description"] = description

        if file:
            database.APPLICATIONS[app_id]["status"] = "updating"
            file_content = await file.read()
            background_tasks.add_task(update_file, file_content.decode("utf-8"), app_id, current_user.username)

        return JSONResponse(content={"message": "Application updated"})
    except Exception as e:
        logging.error(f"Error updating application {app_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
@router.delete("/{app_id}", response_model=Dict[str, str])
async def delete_application(app_id: str, current_user: TokenData = Depends(get_current_user)) -> JSONResponse:
    try:
        if app_id not in database.APPLICATIONS:
            raise HTTPException(status_code=404, detail="Application not found")

        if app_id not in database.USERS[current_user.username]:
            raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

        database.USERS[current_user.username].remove(app_id)
        app_dependencies = database.APPLICATIONS[app_id]["dependencies"]

        for dep, version in app_dependencies.items():
            if app_id in database.DEPENDENCIES[dep][version]["used_by"]:
                database.DEPENDENCIES[dep][version]["used_by"].remove(app_id)
                if not database.DEPENDENCIES[dep][version]["used_by"]:
                    del database.DEPENDENCIES[dep][version]
                    if not database.DEPENDENCIES[dep]:
                        del database.DEPENDENCIES[dep]

        del database.APPLICATIONS[app_id]

        return JSONResponse(content={"message": "Application deleted successfully"})
    except Exception as e:
        logging.error(f"Error deleting application {app_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
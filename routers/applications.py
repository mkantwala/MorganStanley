from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse

from core.security import get_current_user
from models import TokenData
from databases import database
import uuid
import time
import logging
from typing import Optional
import aiohttp
import asyncio
from utils import process_file,update_file

router = APIRouter()

logging.basicConfig(level=logging.INFO)

@router.get("/")
def list_applications(current_user: TokenData = Depends(get_current_user)):
    apps = list(database.USERS[current_user.username])
    return JSONResponse(content=apps)

@router.post("/")
async def create_application(background_tasks: BackgroundTasks,
        current_user: TokenData = Depends(get_current_user),
                             name: str = Form(...),
                             description: str = Form(...),
                             file: UploadFile = File(...),
        ):

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


@router.get("/{app_id}")
def get_application(app_id: str, current_user: TokenData = Depends(get_current_user)):

    if database.APPLICATIONS[app_id] is None:
        raise HTTPException(status_code=404, detail="Application invalid app id")

    if app_id not in database.USERS[current_user.username]:
        raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

    app_ids = list(database.USERS[current_user.username])
    applications = []

    for app_id in app_ids:
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

@router.get("/{app_id}/dep")
def get_application_dependencies(app_id: str, current_user: TokenData = Depends(get_current_user)):

    if app_id not in database.APPLICATIONS:
        raise HTTPException(status_code=404, detail="Application not found")

    if app_id not in database.USERS[current_user.username]:
        raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

    dependencies = database.APPLICATIONS[app_id].get("dependencies", {})

    return JSONResponse(content=dependencies)

@router.put("/{app_id}")
async def update_application(
        app_id: str,
        background_tasks: BackgroundTasks,
        current_user: TokenData = Depends(get_current_user),
        name: Optional[str] = Form(None),
        description: Optional[str] = Form(None),
        file: Optional[UploadFile] = File(None),
):
    # Check if the application exists
    if app_id not in database.APPLICATIONS:
        raise HTTPException(status_code=404, detail="Application not found")

    # Check if the user is authorized to update the application
    if app_id not in database.USERS[current_user.username]:
        raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

    # Update name and description if provided
    if name:
        database.APPLICATIONS[app_id]["name"] = name
    if description:
        database.APPLICATIONS[app_id]["description"] = description

    if file:
        # Change status to "updating"
        database.APPLICATIONS[app_id]["status"] = "updating"
        file_content = await file.read()
        background_tasks.add_task(update_file, file_content.decode("utf-8"), app_id, current_user.username)

    return JSONResponse(content={"message": "Application updated"})

@router.delete("/{app_id}")
def delete_application(app_id: str, current_user: TokenData = Depends(get_current_user)):

    if app_id not in database.APPLICATIONS:
        raise HTTPException(status_code=404, detail="Application not found")

    if app_id not in database.USERS[current_user.username]:
        raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

    # Remove the application from the user's set
    database.USERS[current_user.username].remove(app_id)

    # Get the application's dependencies
    app_dependencies = database.APPLICATIONS[app_id]["dependencies"]

    # Loop through all dependencies and update the "used_by" tag
    for dep, version in app_dependencies.items():
        if app_id in database.DEPENDENCIES[dep][version]["used_by"]:
            database.DEPENDENCIES[dep][version]["used_by"].remove(app_id)
            # If "used_by" is empty, remove the dependency version
            if not database.DEPENDENCIES[dep][version]["used_by"]:
                del database.DEPENDENCIES[dep][version]
                # If no versions are left, remove the dependency itself
                if not database.DEPENDENCIES[dep]:
                    del database.DEPENDENCIES[dep]

    # Remove the application from the APPLICATIONS
    del database.APPLICATIONS[app_id]

    return JSONResponse(content={"message": "Application deleted successfully"})

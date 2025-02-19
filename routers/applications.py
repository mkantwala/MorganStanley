from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from core.security import get_current_user
from models import TokenData
from databases import database
import uuid
import logging
from typing import Optional, List, Dict, Any
from utils import process_file, update_file

# Initialize the APIRouter for application-related endpoints
router = APIRouter()

# Configure logging
logging.basicConfig(level=logging.INFO)

@router.get("/", response_model=List[str])
async def list_applications(current_user: TokenData = Depends(get_current_user)) -> JSONResponse:
    """
    List all applications for the current user.

    Args:
        current_user (TokenData): The current authenticated user.

    Returns:
        JSONResponse: A JSON response containing a list of application.
    """
    try:
        # apps = list(database.USERS[current_user.username])
        applications =[]
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
        logging.error(f"Error listing applications: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/", response_model=Dict[str, str])
async def create_application(
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user),
    name: str = Form(...),
    description: str = Form(...),
    file: UploadFile = File(..., media_type="text/plain"),
) -> JSONResponse:
    """
    Create a new application for the current user.

    Args:
        background_tasks (BackgroundTasks): Background tasks to be executed.
        current_user (TokenData): The current authenticated user.
        name (str): The name of the application.
        description (str): The description of the application.
        file (UploadFile): The uploaded file containing dependencies.

    Returns:
        JSONResponse: A JSON response containing a message with the application ID.
    """
    try:
        logging.info("create_application called")
        app_id = str(uuid.uuid4())

        # Add the application to the user's list and initialize its details
        database.USERS[current_user.username].add(app_id)
        database.APPLICATIONS[app_id] = {
            "name": name,
            "description": description,
            "vulnerabilities": 0,
            "dependencies": {},
            "status": "processing",
        }

        # Read the file content and process it in the background
        file_content = await file.read()
        background_tasks.add_task(process_file, file_content.decode("utf-8"), app_id, current_user.username)

        return JSONResponse(content={"message": "Application created - {}".format(app_id)})
    except Exception as e:
        logging.error(f"Error creating application: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{app_id}", response_model=List[Dict[str, Any]])
async def get_application(app_id: str, current_user: TokenData = Depends(get_current_user)) -> JSONResponse:
    """
    Get details of a specific application for the current user.

    Args:
        app_id (str): The ID of the application.
        current_user (TokenData): The current authenticated user.

    Returns:
        JSONResponse: A JSON response containing application details.
    """
    try:
        if app_id not in database.APPLICATIONS:
            raise HTTPException(status_code=404, detail="Application not found")

        if app_id not in database.USERS[current_user.username]:
            raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

        applications = []
        # for app_id in database.USERS[current_user.username]:
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
    """
    Get the dependencies of a specific application for the current user.

    Args:
        app_id (str): The ID of the application.
        current_user (TokenData): The current authenticated user.

    Returns:
        JSONResponse: A JSON response containing dependencies and their vulnerabilities.
    """
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
    """
    Update the details of a specific application for the current user.

    Args:
        app_id (str): The ID of the application.
        background_tasks (BackgroundTasks): Background tasks to be executed.
        current_user (TokenData): The current authenticated user.
        name (Optional[str]): The new name of the application.
        description (Optional[str]): The new description of the application.
        file (Optional[UploadFile]): The new uploaded file containing dependencies.

    Returns:
        JSONResponse: A JSON response containing a message indicating the update status.
    """
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
    """
    Delete a specific application for the current user.

    Args:
        app_id (str): The ID of the application.
        current_user (TokenData): The current authenticated user.

    Returns:
        JSONResponse: A JSON response containing a message indicating the deletion status.
    """
    try:
        if app_id not in database.APPLICATIONS:
            raise HTTPException(status_code=404, detail="Application not found")

        if app_id not in database.USERS[current_user.username]:
            raise HTTPException(status_code=403, detail="Unauthorized: Access is denied")

        # Remove the application from the user's list and delete its dependencies
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
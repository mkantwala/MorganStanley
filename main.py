from fastapi import FastAPI
from routers import applications, auth, dependencies
from databases import database

# Initialize FastAPI app
app = FastAPI(title="Vulnerability Tracker API")

# Include routers for different endpoints
app.include_router(applications.router, prefix="/applications", tags=["Applications"])
app.include_router(dependencies.router, prefix="/dependencies", tags=["Dependencies"])
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])

@app.get("/user")
def get_user():
    """
    Endpoint to get the list of users.
    Returns:
        dict: A dictionary containing the users.
    """
    return {"user": database.USERS}

@app.get("/applications")
def get_applications():
    """
    Endpoint to get the list of applications.
    Returns:
        dict: A dictionary containing the applications.
    """
    return {"apps": database.APPLICATIONS}

@app.get("/dependencies")
def get_dependencies():
    """
    Endpoint to get the list of dependencies.
    Returns:
        dict: A dictionary containing the dependencies.
    """
    return {"user": database.DEPENDENCIES}
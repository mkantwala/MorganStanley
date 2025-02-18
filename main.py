from fastapi import FastAPI
from routers import applications,auth,dependencies
# from auth.router import router as auth_router

from fastapi.templating import Jinja2Templates
from core.config import settings
from databases import database
app = FastAPI(title="Vulnerability Tracker API")

app.include_router(applications.router, prefix="/applications", tags=["Applications"])
app.include_router(dependencies.router, prefix="/dependencies", tags=["Dependencies"])
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])

@app.get("/user")
def user():
    return {"user": database.USERS}

@app.get("/applications")
def applications():
    return {"apps": database.APPLICATIONS}

@app.get("/dependencies")
def user():
    return {"user": database.DEPENDENCIES}
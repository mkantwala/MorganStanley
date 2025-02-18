from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
from core.security import *
from core.config import settings
from databases import database
from fastapi import FastAPI, HTTPException, Depends, Response, status, Cookie
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter()

@router.post("/login")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):

    username = form_data.username
    access_token = create_access_token(username)

    response.set_cookie(
        key="token",
        value=access_token,
        httponly=True,
    )

    if username not in database.USERS:
        database.USERS[username] = set()

    return {"message": f"Logged in as {username}"}

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="token")
    return {"message": "Logged out successfully"}

@router.get("/test")
async def test_route(current_user: TokenData = Depends(get_current_user)):
    if current_user.username != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: admin access required."
        )
    return {"message": f"Hello {current_user.username}, you are authorized to access this route."}


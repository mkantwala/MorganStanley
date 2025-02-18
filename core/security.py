from datetime import datetime, timedelta
from typing import Any, Optional
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from models import TokenData
from core.config import settings
from fastapi import HTTPException, status, Cookie

def create_access_token(username: str | Any , expiration : timedelta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    expiration_time = datetime.utcnow() + expiration

    payload = {
        "sub": username,
        "exp": expiration_time,
        "iat": datetime.utcnow(),
    }

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])

def verify_token(token: str) -> TokenData:

    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload invalid",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return TokenData(username=username)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired Login Again",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token: Optional[str] = Cookie(None)) -> TokenData:

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authenticated - Token Cookie Missing - Please LOGIN",
        )
    return verify_token(token)


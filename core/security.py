from datetime import datetime, timedelta
from typing import Any, Optional, Dict
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from models import TokenData
from core.config import settings
from fastapi import HTTPException, status, Cookie
import logging

logging.basicConfig(level=logging.INFO)

def create_access_token(username: str, expiration: timedelta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    expiration_time = datetime.utcnow() + expiration
    payload = {
        "sub": username,
        "exp": expiration_time,
        "iat": datetime.utcnow(),
    }
    logging.info(f"Creating access token for user: {username}")
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        logging.info("Decoding access token")
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except ExpiredSignatureError:
        logging.error("Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired. Please login again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        logging.error("Invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def verify_token(token: str) -> TokenData:
    payload = decode_access_token(token)
    username: str = payload.get("sub")
    if username is None:
        logging.error("Token payload invalid")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logging.info(f"Token verified for user: {username}")
    return TokenData(username=username)

async def get_current_user(token: Optional[str] = Cookie(None)) -> TokenData:
    if token is None:
        logging.error("Token cookie missing")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authenticated - Token Cookie Missing - Please LOGIN",
        )
    return verify_token(token)
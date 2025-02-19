from datetime import datetime, timedelta
from typing import Any, Optional, Dict
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from models import TokenData
from core.config import settings
from fastapi import HTTPException, status, Cookie
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def create_access_token(username: str, expiration: timedelta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    """
    Create a JWT access token for the given username.

    Args:
        username (str): The username for which the token is created.
        expiration (timedelta): The expiration time for the token.

    Returns:
        str: The encoded JWT token.
    """
    expiration_time = datetime.utcnow() + expiration
    payload = {
        "sub": username,
        "exp": expiration_time,
        "iat": datetime.utcnow(),
    }
    logging.info(f"Creating access token for user: {username}")
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode a JWT access token.

    Args:
        token (str): The JWT token to decode.

    Returns:
        Dict[str, Any]: The decoded token payload.

    Raises:
        HTTPException: If the token is expired or invalid.
    """
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
    """
    Verify the JWT token and extract the username.

    Args:
        token (str): The JWT token to verify.

    Returns:
        TokenData: The token data containing the username.

    Raises:
        HTTPException: If the token payload is invalid.
    """
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
    """
    Get the current user from the JWT token stored in cookies.

    Args:
        token (Optional[str]): The JWT token from cookies.

    Returns:
        TokenData: The token data containing the username.

    Raises:
        HTTPException: If the token is missing or invalid.
    """
    if token is None:
        logging.error("Token cookie missing")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authenticated - Token Cookie Missing - Please LOGIN",
        )
    return verify_token(token)
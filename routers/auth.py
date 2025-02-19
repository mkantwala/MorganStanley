from fastapi import APIRouter, Depends, HTTPException, status, Response
from core.security import create_access_token
from databases import database
from fastapi.security import OAuth2PasswordRequestForm
import logging
from models import LoginResponse, LogoutResponse

# Initialize the APIRouter for authentication-related endpoints
router = APIRouter()

# Configure logging
logging.basicConfig(level=logging.INFO)

@router.post("/login", response_model=LoginResponse)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()) -> LoginResponse:
    """
    Handle user login and generate a JWT access token.

    Args:
        response (Response): The response object to set cookies.
        form_data (OAuth2PasswordRequestForm): The form data containing username and password.

    Returns:
        LoginResponse: A response model containing a login message.
    """
    username = form_data.username
    logging.info(f"Login attempt for user: {username}")

    try:
        # Create a JWT access token for the user
        access_token = create_access_token(username)
        response.set_cookie(
            key="token",
            value=access_token,
            httponly=True,
        )

        # Add the user to the database if not already present
        if username not in database.USERS:
            database.USERS[username] = set()

        logging.info(f"User {username} logged in successfully")
        return LoginResponse(message=f"Logged in as {username}")
    except Exception as e:
        logging.error(f"Error during login for user {username}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.post("/logout", response_model=LogoutResponse)
async def logout(response: Response) -> LogoutResponse:
    """
    Handle user logout by deleting the JWT token cookie.

    Args:
        response (Response): The response object to delete cookies.

    Returns:
        LogoutResponse: A response model containing a logout message.
    """
    try:
        # Delete the JWT token cookie
        response.delete_cookie(key="token")
        logging.info("User logged out successfully")
        return LogoutResponse(message="Logged out successfully")
    except Exception as e:
        logging.error(f"Error during logout: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
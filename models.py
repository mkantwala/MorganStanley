from pydantic import BaseModel
from typing import Optional

class Token(BaseModel):
    """
    Model representing an access token.
    Attributes:
        access_token (str): The access token string.
        token_type (str): The type of the token.
    """
    access_token: str
    token_type: str

class VulnerabilityResponse(BaseModel):
    """
    Model representing a vulnerability response.
    Attributes:
        id (str): The ID of the vulnerability.
        summary (str): A brief summary of the vulnerability.
        details (str): Detailed information about the vulnerability.
    """
    id: str
    summary: Optional[str] = None
    details : Optional[str] = None

class PackageInfoResponse(BaseModel):
    """
    Model representing package information response.
    Attributes:
        description (str): The description of the package.
        summary (str): A brief summary of the package.
    """
    description: str
    summary: str

class VulnsResponse(BaseModel):
    """
    Model representing vulnerabilities response.
    Attributes:
        results (list): A list of vulnerability results.
    """
    results: list

class LoginResponse(BaseModel):
    """
    Model representing a login response.
    Attributes:
        message (str): A message indicating the login status.
    """
    message: str

class LogoutResponse(BaseModel):
    """
    Model representing a logout response.
    Attributes:
        message (str): A message indicating the logout status.
    """
    message: str

class TokenData(BaseModel):
    """
    Model representing token data.
    Attributes:
        username (Optional[str]): The username associated with the token.
    """
    username: Optional[str] = None
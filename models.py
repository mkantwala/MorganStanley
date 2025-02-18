from pydantic import BaseModel
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str

class VulnerabilityResponse(BaseModel):
    id: str
    summary: str
    details: str

class PackageInfoResponse(BaseModel):
    description: str
    summary: str
class VulnsResponse(BaseModel):
    results: list

class LoginResponse(BaseModel):
    message: str

class LogoutResponse(BaseModel):
    message: str

class TokenData(BaseModel):
    username: Optional[str] = None
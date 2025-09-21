from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class RegisterForm(BaseModel):
    email: EmailStr
    password: str

class LoginForm(BaseModel):
    email: EmailStr
    password: str

class SiteForm(BaseModel):
    name: str
    url: str
    description: Optional[str] = ""
    interval_seconds: int = Field(ge=60, le=86400)
    timeout_seconds: int = Field(ge=5, le=120)
    expected_status: int = 200

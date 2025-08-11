from pydantic import BaseModel, EmailStr
from typing import Optional

class User(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    picture: Optional[str] = None
    totp_enabled: Optional[bool] = False

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    picture: Optional[str] = None

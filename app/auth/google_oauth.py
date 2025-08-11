from datetime import datetime
from typing import Optional, Dict, Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer

from app.core.config import JWT_SECRET, JWT_ALG, JWT_EXPIRE
from app.core.config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # not used directly

__all__ = [
    "get_google_user",
    "create_access_token",
    "get_current_user",
    "oauth2_scheme",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REDIRECT_URI",
]

async def get_google_user(access_token: str) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    exp = datetime.utcnow() + JWT_EXPIRE
    to_encode.update({"exp": exp})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def _get_token_from_cookie(request: Request) -> Optional[str]:
    raw = request.cookies.get("access_token")
    if not raw:
        return None
    parts = raw.split(" ", 1)
    return parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else raw

async def get_current_user(request: Request) -> Dict[str, Any]:
    token = _get_token_from_cookie(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return {"email": sub}

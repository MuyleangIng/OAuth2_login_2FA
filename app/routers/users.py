import base64
import datetime
import io
import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request, Form, Body
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
import httpx
import qrcode

from app.auth.google_oauth import (
    get_google_user,
    create_access_token,
    get_current_user,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
)
from app.auth.schemas import User, UserCreate
from app.database.database import get_db
from app.auth.models import User as UserModel
from app.auth.dependencies import templates
from app.auth.mfa_utils import (
    create_totp_secret,
    totp_uri,
    verify_totp,
    sign_pending,
    unsign_pending,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

PENDING_COOKIE = "pending_user"
ACCESS_COOKIE = "access_token"
# routes.py
COOKIE_OPTS = dict(httponly=True, samesite="lax", secure=True)  # Cloud Run is HTTPS

DEV_MODE = os.getenv("DEV_MODE") == "1"

# ---------- login page ----------
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "google_client_id": GOOGLE_CLIENT_ID,
            "google_redirect_uri": GOOGLE_REDIRECT_URI,
        },
    )

# ---------- Google OAuth callback ----------
@router.get("/google/callback")
async def google_callback(code: str, db: Session = Depends(get_db)):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
            tokens = resp.json()
            if "error" in tokens:
                raise HTTPException(status_code=400, detail=tokens.get("error_description", "Google OAuth failed"))
            access_token = tokens.get("access_token")

        user_info = await get_google_user(access_token)

        user = db.query(UserModel).filter(UserModel.email == user_info["email"]).first()
        if not user:
            user = UserModel(
                email=user_info["email"],
                name=user_info.get("name"),
                picture=user_info.get("picture"),
            )
            db.add(user); db.commit(); db.refresh(user)

        # If TOTP enabled → go to /auth/mfa
        if user.totp_enabled and user.totp_secret:
            pending = sign_pending(user.email)
            resp = RedirectResponse(url="/auth/mfa", status_code=307)  # GET -> 307 is fine
            resp.set_cookie(PENDING_COOKIE, pending, **COOKIE_OPTS)
            return resp

        # Else issue JWT and success (GET redirect OK as 307/302)
        jwt_token = create_access_token({"sub": user.email})
        resp = RedirectResponse(url="/auth/success", status_code=307)
        resp.set_cookie(ACCESS_COOKIE, f"Bearer {jwt_token}", **COOKIE_OPTS)
        return resp

    except Exception as e:
        logger.exception("Authentication failed")
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

# ---------- MFA verify (HTML form) ----------
@router.get("/mfa", response_class=HTMLResponse)
async def mfa_page(request: Request):
    return templates.TemplateResponse("mfa.html", {"request": request})

@router.post("/mfa/verify")
async def mfa_verify(request: Request, code: str = Form(...), db: Session = Depends(get_db)):
    pending = request.cookies.get(PENDING_COOKIE)
    email = unsign_pending(pending) if pending else None
    if not email:
        raise HTTPException(status_code=400, detail="MFA session expired. Login again.")
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="MFA not configured.")
    if verify_totp(user.totp_secret, code):
        jwt_token = create_access_token({"sub": user.email})
        # IMPORTANT: 303 so browser converts POST -> GET at /auth/success
        resp = RedirectResponse(url="/auth/success", status_code=303)
        resp.delete_cookie(PENDING_COOKIE)
        resp.set_cookie(ACCESS_COOKIE, f"Bearer {jwt_token}", **COOKIE_OPTS)
        return resp
    raise HTTPException(status_code=401, detail="Invalid code.")

# ---------- MFA verify (JSON) ----------
@router.post("/mfa/verify/json")
async def mfa_verify_json(request: Request, payload: dict = Body(...), db: Session = Depends(get_db)):
    code = str(payload.get("code", "")).strip()
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    pending = request.cookies.get(PENDING_COOKIE)
    email = unsign_pending(pending) if pending else None
    if not email:
        raise HTTPException(status_code=400, detail="MFA session expired. Login again.")
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="MFA not configured.")
    if verify_totp(user.totp_secret, code):
        jwt_token = create_access_token({"sub": user.email})
        # IMPORTANT: 303 so POST -> GET
        resp = RedirectResponse(url="/auth/success", status_code=303)
        resp.delete_cookie(PENDING_COOKIE)
        resp.set_cookie(ACCESS_COOKIE, f"Bearer {jwt_token}", **COOKIE_OPTS)
        return resp
    raise HTTPException(status_code=401, detail="Invalid code.")

# ---------- 2FA enrollment ----------
@router.get("/2fa/setup", response_class=HTMLResponse)
async def twofa_setup(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == current_user["email"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.totp_secret or not user.totp_enabled:
        if not user.totp_secret:
            user.totp_secret = create_totp_secret()
            db.add(user); db.commit(); db.refresh(user)

    uri = totp_uri(user.totp_secret, user.email)
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse("2fa_setup.html", {"request": request, "qr_b64": qr_b64, "otpauth_uri": uri})

@router.post("/2fa/activate", response_class=HTMLResponse)
async def twofa_activate(request: Request, code: str = Form(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == current_user["email"]).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=400, detail="No TOTP secret to verify.")
    if not verify_totp(user.totp_secret, code):
        raise HTTPException(status_code=400, detail="Incorrect code.")
    user.totp_enabled = True
    user.totp_verified_at = datetime.datetime.utcnow()
    db.add(user); db.commit(); db.refresh(user)
    # IMPORTANT: 303 so POST -> GET
    return RedirectResponse(url="/auth/success", status_code=303)

@router.post("/2fa/disable")
async def twofa_disable(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == current_user["email"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_verified_at = None
    db.add(user); db.commit()
    return {"ok": True}

# ---------- logout ----------
@router.post("/logout")
def logout():
    # IMPORTANT: 303 so POST -> GET
    resp = RedirectResponse(url="/auth/login", status_code=303)
    resp.delete_cookie(PENDING_COOKIE)
    resp.delete_cookie(ACCESS_COOKIE)
    return resp

# ---------- dev helpers ----------
def _ensure_dev():
    if not DEV_MODE:
        raise HTTPException(status_code=403, detail="DEV helpers disabled")

@router.get("/dev/start")
async def dev_start(email: str, db: Session = Depends(get_db)):
    _ensure_dev()
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        user = UserModel(email=email, name="Dev User")
        db.add(user); db.commit(); db.refresh(user)
    if not user.totp_secret:
        user.totp_secret = create_totp_secret()
    user.totp_enabled = True
    db.add(user); db.commit(); db.refresh(user)

    pending = sign_pending(user.email)
    resp = RedirectResponse(url="/auth/mfa", status_code=307)
    resp.set_cookie(PENDING_COOKIE, pending, **COOKIE_OPTS)

    try:
        import pyotp
        current_code = pyotp.TOTP(user.totp_secret).now()
    except Exception:
        current_code = "n/a"

    resp.headers["X-Dev-Otpauth"] = totp_uri(user.totp_secret, user.email)
    resp.headers["X-Dev-Code"] = str(current_code)
    return resp

@router.get("/dev/totp")
async def dev_totp(request: Request, db: Session = Depends(get_db)):
    _ensure_dev()
    import pyotp
    pending = request.cookies.get(PENDING_COOKIE)
    email = unsign_pending(pending) if pending else None
    if not email:
        raise HTTPException(status_code=400, detail="No pending user")
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=404, detail="User/secret not found")
    return {"email": email, "code": pyotp.TOTP(user.totp_secret).now()}

# ---------- success & user utilities ----------
@router.get("/success", response_class=HTMLResponse)
async def success_page(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(UserModel).filter(UserModel.email == current_user["email"]).first()
    return templates.TemplateResponse("success.html", {"request": request, "user": u})

@router.get("/me", response_model=User)
async def get_current_user_route(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/users", response_class=HTMLResponse)
async def list_users(request: Request, db: Session = Depends(get_db)):
    users = db.query(UserModel).all()
    return templates.TemplateResponse("users.html", {"request": request, "users": users})

@router.get("/users/json", response_model=list[User])
async def list_users_json(db: Session = Depends(get_db)):
    return db.query(UserModel).all()

@router.post("/users", response_model=User)
async def add_user(user: UserCreate, db: Session = Depends(get_db)):
    exists = db.query(UserModel).filter(UserModel.email == user.email).first()
    if exists:
        raise HTTPException(status_code=400, detail="User exists")
    new_user = UserModel(email=user.email, name=user.name, picture=user.picture)
    db.add(new_user); db.commit(); db.refresh(new_user)
    return new_user

@router.post("/2fa/disable/redirect")
async def twofa_disable_redirect(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter(UserModel.email == current_user["email"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.totp_enabled = False
    user.totp_secret = None
    user.totp_verified_at = None
    user.totp_backup_codes = None
    db.add(user); db.commit()

    # 303 so POST -> GET
    return RedirectResponse(url="/auth/success", status_code=303)
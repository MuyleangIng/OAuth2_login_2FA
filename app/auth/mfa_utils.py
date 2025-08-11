import hashlib
import secrets
import pyotp
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from app.core.config import APP_SECRET, ISSUER_NAME

_signer = TimestampSigner(APP_SECRET)

def create_totp_secret() -> str:
    return pyotp.random_base32()

def totp_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER_NAME)

def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=valid_window)

def sign_pending(email: str) -> str:
    return _signer.sign(email.encode()).decode()

def unsign_pending(value: str, max_age: int = 300) -> str | None:
    try:
        return _signer.unsign(value, max_age=max_age).decode()
    except (BadSignature, SignatureExpired):
        return None

def hash_code(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def generate_backup_codes(n=8):
    codes = [secrets.token_hex(5) for _ in range(n)]
    return codes, [hash_code(c) for c in codes]

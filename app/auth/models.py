# from sqlalchemy import Column, Integer, String
# from app.database.database import Base
# from sqlalchemy import Boolean, Column, DateTime, String, JSON


# class User(Base):
#     __tablename__ = "users"

#     id = Column(Integer, primary_key=True, index=True)
#     email = Column(String, unique=True, index=True)
#     name = Column(String)
#     picture = Column(String)

#     # 2FA / TOTP
#     totp_secret = Column(String, nullable=True)       # store encrypted at rest in prod
#     totp_enabled = Column(Boolean, default=False)
#     totp_verified_at = Column(DateTime(timezone=True), nullable=True)
#     totp_backup_codes = Column(JSON, nullable=True)   # list of hashed backup codes

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from app.database.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    picture = Column(String, nullable=True)

    # TOTP / MFA
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    totp_verified_at = Column(DateTime, nullable=True)
    # If you use backup codes, store hashed strings or JSON;
    # kept as TEXT for simplicity.
    totp_backup_codes = Column(String, nullable=True)

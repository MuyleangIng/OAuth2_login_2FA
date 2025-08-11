import os
from datetime import timedelta

APP_SECRET = os.getenv("APP_SECRET", "dev-change-me")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me-too")
JWT_ALG = "HS256"
JWT_EXPIRE = timedelta(hours=12)

# Google OAuth

# Shown in authenticator app
ISSUER_NAME = os.getenv("ISSUER_NAME", "Qummit")


GOOGLE_CLIENT_ID = "48242718990-2rlm0qal247bm1deq8p9l8eajracsp2f.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"
JWT_SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
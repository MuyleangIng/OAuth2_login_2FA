import os
from datetime import timedelta

APP_SECRET = os.getenv("APP_SECRET", "dev-change-me")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me-too")
JWT_ALG = "HS256"
JWT_EXPIRE = timedelta(hours=12)

# Google OAuth

# Shown in authenticator app
ISSUER_NAME = os.getenv("ISSUER_NAME", "Qummit")


GOOGLE_CLIENT_ID = "48242718990-ah5ejh83719uqmsfq72jdu8pfvgq6aln.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_REDIRECT_URI = "https://google.dqummit.work/auth/google/callback"
JWT_SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
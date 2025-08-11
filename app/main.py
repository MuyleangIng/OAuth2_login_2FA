from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import users
from app.database.database import engine
from app.auth.models import Base
from fastapi import FastAPI, Response
from fastapi.responses import RedirectResponse

app = FastAPI(title="FastAPI Google OAuth")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables
Base.metadata.create_all(bind=engine)
# Silence Chrome devtools probe noise
@app.get("/.well-known/appspecific/com.chrome.devtools.json")
def chrome_probe():
    return Response(status_code=204)
# Include routers
app.include_router(users.router)

@app.get("/")
async def root():
    return RedirectResponse(url="/auth/login")
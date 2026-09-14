import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.db.session import Base, engine
from app.api.routes import router

settings = get_settings()

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("clonedetector")

app = FastAPI(
    title="Fake / Cloned Android App Detection System",
    description="Local-first MVP: static analysis of two APKs to estimate clone probability and malware risk.",
    version="0.1.0-mvp",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.on_event("startup")
def on_startup():
    # MVP: create tables directly. Swap for Alembic migrations before this
    # goes anywhere near a shared/production database.
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ensured. Scoring weights: %s", settings.scoring_weights)


@app.get("/")
def root():
    return {"service": "android-clone-detector-api", "status": "running", "docs": "/docs"}

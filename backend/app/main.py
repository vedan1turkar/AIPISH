"""FastAPI application factory. CORS, error envelope, health gate."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.errors import generic_error_handler, http_error_handler, validation_error_handler
from app.api.case_router import router as case_router
from app.api.ml_router import router as ml_router
from app.api.router import router
from app.core.config import get_settings
from app.core.db import Base, engine


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Email Forensics Platform",
        version="0.1.0",
        description="AI-powered email threat detection, geolocation and forensic intelligence.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID"],
    )

    # Create tables on startup (SQLite-friendly for the MVP).
    Base.metadata.create_all(bind=engine)

    # Uniform error envelope for every non-2xx.
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_error_handler)
    app.add_exception_handler(Exception, generic_error_handler)

    app.include_router(router, prefix="/api/v1")
    app.include_router(case_router, prefix="/api/v1")
    app.include_router(ml_router, prefix="/api/v1")
    return app


app = create_app()

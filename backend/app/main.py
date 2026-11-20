"""FastAPI application factory. CORS, error envelope, security headers, access control.

Access control (P5b): ``enforce_access`` is an application-level dependency, so
every API route — including ones added later — goes through the central
permission map and is denied unless mapped. Startup fails closed when the JWT
secret is missing or weak (outside APP_ENV=test).
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.errors import generic_error_handler, http_error_handler, validation_error_handler
from app.api.case_router import router as case_router
from app.api.ml_router import router as ml_router
from app.api.llm_router import router as llm_router
from app.api.intel_router import router as intel_router
from app.api.auth_router import router as auth_router
from app.api.admin_router import router as admin_router
from app.api.correlation_router import router as correlation_router
from app.api.router import router
from app.core.config import get_settings
from app.core.db import engine
from app.security.deps import enforce_access
from app.security.tokens import set_auth_config, load_auth_config

DOCS_ENVS = {"dev", "test"}
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}


def create_app() -> FastAPI:
    settings = get_settings()
    # Fail closed: raises AuthConfigError (app does not start) on a missing/weak secret outside test.
    set_auth_config(load_auth_config(settings.env))

    app = FastAPI(
        title="Email Forensics Platform",
        version="0.1.0",
        description="AI-powered email threat detection, geolocation and forensic intelligence.",
        dependencies=[Depends(enforce_access)],
        docs_url=None, redoc_url=None, openapi_url=None,   # re-added below, admin-only, dev/test only
    )

    # Bearer tokens only (no cookies), so credentials stay off; never a wildcard origin.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o for o in settings.allowed_origins if o and o != "*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Evidence-Key"],
        expose_headers=["Content-Disposition", "Retry-After"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/") or request.url.path == "/openapi.json":
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    # Create tables + additive, idempotent migrations (shared with the CLI).
    from app.core.db import SessionLocal
    from app.core.models import migrate_assessments, run_additive_migrations
    run_additive_migrations(engine)
    # Additive, idempotent migration of P4 assessments into versioned history.
    with SessionLocal() as db:
        migrate_assessments(db)

    # Uniform error envelope for every non-2xx.
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_error_handler)
    app.add_exception_handler(Exception, generic_error_handler)

    app.include_router(router, prefix="/api/v1")
    app.include_router(case_router, prefix="/api/v1")
    app.include_router(ml_router, prefix="/api/v1")
    app.include_router(llm_router, prefix="/api/v1")
    app.include_router(intel_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(admin_router, prefix="/api/v1")
    app.include_router(correlation_router, prefix="/api/v1")

    if (settings.env or "").lower() in DOCS_ENVS:
        @app.get("/openapi.json", include_in_schema=False)
        def openapi_schema() -> dict:
            return app.openapi()

        @app.get("/docs", include_in_schema=False)
        def swagger_docs():
            return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} – docs")

        @app.get("/redoc", include_in_schema=False)
        def redoc_docs():
            return get_redoc_html(openapi_url="/openapi.json", title=f"{app.title} – ReDoc")
    return app


app = create_app()

"""Error envelope for all non-2xx responses."""
from __future__ import annotations

import logging

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


def error_envelope(status_code: int, code: str, message: str, request_id: str | None = None) -> JSONResponse:
    """Shape: {"error": {"code", "message", "request_id"}}."""
    payload: dict[str, object] = {"code": code, "message": message}
    if request_id:
        payload["request_id"] = request_id
    return JSONResponse(status_code=status_code, content={"error": payload})


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """RequestValidationError → 400 with a field-aware message."""
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", []) if p != "body")
    return error_envelope(400, "VALIDATION_ERROR", f"Invalid request: {field}")


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """HTTPException (incl. Starlette routing 404/405) → envelope.

    If the detail carries a structured error code (``{"code": …, "message": …}``),
    preserve the specific code (e.g. PAYLOAD_TOO_LARGE) instead of the generic
    ``HTTP_ERROR`` label.
    """
    if isinstance(exc.detail, dict) and "code" in exc.detail:
        message = str(exc.detail.get("message", "Request failed."))
        return error_envelope(exc.status_code, str(exc.detail["code"]), message)
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
    return error_envelope(exc.status_code, "HTTP_ERROR", detail)


async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler; leaks nothing internal, logs the real error."""
    logger.exception("unhandled error", exc_info=exc)
    return error_envelope(500, "INTERNAL_ERROR", "Internal server error.")

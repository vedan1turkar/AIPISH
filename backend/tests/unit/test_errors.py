"""Uniform error envelope tests."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.errors import validation_error_handler
from app.main import create_app


def test_unknown_route_returns_envelope() -> None:
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    res = client.get("/api/v1/nonexistent")
    assert res.status_code == 404
    body = res.json()
    assert set(body["error"].keys()) >= {"code", "message"}


def test_validation_error_maps_to_envelope() -> None:
    app = create_app()

    @app.get("/api/v1/bad-endpoint")
    def bad(q: int) -> dict[str, int]:
        return {"q": q}

    client = TestClient(app, raise_server_exceptions=False)
    res = client.get("/api/v1/bad-endpoint?q=not-a-number")
    assert res.status_code == 400
    body = res.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert "q" in body["error"]["message"]


def test_validation_handler_maps_field_directly() -> None:
    # Unit-level: exercise the handler without HTTP wiring.
    import asyncio

    from fastapi.exceptions import RequestValidationError

    exc = RequestValidationError([{"loc": ("query", "q"), "msg": "not int", "type": "int_parsing"}])
    response = asyncio.run(validation_error_handler(request=None, exc=exc))  # type: ignore[arg-type]
    assert response.status_code == 400
    assert b"VALIDATION_ERROR" in response.body
    assert b"q" in response.body

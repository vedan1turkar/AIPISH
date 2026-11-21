from fastapi.testclient import TestClient

from app.main import create_app


def test_health_ok() -> None:
    """P5g hardening: anonymous liveness discloses only the status (no version or environment)."""
    app = create_app()
    client = TestClient(app)
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    body = res.json()
    assert body == {"status": "ok"}


def test_system_info_moves_version_behind_auth(client, anon_client) -> None:
    """The version / db check formerly on /health now needs a signed-in user (viewer+)."""
    assert anon_client.get("/api/v1/system/info").status_code == 401
    res = client.get("/api/v1/system/info")
    assert res.status_code == 200
    body = res.json()
    assert body["version"] == "0.1.0"
    assert body["db_connected"] is True
    assert body["environment"] == "test"
    assert body["database"] in ("sqlite", "postgresql")
    assert body["schema_version"] >= 4

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_ok() -> None:
    app = create_app()
    client = TestClient(app)
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"
    assert body["db_connected"] is True

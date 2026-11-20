"""Ingestion API integration tests via TestClient (no network)."""
import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.authutil import authed_client  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "eml"


@pytest.fixture
def client() -> TestClient:
    return authed_client()


def _upload(client: TestClient, path: Path, filename: str | None = None):
    data = path.read_bytes()
    return client.post(
        "/api/v1/analyses",
        files={"file": (filename or path.name, data, "message/rfc822")},
    )


def test_upload_benign_returns_detail(client: TestClient) -> None:
    res = _upload(client, FIXTURES / "benign.eml")
    assert res.status_code == 201, res.text
    body = res.json()
    assert len(body["sha256"]) == 64
    assert body["subject"] == "Quarterly report attached below"
    assert body["from"]["email"] == "alice@example.com"
    assert body["received_count"] == 0
    assert body["urls"][0]["url"].startswith("https://example.com")
    assert body["parse_defects"] == []


def test_upload_persists_and_get_roundtrip(client: TestClient) -> None:
    up = _upload(client, FIXTURES / "benign.eml").json()
    listed = client.get("/api/v1/analyses").json()
    assert any(item["id"] == up["id"] for item in listed)
    got = client.get(f"/api/v1/analyses/{up['id']}")
    assert got.status_code == 200
    assert got.json()["sha256"] == up["sha256"]


def test_upload_phishing_multipart(client: TestClient) -> None:
    res = _upload(client, FIXTURES / "phishing_multipart.eml")
    assert res.status_code == 201
    body = res.json()
    assert body["from"]["display_name"] == "PayPal Security Team"
    assert body["from"]["email"].endswith("paypa1-secure.com")
    assert body["received_count"] == 1
    assert len(body["attachments"]) == 1
    assert len(body["attachments"][0]["sha256"]) == 64
    assert body["attachments"][0]["filename"] == "statement.txt"
    assert any("paypa1-secure.com/verify" in u["url"] for u in body["urls"])


def test_upload_malformed_still_201(client: TestClient) -> None:
    res = _upload(client, FIXTURES / "malformed.eml")
    assert res.status_code == 201, res.text
    body = res.json()
    assert len(body["sha256"]) == 64


def test_oversized_file_rejected_413(client: TestClient) -> None:
    big = b"From: a@b.c\r\nSubject: big\r\n\r\n" + b"x" * (11 * 1024 * 1024)
    res = client.post(
        "/api/v1/analyses",
        files={"file": ("big.eml", big, "message/rfc822")},
    )
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_empty_file_rejected_400(client: TestClient) -> None:
    res = client.post(
        "/api/v1/analyses",
        files={"file": ("empty.eml", b"", "message/rfc822")},
    )
    assert res.status_code == 400


def test_wrong_type_rejected_415(client: TestClient) -> None:
    res = client.post(
        "/api/v1/analyses",
        files={"file": ("photo.png", b"\x89PNG fake", "image/png")},
    )
    assert res.status_code == 415


def test_missing_file_400(client: TestClient) -> None:
    res = client.post("/api/v1/analyses")
    assert res.status_code in (400, 422)


def test_get_unknown_id_404(client: TestClient) -> None:
    res = client.get("/api/v1/analyses/doesnotexist")
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"


def test_api_responsive_after_malformed(client: TestClient) -> None:
    """Malformed upload must not wedge the service."""
    _upload(client, FIXTURES / "malformed.eml")
    ok = _upload(client, FIXTURES / "benign.eml")
    assert ok.status_code == 201
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

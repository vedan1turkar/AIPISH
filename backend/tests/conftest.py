import os

# Offline by default: the upload pipeline skips live DNS/SPF/DKIM/DMARC and
# enrichment when APP_ENV=test. Must be set before the app (and its cached
# settings) is imported. Live-provider tests call providers directly.
os.environ["APP_ENV"] = "test"
# Never pick up locally trained models implicitly; ML tests point at temp bundles.
os.environ["AIPISH_MODEL_DIR"] = str(__import__("pathlib").Path(__file__).parent / "_no_model")

# ── Database isolation (P5i) ──────────────────────────────────────────────
# Default: a fresh temporary SQLite file per session, so `pytest` can never touch the dev database.
# Opt-in PostgreSQL: TEST_DATABASE_URL=postgresql://…/aipish_test (run with --allow-hosts=127.0.0.1);
# that dedicated test database is dropped/re-created here and dropped again at the end.
_TEST_PG_URL = (os.environ.get("TEST_DATABASE_URL") or "").strip()
if _TEST_PG_URL:
    from tests.pgtest import prepare_test_database  # noqa: E402
    os.environ["DATABASE_URL"] = prepare_test_database(_TEST_PG_URL)
else:
    os.environ["DATABASE_URL"] = ""          # never inherit a server DATABASE_URL from .env
    if not os.environ.get("APP_DB_PATH"):
        import tempfile  # noqa: E402
        os.environ["APP_DB_PATH"] = os.path.join(tempfile.mkdtemp(prefix="aipish-test-"), "test.sqlite")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402


def pytest_collection_modifyitems(config, items):
    gates = {"live": "AIPISH_RUN_LIVE", "integration": "AIPISH_RUN_INTEGRATION"}
    for item in items:
        for marker, var in gates.items():
            if item.get_closest_marker(marker) is None:
                continue
            if os.environ.get(var) == "1":
                item.add_marker(pytest.mark.enable_socket)
            else:
                item.add_marker(pytest.mark.skip(reason=f"{marker} test: set {var}=1 to run"))


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    # Failed-login counters are in-memory and process-wide; keep tests independent.
    from app.security import throttle
    throttle.reset_all()
    yield
    throttle.reset_all()


@pytest.fixture
def client() -> TestClient:
    """Authenticated (admin) client: real user + real signed JWT (P5b)."""
    from tests.authutil import authed_client
    return authed_client(create_app(), "admin")


@pytest.fixture
def anon_client() -> TestClient:
    return TestClient(create_app())


def pytest_sessionfinish(session, exitstatus):
    if not _TEST_PG_URL or os.environ.get("AIPISH_KEEP_TEST_DB") == "1":
        return
    from app.core.db import engine
    engine.dispose()
    from tests.pgtest import drop_test_database
    drop_test_database(_TEST_PG_URL)

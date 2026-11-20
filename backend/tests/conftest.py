import os

# Offline by default: the upload pipeline skips live DNS/SPF/DKIM/DMARC and
# enrichment when APP_ENV=test. Must be set before the app (and its cached
# settings) is imported. Live-provider tests call providers directly.
os.environ["APP_ENV"] = "test"
# Never pick up locally trained models implicitly; ML tests point at temp bundles.
os.environ["AIPISH_MODEL_DIR"] = str(__import__("pathlib").Path(__file__).parent / "_no_model")

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

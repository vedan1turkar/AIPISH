import os

# Offline by default: the upload pipeline skips live DNS/SPF/DKIM/DMARC and
# enrichment when APP_ENV=test. Must be set before the app (and its cached
# settings) is imported. Live-provider tests call providers directly.
os.environ["APP_ENV"] = "test"

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


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())

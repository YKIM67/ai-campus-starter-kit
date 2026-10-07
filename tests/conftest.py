import os
import sys
import tempfile

import pytest

# Configure an isolated DB and a known admin token BEFORE main is imported,
# since main reads env vars and initializes the schema at import time.
_TMP_DIR = tempfile.mkdtemp(prefix="toy_service_test_")
os.environ["DB_FILE"] = os.path.join(_TMP_DIR, "test_service.db")
os.environ["ADMIN_MASTER_TOKEN"] = "test-admin-token"
os.environ["PBKDF2_ITERATIONS"] = "1000"  # keep tests fast

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN_TOKEN = os.environ["ADMIN_MASTER_TOKEN"]


@pytest.fixture()
def client():
    conn = main.get_db_connection()
    conn.execute("DELETE FROM items")
    conn.execute("DELETE FROM users")
    conn.commit()
    conn.close()
    return TestClient(main.app)


@pytest.fixture()
def admin_headers():
    return {"x-auth-token": ADMIN_TOKEN}

import main


# ---------------------------------------------------------------------
# 1. Basic CRUD
# ---------------------------------------------------------------------
def test_health_check(client):
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_create_and_search_items(client, admin_headers):
    res = client.post("/api/items", json={"title": "Buy milk", "content": "2L"}, headers=admin_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["title"] == "Buy milk"

    client.post("/api/items", json={"title": "Walk dog"}, headers=admin_headers)

    all_items = client.get("/api/items").json()
    assert all_items["total"] == 2

    found = client.get("/api/items", params={"keyword": "milk"}).json()
    assert found["total"] == 1
    assert found["items"][0]["title"] == "Buy milk"


def test_register_and_login(client):
    res = client.post("/api/auth/register", json={"username": "alice", "password": "s3cret-pass"})
    assert res.status_code == 200

    dup = client.post("/api/auth/register", json={"username": "alice", "password": "other"})
    assert dup.status_code == 400

    ok = client.post("/api/auth/login", json={"username": "alice", "password": "s3cret-pass"})
    assert ok.status_code == 200
    assert ok.json()["user"]["username"] == "alice"
    # Regular users must not receive the admin token.
    assert ok.json()["token"] is None

    bad = client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    assert bad.status_code == 401


def test_password_is_salted_not_plain_or_md5(client):
    client.post("/api/auth/register", json={"username": "bob", "password": "hunter2-pass"})
    conn = main.get_db_connection()
    stored = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("bob",)).fetchone()[0]
    conn.close()
    assert "hunter2-pass" not in stored
    assert "$" in stored and len(stored.split("$")[1]) == 64  # salt$sha256


# ---------------------------------------------------------------------
# 2. SQL Injection protection
# ---------------------------------------------------------------------
def test_sql_injection_in_search_is_treated_as_literal(client, admin_headers):
    client.post("/api/items", json={"title": "Safe item"}, headers=admin_headers)

    payload = "' OR '1'='1"
    res = client.get("/api/items", params={"keyword": payload})
    assert res.status_code == 200
    assert res.json()["total"] == 0

    drop = "x'; DROP TABLE items; --"
    res = client.get("/api/items", params={"keyword": drop})
    assert res.status_code == 200
    # Table still exists and data intact.
    assert client.get("/api/items").json()["total"] == 1


def test_sql_injection_login_bypass_fails(client):
    client.post("/api/auth/register", json={"username": "admin", "password": "realpass123"})
    res = client.post("/api/auth/login", json={"username": "admin' --", "password": "anything"})
    assert res.status_code == 401
    res = client.post("/api/auth/login", json={"username": "admin", "password": "' OR '1'='1"})
    assert res.status_code == 401


def test_sql_injection_payload_stored_verbatim(client, admin_headers):
    title = "Robert'); DROP TABLE items;--"
    res = client.post("/api/items", json={"title": title, "content": "' OR 1=1 --"}, headers=admin_headers)
    assert res.status_code == 200
    items = client.get("/api/items").json()["items"]
    assert len(items) == 1
    assert items[0]["title"] == title


# ---------------------------------------------------------------------
# 3. Admin token enforcement
# ---------------------------------------------------------------------
def test_invalid_admin_token_rejected(client):
    res = client.post("/api/items", json={"title": "Hack"}, headers={"x-auth-token": "wrong-token"})
    assert res.status_code in (401, 403)


def test_missing_admin_token_rejected(client):
    res = client.post("/api/items", json={"title": "Hack"})
    assert res.status_code in (401, 403)
    assert client.get("/api/items").json()["total"] == 0


# ---------------------------------------------------------------------
# 4. Input validation
# ---------------------------------------------------------------------
def test_empty_title_rejected(client, admin_headers):
    for bad_title in ["", "   "]:
        res = client.post("/api/items", json={"title": bad_title}, headers=admin_headers)
        assert res.status_code == 422, bad_title
    assert client.get("/api/items").json()["total"] == 0


def test_missing_title_rejected(client, admin_headers):
    res = client.post("/api/items", json={"content": "no title"}, headers=admin_headers)
    assert res.status_code == 422


def test_blank_username_rejected(client):
    res = client.post("/api/auth/register", json={"username": "  ", "password": "pw123456"})
    assert res.status_code == 422


# ---------------------------------------------------------------------
# 5. Performance & concurrency guardrails
# ---------------------------------------------------------------------
def test_deduplicate_records_preserves_order():
    records = [{"id": 1}, {"id": 2}, {"id": 1}, {"id": 3}, {"id": 2}]
    assert main.deduplicate_records(records) == [{"id": 1}, {"id": 2}, {"id": 3}]


def test_sqlite_wal_and_busy_timeout_enabled():
    conn = main.get_db_connection()
    assert conn.execute("PRAGMA journal_mode;").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA busy_timeout;").fetchone()[0] == main.SQLITE_BUSY_TIMEOUT_MS
    conn.close()

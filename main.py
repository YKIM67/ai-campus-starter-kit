"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

=== ARCHITECTURE SPECIFICATION & CODING CONVENTIONS ===
See harness/AGENTS.md for the full rules. In short:
1. [ZERO-DEPENDENCY] Use Python built-ins (sqlite3, hashlib, hmac, secrets); no external ORMs.
2. [CONFIGURATION] Read secrets from environment variables (os.getenv). Never hardcode them;
   when unset, generate a random value at startup so local runs still need zero setup.
3. [DATA ACCESS] Always use parameterized queries (`?` placeholders). Never format SQL strings.
4. [HASHING] Hash passwords with salted PBKDF2-HMAC-SHA256; compare with hmac.compare_digest.
5. [ALGORITHMS] Use set/dict for membership checks and deduplication (no nested O(N^2) scans).
======================================================================
"""

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# =====================================================================
# Module Configuration Constants (Inline Standard)
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.1.0-alpha"
DB_FILE = os.getenv("DB_FILE", "service.db")
SESSION_TOKEN_TTL_SECONDS = int(os.getenv("SESSION_TOKEN_TTL_SECONDS", "3600"))
PASSWORD_HASH_ITERATIONS = 200_000
BLOCKED_TAGS = ["spam", "ad", "private", "temp"]

logger = logging.getLogger("uvicorn.error")


def load_secret(env_name: str) -> str:
    """Read a secret from the environment, or generate a random one for local dev."""
    value = os.getenv(env_name)
    if value:
        return value
    value = secrets.token_urlsafe(16)
    logger.warning("%s is not set; generated a temporary value for this run: %s", env_name, value)
    return value


# Secrets come from environment variables (see harness/AGENTS.md, CWE-798)
ADMIN_MASTER_TOKEN = load_secret("ADMIN_MASTER_TOKEN")
TODO_ADMIN_PASSWORD = load_secret("TODO_ADMIN_PASSWORD")

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# Database Initialization & Helpers
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Base Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 2. Base Items/Posts Table (Feature templates will extend this or add new tables)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_username TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Todos Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            is_completed INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT DEFAULT ''
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_todos_created_at ON todos (created_at)")
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# Core Security & Utility Functions
# =====================================================================
def hash_credential(raw_secret: str) -> str:
    """Salted PBKDF2-HMAC-SHA256 digest, stored as '<salt_hex>$<hash_hex>'."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_credential(raw_secret: str, stored_hash: str) -> bool:
    salt_hex, sep, digest_hex = stored_hash.partition("$")
    if not sep:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return hmac.compare_digest(digest.hex(), digest_hex)


def deduplicate_records(records: list) -> list:
    """Deduplicate by id in O(N), maintaining insertion order."""
    unique_items = []
    seen_ids = set()
    for item in records:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_items.append(item)
    return unique_items


def escape_like(keyword: str) -> str:
    """Escape LIKE wildcards so the keyword is matched literally (use with ESCAPE '\\')."""
    return keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# Issued session tokens ->{"username", "role", "expires_at"} (in-memory; reset on restart)
session_tokens = {}


def issue_session_token(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    session_tokens[token] = {
        "username": username,
        "role": role,
        "expires_at": time.time() + SESSION_TOKEN_TTL_SECONDS,
    }
    return token


def get_session(token: Optional[str]) -> Optional[dict]:
    session = session_tokens.get(token) if token else None
    if session is None:
        return None
    if session["expires_at"] < time.time():
        session_tokens.pop(token, None)
        return None
    return session


# =====================================================================
# Pydantic Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str
    password: str


class ItemCreateRequest(BaseModel):
    title: str
    content: Optional[str] = ""


class TodoCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    is_completed: bool = False
    tags: Optional[str] = ""  # comma-separated, e.g. "work,urgent"


class AdminLoginRequest(BaseModel):
    password: str


# =====================================================================
# Todo Helpers
# =====================================================================
def normalize_tags(raw_tags: Optional[str]) -> str:
    """Trim, lowercase and drop empty/duplicate entries from a comma-separated tag string."""
    if not raw_tags:
        return ""
    tags = []
    seen = set()
    for tag in raw_tags.split(","):
        tag = tag.strip().lower()
        if tag and tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return ",".join(tags)


def todo_row_to_dict(row: sqlite3.Row) -> dict:
    todo = dict(row)
    todo["is_completed"] = bool(todo["is_completed"])
    return todo


def verify_admin_token(token: Optional[str]) -> None:
    session = get_session(token)
    if session is None or session["role"] != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized: invalid, expired or missing admin token")


# =====================================================================
# Base API Endpoints
# =====================================================================
@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION
    }


@app.post("/api/auth/register")
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (req.username, hashed_pw),
        )
        conn.commit()
        return {"success": True, "message": f"User {req.username} registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, password_hash FROM users WHERE username = ?",
        (req.username,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row or not verify_credential(req.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user = {"id": row["id"], "username": row["username"], "role": row["role"]}
    return {
        "success": True,
        "token": issue_session_token(user["username"], user["role"]),
        "user": user
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if keyword:
        pattern = "%" + escape_like(keyword) + "%"
        cursor.execute(
            "SELECT * FROM items WHERE title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\'",
            (pattern, pattern),
        )
    else:
        cursor.execute("SELECT * FROM items")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    # Procedural deduplication pass
    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    if x_auth_token and hmac.compare_digest(x_auth_token, ADMIN_MASTER_TOKEN):
        owner_username = "admin"
    else:
        session = get_session(x_auth_token)
        if session is None:
            raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")
        owner_username = session["username"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
        (req.title, req.content or "", owner_username),
    )
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# Todo API Endpoints
# =====================================================================
@app.get("/todos")
def list_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY created_at DESC, id DESC")
    todos = [todo_row_to_dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"total": len(todos), "todos": todos}


@app.post("/todos", status_code=201)
def create_todo(req: TodoCreateRequest):
    if not req.title.strip():
        raise HTTPException(status_code=400, detail="Title must not be empty")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO todos (title, description, is_completed, tags) VALUES (?, ?, ?, ?)",
        (req.title.strip(), req.description or "", int(req.is_completed), normalize_tags(req.tags)),
    )
    todo_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    todo = todo_row_to_dict(cursor.fetchone())
    conn.close()
    return {"success": True, "todo": todo}


@app.get("/todos/search")
def search_todos(q: str):
    if not q.strip():
        raise HTTPException(status_code=400, detail="Query parameter 'q' must not be empty")

    pattern = "%" + escape_like(q) + "%"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM todos WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' "
        "ORDER BY created_at DESC, id DESC",
        (pattern, pattern),
    )
    todos = [todo_row_to_dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"query": q, "total": len(todos), "todos": todos}


@app.get("/todos/filtered")
def filtered_todos():
    blocked_set = set(BLOCKED_TAGS)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY created_at DESC, id DESC")
    rows = cursor.fetchall()
    conn.close()

    clean_todos = []
    for row in rows:
        tags = row["tags"].split(",") if row["tags"] else []
        if not any(tag in blocked_set for tag in tags):
            clean_todos.append(todo_row_to_dict(row))
    return {"blocked_tags": BLOCKED_TAGS, "total": len(clean_todos), "todos": clean_todos}


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if not hmac.compare_digest(req.password.encode("utf-8"), TODO_ADMIN_PASSWORD.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid admin password")
    token = issue_session_token("admin", "admin")
    return {"success": True, "token": token, "expires_in": SESSION_TOKEN_TTL_SECONDS}


@app.delete("/admin/todos/{todo_id}")
def admin_delete_todo(todo_id: int, x_admin_token: Optional[str] = Header(None)):
    verify_admin_token(x_admin_token)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"success": True, "deleted_id": todo_id}

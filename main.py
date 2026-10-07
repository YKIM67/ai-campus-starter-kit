"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

Toy Service MVP API.
Engineering standards: see harness/AGENTS.md
  - Secrets are read from environment variables (CWE-798)
  - All SQL uses parameterized binding with `?` placeholders (CWE-89)
  - Passwords use salted PBKDF2-HMAC-SHA256 (CWE-327)
  - SQLite runs in WAL mode with a busy timeout (CWE-400)
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field, field_validator

# =====================================================================
# Configuration (environment-driven, safe defaults)
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.1.0-alpha"
# No usable default: if unset, a random per-process token is generated so a
# known/guessable admin token can never ship by accident.
ADMIN_MASTER_TOKEN = os.getenv("ADMIN_MASTER_TOKEN") or secrets.token_urlsafe(32)
DB_FILE = os.getenv("DB_FILE", "service.db")
SQLITE_BUSY_TIMEOUT_MS = int(os.getenv("SQLITE_BUSY_TIMEOUT_MS", "5000"))
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "200000"))

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# Database Initialization & Helpers
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    # WAL lets readers and a writer proceed concurrently; busy_timeout makes
    # contending writers wait instead of failing with "database is locked".
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS:d};")
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
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_items_owner ON items(owner_username)")
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# Core Security & Utility Functions
# =====================================================================
def hash_credential(raw_secret: str, salt: Optional[bytes] = None) -> str:
    """Salted PBKDF2-HMAC-SHA256 digest, stored as 'salt_hex$hash_hex'."""
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_credential(raw_secret: str, stored: str) -> bool:
    try:
        salt_hex, _ = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    return hmac.compare_digest(hash_credential(raw_secret, salt), stored)


def is_valid_admin_token(token: Optional[str]) -> bool:
    return token is not None and hmac.compare_digest(token, ADMIN_MASTER_TOKEN)


def deduplicate_records(records: list) -> list:
    """O(N) deduplication by id using a hash set, preserving insertion order."""
    seen_ids = set()
    unique_items = []
    for item in records:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_items.append(item)
    return unique_items


# =====================================================================
# Pydantic Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def username_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("username must not be blank")
        return v


class ItemCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: Optional[str] = Field(default="", max_length=10000)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("title must not be blank")
        return v


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
        # Only admins receive the privileged token; regular users get none.
        "token": ADMIN_MASTER_TOKEN if row["role"] == "admin" else None,
        "user": user
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    if keyword:
        pattern = f"%{keyword}%"
        cursor.execute(
            "SELECT * FROM items WHERE title LIKE ? OR content LIKE ?",
            (pattern, pattern),
        )
    else:
        cursor.execute("SELECT * FROM items")

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    if x_auth_token is None:
        raise HTTPException(status_code=401, detail="Unauthorized: missing token")
    if not is_valid_admin_token(x_auth_token):
        raise HTTPException(status_code=403, detail="Forbidden: invalid token")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
        (req.title, req.content, "admin"),
    )
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {"success": True, "item_id": item_id, "title": req.title}

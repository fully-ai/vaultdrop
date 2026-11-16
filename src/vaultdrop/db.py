"""Async SQLite persistence for users, encrypted file metadata, share links, and download logs."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite


def utcnow() -> datetime:
    return datetime.now(UTC)


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
    quota_bytes INTEGER NOT NULL,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256_hex TEXT NOT NULL,
    wrapped_dek_b64 TEXT NOT NULL,
    wrap_nonce_b64 TEXT NOT NULL,
    data_nonce_b64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS share_links (
    token TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    passcode_hash TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS download_logs (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    share_token TEXT,
    actor_user_id TEXT,
    client_ip TEXT NOT NULL,
    downloaded_at TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);
"""


class VaultDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not initialized")
        return self._conn

    async def create_user(self, username: str, password_hash: str, quota_bytes: int) -> dict[str, Any]:
        cursor = await self.conn.execute("SELECT COUNT(*) as cnt FROM users")
        row = await cursor.fetchone()
        role = "admin" if row and row["cnt"] == 0 else "user"
        user_id = uuid.uuid4().hex
        now = utcnow().isoformat()
        await self.conn.execute(
            """
            INSERT INTO users (id, username, password_hash, role, quota_bytes, used_bytes, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (user_id, username, password_hash, role, quota_bytes, now),
        )
        await self.conn.commit()
        return await self.get_user_by_id(user_id)  # type: ignore[return-value]

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        cur = await self.conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        cur = await self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def list_users(self) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT id, username, role, quota_bytes, used_bytes, created_at FROM users ORDER BY username ASC"
        )
        return [dict(r) for r in await cur.fetchall()]

    async def update_quota(self, user_id: str, quota_bytes: int) -> dict[str, Any] | None:
        cur = await self.conn.execute("UPDATE users SET quota_bytes = ? WHERE id = ?", (quota_bytes, user_id))
        await self.conn.commit()
        if cur.rowcount == 0:
            return None
        return await self.get_user_by_id(user_id)

    async def create_file(
        self,
        file_id: str,
        owner_id: str,
        original_name: str,
        stored_name: str,
        size_bytes: int,
        sha256_hex: str,
        wrapped_dek_b64: str,
        wrap_nonce_b64: str,
        data_nonce_b64: str,
    ) -> dict[str, Any]:
        now = utcnow().isoformat()
        await self.conn.execute(
            """
            INSERT INTO files (
                id, owner_id, original_name, stored_name, size_bytes,
                sha256_hex, wrapped_dek_b64, wrap_nonce_b64, data_nonce_b64, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                owner_id,
                original_name,
                stored_name,
                size_bytes,
                sha256_hex,
                wrapped_dek_b64,
                wrap_nonce_b64,
                data_nonce_b64,
                now,
            ),
        )
        await self.conn.execute(
            "UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?",
            (size_bytes, owner_id),
        )
        await self.conn.commit()
        return await self.get_file(file_id)  # type: ignore[return-value]

    async def list_files_for_user(self, owner_id: str) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            """
            SELECT id, owner_id, original_name, size_bytes, sha256_hex, created_at
            FROM files WHERE owner_id = ? ORDER BY created_at DESC
            """,
            (owner_id,),
        )
        return [dict(r) for r in await cur.fetchall()]

    async def get_file(self, file_id: str) -> dict[str, Any] | None:
        cur = await self.conn.execute("SELECT * FROM files WHERE id = ?", (file_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def delete_file(self, file_id: str, owner_id: str, size_bytes: int) -> None:
        await self.conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await self.conn.execute(
            "UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE id = ?",
            (size_bytes, owner_id),
        )
        await self.conn.commit()

    async def create_share_link(
        self,
        file_id: str,
        created_by: str,
        ttl_minutes: int,
        max_downloads: int | None,
        passcode_hash: str | None,
    ) -> dict[str, Any]:
        token = secrets.token_urlsafe(24)
        now = utcnow()
        expires = now + timedelta(minutes=ttl_minutes)
        await self.conn.execute(
            """
            INSERT INTO share_links (token, file_id, created_by, expires_at, max_downloads, passcode_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (token, file_id, created_by, expires.isoformat(), max_downloads, passcode_hash, now.isoformat()),
        )
        await self.conn.commit()
        return await self.get_share_link(token)  # type: ignore[return-value]

    async def get_share_link(self, token: str) -> dict[str, Any] | None:
        cur = await self.conn.execute("SELECT * FROM share_links WHERE token = ?", (token,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def increment_share_download(self, token: str) -> None:
        await self.conn.execute(
            "UPDATE share_links SET download_count = download_count + 1 WHERE token = ?",
            (token,),
        )
        await self.conn.commit()

    async def revoke_share_link(self, token: str, owner_id: str) -> bool:
        cur = await self.conn.execute(
            "UPDATE share_links SET revoked = 1 WHERE token = ? AND created_by = ?",
            (token, owner_id),
        )
        await self.conn.commit()
        return cur.rowcount > 0

    async def record_download(
        self,
        file_id: str,
        client_ip: str,
        share_token: str | None = None,
        actor_user_id: str | None = None,
    ) -> None:
        await self.conn.execute(
            """
            INSERT INTO download_logs (id, file_id, share_token, actor_user_id, client_ip, downloaded_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (uuid.uuid4().hex, file_id, share_token, actor_user_id, client_ip, utcnow().isoformat()),
        )
        await self.conn.commit()

    async def list_download_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            """
            SELECT dl.*, f.original_name
            FROM download_logs dl
            JOIN files f ON f.id = dl.file_id
            ORDER BY dl.downloaded_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in await cur.fetchall()]

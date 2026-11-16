"""Runtime configuration and key initialization for VaultDrop."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VAULTDROP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = Field(default=8090, ge=1, le=65535)
    data_dir: Path = Path("./data")
    max_file_bytes: int = Field(default=25 * 1024 * 1024, ge=1024)
    default_quota_bytes: int = Field(default=100 * 1024 * 1024, ge=1024)
    master_key_hex: str = ""
    jwt_secret: str = ""

    @property
    def db_path(self) -> Path:
        return self.data_dir / "vaultdrop.db"

    @property
    def blob_dir(self) -> Path:
        return self.data_dir / "blobs"

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.blob_dir.mkdir(parents=True, exist_ok=True)

    def resolve_master_key(self) -> bytes:
        if self.master_key_hex:
            key = bytes.fromhex(self.master_key_hex)
            if len(key) != 32:
                raise ValueError("VAULTDROP_MASTER_KEY_HEX must decode to exactly 32 bytes (64 hex chars)")
            return key
        key_file = self.data_dir / "master.key"
        if key_file.is_file():
            return bytes.fromhex(key_file.read_text(encoding="utf-8").strip())
        key = secrets.token_bytes(32)
        self.ensure_directories()
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(key.hex())
        return key

    def resolve_jwt_secret(self) -> str:
        if self.jwt_secret:
            return self.jwt_secret
        secret_file = self.data_dir / "jwt.key"
        if secret_file.is_file():
            return secret_file.read_text(encoding="utf-8").strip()
        secret = secrets.token_hex(32)
        self.ensure_directories()
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(secret)
        return secret

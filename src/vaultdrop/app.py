"""FastAPI application for VaultDrop encrypted file sharing."""

import re
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import jwt
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from vaultdrop.config import Settings
from vaultdrop.crypto import IntegrityError, decrypt_payload, encrypt_payload, hash_secret, verify_secret
from vaultdrop.db import VaultDatabase

STATIC_DIR = Path(__file__).parent / "static"
_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")


class AuthRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(min_length=8, max_length=128)


class ShareCreateRequest(BaseModel):
    ttl_minutes: int = Field(default=60, ge=1, le=43200)
    max_downloads: int | None = Field(default=None, ge=1, le=1000)
    passcode: str | None = Field(default=None, min_length=4, max_length=64)


class ShareDownloadRequest(BaseModel):
    passcode: str | None = None


class QuotaUpdateRequest(BaseModel):
    quota_bytes: int = Field(ge=1024)


def sanitize_filename(raw: str) -> str:
    base = Path(raw).name
    cleaned = _SAFE_NAME_RE.sub("_", base).strip("._")
    return cleaned[:120] or "file.bin"


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    cfg.ensure_directories()
    master_key = cfg.resolve_master_key()
    jwt_secret = cfg.resolve_jwt_secret()
    db = VaultDatabase(cfg.db_path)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await db.connect()
        try:
            yield
        finally:
            await db.close()

    app = FastAPI(title="VaultDrop", version="0.1.0", lifespan=lifespan)

    def issue_token(user: dict[str, Any]) -> str:
        exp = datetime.now(UTC) + timedelta(hours=12)
        return str(jwt.encode({"sub": user["id"], "role": user["role"], "exp": exp}, jwt_secret, algorithm="HS256"))

    async def current_user(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        try:
            payload = jwt.decode(authorization[7:], jwt_secret, algorithms=["HS256"])
            user = await db.get_user_by_id(payload["sub"])
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    async def admin_user(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Admin role required")
        return user

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/auth/register", status_code=201)
    async def register(req: AuthRequest) -> dict[str, Any]:
        if await db.get_user_by_username(req.username):
            raise HTTPException(status_code=409, detail="Username already exists")
        user = await db.create_user(req.username, hash_secret(req.password), cfg.default_quota_bytes)
        return {
            "token": issue_token(user),
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "quota_bytes": user["quota_bytes"],
                "used_bytes": user["used_bytes"],
            },
        }

    @app.post("/api/auth/login")
    async def login(req: AuthRequest) -> dict[str, Any]:
        user = await db.get_user_by_username(req.username)
        if not user or not verify_secret(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {
            "token": issue_token(user),
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "quota_bytes": user["quota_bytes"],
                "used_bytes": user["used_bytes"],
            },
        }

    @app.get("/api/auth/me")
    async def me(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "quota_bytes": user["quota_bytes"],
            "used_bytes": user["used_bytes"],
        }

    @app.post("/api/files", status_code=201)
    async def upload_file(
        file: Annotated[UploadFile, File()],
        user: Annotated[dict[str, Any], Depends(current_user)],
    ) -> dict[str, Any]:
        content = await file.read(cfg.max_file_bytes + 1)
        if not content:
            raise HTTPException(status_code=400, detail="Empty file")
        if len(content) > cfg.max_file_bytes:
            raise HTTPException(status_code=413, detail="File exceeds configured max size")
        if user["used_bytes"] + len(content) > user["quota_bytes"]:
            raise HTTPException(status_code=413, detail="Storage quota exceeded")

        file_id = uuid.uuid4().hex
        safe_name = sanitize_filename(file.filename or "upload.bin")
        stored_name = f"{file_id}.enc"
        blob_path = (cfg.blob_dir / stored_name).resolve()
        if blob_path.parent != cfg.blob_dir.resolve():
            raise HTTPException(status_code=400, detail="Invalid storage path")

        enc = encrypt_payload(master_key, file_id, content)
        blob_path.write_bytes(enc.ciphertext)

        record = await db.create_file(
            file_id=file_id,
            owner_id=user["id"],
            original_name=safe_name,
            stored_name=stored_name,
            size_bytes=len(content),
            sha256_hex=enc.sha256_hex,
            wrapped_dek_b64=enc.wrapped_dek_b64,
            wrap_nonce_b64=enc.wrap_nonce_b64,
            data_nonce_b64=enc.data_nonce_b64,
        )
        return {
            "id": record["id"],
            "original_name": record["original_name"],
            "size_bytes": record["size_bytes"],
            "sha256_hex": record["sha256_hex"],
            "created_at": record["created_at"],
        }

    @app.get("/api/files")
    async def list_files(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
        return {"files": await db.list_files_for_user(user["id"])}

    def _decrypt_file_record(record: dict[str, Any]) -> bytes:
        blob_path = (cfg.blob_dir / Path(record["stored_name"]).name).resolve()
        if not blob_path.is_file():
            raise HTTPException(status_code=404, detail="Encrypted blob missing")
        try:
            return decrypt_payload(
                master_key=master_key,
                file_id=record["id"],
                ciphertext=blob_path.read_bytes(),
                expected_sha256=record["sha256_hex"],
                wrapped_dek_b64=record["wrapped_dek_b64"],
                wrap_nonce_b64=record["wrap_nonce_b64"],
                data_nonce_b64=record["data_nonce_b64"],
            )
        except IntegrityError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/files/{file_id}/download")
    async def download_own_file(
        file_id: str,
        request: Request,
        user: Annotated[dict[str, Any], Depends(current_user)],
    ) -> Response:
        record = await db.get_file(file_id)
        if not record or (record["owner_id"] != user["id"] and user["role"] != "admin"):
            raise HTTPException(status_code=404, detail="File not found")
        plaintext = _decrypt_file_record(record)
        client_ip = request.client.host if request.client else "unknown"
        await db.record_download(file_id, client_ip=client_ip, actor_user_id=user["id"])
        return Response(
            content=plaintext,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{record["original_name"]}"',
                "X-Content-SHA256": record["sha256_hex"],
            },
        )

    @app.delete("/api/files/{file_id}")
    async def delete_file(
        file_id: str,
        user: Annotated[dict[str, Any], Depends(current_user)],
    ) -> dict[str, str]:
        record = await db.get_file(file_id)
        if not record or (record["owner_id"] != user["id"] and user["role"] != "admin"):
            raise HTTPException(status_code=404, detail="File not found")
        blob_path = (cfg.blob_dir / Path(record["stored_name"]).name).resolve()
        if blob_path.is_file():
            blob_path.unlink()
        await db.delete_file(file_id, record["owner_id"], record["size_bytes"])
        return {"status": "deleted"}

    @app.post("/api/files/{file_id}/share", status_code=201)
    async def create_share(
        file_id: str,
        req: ShareCreateRequest,
        user: Annotated[dict[str, Any], Depends(current_user)],
    ) -> dict[str, Any]:
        record = await db.get_file(file_id)
        if not record or record["owner_id"] != user["id"]:
            raise HTTPException(status_code=404, detail="File not found")
        p_hash = hash_secret(req.passcode) if req.passcode else None
        link = await db.create_share_link(
            file_id=file_id,
            created_by=user["id"],
            ttl_minutes=req.ttl_minutes,
            max_downloads=req.max_downloads,
            passcode_hash=p_hash,
        )
        return {
            "token": link["token"],
            "file_id": link["file_id"],
            "expires_at": link["expires_at"],
            "max_downloads": link["max_downloads"],
            "passcode_protected": bool(p_hash),
        }

    @app.post("/api/share/{token}/revoke")
    async def revoke_share(
        token: str,
        user: Annotated[dict[str, Any], Depends(current_user)],
    ) -> dict[str, str]:
        if not await db.revoke_share_link(token, user["id"]):
            raise HTTPException(status_code=404, detail="Share link not found")
        return {"status": "revoked"}

    @app.post("/api/share/{token}/download")
    async def download_shared(
        token: str,
        request: Request,
        req: ShareDownloadRequest | None = None,
    ) -> Response:
        link = await db.get_share_link(token)
        if not link or link["revoked"]:
            raise HTTPException(status_code=404, detail="Share link not found or revoked")
        if datetime.fromisoformat(link["expires_at"]) <= datetime.now(UTC):
            raise HTTPException(status_code=410, detail="Share link has expired")
        if link["max_downloads"] is not None and link["download_count"] >= link["max_downloads"]:
            raise HTTPException(status_code=410, detail="Download limit reached")
        if link["passcode_hash"]:
            passcode = req.passcode if req else None
            if not passcode or not verify_secret(passcode, link["passcode_hash"]):
                raise HTTPException(status_code=403, detail="Invalid or missing passcode")

        record = await db.get_file(link["file_id"])
        if not record:
            raise HTTPException(status_code=404, detail="File missing")

        plaintext = _decrypt_file_record(record)
        await db.increment_share_download(token)
        client_ip = request.client.host if request.client else "unknown"
        await db.record_download(record["id"], client_ip=client_ip, share_token=token)
        return Response(
            content=plaintext,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{record["original_name"]}"',
                "X-Content-SHA256": record["sha256_hex"],
            },
        )

    # Admin routes
    @app.get("/api/admin/users")
    async def admin_list_users(_admin: Annotated[dict[str, Any], Depends(admin_user)]) -> dict[str, Any]:
        return {"users": await db.list_users()}

    @app.patch("/api/admin/users/{user_id}/quota")
    async def admin_set_quota(
        user_id: str,
        req: QuotaUpdateRequest,
        _admin: Annotated[dict[str, Any], Depends(admin_user)],
    ) -> dict[str, Any]:
        updated = await db.update_quota(user_id, req.quota_bytes)
        if not updated:
            raise HTTPException(status_code=404, detail="User not found")
        return {"id": updated["id"], "quota_bytes": updated["quota_bytes"], "used_bytes": updated["used_bytes"]}

    @app.get("/api/admin/logs")
    async def admin_logs(_admin: Annotated[dict[str, Any], Depends(admin_user)]) -> dict[str, Any]:
        return {"logs": await db.list_download_logs()}

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app

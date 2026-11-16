"""Unit and integration tests for VaultDrop encryption, quotas, share links, and integrity."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vaultdrop.app import create_app
from vaultdrop.config import Settings
from vaultdrop.crypto import IntegrityError, decrypt_payload, encrypt_payload


def test_aes_gcm_roundtrip_and_tamper_detection() -> None:
    master_key = b"\x01" * 32
    blob = encrypt_payload(master_key, "file-123", b"classified blueprint")
    plain = decrypt_payload(
        master_key,
        "file-123",
        blob.ciphertext,
        blob.sha256_hex,
        blob.wrapped_dek_b64,
        blob.wrap_nonce_b64,
        blob.data_nonce_b64,
    )
    assert plain == b"classified blueprint"

    tampered = bytearray(blob.ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(IntegrityError):
        decrypt_payload(
            master_key,
            "file-123",
            bytes(tampered),
            blob.sha256_hex,
            blob.wrapped_dek_b64,
            blob.wrap_nonce_b64,
            blob.data_nonce_b64,
        )


def test_vaultdrop_api_quotas_shares_and_audit_logs(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "vault",
        max_file_bytes=4096,
        default_quota_bytes=4096,
    )
    app = create_app(settings)

    with TestClient(app) as tc:
        # First user becomes admin
        r1 = tc.post("/api/auth/register", json={"username": "admin1", "password": "strongpassword1"})
        assert r1.status_code == 201
        admin_token = r1.json()["token"]
        assert r1.json()["user"]["role"] == "admin"
        admin_hdr = {"Authorization": f"Bearer {admin_token}"}

        # Upload encrypted file
        payload = b"hello encrypted world!" * 10
        up = tc.post("/api/files", headers=admin_hdr, files={"file": ("secret.txt", payload, "text/plain")})
        assert up.status_code == 201
        file_id = up.json()["id"]

        # Stored file on disk must NOT equal plaintext
        enc_blob = (settings.blob_dir / f"{file_id}.enc").read_bytes()
        assert b"hello encrypted world" not in enc_blob

        # Authenticated download decrypts and verifies SHA-256
        dl = tc.get(f"/api/files/{file_id}/download", headers=admin_hdr)
        assert dl.status_code == 200
        assert dl.content == payload

        # Quota enforcement
        too_big_for_remaining = b"x" * 4000
        q_fail = tc.post("/api/files", headers=admin_hdr, files={"file": ("big.bin", too_big_for_remaining)})
        assert q_fail.status_code == 413

        # Create share link with passcode and max_downloads=1
        share = tc.post(
            f"/api/files/{file_id}/share",
            headers=admin_hdr,
            json={"ttl_minutes": 30, "max_downloads": 1, "passcode": "vault42"},
        )
        assert share.status_code == 201
        share_token = share.json()["token"]

        # Wrong passcode fails
        bad_pass = tc.post(f"/api/share/{share_token}/download", json={"passcode": "wrong"})
        assert bad_pass.status_code == 403

        # Valid passcode succeeds once
        ok_dl = tc.post(f"/api/share/{share_token}/download", json={"passcode": "vault42"})
        assert ok_dl.status_code == 200
        assert ok_dl.content == payload

        # Second download exceeds max_downloads=1 -> 410 Gone
        exhausted = tc.post(f"/api/share/{share_token}/download", json={"passcode": "vault42"})
        assert exhausted.status_code == 410

        # Audit logs recorded both downloads
        logs = tc.get("/api/admin/logs", headers=admin_hdr).json()["logs"]
        assert len(logs) == 2

        # Delete reclaims quota
        assert tc.delete(f"/api/files/{file_id}", headers=admin_hdr).status_code == 200
        me = tc.get("/api/auth/me", headers=admin_hdr).json()
        assert me["used_bytes"] == 0

        # Expired link check
        up2 = tc.post("/api/files", headers=admin_hdr, files={"file": ("exp.txt", b"ttl", "text/plain")})
        fid2 = up2.json()["id"]
        s2 = tc.post(f"/api/files/{fid2}/share", headers=admin_hdr, json={"ttl_minutes": 10}).json()
        past = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        with sqlite3.connect(settings.db_path) as conn:
            conn.execute("UPDATE share_links SET expires_at = ? WHERE token = ?", (past, s2["token"]))
            conn.commit()
        exp_dl = tc.post(f"/api/share/{s2['token']}/download")
        assert exp_dl.status_code == 410

        # Share link revocation
        s3 = tc.post(f"/api/files/{fid2}/share", headers=admin_hdr, json={"ttl_minutes": 10}).json()
        assert tc.post(f"/api/share/{s3['token']}/revoke", headers=admin_hdr).status_code == 200
        assert tc.post(f"/api/share/{s3['token']}/download").status_code == 404

        # Admin user list & quota update
        users = tc.get("/api/admin/users", headers=admin_hdr).json()["users"]
        assert len(users) == 1
        upd = tc.patch(f"/api/admin/users/{users[0]['id']}/quota", headers=admin_hdr, json={"quota_bytes": 16384})
        assert upd.status_code == 200
        assert upd.json()["quota_bytes"] == 16384

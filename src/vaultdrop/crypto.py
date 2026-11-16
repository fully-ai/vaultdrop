"""Cryptographic primitives using the audited Python `cryptography` library."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class IntegrityError(RuntimeError):
    """Raised when ciphertext authentication or SHA-256 verification fails."""


@dataclass(slots=True)
class EncryptedBlob:
    ciphertext: bytes
    sha256_hex: str
    wrapped_dek_b64: str
    wrap_nonce_b64: str
    data_nonce_b64: str


def _derive_kek(master_key: bytes, file_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=file_id.encode("utf-8"),
        info=b"vaultdrop-kek-v1",
    )
    return hkdf.derive(master_key)


def encrypt_payload(master_key: bytes, file_id: str, plaintext: bytes) -> EncryptedBlob:
    """Encrypt plaintext with a random 256-bit DEK and wrap DEK via HKDF-derived KEK."""
    digest = hashlib.sha256(plaintext).hexdigest()
    dek = AESGCM.generate_key(bit_length=256)
    data_nonce = secrets.token_bytes(12)
    aad = file_id.encode("utf-8")
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, aad)

    kek = _derive_kek(master_key, file_id)
    wrap_nonce = secrets.token_bytes(12)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, aad)

    return EncryptedBlob(
        ciphertext=ciphertext,
        sha256_hex=digest,
        wrapped_dek_b64=base64.b64encode(wrapped_dek).decode("ascii"),
        wrap_nonce_b64=base64.b64encode(wrap_nonce).decode("ascii"),
        data_nonce_b64=base64.b64encode(data_nonce).decode("ascii"),
    )


def decrypt_payload(
    master_key: bytes,
    file_id: str,
    ciphertext: bytes,
    expected_sha256: str,
    wrapped_dek_b64: str,
    wrap_nonce_b64: str,
    data_nonce_b64: str,
) -> bytes:
    """Unwrap per-file DEK, decrypt ciphertext, and verify SHA-256 digest."""
    aad = file_id.encode("utf-8")
    kek = _derive_kek(master_key, file_id)
    try:
        dek = AESGCM(kek).decrypt(
            base64.b64decode(wrap_nonce_b64),
            base64.b64decode(wrapped_dek_b64),
            aad,
        )
        plaintext = AESGCM(dek).decrypt(
            base64.b64decode(data_nonce_b64),
            ciphertext,
            aad,
        )
    except InvalidTag as exc:
        raise IntegrityError("Ciphertext authentication tag verification failed") from exc

    actual_sha256 = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise IntegrityError("Decrypted payload SHA-256 mismatch")
    return plaintext


def hash_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"{salt.hex()}:{derived.hex()}"


def verify_secret(secret: str, stored_hash: str) -> bool:
    try:
        salt_hex, key_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(key_hex)
    except ValueError:
        return False
    actual = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return hmac.compare_digest(actual, expected)

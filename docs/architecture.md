# Architecture — VaultDrop

## Security & Encryption Flow

- **Key Hierarchy (`src/vaultdrop/crypto.py`)**:
  - Server master key (`VAULTDROP_MASTER_KEY_HEX` or `master.key` written with `0600` permissions) derives per-file Key Encryption Keys (KEKs) via HKDF-SHA256 using `file_id` as salt.
  - Each uploaded file receives a freshly generated 256-bit Data Encryption Key (DEK) for AES-256-GCM encryption, and the DEK itself is wrapped with the derived KEK.
  - Both AES-GCM authentication tags and plaintext SHA-256 digests are verified on every download.
- **Access & Quotas (`src/vaultdrop/db.py`, `src/vaultdrop/app.py`)**:
  - Enforces per-user byte quotas, expiring share tokens, maximum download counts, optional scrypt-hashed passcodes, and download audit logs.

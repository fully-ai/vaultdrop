# Security Policy

Report security vulnerabilities privately via GitHub Security Advisories.

## Cryptographic Design

- All cryptographic operations rely on Python's `cryptography` package (`AESGCM`, `HKDF`) and `hashlib.scrypt` / `hashlib.sha256`.
- Each file receives a unique 256-bit Data Encryption Key (DEK) wrapped by a per-file Key Encryption Key (KEK) derived from the master key via HKDF-SHA256.
- File integrity is verified by both AES-GCM authentication tags and stored SHA-256 digests on every download.

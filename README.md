# VaultDrop

Encrypted self-hosted file sharing and transfer platform built with FastAPI, SQLite, and Python's `cryptography` library.

## Features

- **Envelope AES-256-GCM Encryption**: Every uploaded file is encrypted at rest with a unique random 256-bit DEK wrapped by an HKDF-SHA256 key derived from the server master key.
- **Integrity Verification**: Validates AES-GCM authentication tags and SHA-256 plaintext digests on every download.
- **Expiring Share Links**: Generate time-limited share tokens with optional download limits, passcode protection, and instant revocation.
- **Quotas & Access Control**: Per-user storage quotas, file size limits, scrypt password hashing, JWT authentication, and admin quota/audit endpoints.
- **Audit Trail**: Records authenticated and shared downloads with timestamp, file ID, token, and client IP.

## Installation & Running

```bash
git clone https://github.com/fully-ai/vaultdrop.git
cd vaultdrop
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
vaultdrop
```

## Testing

```bash
ruff check src tests
mypy src
pytest -v
```

## Docker Deployment

```bash
docker compose up -d --build
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

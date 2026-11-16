# Changelog

## [0.2.0] - 2026-11-16

### Added
- Admin Panel (user quota management and download audit logs) and file delete controls in the web UI.
- Integration tests for share-link revocation and admin quota updates.
- Complete maintainer README with Mermaid diagram, API documentation, and security/limitation notes.

## [0.1.0] - 2026-11-16

### Added
- Envelope AES-256-GCM encryption at rest with HKDF-SHA256 per-file key derivation.
- Expiring share links with max-download limits, revocation, and optional passcode protection.
- User authentication, per-user storage quotas, SHA-256 integrity checks, and admin audit logs.
- Web UI, Docker Compose setup, and automated tests.

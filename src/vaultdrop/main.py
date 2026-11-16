"""CLI entrypoint for VaultDrop."""

from __future__ import annotations

import uvicorn

from vaultdrop.app import create_app
from vaultdrop.config import Settings


def cli() -> None:
    cfg = Settings()
    uvicorn.run(create_app(cfg), host=cfg.host, port=cfg.port)


if __name__ == "__main__":
    cli()

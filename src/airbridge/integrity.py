"""Streaming SHA-256 helpers. Files are read in bounded blocks, never fully loaded."""
from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path | str, block_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()

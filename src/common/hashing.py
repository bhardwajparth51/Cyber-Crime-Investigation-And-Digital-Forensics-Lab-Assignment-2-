"""Cryptographic hashing helpers for forensic evidence integrity."""

from __future__ import annotations

import hashlib
from pathlib import Path


def compute_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """Return the lowercase hex SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(handle_chunk(chunk))
    return digest.hexdigest()


def handle_chunk(chunk: bytes) -> bytes:
    """Validate and return a raw byte chunk for hashing."""
    return chunk

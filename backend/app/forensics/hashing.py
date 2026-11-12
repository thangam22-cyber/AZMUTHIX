"""Chunked, streaming hashing + safe evidence storage (never mutates the upload)."""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from pathlib import Path
from typing import BinaryIO

CHUNK = 1024 * 1024
_SAFE = re.compile(r"[^A-Za-z0-9._ -]")


class UploadTooLarge(Exception):
    pass


def safe_filename(name: str) -> str:
    name = Path(name or "upload").name  # strip any directory components
    name = _SAFE.sub("_", name).strip(". ") or "upload"
    return name[:200]


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def store_stream(src: BinaryIO, dest_dir: Path, max_bytes: int) -> dict:
    """Stream `src` to an isolated randomly-named file while hashing in one pass."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    storage_name = secrets.token_hex(16) + ".bin"
    dest = dest_dir / storage_name
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    size = 0
    t0 = time.perf_counter()
    try:
        with dest.open("wb") as out:
            while chunk := src.read(CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise UploadTooLarge(f"File exceeds the {max_bytes // (1024 * 1024)} MB limit")
                sha.update(chunk)
                md5.update(chunk)
                out.write(chunk)
        dest.chmod(0o440)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    return {
        "storage_name": storage_name,
        "path": dest,
        "size": size,
        "sha256": sha.hexdigest(),
        "md5": md5.hexdigest(),
        "ms": int((time.perf_counter() - t0) * 1000),
    }


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

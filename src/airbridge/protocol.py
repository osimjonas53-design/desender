"""Shared protocol constants and filename / destination safety rules.

Everything that touches a file name supplied by a remote peer goes through
``sanitize_filename`` and ``resolve_destination``. The receiver never uses a
path supplied by the sender.
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

PROTOCOL_VERSION = 1
DEFAULT_CHUNK_SIZE = 1024 * 1024          # 1 MiB upload unit
MAX_CHUNK_SIZE = 4 * 1024 * 1024          # receiver refuses larger single PUTs
MAX_JSON_BODY = 64 * 1024                 # control messages are tiny
MAX_FILE_SIZE = 1 << 40                   # 1 TiB sanity cap
MAX_NAME_LEN = 200
PARTIAL_DIR_NAME = ".airbridge-partial"
SHA256_RE = re.compile(r"[0-9a-f]{64}")

_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_FORBIDDEN_CHARS = set('<>:"|?*')


def sanitize_filename(raw: object) -> str:
    """Reduce an untrusted name to a safe, single path component.

    Strips directory components (both separators), control characters and
    characters invalid on Windows, avoids reserved device names, and caps
    the length while keeping the extension.
    """
    if not isinstance(raw, str):
        raise ValueError("file name must be a string")
    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
    name = unicodedata.normalize("NFC", name)
    name = "".join(ch for ch in name if ch.isprintable() and ch not in _FORBIDDEN_CHARS)
    name = name.strip(" .")
    if not name:
        raise ValueError("invalid file name")

    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    if stem.upper() in _WINDOWS_RESERVED:
        stem = "_" + stem
    if len(name) > MAX_NAME_LEN:
        ext = ext[:64]
        room = MAX_NAME_LEN - (len(ext) + 1 if ext else 0)
        stem = stem[:room]
    return f"{stem}.{ext}" if ext else stem


def resolve_destination(save_dir: Path, raw_name: str) -> Path:
    """Return the absolute target path, guaranteed to sit directly in save_dir."""
    base = Path(save_dir).resolve()
    target = (base / sanitize_filename(raw_name)).resolve()
    if target.parent != base:
        raise ValueError("destination escapes the save directory")
    return target


def unique_path(target: Path) -> Path:
    """Apply the 'rename' collision policy: name.txt -> name (1).txt, ..."""
    if not target.exists():
        return target
    for i in range(1, 10_000):
        candidate = target.with_name(f"{target.stem} ({i}){target.suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"no free name available for {target.name}")

"""Pairing codes and persistent, revocable device sessions.

* A pairing code is 6 random digits, single use, expires after ``code_ttl``
  seconds, and is locked out after ``max_attempts`` wrong guesses.
* A successful redemption issues a random 256-bit bearer token for the
  device. The token expires after ``session_ttl`` seconds.
* Only a SHA-256 hash of each token is stored, so the trusted-device file
  cannot be used to impersonate a device.
* Each session has a public id, which the dashboard uses to revoke it.
* Sessions persist across restarts when a ``store_path`` is given.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


class PairingError(Exception):
    pass


@dataclass
class Session:
    session_id: str
    token_hash: str
    device: str
    created: float
    expires: float
    last_seen: float


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class PlainFileStore:
    """Session records as a plain file. Used by tests; the receiver uses VaultStore."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def load(self) -> bytes | None:
        return self.path.read_bytes() if self.path.exists() else None

    def save(self, data: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, self.path)


class VaultStore:
    """Session records sealed in the vault, so token hashes are never plain on disk."""

    ITEM = "trusted-devices"

    def __init__(self, vault) -> None:
        self.vault = vault

    def load(self) -> bytes | None:
        return self.vault.unseal(self.ITEM)

    def save(self, data: bytes) -> None:
        self.vault.seal(self.ITEM, data)


class PairingManager:
    def __init__(
        self,
        code_ttl: float = 300.0,
        max_attempts: int = 5,
        session_ttl: float = 8 * 3600.0,
        clock: Callable[[], float] = time.time,
        store_path: Path | str | None = None,
        store=None,
    ) -> None:
        self._code_ttl = code_ttl
        self._max_attempts = max_attempts
        self._session_ttl = session_ttl
        self._clock = clock
        if store is None and store_path is not None:
            store = PlainFileStore(store_path)
        self._store = store
        self._lock = threading.Lock()
        self._code: str | None = None
        self._code_expires = 0.0
        self._failures = 0
        self._sessions: dict[str, Session] = {}   # token_hash -> Session
        self._load()

    # ----- pairing codes ---------------------------------------------------
    def new_code(self) -> str:
        with self._lock:
            self._code = f"{secrets.randbelow(10**6):06d}"
            self._code_expires = self._clock() + self._code_ttl
            self._failures = 0
            return self._code

    def current_code(self) -> str | None:
        """The live code, or None if none is active. For the local dashboard only."""
        with self._lock:
            if self._code is None or self._clock() >= self._code_expires:
                return None
            if self._failures >= self._max_attempts:
                return None
            return self._code

    def code_seconds_left(self) -> int:
        with self._lock:
            if self._code is None:
                return 0
            return max(0, int(self._code_expires - self._clock()))

    def redeem(self, code: str, device: str = "Unnamed device") -> str:
        with self._lock:
            now = self._clock()
            if self._code is None or now >= self._code_expires:
                raise PairingError("pairing code expired; generate a new one on the receiver")
            if self._failures >= self._max_attempts:
                self._code = None
                raise PairingError("too many wrong attempts; generate a new pairing code")
            if not hmac.compare_digest(str(code).strip().encode(), self._code.encode()):
                self._failures += 1
                raise PairingError("incorrect pairing code")
            self._code = None  # single use
            self._prune(now)
            token = secrets.token_urlsafe(32)
            digest = _hash_token(token)
            self._sessions[digest] = Session(
                session_id=secrets.token_urlsafe(8),
                token_hash=digest,
                device=device,
                created=now,
                expires=now + self._session_ttl,
                last_seen=now,
            )
            self._save()
            return token

    # ----- sessions --------------------------------------------------------
    def is_valid(self, token: str) -> bool:
        if not isinstance(token, str) or not token:
            return False
        digest = _hash_token(token)
        with self._lock:
            session = self._sessions.get(digest)
            if session is None:
                return False
            now = self._clock()
            if now >= session.expires:
                del self._sessions[digest]
                self._save()
                return False
            session.last_seen = now
            return True

    def list_sessions(self) -> list[dict]:
        with self._lock:
            self._prune(self._clock())
            return [
                {"id": s.session_id, "device": s.device, "created": s.created,
                 "expires": s.expires, "last_seen": s.last_seen}
                for s in sorted(self._sessions.values(), key=lambda s: s.created)
            ]

    def revoke(self, session_id: str) -> bool:
        with self._lock:
            for digest, session in list(self._sessions.items()):
                if session.session_id == session_id:
                    del self._sessions[digest]
                    self._save()
                    return True
            return False

    def revoke_all(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._save()

    # ----- internals -------------------------------------------------------
    def _prune(self, now: float) -> None:
        expired = [d for d, s in self._sessions.items() if now >= s.expires]
        for digest in expired:
            del self._sessions[digest]
        if expired:
            self._save()

    def _save(self) -> None:
        if self._store is None:
            return
        data = json.dumps([asdict(s) for s in self._sessions.values()], indent=2).encode("utf-8")
        self._store.save(data)

    def _load(self) -> None:
        if self._store is None:
            return
        try:
            raw = self._store.load()
        except Exception:
            return  # unreadable store: no trusted devices; devices must pair again
        if raw is None:
            return
        try:
            records = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return  # a corrupt store means no trusted devices; devices must pair again
        now = self._clock()
        for rec in records:
            try:
                session = Session(**rec)
            except TypeError:
                continue
            if now < session.expires:
                self._sessions[session.token_hash] = session

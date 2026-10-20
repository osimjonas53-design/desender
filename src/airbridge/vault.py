"""Encrypted storage for receiver secrets.

What is protected: the receiver's TLS private key and the trusted-device store
(which holds token hashes). Both are sealed with AES-256-GCM under a random
32-byte data key. The data key is wrapped by a backend and never stored in
plain form.

Backends
--------
passphrase  scrypt(passphrase) -> key-encryption key -> AES-GCM wrap. Works on
            every platform. Tested.
dpapi       Windows Data Protection API (CryptProtectData), bound to the user
            account. Written but NOT run in this build environment.
keychain    macOS Keychain generic password holding the data key. Written but
            NOT run in this build environment. The security CLI receives the
            value as an argument, so it is briefly visible to other processes
            of the same user.

Sealed file format: magic "ABV1" | 12-byte nonce | AES-GCM ciphertext+tag.
The file name is bound as associated data, so a sealed file cannot be
renamed to stand in for another.

Vault metadata (vault.json) holds only public parameters: the backend name,
KDF settings and salt, and the wrapped data key. It contains no secrets.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ABV1"
VAULT_META = "vault.json"
VERSION = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024


class VaultError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, AttributeError) as exc:
        raise VaultError("vault metadata is damaged") from exc


# ----- backends -----------------------------------------------------------------
class Backend(ABC):
    name: str

    @abstractmethod
    def wrap(self, data_key: bytes) -> dict:
        """Return public metadata that lets this backend recover ``data_key``."""

    @abstractmethod
    def unwrap(self, meta: dict) -> bytes:
        """Recover the data key from the metadata produced by ``wrap``."""


class PassphraseBackend(Backend):
    name = "passphrase"

    def __init__(self, passphrase: str, n: int = 2 ** 15, r: int = 8, p: int = 1) -> None:
        if not passphrase:
            raise VaultError("a passphrase is required for this key store")
        self._passphrase = passphrase.encode("utf-8")
        self._n, self._r, self._p = n, r, p

    def _kek(self, salt: bytes, n: int, r: int, p: int) -> bytes:
        import hashlib
        return hashlib.scrypt(self._passphrase, salt=salt, n=n, r=r, p=p,
                              dklen=32, maxmem=_SCRYPT_MAXMEM)

    def wrap(self, data_key: bytes) -> dict:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        kek = self._kek(salt, self._n, self._r, self._p)
        wrapped = AESGCM(kek).encrypt(nonce, data_key, b"airbridge-dek-v1")
        return {"kdf": {"name": "scrypt", "n": self._n, "r": self._r, "p": self._p,
                        "salt": _b64(salt)},
                "nonce": _b64(nonce), "wrapped": _b64(wrapped)}

    def unwrap(self, meta: dict) -> bytes:
        kdf = meta.get("kdf", {})
        if kdf.get("name") != "scrypt":
            raise VaultError("unsupported key-derivation function")
        kek = self._kek(_unb64(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
        try:
            return AESGCM(kek).decrypt(_unb64(meta["nonce"]), _unb64(meta["wrapped"]),
                                       b"airbridge-dek-v1")
        except InvalidTag as exc:
            raise VaultError("wrong passphrase, or the vault has been modified") from exc


class DpapiBackend(Backend):
    """Windows DPAPI. Not executed in the build environment; see module docstring."""
    name = "dpapi"

    def wrap(self, data_key: bytes) -> dict:
        return {"wrapped": _b64(_dpapi(data_key, protect=True))}

    def unwrap(self, meta: dict) -> bytes:
        try:
            return _dpapi(_unb64(meta["wrapped"]), protect=False)
        except OSError as exc:
            raise VaultError("Windows could not unlock the vault for this user account") from exc


def _dpapi(data: bytes, protect: bool) -> bytes:  # pragma: no cover - Windows only
    if sys.platform != "win32":
        raise VaultError("DPAPI is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


class KeychainBackend(Backend):
    """macOS Keychain. Not executed in the build environment; see module docstring."""
    name = "keychain"
    SERVICE = "AirBridge"

    def wrap(self, data_key: bytes) -> dict:
        account = secrets.token_hex(8)
        self._run(["add-generic-password", "-a", account, "-s", self.SERVICE,
                   "-w", data_key.hex(), "-U"])
        return {"account": account}

    def unwrap(self, meta: dict) -> bytes:
        out = self._run(["find-generic-password", "-a", meta["account"], "-s", self.SERVICE, "-w"])
        try:
            return bytes.fromhex(out.strip())
        except ValueError as exc:
            raise VaultError("keychain entry is damaged") from exc

    @staticmethod
    def _run(args: list[str]) -> str:  # pragma: no cover - macOS only
        import subprocess
        if sys.platform != "darwin":
            raise VaultError("the Keychain backend is only available on macOS")
        proc = subprocess.run(["security", *args], capture_output=True, text=True)
        if proc.returncode != 0:
            raise VaultError("the macOS Keychain refused the request")
        return proc.stdout


def default_backend_name() -> str:
    if sys.platform == "win32":
        return "dpapi"
    if sys.platform == "darwin":
        return "keychain"
    return "passphrase"


def backend_for(name: str, passphrase: str | None = None) -> Backend:
    if name == "passphrase":
        if passphrase is None:
            raise VaultError("this key store needs a passphrase")
        return PassphraseBackend(passphrase)
    if name == "dpapi":
        return DpapiBackend()
    if name == "keychain":
        return KeychainBackend()
    raise VaultError(f"unknown key store backend {name!r}")


# ----- vault ----------------------------------------------------------------------
def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def shred(path: Path) -> None:
    """Overwrite a file with random bytes, then delete it. Best effort on journaled file systems."""
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except FileNotFoundError:
        pass


class Vault:
    def __init__(self, directory: Path | str) -> None:
        self.dir = Path(directory).expanduser()
        self._dek: bytes | None = None
        self.backend_name: str | None = None

    @property
    def meta_path(self) -> Path:
        return self.dir / VAULT_META

    def exists(self) -> bool:
        return self.meta_path.exists()

    def create(self, backend: Backend) -> None:
        if self.exists():
            raise VaultError("a vault already exists here")
        self.dir.mkdir(parents=True, exist_ok=True)
        data_key = secrets.token_bytes(32)
        meta = {"version": VERSION, "backend": backend.name, "meta": backend.wrap(data_key)}
        _write_private(self.meta_path, json.dumps(meta, indent=2).encode("utf-8"))
        self._dek = data_key
        self.backend_name = backend.name

    def open(self, backend: Backend) -> None:
        try:
            meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VaultError("vault metadata is missing or damaged") from exc
        if meta.get("version") != VERSION:
            raise VaultError("unsupported vault version")
        if meta.get("backend") != backend.name:
            raise VaultError(f"this vault uses the '{meta.get('backend')}' key store, "
                             f"not '{backend.name}'")
        self._dek = backend.unwrap(meta["meta"])
        self.backend_name = backend.name

    @property
    def is_open(self) -> bool:
        return self._dek is not None

    def _require_open(self) -> bytes:
        if self._dek is None:
            raise VaultError("the vault is locked")
        return self._dek

    def _path(self, name: str) -> Path:
        if not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid vault item name")
        return self.dir / f"{name}.enc"

    def seal(self, name: str, plaintext: bytes) -> None:
        dek = self._require_open()
        nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, self._aad(name))
        _write_private(self._path(name), MAGIC + nonce + ciphertext)

    def unseal(self, name: str) -> bytes | None:
        dek = self._require_open()
        path = self._path(name)
        if not path.exists():
            return None
        blob = path.read_bytes()
        if len(blob) < 4 + 12 + 16 or blob[:4] != MAGIC:
            raise VaultError(f"{name} is damaged")
        try:
            return AESGCM(dek).decrypt(blob[4:16], blob[16:], self._aad(name))
        except InvalidTag as exc:
            raise VaultError(f"{name} has been modified or is not from this vault") from exc

    def has(self, name: str) -> bool:
        return self._path(name).exists()

    def lock(self) -> None:
        self._dek = None

    @staticmethod
    def _aad(name: str) -> bytes:
        return f"airbridge-vault-v{VERSION}|{name}".encode("utf-8")

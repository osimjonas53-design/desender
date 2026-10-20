"""Device identity and TLS configuration.

Each device has a long-lived self-signed certificate. Peers do not trust it
through a certificate authority. Instead the sender pins the certificate by
its fingerprint, which the receiver displays next to the pairing code. A
network attacker cannot present a certificate with that fingerprint without
a preimage attack on SHA-256, so a man-in-the-middle fails the handshake.

The certificate is public and stored as PEM. The private key is never stored
in plain form: it is sealed in the vault (see vault.py). When TLS needs the
key, it is decrypted into a private temporary directory, loaded into the SSL
context, and shredded again straight away.

The fingerprint shown to people is the first 64 bits of SHA-256 over the
DER-encoded certificate, written as 16 hex characters in groups of four.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import ssl
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .vault import Vault, VaultError, shred

FINGERPRINT_HEX_LEN = 16  # 64 bits
KEY_ITEM = "device-key"
CERT_FILE = "device-cert.pem"
LEGACY_KEY_FILE = "device-key.pem"   # plaintext key written by earlier versions


class PinMismatch(Exception):
    """The peer's certificate does not match the fingerprint the user entered."""


@dataclass(frozen=True)
class Identity:
    cert_path: Path
    vault: Vault

    @property
    def fingerprint(self) -> str:
        return fingerprint_of_der(self.cert_der())

    def cert_der(self) -> bytes:
        pem = self.cert_path.read_bytes()
        return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


def fingerprint_of_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()[:FINGERPRINT_HEX_LEN]


def format_fingerprint(fp: str) -> str:
    """Human form: 'ab12 cd34 ef56 7890'."""
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))


def normalise_fingerprint(text: str) -> str:
    """Accept spaces, dashes or colons from the user; return lowercase hex."""
    cleaned = "".join(ch for ch in text.lower() if ch in "0123456789abcdef")
    if len(cleaned) != FINGERPRINT_HEX_LEN:
        raise ValueError(f"fingerprint must be {FINGERPRINT_HEX_LEN} hex characters")
    return cleaned


def _new_identity(directory: Path, vault: Vault) -> Identity:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AirBridge device")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    # Seal the key before writing the certificate. A crash in between leaves
    # no certificate, so the next start creates a fresh identity cleanly.
    vault.seal(KEY_ITEM, key_pem)
    cert_path = directory / CERT_FILE
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return Identity(cert_path, vault)


def _migrate_plaintext_key(directory: Path, vault: Vault) -> bool:
    """Seal a key left in plaintext by an earlier version, then destroy the plaintext."""
    legacy = directory / LEGACY_KEY_FILE
    if not legacy.exists():
        return False
    key_pem = legacy.read_bytes()
    vault.seal(KEY_ITEM, key_pem)
    shred(legacy)
    return True


def load_or_create_identity(directory: Path | str, vault: Vault) -> Identity:
    """Return this device's identity, creating it on first use. The vault must be open."""
    if not vault.is_open:
        raise VaultError("open the vault before loading the device identity")
    directory = Path(directory).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / CERT_FILE

    if cert_path.exists() and vault.has(KEY_ITEM):
        return Identity(cert_path, vault)
    if cert_path.exists() and (directory / LEGACY_KEY_FILE).exists():
        _migrate_plaintext_key(directory, vault)
        return Identity(cert_path, vault)
    return _new_identity(directory, vault)


@contextmanager
def _temporary_pem_pair(cert_pem: bytes, key_pem: bytes) -> Iterator[tuple[str, str]]:
    """Write the PEM pair to a private temp directory, yield the paths, then destroy them."""
    tmpdir = Path(tempfile.mkdtemp(prefix="airbridge-"))
    cert_file = tmpdir / "cert.pem"
    key_file = tmpdir / "key.pem"
    try:
        os.chmod(tmpdir, 0o700)
        cert_file.write_bytes(cert_pem)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key_pem)
        yield str(cert_file), str(key_file)
    finally:
        shred(key_file)
        for leftover in tmpdir.glob("*"):
            shred(leftover)
        try:
            tmpdir.rmdir()
        except OSError:
            pass


def server_context(identity: Identity) -> ssl.SSLContext:
    key_pem = identity.vault.unseal(KEY_ITEM)
    if key_pem is None:
        raise VaultError("the device key is missing from the vault")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with _temporary_pem_pair(identity.cert_path.read_bytes(), key_pem) as (cert_file, key_file):
        ctx.load_cert_chain(cert_file, key_file)
    return ctx


def pinned_client_context() -> ssl.SSLContext:
    """Client context for pinned connections.

    Chain and hostname checks are off on purpose: the device certificate is
    self-signed and the peer is reached by IP address. Identity is instead
    established by ``check_pin``, which runs before any request is sent.
    Ordinary CA verification must not be used for these connections.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def check_pin(der: bytes | None, expected_fp: str) -> None:
    if not der:
        raise PinMismatch("the receiver presented no certificate")
    actual = fingerprint_of_der(der)
    if not hmac.compare_digest(actual.encode(), expected_fp.encode()):
        raise PinMismatch("the receiver's certificate does not match the fingerprint you entered; "
                          "check the fingerprint on the receiving screen")

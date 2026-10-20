import http.client
import os
import tempfile
import unittest
from pathlib import Path

from airbridge.client import PinRejected, Sender, TransferError
from airbridge.server import ReceiverServer
from airbridge.tls import (
    check_pin,
    fingerprint_of_der,
    format_fingerprint,
    load_or_create_identity,
    normalise_fingerprint,
    PinMismatch,
)


TEST_PASSPHRASE = "test-passphrase-123"

class IdentityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name) / "identity"

    def tearDown(self):
        self._tmp.cleanup()

    def open_vault(self, directory=None, passphrase=TEST_PASSPHRASE):
        from airbridge.vault import PassphraseBackend, Vault
        vault = Vault(directory or self.dir)
        if vault.exists():
            vault.open(PassphraseBackend(passphrase))
        else:
            vault.create(PassphraseBackend(passphrase, n=2 ** 10))
        return vault

    def identity(self, directory=None):
        d = directory or self.dir
        return load_or_create_identity(d, self.open_vault(d))

    def test_identity_is_created_once_and_then_reused(self):
        first = self.identity()
        second = self.identity()
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(len(first.fingerprint), 16)

    def test_private_key_is_never_stored_in_plain_form(self):
        self.identity()
        for path in self.dir.iterdir():
            self.assertNotIn(b"PRIVATE KEY", path.read_bytes(), path.name)
        self.assertTrue((self.dir / "device-key.enc").exists())

    def test_sealed_key_is_owner_readable_only_on_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits only")
        self.identity()
        self.assertEqual((self.dir / "device-key.enc").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.dir / "vault.json").stat().st_mode & 0o777, 0o600)

    def test_distinct_devices_have_distinct_fingerprints(self):
        a = self.identity(Path(self._tmp.name) / "a")
        b = self.identity(Path(self._tmp.name) / "b")
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_fingerprint_input_is_forgiving_but_strict_about_length(self):
        self.assertEqual(normalise_fingerprint("AB12-CD34 ef56:7890"), "ab12cd34ef567890")
        self.assertEqual(format_fingerprint("ab12cd34ef567890"), "ab12 cd34 ef56 7890")
        with self.assertRaises(ValueError):
            normalise_fingerprint("ab12cd34")
        with self.assertRaises(ValueError):
            normalise_fingerprint("zz" * 8)

    def test_pin_check_accepts_matching_and_rejects_others(self):
        ident = self.identity()
        der = ident.cert_der()
        check_pin(der, fingerprint_of_der(der))  # no exception
        with self.assertRaises(PinMismatch):
            check_pin(der, "0" * 16)
        with self.assertRaises(PinMismatch):
            check_pin(None, "0" * 16)

    def test_identity_needs_an_open_vault(self):
        from airbridge.vault import Vault, VaultError
        with self.assertRaises(VaultError):
            load_or_create_identity(self.dir, Vault(self.dir))

    def test_plaintext_key_from_an_earlier_version_is_migrated_and_destroyed(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography import x509
        import datetime as dt
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID

        # Build what version 0.3 would have written: a plaintext key and certificate.
        self.dir.mkdir(parents=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AirBridge device")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        (self.dir / "device-cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (self.dir / "device-key.pem").write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))
        old_fp = fingerprint_of_der(cert.public_bytes(serialization.Encoding.DER))

        ident = self.identity()
        self.assertEqual(ident.fingerprint, old_fp)
        self.assertFalse((self.dir / "device-key.pem").exists())
        self.assertTrue((self.dir / "device-key.enc").exists())
        for path in self.dir.iterdir():
            self.assertNotIn(b"PRIVATE KEY", path.read_bytes(), path.name)

    def test_wrong_passphrase_cannot_open_the_vault(self):
        from airbridge.vault import VaultError
        self.identity()
        with self.assertRaises(VaultError):
            self.open_vault(passphrase="not-the-passphrase")


class PinnedConnectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.receiver = ReceiverServer(root / "rx", identity_dir=root / "rx-id", passphrase=TEST_PASSPHRASE,
                                       host="127.0.0.1", port=0)
        self.code = self.receiver.start()
        self.url = f"https://127.0.0.1:{self.receiver.port}"
        self.real_fp = self.receiver.fingerprint

    def tearDown(self):
        self.receiver.stop()
        self._tmp.cleanup()

    def test_wrong_fingerprint_refuses_and_does_not_use_the_pairing_code(self):
        wrong = "0" * 16 if self.real_fp != "0" * 16 else "f" * 16
        attacker_view = Sender(self.url, fingerprint=wrong)
        with self.assertRaises(PinRejected):
            attacker_view.pair(self.code)
        # The code was never presented, so the legitimate sender can still pair.
        legit = Sender(self.url, fingerprint=self.real_fp)
        legit.pair(self.code)
        self.assertIsNotNone(legit.token)

    def test_impersonating_receiver_is_rejected(self):
        # A second device on the network answers on another port with its own
        # certificate. The sender pinned the real device's fingerprint.
        root = Path(self._tmp.name)
        impostor = ReceiverServer(root / "fake", identity_dir=root / "fake-id", passphrase=TEST_PASSPHRASE,
                                  host="127.0.0.1", port=0)
        fake_code = impostor.start()
        try:
            sender = Sender(f"https://127.0.0.1:{impostor.port}", fingerprint=self.real_fp)
            with self.assertRaises(PinRejected):
                sender.pair(fake_code)
            self.assertIsNone(sender.token)
        finally:
            impostor.stop()

    def test_plain_http_addresses_are_refused_outright(self):
        with self.assertRaises(ValueError):
            Sender(f"http://127.0.0.1:{self.receiver.port}", fingerprint=self.real_fp)

    def test_plaintext_client_cannot_talk_to_the_peer_port(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.receiver.port, timeout=5)
        with self.assertRaises((OSError, http.client.HTTPException)):
            conn.request("GET", "/v1/info")
            conn.getresponse().read()
        conn.close()

    def test_peer_port_does_not_serve_dashboard(self):
        sender = Sender(self.url, fingerprint=self.real_fp)
        status, _ = sender._request("GET", "/admin/state")
        self.assertEqual(status, 404)
        status, _ = sender._request("GET", "/")
        self.assertEqual(status, 404)

    def test_dashboard_port_does_not_serve_transfer_protocol(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.receiver.dashboard_port, timeout=5)
        conn.request("GET", "/v1/info", headers={"Host": f"127.0.0.1:{self.receiver.dashboard_port}"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 404)

    def test_dashboard_listens_on_loopback_only(self):
        self.assertEqual(self.receiver._dash.server_address[0], "127.0.0.1")

    def test_pairing_works_end_to_end_over_tls(self):
        sender = Sender(self.url, fingerprint=self.real_fp)
        sender.pair(self.code)
        self.assertTrue(self.receiver.pairing.is_valid(sender.token))

    def test_pairing_code_is_still_single_use_over_tls(self):
        Sender(self.url, fingerprint=self.real_fp).pair(self.code)
        with self.assertRaises(TransferError):
            Sender(self.url, fingerprint=self.real_fp).pair(self.code)


if __name__ == "__main__":
    unittest.main()

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from airbridge.server import ReceiverServer
from airbridge.tls import load_or_create_identity, server_context
from airbridge.vault import (
    DpapiBackend,
    KeychainBackend,
    PassphraseBackend,
    Vault,
    VaultError,
    shred,
)

PASS = "correct horse battery staple"


def fast(passphrase=PASS):
    return PassphraseBackend(passphrase, n=2 ** 10)  # small scrypt cost keeps tests quick


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name) / "vault"

    def tearDown(self):
        self._tmp.cleanup()

    def new_vault(self, passphrase=PASS):
        v = Vault(self.dir)
        v.create(fast(passphrase))
        return v


class SealingTests(VaultTestCase):
    def test_seal_and_unseal_round_trip(self):
        v = self.new_vault()
        v.seal("item", b"secret bytes")
        self.assertEqual(v.unseal("item"), b"secret bytes")

    def test_empty_secret_round_trips(self):
        v = self.new_vault()
        v.seal("empty", b"")
        self.assertEqual(v.unseal("empty"), b"")

    def test_missing_item_is_none_not_an_error(self):
        v = self.new_vault()
        self.assertIsNone(v.unseal("never-written"))

    def test_sealed_file_is_not_plaintext(self):
        v = self.new_vault()
        v.seal("item", b"PRIVATE KEY MATERIAL" * 4)
        self.assertNotIn(b"PRIVATE KEY", (self.dir / "item.enc").read_bytes())

    def test_each_seal_uses_a_fresh_nonce(self):
        v = self.new_vault()
        v.seal("item", b"same")
        first = (self.dir / "item.enc").read_bytes()
        v.seal("item", b"same")
        self.assertNotEqual(first, (self.dir / "item.enc").read_bytes())

    def test_tampered_ciphertext_is_detected(self):
        v = self.new_vault()
        v.seal("item", b"important")
        path = self.dir / "item.enc"
        blob = bytearray(path.read_bytes())
        blob[-1] ^= 0x01
        path.write_bytes(bytes(blob))
        with self.assertRaises(VaultError):
            v.unseal("item")

    def test_sealed_file_cannot_be_renamed_to_stand_in_for_another(self):
        v = self.new_vault()
        v.seal("device-key", b"the real key")
        shutil.copy(self.dir / "device-key.enc", self.dir / "trusted-devices.enc")
        with self.assertRaises(VaultError):
            v.unseal("trusted-devices")

    def test_truncated_or_foreign_files_are_damaged_not_crashes(self):
        v = self.new_vault()
        v.seal("item", b"x" * 40)
        (self.dir / "item.enc").write_bytes(b"ABV1short")
        with self.assertRaises(VaultError):
            v.unseal("item")
        (self.dir / "item.enc").write_bytes(b"not a vault file at all")
        with self.assertRaises(VaultError):
            v.unseal("item")

    def test_item_names_cannot_escape_the_vault_directory(self):
        v = self.new_vault()
        for bad in ("../escape", "a/b", "", "name with spaces", "x\x00y"):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    v.seal(bad, b"x")
        self.assertFalse((Path(self._tmp.name) / "escape.enc").exists())


class PassphraseTests(VaultTestCase):
    def test_reopening_with_the_right_passphrase_works(self):
        self.new_vault().seal("item", b"kept")
        reopened = Vault(self.dir)
        reopened.open(fast())
        self.assertEqual(reopened.unseal("item"), b"kept")

    def test_wrong_passphrase_is_refused(self):
        self.new_vault().seal("item", b"kept")
        with self.assertRaises(VaultError):
            Vault(self.dir).open(fast("wrong passphrase"))

    def test_empty_passphrase_is_refused(self):
        with self.assertRaises(VaultError):
            PassphraseBackend("")

    def test_metadata_holds_no_plaintext_key_material(self):
        v = self.new_vault()
        v.seal("item", b"hello")
        meta = json.loads((self.dir / "vault.json").read_text())
        self.assertNotIn(PASS, json.dumps(meta))
        self.assertEqual(meta["backend"], "passphrase")

    def test_damaged_vault_metadata_is_refused(self):
        self.new_vault()
        (self.dir / "vault.json").write_text("{not json")
        with self.assertRaises(VaultError):
            Vault(self.dir).open(fast())

    def test_vault_cannot_be_created_twice(self):
        self.new_vault()
        with self.assertRaises(VaultError):
            Vault(self.dir).create(fast())

    def test_backend_mismatch_is_reported_before_any_unwrap(self):
        self.new_vault()

        class Other:
            name = "dpapi"

            def unwrap(self, meta):
                raise AssertionError("must not be called on a backend mismatch")

        with self.assertRaises(VaultError) as ctx:
            Vault(self.dir).open(Other())
        self.assertIn("passphrase", str(ctx.exception))


class LockTests(VaultTestCase):
    def test_locked_vault_refuses_seal_and_unseal(self):
        v = self.new_vault()
        v.seal("item", b"x")
        v.lock()
        self.assertFalse(v.is_open)
        with self.assertRaises(VaultError):
            v.seal("item", b"y")
        with self.assertRaises(VaultError):
            v.unseal("item")

    def test_unopened_vault_refuses_use(self):
        self.new_vault().seal("item", b"x")
        with self.assertRaises(VaultError):
            Vault(self.dir).unseal("item")


class PlatformBackendTests(unittest.TestCase):
    """DPAPI and Keychain are written but not run here. These tests check only
    that they fail closed on the wrong platform."""

    def test_dpapi_refuses_to_run_off_windows(self):
        if sys.platform == "win32":
            self.skipTest("this check is for non-Windows systems")
        with self.assertRaises(VaultError):
            DpapiBackend().wrap(b"0" * 32)

    def test_keychain_refuses_to_run_off_macos(self):
        if sys.platform == "darwin":
            self.skipTest("this check is for non-macOS systems")
        with self.assertRaises(VaultError):
            KeychainBackend().wrap(b"0" * 32)


class ShredTests(unittest.TestCase):
    def test_shred_removes_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "f"
            path.write_bytes(b"sensitive")
            shred(path)
            self.assertFalse(path.exists())

    def test_shred_tolerates_missing_files(self):
        with tempfile.TemporaryDirectory() as d:
            shred(Path(d) / "absent")  # no exception


class ReceiverIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.idir = self.root / "identity"

    def tearDown(self):
        self._tmp.cleanup()

    def start(self, passphrase=PASS):
        from airbridge.vault import PassphraseBackend as PB
        server = ReceiverServer(self.root / "dst", identity_dir=self.idir,
                                host="127.0.0.1", port=0,
                                key_backend=PB(passphrase, n=2 ** 10))
        server.start()
        return server

    def test_no_plaintext_secret_is_left_anywhere_in_the_identity_directory(self):
        server = self.start()
        try:
            token = server.pairing.redeem(server.pairing.new_code(), "Laptop")
            digest = hashlib.sha256(token.encode()).hexdigest()
        finally:
            server.stop()
        for path in self.idir.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                self.assertNotIn(b"PRIVATE KEY", data, path.name)
                self.assertNotIn(digest.encode(), data, path.name)
                self.assertNotIn(token.encode(), data, path.name)

    def test_trusted_sessions_survive_a_restart_with_the_same_passphrase(self):
        server = self.start()
        token = server.pairing.redeem(server.pairing.new_code(), "Laptop")
        server.stop()
        restarted = self.start()
        try:
            self.assertTrue(restarted.pairing.is_valid(token))
            self.assertEqual(restarted.pairing.list_sessions()[0]["device"], "Laptop")
        finally:
            restarted.stop()

    def test_receiver_will_not_start_with_the_wrong_passphrase(self):
        self.start().stop()
        with self.assertRaises(VaultError):
            self.start(passphrase="wrong")

    def test_identity_fingerprint_is_stable_across_restarts(self):
        first = self.start()
        fp = first.fingerprint
        first.stop()
        second = self.start()
        try:
            self.assertEqual(second.fingerprint, fp)
        finally:
            second.stop()

    def test_temporary_key_files_are_removed_after_tls_setup(self):
        before = set(Path(tempfile.gettempdir()).glob("airbridge-*"))
        server = self.start()
        try:
            after = set(Path(tempfile.gettempdir()).glob("airbridge-*"))
            self.assertEqual(after - before, set(), "temporary key directory was left behind")
        finally:
            server.stop()

    def test_stop_without_start_returns_promptly(self):
        import threading
        server = ReceiverServer(self.root / "dst", identity_dir=self.idir, host="127.0.0.1",
                                port=0, key_backend=PassphraseBackend(PASS, n=2 ** 10))
        finished = threading.Event()
        threading.Thread(target=lambda: (server.stop(), finished.set()), daemon=True).start()
        self.assertTrue(finished.wait(5), "stop() blocked on a server that was never started")

    def test_legacy_plaintext_sessions_are_migrated_and_destroyed(self):
        # Build a version 0.4-style plaintext session file for a token we control.
        self.idir.mkdir(parents=True)
        token = "legacy-token-for-migration-test-0123456789"
        now = 4_000_000_000.0  # far in the future so the record is still valid
        record = [{"session_id": "legacy1", "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                   "device": "Old laptop", "created": 1.0, "expires": now, "last_seen": 1.0}]
        legacy = self.idir / "trusted-devices.json"
        legacy.write_text(json.dumps(record))

        server = self.start()
        try:
            self.assertFalse(legacy.exists())
            self.assertTrue(server.pairing.is_valid(token))
        finally:
            server.stop()


class TlsContextTests(unittest.TestCase):
    def test_server_context_builds_without_leaving_key_material_behind(self):
        with tempfile.TemporaryDirectory() as d:
            v = Vault(Path(d) / "id")
            v.create(fast())
            ident = load_or_create_identity(Path(d) / "id", v)
            before = set(Path(tempfile.gettempdir()).glob("airbridge-*"))
            ctx = server_context(ident)
            self.assertIsNotNone(ctx)
            self.assertEqual(set(Path(tempfile.gettempdir()).glob("airbridge-*")) - before, set())


if __name__ == "__main__":
    unittest.main()

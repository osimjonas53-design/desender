import json
import os
import tempfile
import unittest
from pathlib import Path

from airbridge.pairing import PairingManager


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Path(self._tmp.name) / "trusted-devices.json"
        self.clock = FakeClock()

    def tearDown(self):
        self._tmp.cleanup()

    def manager(self):
        return PairingManager(clock=self.clock, store_path=self.store, session_ttl=3600)

    def pair(self, pm, device="Laptop"):
        return pm.redeem(pm.new_code(), device)

    def test_listed_session_carries_the_device_label(self):
        pm = self.manager()
        self.pair(pm, "Ada's phone")
        sessions = pm.list_sessions()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["device"], "Ada's phone")

    def test_revoking_by_id_invalidates_the_token(self):
        pm = self.manager()
        token = self.pair(pm)
        session_id = pm.list_sessions()[0]["id"]
        self.assertTrue(pm.is_valid(token))
        self.assertTrue(pm.revoke(session_id))
        self.assertFalse(pm.is_valid(token))
        self.assertEqual(pm.list_sessions(), [])

    def test_revoking_unknown_id_does_nothing(self):
        pm = self.manager()
        token = self.pair(pm)
        self.assertFalse(pm.revoke("not-a-session"))
        self.assertTrue(pm.is_valid(token))

    def test_sessions_survive_a_restart(self):
        pm = self.manager()
        token = self.pair(pm)
        restarted = self.manager()   # new process, same store file
        self.assertTrue(restarted.is_valid(token))
        self.assertEqual(len(restarted.list_sessions()), 1)

    def test_revocation_survives_a_restart(self):
        pm = self.manager()
        token = self.pair(pm)
        pm.revoke(pm.list_sessions()[0]["id"])
        restarted = self.manager()
        self.assertFalse(restarted.is_valid(token))

    def test_expired_sessions_are_not_loaded(self):
        pm = self.manager()
        token = self.pair(pm)
        self.clock.t += 3601
        restarted = self.manager()
        self.assertFalse(restarted.is_valid(token))
        self.assertEqual(restarted.list_sessions(), [])

    def test_store_holds_hashes_not_tokens(self):
        pm = self.manager()
        token = self.pair(pm)
        raw = self.store.read_text()
        self.assertNotIn(token, raw)
        records = json.loads(raw)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0]["token_hash"]), 64)

    def test_store_is_owner_readable_only_on_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits only")
        pm = self.manager()
        self.pair(pm)
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o600)

    def test_corrupt_store_means_no_trusted_devices_not_a_crash(self):
        self.store.write_text("{not json")
        pm = self.manager()
        self.assertEqual(pm.list_sessions(), [])
        token = self.pair(pm)     # pairing still works
        self.assertTrue(pm.is_valid(token))

    def test_session_last_seen_is_updated_on_use(self):
        pm = self.manager()
        token = self.pair(pm)
        created_seen = pm.list_sessions()[0]["last_seen"]
        self.clock.t += 120
        pm.is_valid(token)
        self.assertGreater(pm.list_sessions()[0]["last_seen"], created_seen)

    def test_single_use_code_still_enforced_with_store(self):
        pm = self.manager()
        code = pm.new_code()
        pm.redeem(code, "A")
        from airbridge.pairing import PairingError
        with self.assertRaises(PairingError):
            pm.redeem(code, "B")


if __name__ == "__main__":
    unittest.main()

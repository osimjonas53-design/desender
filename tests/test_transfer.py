import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from airbridge.client import IntegrityError, PairingRejected, Sender, TransferRejected
from airbridge.protocol import PARTIAL_DIR_NAME
from airbridge.server import ReceiverServer
TEST_PASSPHRASE = "test-passphrase-123"

class TransferTestCase(unittest.TestCase):
    """Runs a real ReceiverServer on 127.0.0.1 with a random port."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.root = root
        self.src = root / "src"
        self.src.mkdir()
        self.dst = root / "dst"
        self.accept = True
        self.offers = []
        self.server = ReceiverServer(self.dst, identity_dir=self.root / "identity", passphrase=TEST_PASSPHRASE,
                                     approve=self._approve, host="127.0.0.1", port=0,
                                     device_name="test-rx")
        self.code = self.server.start()
        self.fp = self.server.fingerprint
        self.url = f"https://127.0.0.1:{self.server.port}"

    def tearDown(self):
        self.server.stop()
        self._tmp.cleanup()

    def _approve(self, offer):
        self.offers.append(offer)
        return self.accept

    def make_src(self, name, data):
        path = self.src / name
        path.write_bytes(data)
        return path

    def paired_sender(self, **kwargs):
        kwargs.setdefault("sleep", lambda _s: None)
        sender = Sender(self.url, fingerprint=self.fp, **kwargs)
        sender.pair(self.code)
        return sender

    def saved_files(self):
        return sorted(p.name for p in self.dst.iterdir() if p.name != PARTIAL_DIR_NAME)

    def leftover_partials(self):
        return list((self.dst / PARTIAL_DIR_NAME).glob("*"))


class RoundTripTests(TransferTestCase):
    def test_multichunk_round_trip_is_byte_identical(self):
        data = os.urandom(3_500_000)
        src = self.make_src("photo.bin", data)
        sender = self.paired_sender(chunk_size=256 * 1024)

        result = sender.send_file(src)

        saved = self.dst / result["saved_as"]
        self.assertEqual(saved.read_bytes(), data)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(len(sender.put_offsets), 14)  # ceil(3.5 MB / 256 KiB)
        self.assertEqual(self.leftover_partials(), [])  # partial moved, not copied
        self.assertEqual(self.offers[0]["name"], "photo.bin")

    def test_empty_file_transfers(self):
        src = self.make_src("empty.txt", b"")
        result = self.paired_sender().send_file(src)
        self.assertEqual((self.dst / result["saved_as"]).read_bytes(), b"")

    def test_collision_renames_and_keeps_original(self):
        self.dst.mkdir(exist_ok=True)
        (self.dst / "notes.txt").write_bytes(b"old")
        src = self.make_src("notes.txt", b"new")
        result = self.paired_sender().send_file(src)
        self.assertEqual(result["saved_as"], "notes (1).txt")
        self.assertEqual((self.dst / "notes.txt").read_bytes(), b"old")
        self.assertEqual((self.dst / "notes (1).txt").read_bytes(), b"new")


class AuthorisationTests(TransferTestCase):
    def test_wrong_code_then_lockout(self):
        wrong = "000000" if self.code != "000000" else "111111"
        probe = Sender(self.url, fingerprint=self.fp, sleep=lambda _s: None)
        for _ in range(5):
            with self.assertRaises(PairingRejected):
                probe.pair(wrong)
        with self.assertRaises(PairingRejected):
            probe.pair(self.code)  # locked out even with the right code

    def test_offer_without_token_is_unauthorised(self):
        sender = Sender(self.url, fingerprint=self.fp)  # never paired
        status, _ = sender._request("POST", "/v1/offers",
                                    json_body={"name": "a.txt", "size": 1,
                                               "sha256": "0" * 64})
        self.assertEqual(status, 401)
        self.assertEqual(self.offers, [])

    def test_transfer_endpoints_require_token(self):
        paired = self.paired_sender()
        _, offer = paired._request("POST", "/v1/offers",
                                   json_body={"name": "a.txt", "size": 1,
                                              "sha256": "0" * 64})
        stranger = Sender(self.url, fingerprint=self.fp)
        status, _ = stranger._request("PUT", f"/v1/transfers/{offer['transfer_id']}/data?offset=0",
                                      body=b"x")
        self.assertEqual(status, 401)

    def test_revoked_session_stops_working(self):
        sender = self.paired_sender()
        self.server.pairing.revoke_all()
        with self.assertRaises(PairingRejected):
            sender.send_file(self.make_src("a.txt", b"hi"))

    def test_malformed_offer_metadata_is_rejected(self):
        sender = self.paired_sender()
        for body in ({"name": "a", "size": -1, "sha256": "0" * 64},
                     {"name": "a", "size": "5", "sha256": "0" * 64},
                     {"name": "a", "size": 5, "sha256": "not-hex"},
                     {"name": "", "size": 5, "sha256": "0" * 64}):
            with self.subTest(body=body):
                status, _ = sender._request("POST", "/v1/offers", json_body=body)
                self.assertEqual(status, 400)


class ConsentTests(TransferTestCase):
    def test_rejected_offer_writes_nothing(self):
        self.accept = False
        src = self.make_src("secret.pdf", os.urandom(200_000))
        with self.assertRaises(TransferRejected):
            self.paired_sender().send_file(src)
        self.assertEqual(self.saved_files(), [])
        self.assertEqual(self.leftover_partials(), [])


class IntegrityTests(TransferTestCase):
    def test_hash_mismatch_is_reported_and_partial_discarded(self):
        good = b"the real content"
        claimed = hashlib.sha256(b"something else entirely").hexdigest()
        sender = self.paired_sender()
        _, offer = sender._request("POST", "/v1/offers",
                                   json_body={"name": "bad.bin", "size": len(good),
                                              "sha256": claimed})
        tid = offer["transfer_id"]
        status, _ = sender._request("PUT", f"/v1/transfers/{tid}/data?offset=0", body=good)
        self.assertEqual(status, 200)

        status, body = sender._request("POST", f"/v1/transfers/{tid}/complete")
        self.assertEqual(status, 422)
        self.assertEqual(body["error"], "integrity_check_failed")
        self.assertEqual(self.saved_files(), [])
        self.assertEqual(self.leftover_partials(), [])

    def test_sender_surfaces_integrity_error_type(self):
        # Corrupt the partial file between upload and completion, the way a
        # bad disk or a dropped chunk would.
        src = self.make_src("data.bin", os.urandom(300_000))
        sender = self.paired_sender(chunk_size=100_000)
        original_request = sender._request

        def corrupting_request(method, path, body=None, json_body=None, **kw):
            status, payload = original_request(method, path, body=body, json_body=json_body, **kw)
            if method == "PUT" and path.endswith("offset=200000"):
                for part in (self.dst / PARTIAL_DIR_NAME).glob("*.part"):
                    with open(part, "r+b") as fh:
                        fh.seek(10)
                        fh.write(b"\xff\xff\xff")
            return status, payload

        sender._request = corrupting_request
        with self.assertRaises(IntegrityError):
            sender.send_file(src)
        self.assertEqual(self.saved_files(), [])


class SecurityTests(TransferTestCase):
    def test_path_traversal_name_is_confined_to_save_dir(self):
        data = b"hello"
        sender = self.paired_sender()
        _, offer = sender._request("POST", "/v1/offers",
                                   json_body={"name": "../../../evil.txt", "size": len(data),
                                              "sha256": hashlib.sha256(data).hexdigest()})
        tid = offer["transfer_id"]
        sender._request("PUT", f"/v1/transfers/{tid}/data?offset=0", body=data)
        status, body = sender._request("POST", f"/v1/transfers/{tid}/complete")

        self.assertEqual(status, 200)
        self.assertEqual(body["saved_as"], "evil.txt")
        self.assertTrue((self.dst / "evil.txt").exists())
        self.assertFalse((self.root / "evil.txt").exists())

    def test_oversized_chunk_is_refused(self):
        sender = self.paired_sender()
        _, offer = sender._request("POST", "/v1/offers",
                                   json_body={"name": "big.bin", "size": 10_000_000,
                                              "sha256": "0" * 64})
        tid = offer["transfer_id"]
        status, _ = sender._request("PUT", f"/v1/transfers/{tid}/data?offset=0",
                                    body=b"x" * (self.server.max_chunk + 1))
        self.assertEqual(status, 413)

    def test_chunk_past_declared_size_is_refused(self):
        sender = self.paired_sender()
        _, offer = sender._request("POST", "/v1/offers",
                                   json_body={"name": "s.bin", "size": 4, "sha256": "0" * 64})
        status, _ = sender._request("PUT", f"/v1/transfers/{offer['transfer_id']}/data?offset=0",
                                    body=b"toolong")
        self.assertEqual(status, 400)

    def test_cannot_write_at_arbitrary_offset(self):
        sender = self.paired_sender()
        _, offer = sender._request("POST", "/v1/offers",
                                   json_body={"name": "s.bin", "size": 10, "sha256": "1" * 64})
        status, body = sender._request("PUT", f"/v1/transfers/{offer['transfer_id']}/data?offset=5",
                                       body=b"abcde")
        self.assertEqual(status, 409)
        self.assertEqual(body["expected_offset"], 0)

    def test_unknown_transfer_is_404(self):
        sender = self.paired_sender()
        status, _ = sender._request("POST", "/v1/transfers/does-not-exist/complete")
        self.assertEqual(status, 404)

    def test_info_endpoint_is_minimal_and_unauthenticated(self):
        status, body = Sender(self.url, fingerprint=self.fp)._request("GET", "/v1/info")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"device", "protocol", "capabilities"})


class ResumeTests(TransferTestCase):
    def test_resume_after_interruption_uploads_only_missing_bytes(self):
        data = os.urandom(1_000_000)
        half = 500_000
        src = self.make_src("big.bin", data)
        sender = self.paired_sender(chunk_size=256 * 1024)
        digest = hashlib.sha256(data).hexdigest()

        # Simulate a sender that uploaded half the file and then vanished.
        _, offer = sender._request("POST", "/v1/offers",
                                   json_body={"name": "big.bin", "size": len(data),
                                              "sha256": digest})
        status, _ = sender._request("PUT", f"/v1/transfers/{offer['transfer_id']}/data?offset=0",
                                    body=data[:half])
        self.assertEqual(status, 200)

        # A later attempt (possibly after an app restart) must resume.
        result = sender.send_file(src)
        self.assertEqual(sender.put_offsets[0], half)
        self.assertEqual((self.dst / result["saved_as"]).read_bytes(), data)

    def test_flaky_connection_recovers_mid_transfer(self):
        data = os.urandom(900_000)
        src = self.make_src("flaky.bin", data)

        class FlakySender(Sender):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self._puts = 0
                self._failed = False

            def _request(self, method, path, body=None, json_body=None, **kw):
                if method == "PUT":
                    self._puts += 1
                    if self._puts == 2 and not self._failed:
                        self._failed = True
                        raise ConnectionResetError("simulated network drop")
                return super()._request(method, path, body=body, json_body=json_body, **kw)

        sender = FlakySender(self.url, fingerprint=self.fp, chunk_size=300_000, sleep=lambda _s: None)
        sender.pair(self.code)
        result = sender.send_file(src)

        self.assertTrue(sender._failed)
        self.assertEqual((self.dst / result["saved_as"]).read_bytes(), data)
        # The chunk that failed is retried from the offset the server reports.
        self.assertEqual(sender.put_offsets, [0, 300_000, 300_000, 600_000])


if __name__ == "__main__":
    unittest.main()

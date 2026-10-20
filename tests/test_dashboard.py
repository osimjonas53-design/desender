import hashlib
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from airbridge.client import Sender, TransferRejected
from airbridge.server import ReceiverServer
TEST_PASSPHRASE = "test-passphrase-123"

class DashboardTestCase(unittest.TestCase):
    approval_timeout = 10.0

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        self.dst = self.root / "dst"
        self.server = ReceiverServer(self.dst, identity_dir=self.root / "identity", passphrase=TEST_PASSPHRASE,
                                     approve=None, host="127.0.0.1", port=0,
                                     device_name="test-rx",
                                     approval_timeout=self.approval_timeout)
        self.code = self.server.start()
        self.port = self.server.port            # peer listener (TLS)
        self.dport = self.server.dashboard_port  # dashboard listener (loopback, plain)
        self.good_host = f"127.0.0.1:{self.dport}"

    def tearDown(self):
        self.server.stop()
        self._tmp.cleanup()

    def http(self, method, path, host=None, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.dport, timeout=15)
        hdrs = {"Host": host if host is not None else self.good_host}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def admin(self, method, path):
        return self.http(method, path, headers={"X-AirBridge-Admin": "1"})

    def admin_state(self):
        status, _, data = self.admin("GET", "/admin/state")
        self.assertEqual(status, 200)
        return json.loads(data)

    def wait_for_pending(self, count=1, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            pending = self.admin_state()["pending"]
            if len(pending) >= count:
                return pending
            time.sleep(0.05)
        self.fail("offer never reached the dashboard")

    def start_send(self, name, data, sender=None):
        path = self.src / name
        path.write_bytes(data)
        if sender is None:
            sender = Sender(f"https://127.0.0.1:{self.port}", fingerprint=self.server.fingerprint, sleep=lambda _s: None)
            sender.pair(self.code)
        outcome = {}

        def run():
            try:
                outcome["result"] = sender.send_file(path)
            except Exception as exc:  # captured for the main thread to assert on
                outcome["error"] = exc

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread, outcome


class AccessControlTests(DashboardTestCase):
    def test_dashboard_page_is_served_with_strict_headers(self):
        status, headers, body = self.http("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"AirBridge", body)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_dns_rebinding_host_is_refused(self):
        # A hostile page resolves its own domain to 127.0.0.1; the Host header
        # still names that domain, so the request must be refused.
        status, _, _ = self.http("GET", "/", host="attacker.example")
        self.assertEqual(status, 404)
        status, _, _ = self.admin_raw_with_host("attacker.example")
        self.assertEqual(status, 404)

    def admin_raw_with_host(self, host):
        return self.http("GET", "/admin/state", host=host,
                         headers={"X-AirBridge-Admin": "1"})

    def test_admin_api_requires_custom_header(self):
        status, _, _ = self.http("GET", "/admin/state")
        self.assertEqual(status, 403)

    def test_cross_site_post_without_custom_header_is_refused(self):
        # A malicious page can make the browser send a POST, but it cannot add
        # X-AirBridge-Admin without a CORS preflight, which is never granted.
        status, _, _ = self.http("POST", "/admin/code",
                                 headers={"Origin": "https://attacker.example"})
        self.assertEqual(status, 403)
        status, _, _ = self.http("POST", "/admin/code",
                                 headers={"Origin": "https://attacker.example",
                                          "Content-Type": "text/plain"})
        self.assertEqual(status, 403)

    def test_admin_state_exposes_current_pairing_code(self):
        state = self.admin_state()
        self.assertEqual(state["pairing"]["code"], self.code)
        self.assertGreater(state["pairing"]["seconds_left"], 0)

    def test_new_code_replaces_old_one(self):
        status, _, data = self.admin("POST", "/admin/code")
        self.assertEqual(status, 200)
        new_code = json.loads(data)["code"]
        self.assertEqual(self.admin_state()["pairing"]["code"], new_code)
        self.assertNotEqual(new_code, self.code)

    def test_static_files_are_allowlisted(self):
        status, _, _ = self.http("GET", "/static/app.js")
        self.assertEqual(status, 200)
        status, _, _ = self.http("GET", "/static/../protocol.py")
        self.assertEqual(status, 404)
        status, _, _ = self.http("GET", "/static/secret.txt")
        self.assertEqual(status, 404)


class ApprovalFlowTests(DashboardTestCase):
    def test_accept_from_dashboard_completes_transfer(self):
        data = os.urandom(400_000)
        thread, outcome = self.start_send("holiday.jpg", data)
        pending = self.wait_for_pending()
        self.assertEqual(pending[0]["name"], "holiday.jpg")
        self.assertEqual(pending[0]["size"], len(data))

        status, _, _ = self.admin("POST", f"/admin/offers/{pending[0]['id']}/accept")
        self.assertEqual(status, 200)
        thread.join(timeout=30)

        self.assertNotIn("error", outcome, outcome.get("error"))
        saved = self.dst / outcome["result"]["saved_as"]
        self.assertEqual(saved.read_bytes(), data)
        history = self.admin_state()["history"]
        self.assertEqual(history[0]["status"], "saved")
        self.assertEqual(history[0]["name"], "holiday.jpg")
        self.assertEqual(self.admin_state()["pending"], [])

    def test_decline_from_dashboard_writes_nothing(self):
        thread, outcome = self.start_send("private.pdf", os.urandom(50_000))
        pending = self.wait_for_pending()
        self.admin("POST", f"/admin/offers/{pending[0]['id']}/decline")
        thread.join(timeout=30)

        self.assertIsInstance(outcome.get("error"), TransferRejected)
        self.assertEqual([p.name for p in self.dst.iterdir()
                          if p.name != ".airbridge-partial"], [])
        self.assertEqual(self.admin_state()["history"][0]["status"], "declined")

    def test_no_answer_times_out_as_decline(self):
        server = ReceiverServer(self.root / "dst2", identity_dir=self.root / "identity", passphrase=TEST_PASSPHRASE,
                                approve=None, host="127.0.0.1", port=0, approval_timeout=0.5)
        code = server.start()
        try:
            sender = Sender(f"https://127.0.0.1:{server.port}", fingerprint=server.fingerprint,
                            sleep=lambda _s: None)
            sender.pair(code)
            path = self.src / "waiting.txt"
            path.write_bytes(b"nobody answers")
            started = time.time()
            with self.assertRaises(TransferRejected):
                sender.send_file(path)
            self.assertLess(time.time() - started, 10)
        finally:
            server.stop()

    def test_decision_on_unknown_offer_is_404(self):
        status, _, _ = self.admin("POST", "/admin/offers/does-not-exist/accept")
        self.assertEqual(status, 404)

    def test_unauthorised_client_cannot_queue_offers_for_the_dashboard(self):
        status, _ = Sender(f"https://127.0.0.1:{self.port}", fingerprint=self.server.fingerprint)._request(
            "POST", "/v1/offers",
            json_body={"name": "x.txt", "size": 1, "sha256": "0" * 64})
        self.assertEqual(status, 401)
        self.assertEqual(self.admin_state()["pending"], [])


class NameSafetyTests(DashboardTestCase):
    def test_markup_in_file_name_is_sanitised_before_display(self):
        hostile = "<img src=x onerror=alert(1)>.txt"
        sender = Sender(f"https://127.0.0.1:{self.port}", fingerprint=self.server.fingerprint, sleep=lambda _s: None)
        sender.pair(self.code)
        digest = hashlib.sha256(b"x").hexdigest()
        outcome = {}

        def offer():
            outcome["status"], outcome["body"] = sender._request(
                "POST", "/v1/offers",
                json_body={"name": hostile, "size": 1, "sha256": digest})

        thread = threading.Thread(target=offer, daemon=True)
        thread.start()
        pending = self.wait_for_pending(count=1)
        self.assertNotIn("<", pending[0]["name"])
        self.assertNotIn(">", pending[0]["name"])
        self.admin("POST", f"/admin/offers/{pending[0]['id']}/decline")
        thread.join(timeout=30)
        self.assertEqual(outcome["status"], 403)


if __name__ == "__main__":
    unittest.main()

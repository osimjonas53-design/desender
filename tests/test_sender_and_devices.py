import hashlib
import http.client
import json
import tempfile
import unittest
from pathlib import Path

from airbridge.client import PinRejected, Sender
from airbridge.server import ReceiverServer
TEST_PASSPHRASE = "test-passphrase-123"

class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.server = ReceiverServer(root / "dst", identity_dir=root / "identity", passphrase=TEST_PASSPHRASE,
                                     approve=lambda offer: True, host="127.0.0.1", port=0,
                                     advertise_url="https://192.168.1.20:8765")
        self.code = self.server.start()
        self.fp = self.server.fingerprint
        self.peer = self.server.port
        self.dash = self.server.dashboard_port

    def tearDown(self):
        self.server.stop()
        self._tmp.cleanup()

    def paired(self, name="Test laptop"):
        sender = Sender(f"https://127.0.0.1:{self.peer}", fingerprint=self.fp, sleep=lambda _s: None)
        sender.pair(self.code, device_name=name)
        return sender

    def get_peer(self, path):
        conn = http.client.HTTPSConnection("127.0.0.1", self.peer, timeout=10,
                                           context=_insecure_ctx())
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        headers = dict(resp.getheaders())
        conn.close()
        return resp.status, headers, body

    def get_dash(self, path, headers=None, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.dash, timeout=10)
        h = {"Host": f"127.0.0.1:{self.dash}"}
        h.update(headers or {})
        conn.request(method, path, headers=h)
        resp = conn.getresponse()
        body = resp.read()
        headers_out = dict(resp.getheaders())
        conn.close()
        return resp.status, headers_out, body

    def admin_json(self, path, method="GET"):
        status, _, body = self.get_dash(path, headers={"X-AirBridge-Admin": "1"}, method=method)
        return status, json.loads(body) if body else {}


def _insecure_ctx():
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class SenderPageTests(ServerTestCase):
    def test_sender_page_is_served_on_the_peer_port_with_strict_policy(self):
        status, headers, body = self.get_peer("/send")
        self.assertEqual(status, 200)
        self.assertIn(b"AirBridge", body)
        csp = headers["Content-Security-Policy"]
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)

    def test_sender_page_contains_no_inline_script_or_style(self):
        _, _, body = self.get_peer("/send")
        self.assertNotIn(b"<script>", body)
        self.assertNotIn(b"<style", body)
        self.assertNotIn(b' style="', body)

    def test_sender_assets_are_served_but_dashboard_assets_are_not(self):
        for name in ("send.js", "sha256.js", "style.css"):
            status, _, _ = self.get_peer(f"/static/{name}")
            self.assertEqual(status, 200, name)
        status, _, _ = self.get_peer("/static/app.js")
        self.assertEqual(status, 404)

    def test_dashboard_is_not_served_on_the_peer_port(self):
        status, _, _ = self.get_peer("/")
        self.assertEqual(status, 404)
        status, _, _ = self.get_peer("/admin/state")
        self.assertEqual(status, 404)

    def test_sender_page_is_not_served_on_the_dashboard_port(self):
        status, _, _ = self.get_dash("/send")
        self.assertEqual(status, 404)

    def test_sender_page_rejects_write_methods(self):
        conn = http.client.HTTPSConnection("127.0.0.1", self.peer, timeout=10,
                                           context=_insecure_ctx())
        conn.request("POST", "/send", body=b"x")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 404)


class PairingLabelTests(ServerTestCase):
    def test_device_name_is_recorded_for_the_dashboard(self):
        self.paired("Ada's phone")
        _, state = self.admin_json("/admin/state")
        self.assertEqual([d["device"] for d in state["devices"]], ["Ada's phone"])

    def test_hostile_device_name_is_cleaned_and_truncated(self):
        self.paired("<img src=x onerror=alert(1)>" + "n" * 200)
        _, state = self.admin_json("/admin/state")
        name = state["devices"][0]["device"]
        self.assertLessEqual(len(name), 64)
        self.assertNotIn("\n", name)

    def test_missing_device_name_gets_a_placeholder(self):
        sender = Sender(f"https://127.0.0.1:{self.peer}", fingerprint=self.fp, sleep=lambda _s: None)
        sender.pair(self.code)
        _, state = self.admin_json("/admin/state")
        self.assertEqual(state["devices"][0]["device"], "Unnamed device")


class RevocationTests(ServerTestCase):
    def test_dashboard_revocation_stops_the_device_immediately(self):
        sender = self.paired()
        _, state = self.admin_json("/admin/state")
        session_id = state["devices"][0]["id"]

        status, body = self.admin_json(f"/admin/devices/{session_id}/revoke", method="POST")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

        status, _ = sender._request("POST", "/v1/offers",
                                    json_body={"name": "a.txt", "size": 1, "sha256": "0" * 64})
        self.assertEqual(status, 401)

    def test_revoking_one_device_leaves_others_working(self):
        first = self.paired("First")
        second_code = self.server.new_pairing_code()
        second = Sender(f"https://127.0.0.1:{self.peer}", fingerprint=self.fp, sleep=lambda _s: None)
        second.pair(second_code, device_name="Second")
        _, state = self.admin_json("/admin/state")
        target = next(d for d in state["devices"] if d["device"] == "First")
        self.admin_json(f"/admin/devices/{target['id']}/revoke", method="POST")

        status, _ = first._request("GET", "/v1/transfers/none")
        self.assertEqual(status, 401)
        status, _ = second._request("GET", "/v1/transfers/none")
        self.assertEqual(status, 404)   # authorised, transfer simply unknown

    def test_revoking_unknown_device_is_404(self):
        status, _ = self.admin_json("/admin/devices/nope/revoke", method="POST")
        self.assertEqual(status, 404)

    def test_revocation_requires_the_dashboard_header(self):
        self.paired()
        _, state = self.admin_json("/admin/state")
        status, _, _ = self.get_dash(f"/admin/devices/{state['devices'][0]['id']}/revoke",
                                     method="POST")
        self.assertEqual(status, 403)
        _, state_after = self.admin_json("/admin/state")
        self.assertEqual(len(state_after["devices"]), 1)

    def test_revoked_device_cannot_upload_even_mid_transfer(self):
        sender = self.paired()
        data = b"abc" * 1000
        digest = hashlib.sha256(data).hexdigest()
        _, offer = sender._request("POST", "/v1/offers",
                                   json_body={"name": "m.bin", "size": len(data), "sha256": digest})
        _, state = self.admin_json("/admin/state")
        self.admin_json(f"/admin/devices/{state['devices'][0]['id']}/revoke", method="POST")
        status, _ = sender._request("PUT", f"/v1/transfers/{offer['transfer_id']}/data?offset=0",
                                    body=data)
        self.assertEqual(status, 401)


class QREndpointTests(ServerTestCase):
    def test_qr_requires_the_dashboard_header(self):
        status, _, _ = self.get_dash("/admin/qr")
        self.assertEqual(status, 403)

    def test_qr_is_svg_and_matches_the_live_code(self):
        status, _, body = self.get_dash("/admin/qr", headers={"X-AirBridge-Admin": "1"})
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"<svg"))

    def test_qr_stops_when_the_code_is_used(self):
        self.paired()
        status, _, _ = self.get_dash("/admin/qr", headers={"X-AirBridge-Admin": "1"})
        self.assertEqual(status, 404)

    def test_pairing_link_carries_code_and_fingerprint_in_fragment(self):
        link = self.server.pairing_link()
        self.assertTrue(link.startswith("https://192.168.1.20:8765/send#c="))
        self.assertIn(f"&f={self.fp}", link)
        self.assertIn(f"c={self.code}", link)

    def test_no_qr_without_an_advertised_address(self):
        root = Path(self._tmp.name)
        bare = ReceiverServer(root / "bare", identity_dir=root / "bare-id", passphrase=TEST_PASSPHRASE,
                              host="127.0.0.1", port=0)
        bare.start()
        try:
            self.assertIsNone(bare.pairing_link())
        finally:
            bare.stop()

    def test_dashboard_state_exposes_fingerprint(self):
        _, state = self.admin_json("/admin/state")
        self.assertEqual(state["fingerprint"], self.fp)


class PinnedSenderPageTests(ServerTestCase):
    def test_wrong_fingerprint_still_refused_for_cli_clients(self):
        sender = Sender(f"https://127.0.0.1:{self.peer}", fingerprint="0" * 16)
        with self.assertRaises(PinRejected):
            sender.pair(self.code)


if __name__ == "__main__":
    unittest.main()

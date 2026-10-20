import random
import socket
import struct
import unittest
from unittest import mock

from airbridge import cli
from airbridge.client import TransferError
from airbridge.discovery import (
    SERVICE,
    TYPE_A,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    Advertisement,
    DecodeError,
    Found,
    Responder,
    _advertisement_records,
    browse,
    clean_instance,
    decode_message,
    encode_query,
    encode_response,
    search,
)

AD = Advertisement(instance="Living room PC", host="airbridge-ab12cd34.local",
                   address="192.168.1.20", port=8765,
                   txt={"proto": "1", "id": "ab12cd34", "caps": "file-transfer"})


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class WireFormatTests(unittest.TestCase):
    def test_advertisement_round_trips_through_the_wire_format(self):
        packet = encode_response(_advertisement_records(AD))
        msg = decode_message(packet)
        self.assertTrue(msg.is_response)
        by_type = {r.rtype: r for r in msg.records}
        self.assertEqual(by_type[TYPE_PTR].value, AD.instance_fqdn)
        self.assertEqual(by_type[TYPE_SRV].value, (8765, AD.host))
        self.assertEqual(by_type[TYPE_A].value, "192.168.1.20")
        self.assertEqual(by_type[TYPE_TXT].value["id"], "ab12cd34")

    def test_query_decodes_as_a_question_not_a_response(self):
        msg = decode_message(encode_query())
        self.assertFalse(msg.is_response)
        self.assertEqual(msg.questions, ((SERVICE, TYPE_PTR),))

    def test_every_truncation_of_a_valid_packet_is_handled_safely(self):
        packet = encode_response(_advertisement_records(AD))
        for cut in range(len(packet)):
            try:
                decode_message(packet[:cut])
            except DecodeError:
                pass   # the only acceptable failure

    def test_random_garbage_only_raises_decode_error(self):
        rng = random.Random(1234)
        for _ in range(3000):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
            try:
                decode_message(data)
            except DecodeError:
                continue

    def test_compression_pointer_loop_is_rejected(self):
        # Header with one question whose name points at itself.
        header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        looping = header + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
        with self.assertRaises(DecodeError):
            decode_message(looping)

    def test_oversized_record_counts_are_refused(self):
        header = struct.pack("!HHHHHH", 0, 0, 500, 0, 0, 0)
        with self.assertRaises(DecodeError):
            decode_message(header)

    def test_names_longer_than_a_label_are_refused_on_encode(self):
        from airbridge.discovery import _name_bytes
        with self.assertRaises(ValueError):
            _name_bytes("x" * 64 + ".local")


class InstanceNameTests(unittest.TestCase):
    def test_dots_and_control_characters_are_removed(self):
        self.assertEqual(clean_instance("Office.PC\n\x00"), "OfficePC")

    def test_long_names_are_cut_within_utf8_limits(self):
        name = clean_instance("é" * 100)
        self.assertLessEqual(len(name.encode("utf-8")), 63)
        name.encode("utf-8")  # must still be valid UTF-8

    def test_empty_name_gets_a_default(self):
        self.assertEqual(clean_instance("..."), "AirBridge")


class ResponderRulesTests(unittest.TestCase):
    class FakeSocket:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    def responder_with_fake_socket(self):
        r = Responder(AD, port=0)
        r._sock = self.FakeSocket()
        return r

    def test_answers_private_addresses(self):
        r = self.responder_with_fake_socket()
        r._handle(encode_query(), ("192.168.1.50", 40000))
        self.assertEqual(len(r._sock.sent), 1)
        self.assertEqual(r._sock.sent[0][1], ("192.168.1.50", 40000))

    def test_ignores_public_addresses(self):
        r = self.responder_with_fake_socket()
        r._handle(encode_query(), ("8.8.8.8", 53))
        self.assertEqual(r._sock.sent, [])

    def test_answers_a_browse_with_all_four_records(self):
        r = self.responder_with_fake_socket()
        r._handle(encode_query(), ("127.0.0.1", 40000))
        msg = decode_message(r._sock.sent[0][0])
        types = sorted(rec.rtype for rec in msg.records)
        self.assertEqual(types, sorted([TYPE_PTR, TYPE_SRV, TYPE_TXT, TYPE_A]))

    def test_ignores_queries_for_other_services(self):
        r = self.responder_with_fake_socket()
        r._handle(encode_query("_printer._tcp.local"), ("127.0.0.1", 40000))
        self.assertEqual(r._sock.sent, [])

    def test_ignores_responses(self):
        r = self.responder_with_fake_socket()
        r._handle(encode_response(_advertisement_records(AD)), ("127.0.0.1", 40000))
        self.assertEqual(r._sock.sent, [])


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.port = _free_udp_port()
        self.responder = Responder(AD, port=self.port)
        self.responder.start()

    def tearDown(self):
        self.responder.stop()

    def test_browse_finds_the_receiver_by_unicast_query(self):
        found = browse(timeout=1.0, port=self.port,
                       unicast_targets=(("127.0.0.1", self.port),))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].instance, "Living room PC")
        self.assertEqual(found[0].address, "192.168.1.20")
        self.assertEqual(found[0].port, 8765)
        self.assertEqual(found[0].txt["id"], "ab12cd34")

    def test_malformed_datagrams_do_not_stop_the_responder(self):
        junk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for payload in (b"", b"\x00" * 5, b"\xff" * 300, b"\x00\x00\x00\x00\x00\x01\x00\x00\xc0\x0c"):
            junk.sendto(payload, ("127.0.0.1", self.port))
        junk.close()
        found = browse(timeout=1.0, port=self.port,
                       unicast_targets=(("127.0.0.1", self.port),))
        self.assertEqual(len(found), 1)

    def test_search_filters_by_name_id_and_address(self):
        found = browse(timeout=1.0, port=self.port,
                       unicast_targets=(("127.0.0.1", self.port),))
        self.assertEqual(len(search(found, "living")), 1)
        self.assertEqual(len(search(found, "AB12CD")), 1)
        self.assertEqual(len(search(found, "192.168.1")), 1)
        self.assertEqual(search(found, "kitchen"), [])

    def test_multicast_browse_when_the_network_allows_it(self):
        found = browse(timeout=1.0, port=self.port)
        if not found:
            self.skipTest("multicast loopback is not available on this machine")
        self.assertEqual(found[0].instance, "Living room PC")


class NameResolutionTests(unittest.TestCase):
    def fake(self, *items):
        return list(items)

    def item(self, name, addr="192.168.1.20", port=8765, id_="ab12cd34"):
        return Found(instance=name, host="h.local", address=addr, port=port, txt={"id": id_})

    def test_addresses_are_used_without_discovery(self):
        with mock.patch.object(cli, "browse") as b:
            self.assertEqual(cli.resolve_target("192.168.1.20:8765"), ("192.168.1.20:8765", None))
            self.assertEqual(cli.resolve_target("https://10.0.0.5:8765"), ("https://10.0.0.5:8765", None))
            b.assert_not_called()

    def test_single_match_resolves_to_its_address(self):
        with mock.patch.object(cli, "browse", return_value=[self.item("Living room PC")]):
            address, info = cli.resolve_target("living")
        self.assertEqual(address, "192.168.1.20:8765")
        self.assertEqual(info["id"], "ab12cd34")

    def test_no_match_is_a_clear_error(self):
        with mock.patch.object(cli, "browse", return_value=[self.item("Living room PC")]):
            with self.assertRaises(TransferError):
                cli.resolve_target("kitchen")

    def test_ambiguous_names_ask_for_an_address(self):
        items = [self.item("Office PC", addr="10.0.0.2", id_="11111111"),
                 self.item("Office PC", addr="10.0.0.3", id_="22222222")]
        with mock.patch.object(cli, "browse", return_value=items):
            with self.assertRaises(TransferError) as ctx:
                cli.resolve_target("office")
        self.assertIn("10.0.0.2", str(ctx.exception))
        self.assertIn("10.0.0.3", str(ctx.exception))

    def test_exact_name_beats_partial_matches(self):
        items = [self.item("Office"), self.item("Office PC", addr="10.0.0.3", id_="22222222")]
        with mock.patch.object(cli, "browse", return_value=items):
            address, _ = cli.resolve_target("Office")
        self.assertEqual(address, "192.168.1.20:8765")


if __name__ == "__main__":
    unittest.main()

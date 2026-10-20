"""LAN discovery of AirBridge receivers over mDNS / DNS-SD (RFC 6762 / 6763).

Receivers advertise ``_airbridge._tcp.local`` with a display name, a port and a
small TXT record. Senders send a PTR query and read the answers.

Discovery finds addresses. It never establishes trust. Anyone on the LAN can
advertise any name, so the sender must still check the device fingerprint
against the receiving screen before pairing.

What is advertised: the display name, the TCP port, the protocol version, a
short fingerprint prefix (to tell devices with the same name apart) and the
capability list. Nothing else.

Implementation notes:
* Pure standard library. The wire format is small: names with compression
  pointers on read, uncompressed names on write.
* Browsers send queries from an ephemeral port and get unicast replies, as
  RFC 6762 section 6.7 allows. They never need to share port 5353.
* Only queries from private, loopback or link-local addresses are answered,
  which limits use of the responder for reflection attacks.
"""
from __future__ import annotations

import ipaddress
import time
import socket
import struct
import threading
from dataclasses import dataclass, field

SERVICE = "_airbridge._tcp.local"
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
TTL = 120

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_SRV = 33
TYPE_ANY = 255
CLASS_IN = 1
FLUSH_BIT = 0x8000
RESPONSE_FLAGS = 0x8400  # QR=1 (response), AA=1

_MAX_NAME = 255
_MAX_LABEL = 63
_MAX_RECORDS = 64


class DecodeError(ValueError):
    pass


@dataclass(frozen=True)
class Record:
    name: str
    rtype: int
    ttl: int
    value: object


@dataclass(frozen=True)
class Message:
    is_response: bool
    questions: tuple
    records: tuple


@dataclass(frozen=True)
class Advertisement:
    instance: str       # display name, e.g. "Living room PC"
    host: str           # mDNS host label, e.g. "airbridge-ab12cd34.local"
    address: str        # IPv4 address to publish
    port: int
    txt: dict = field(default_factory=dict)

    @property
    def instance_fqdn(self) -> str:
        return f"{self.instance}.{SERVICE}"


@dataclass(frozen=True)
class Found:
    instance: str
    host: str
    address: str
    port: int
    txt: dict


def clean_instance(name: str) -> str:
    """Make a display name safe as a single DNS label."""
    cleaned = "".join(ch for ch in str(name) if ch.isprintable() and ch != ".").strip()
    encoded = cleaned.encode("utf-8")[:_MAX_LABEL].decode("utf-8", "ignore").strip()
    return encoded or "AirBridge"


# ----- wire format ------------------------------------------------------------
def _name_bytes(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        raw = label.encode("utf-8")
        if not 0 < len(raw) <= _MAX_LABEL:
            raise ValueError(f"invalid DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    out += b"\x00"
    if len(out) > _MAX_NAME:
        raise ValueError(f"DNS name too long: {name!r}")
    return out


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    hops = 0
    total = 0
    while True:
        if off >= len(data):
            raise DecodeError("name runs past end of packet")
        length = data[off]
        if length & 0xC0 == 0xC0:           # compression pointer
            if off + 1 >= len(data):
                raise DecodeError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[off + 1]
            if end is None:
                end = off + 2
            hops += 1
            if hops > 20 or pointer >= len(data):
                raise DecodeError("pointer loop or out of range")
            off = pointer
            continue
        if length & 0xC0:
            raise DecodeError("reserved label type")
        if length == 0:
            off += 1
            break
        off += 1
        if off + length > len(data):
            raise DecodeError("label runs past end of packet")
        total += length + 1
        if total > _MAX_NAME:
            raise DecodeError("name too long")
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), (end if end is not None else off)


def _read_txt(data: bytes) -> dict:
    out: dict[str, str] = {}
    i = 0
    while i < len(data):
        n = data[i]
        chunk = data[i + 1:i + 1 + n].decode("utf-8", "replace")
        i += 1 + n
        if "=" in chunk:
            key, _, value = chunk.partition("=")
            out.setdefault(key.lower(), value)
    return out


def _txt_bytes(txt: dict) -> bytes:
    out = b""
    for key, value in txt.items():
        raw = f"{key}={value}".encode("utf-8")[:255]
        out += bytes([len(raw)]) + raw
    return out or b"\x00"


def _read_record(data: bytes, off: int) -> tuple[Record, int]:
    name, off = _read_name(data, off)
    if off + 10 > len(data):
        raise DecodeError("truncated record header")
    rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
    off += 10
    if off + rdlen > len(data):
        raise DecodeError("record data runs past end of packet")
    start, stop = off, off + rdlen
    if rtype == TYPE_PTR:
        value, _ = _read_name(data, start)
    elif rtype == TYPE_SRV:
        if rdlen < 7:
            raise DecodeError("short SRV record")
        _, _, port = struct.unpack_from("!HHH", data, start)
        target, _ = _read_name(data, start + 6)
        value = (port, target)
    elif rtype == TYPE_TXT:
        value = _read_txt(data[start:stop])
    elif rtype == TYPE_A:
        if rdlen != 4:
            raise DecodeError("bad A record")
        value = socket.inet_ntoa(data[start:stop])
    else:
        value = None
    return Record(name, rtype, ttl, value), stop


def decode_message(data: bytes) -> Message:
    if len(data) < 12:
        raise DecodeError("packet shorter than a DNS header")
    _, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    if qd + an + ns + ar > _MAX_RECORDS:
        raise DecodeError("too many entries")
    off = 12
    questions = []
    for _ in range(qd):
        name, off = _read_name(data, off)
        if off + 4 > len(data):
            raise DecodeError("truncated question")
        qtype, _ = struct.unpack_from("!HH", data, off)
        off += 4
        questions.append((name, qtype))
    records = []
    for _ in range(an + ns + ar):
        record, off = _read_record(data, off)
        records.append(record)
    return Message(is_response=bool(flags & 0x8000),
                   questions=tuple(questions), records=tuple(records))


def _rr(name: str, rtype: int, rdata: bytes, ttl: int, flush: bool) -> bytes:
    cls = CLASS_IN | (FLUSH_BIT if flush else 0)
    return _name_bytes(name) + struct.pack("!HHIH", rtype, cls, ttl, len(rdata)) + rdata


def _advertisement_records(ad: Advertisement, ttl: int = TTL) -> list[bytes]:
    srv = struct.pack("!HHH", 0, 0, ad.port) + _name_bytes(ad.host)
    return [
        _rr(SERVICE, TYPE_PTR, _name_bytes(ad.instance_fqdn), ttl, flush=False),
        _rr(ad.instance_fqdn, TYPE_SRV, srv, ttl, flush=True),
        _rr(ad.instance_fqdn, TYPE_TXT, _txt_bytes(ad.txt), ttl, flush=True),
        _rr(ad.host, TYPE_A, socket.inet_aton(ad.address), ttl, flush=True),
    ]


def encode_response(records: list[bytes], msg_id: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", msg_id, RESPONSE_FLAGS, 0, len(records), 0, 0)
    return header + b"".join(records)


def encode_query(name: str = SERVICE, qtype: int = TYPE_PTR, msg_id: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", msg_id, 0, 1, 0, 0, 0)
    return header + _name_bytes(name) + struct.pack("!HH", qtype, CLASS_IN)


# ----- sockets ----------------------------------------------------------------
def _responder_socket(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(("", port))
    mreq = socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.settimeout(0.5)
    return sock


def _allowed_source(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


# ----- responder (receiver side) -----------------------------------------------
class Responder:
    """Answers queries for one advertised receiver and announces it on the LAN."""

    def __init__(self, advertisement: Advertisement, port: int = MDNS_PORT) -> None:
        self.ad = advertisement
        self.port = port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._sock = _responder_socket(self.port)
        self._thread = threading.Thread(target=self._loop, daemon=True, name="airbridge-mdns")
        self._thread.start()
        self._announce()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            try:
                goodbye = encode_response(_advertisement_records(self.ad, ttl=0))
                self._sock.sendto(goodbye, (MDNS_GROUP, self.port))
            except OSError:
                pass
            self._sock.close()

    def _announce(self) -> None:
        packet = encode_response(_advertisement_records(self.ad))
        for _ in range(2):
            try:
                self._sock.sendto(packet, (MDNS_GROUP, self.port))
            except OSError:
                return

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, src = self._sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle(data, src)
            except Exception:
                continue   # a malformed packet must never stop the responder

    def _handle(self, data: bytes, src: tuple) -> None:
        if not _allowed_source(src[0]):
            return
        msg = decode_message(data)
        if msg.is_response:
            return
        instance = self.ad.instance_fqdn.lower()
        host = self.ad.host.lower()
        ptr, srv, txt, a = _advertisement_records(self.ad)
        answers: list[bytes] = []
        for name, qtype in msg.questions:
            name = name.lower()
            if name == SERVICE.lower() and qtype in (TYPE_PTR, TYPE_ANY):
                # A browse answer carries the SRV, TXT and A records too, so the
                # querier can resolve the instance without a second round trip.
                answers += [ptr, srv, txt, a]
            if name == instance and qtype in (TYPE_SRV, TYPE_TXT, TYPE_ANY):
                answers += [srv, txt, a]
            if name == host and qtype in (TYPE_A, TYPE_ANY):
                answers.append(a)
        if not answers:
            return
        reply = encode_response(list(dict.fromkeys(answers)), msg_id=0)
        # Answer the querier directly. Standard-port queries also get a multicast reply.
        self._sock.sendto(reply, src)


# ----- browser (sender side) ----------------------------------------------------
def browse(timeout: float = 2.0, port: int = MDNS_PORT,
           unicast_targets: tuple[tuple[str, int], ...] = ()) -> list[Found]:
    """Find receivers. Returns one entry per advertised instance."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.bind(("", 0))                    # ephemeral: replies come back unicast
        sock.settimeout(0.2)
        query = encode_query()
        sock.sendto(query, (MDNS_GROUP, port))
        for target in unicast_targets:
            sock.sendto(query, target)

        ptrs: dict[str, str] = {}             # instance fqdn -> instance fqdn (from PTR)
        srv: dict[str, tuple[int, str]] = {}
        txt: dict[str, dict] = {}
        addr: dict[str, str] = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = decode_message(data)
            except DecodeError:
                continue
            if not msg.is_response:
                continue
            for rec in msg.records:
                if rec.rtype == TYPE_PTR and rec.name.lower() == SERVICE.lower() and rec.value:
                    ptrs[rec.value] = rec.value
                elif rec.rtype == TYPE_SRV and rec.value:
                    srv[rec.name] = rec.value
                elif rec.rtype == TYPE_TXT and isinstance(rec.value, dict):
                    txt[rec.name] = rec.value
                elif rec.rtype == TYPE_A and rec.value:
                    addr[rec.name] = rec.value
    finally:
        sock.close()

    found: list[Found] = []
    for fqdn in sorted(ptrs):
        if fqdn not in srv:
            continue
        port_no, host = srv[fqdn]
        address = addr.get(host)
        if not address:
            continue
        instance = fqdn[: -len(SERVICE) - 1] if fqdn.endswith("." + SERVICE) else fqdn
        found.append(Found(instance=instance, host=host, address=address,
                           port=port_no, txt=txt.get(fqdn, {})))
    return found


def search(found: list[Found], text: str) -> list[Found]:
    """Case-insensitive match on display name, device id, host or address."""
    needle = text.strip().lower()
    if not needle:
        return list(found)
    out = []
    for item in found:
        haystack = " ".join([item.instance, item.txt.get("id", ""), item.host, item.address]).lower()
        if needle in haystack:
            out.append(item)
    return out

"""Receiver side of the AirBridge file transfer protocol (v1), plus the local dashboard.

Peer-facing endpoints (any device that has paired)
--------------------------------------------------
GET    /v1/info                         unauthenticated: name, protocol version
POST   /v1/pair       {code}            -> {token}           (single-use code)
POST   /v1/offers     {name,size,sha256}-> {transfer_id, offset, max_chunk}
                                          waits for approval (dashboard or callback)
GET    /v1/transfers/{id}               -> {name,size,received}
PUT    /v1/transfers/{id}/data?offset=N body = raw bytes, must start at received
POST   /v1/transfers/{id}/complete      hashes the partial file, then atomically
                                          moves it into place; 422 on mismatch
DELETE /v1/transfers/{id}               cancel (partial kept for resume)

Local dashboard (the computer that owns the receiver only)
----------------------------------------------------------
GET    /                                the dashboard page
GET    /static/<allowlisted file>
GET    /admin/state                     pairing code, pending offers, progress, history
POST   /admin/code                      generate a new pairing code
POST   /admin/offers/{id}/accept
POST   /admin/offers/{id}/decline

Every /admin/ request must (a) come from a loopback socket, (b) carry a Host
header naming localhost or 127.0.0.1 on this port (blocks DNS rebinding), and
(c) for API calls, carry the header ``X-AirBridge-Admin: 1``. Browsers cannot
send that header cross-site without a CORS preflight, which we never grant.

Partial data lives in ``<save_dir>/.airbridge-partial/<sha256>-<size>.part``.
The file name is never used to build the partial path.

Transport: peers connect over TLS 1.2+ and pin the receiver's certificate
by fingerprint (see tls.py). The dashboard is plain HTTP on 127.0.0.1 only.
"""
from __future__ import annotations

import collections
import json
import os
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .integrity import sha256_file
from .pairing import PairingError, PairingManager, VaultStore
from .qr import QRTooLong, encode as qr_encode, to_svg
from .tls import load_or_create_identity, server_context
from .vault import Vault, backend_for, default_backend_name
from .protocol import (
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    MAX_FILE_SIZE,
    MAX_JSON_BODY,
    PARTIAL_DIR_NAME,
    PROTOCOL_VERSION,
    SHA256_RE,
    resolve_destination,
    sanitize_filename,
    unique_path,
)

ApproveFn = Callable[[dict], bool]
_READ_BLOCK = 1 << 20
_WEB_DIR = Path(__file__).resolve().parent / "web"
_JS = "application/javascript; charset=utf-8"
_CSS = "text/css; charset=utf-8"
# Dashboard (loopback listener) and browser sender (peer listener) assets.
_DASHBOARD_ASSETS = {"app.js": _JS, "style.css": _CSS}
_SENDER_ASSETS = {"send.js": _JS, "sha256.js": _JS, "style.css": _CSS}
_DASHBOARD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
                  "img-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
_SENDER_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
               "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
               "base-uri 'none'; form-action 'none'")
_LOOPBACK_ADDRS = {"127.0.0.1", "::1"}
_HISTORY_LIMIT = 200


@dataclass
class Transfer:
    transfer_id: str
    name: str
    size: int
    sha256: str
    partial: Path
    sender: str = ""
    started: float = field(default_factory=time.time)


@dataclass
class _Pending:
    pending_id: str
    offer: dict
    created: float
    event: threading.Event = field(default_factory=threading.Event)
    accept: bool = False


class Approvals:
    """Offers waiting for a decision from the local dashboard."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}

    def request(self, offer: dict) -> bool:
        item = _Pending(secrets.token_urlsafe(8), offer, time.time())
        with self._lock:
            self._pending[item.pending_id] = item
        try:
            item.event.wait(self.timeout)   # no answer in time counts as a decline
            return item.accept
        finally:
            with self._lock:
                self._pending.pop(item.pending_id, None)

    def list(self) -> list[dict]:
        with self._lock:
            return [{"id": p.pending_id, **p.offer, "requested_at": p.created}
                    for p in self._pending.values()]

    def decide(self, pending_id: str, accept: bool) -> bool:
        with self._lock:
            item = self._pending.get(pending_id)
        if item is None:
            return False
        item.accept = accept
        item.event.set()
        return True


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _migrate_plain_sessions(directory: Path, vault: Vault) -> None:
    """Move a plaintext trusted-device file from an earlier version into the vault.

    If the file cannot be read, nothing is imported and the file is destroyed:
    devices then pair again. Failing closed is the safe default.
    """
    from .vault import shred
    legacy = directory / "trusted-devices.json"
    if not legacy.exists():
        return
    if not vault.has(VaultStore.ITEM):
        try:
            records = json.loads(legacy.read_text(encoding="utf-8"))
            if isinstance(records, list):
                vault.seal(VaultStore.ITEM, json.dumps(records, indent=2).encode("utf-8"))
        except (OSError, ValueError):
            pass
    shred(legacy)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Keep handshake failures and dropped connections out of the console.
        pass


class ReceiverServer:
    def __init__(
        self,
        save_dir: Path | str,
        approve: ApproveFn | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        device_name: str = "AirBridge",
        max_chunk: int = MAX_CHUNK_SIZE,
        approval_timeout: float = 120.0,
        advertise_url: str | None = None,
        identity_dir: Path | str | None = None,
        key_backend=None,
        passphrase: str | None = None,
        dashboard_port: int = 0,
    ) -> None:
        """If ``approve`` is None, offers wait for the dashboard to accept or decline.

        Peers connect over TLS to ``host:port``. The dashboard is a separate
        plain-HTTP listener bound to 127.0.0.1 only, so it never leaves the
        computer and needs no certificate.
        """
        self.save_dir = Path(save_dir).expanduser().resolve()
        self.partial_dir = self.save_dir / PARTIAL_DIR_NAME
        self.partial_dir.mkdir(parents=True, exist_ok=True)
        self.approve = approve
        self.approvals = Approvals(approval_timeout)
        self.device_name = device_name
        self.max_chunk = max_chunk
        self.advertise_url = advertise_url
        self.discovery_name: str | None = None   # set when mDNS advertising is running
        directory = Path(identity_dir or Path.home() / ".airbridge" / "identity").expanduser()
        self.vault = Vault(directory)
        if key_backend is None:
            key_backend = backend_for(default_backend_name(), passphrase)
        if self.vault.exists():
            self.vault.open(key_backend)
        else:
            self.vault.create(key_backend)
        self.identity = load_or_create_identity(directory, self.vault)
        self.fingerprint = self.identity.fingerprint
        _migrate_plain_sessions(directory, self.vault)
        self.pairing = PairingManager(store=VaultStore(self.vault))
        self._transfers: dict[str, Transfer] = {}
        self._history: collections.deque = collections.deque(maxlen=_HISTORY_LIMIT)
        self._tlock = threading.Lock()   # guards the transfer table and history
        self._io_lock = threading.Lock() # serialises partial-file writes and finalisation
        peer_handler = type("AirBridgePeerHandler", (_Handler,), {
            "owner": self, "serves_peers": True, "serves_dashboard": False, "use_tls": True})
        self._httpd = _Server((host, port), peer_handler)
        self._httpd.socket = server_context(self.identity).wrap_socket(
            self._httpd.socket, server_side=True, do_handshake_on_connect=False)

        dash_handler = type("AirBridgeDashboardHandler", (_Handler,), {
            "owner": self, "serves_peers": False, "serves_dashboard": True, "use_tls": False})
        self._dash = _Server(("127.0.0.1", dashboard_port), dash_handler)
        self._threads: list[threading.Thread] = []

    # ----- lifecycle -------------------------------------------------------
    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def dashboard_port(self) -> int:
        return self._dash.server_address[1]

    def start(self) -> str:
        """Start both listeners in background threads. Returns the first pairing code."""
        code = self.pairing.new_code()
        for srv, name in ((self._httpd, "airbridge-peers"), (self._dash, "airbridge-dashboard")):
            t = threading.Thread(target=srv.serve_forever, daemon=True, name=name)
            t.start()
            self._threads.append(t)
        return code

    def new_pairing_code(self) -> str:
        return self.pairing.new_code()

    def stop(self) -> None:
        if self._threads:  # shutdown() blocks forever on a server that never started
            for srv in (self._httpd, self._dash):
                srv.shutdown()
        for srv in (self._httpd, self._dash):
            srv.server_close()
        # Trusted sessions are kept on purpose: they survive restarts until they
        # expire or are revoked from the dashboard.

    # ----- transfer table (called from handler threads) ---------------------
    def _get(self, tid: str) -> Transfer | None:
        with self._tlock:
            return self._transfers.get(tid)

    def _drop(self, tid: str) -> None:
        with self._tlock:
            self._transfers.pop(tid, None)

    def _record(self, **entry) -> None:
        entry["at"] = time.time()
        with self._tlock:
            self._history.appendleft(entry)

    def register_offer(self, offer: dict) -> dict:
        partial = self.partial_dir / f"{offer['sha256']}-{offer['size']}.part"
        tid = secrets.token_urlsafe(16)
        with self._io_lock:
            offset = _size(partial)
            if offset > offer["size"]:
                partial.unlink(missing_ok=True)
                offset = 0
            with self._tlock:
                # A new offer for the same content supersedes any older one.
                for old_id in [k for k, t in self._transfers.items() if t.partial == partial]:
                    del self._transfers[old_id]
                self._transfers[tid] = Transfer(tid, offer["name"], offer["size"],
                                                offer["sha256"], partial,
                                                sender=offer.get("sender", ""))
        return {"transfer_id": tid, "offset": offset, "max_chunk": self.max_chunk,
                "chunk_size": DEFAULT_CHUNK_SIZE}

    def write_chunk(self, tid: str, offset: int, n: int, rfile) -> tuple[int, dict]:
        with self._io_lock:
            t = self._get(tid)
            if t is None:
                return 404, {"error": "unknown transfer"}
            current = _size(t.partial)
            if offset != current:
                return 409, {"expected_offset": current}
            if offset + n > t.size:
                return 400, {"error": "chunk exceeds declared file size"}
            remaining = n
            with open(t.partial, "ab") as fh:
                while remaining:
                    buf = rfile.read(min(remaining, _READ_BLOCK))
                    if not buf:
                        break
                    fh.write(buf)
                    remaining -= len(buf)
            received = _size(t.partial)
            if remaining:
                return 400, {"error": "incomplete body", "received": received}
            return 200, {"received": received}

    def finalize(self, tid: str) -> tuple[int, dict]:
        with self._io_lock:
            t = self._get(tid)
            if t is None:
                return 404, {"error": "unknown transfer"}
            current = _size(t.partial)
            if current != t.size:
                return 409, {"error": "incomplete", "received": current}
            if current == 0:
                t.partial.touch(exist_ok=True)
            actual = sha256_file(t.partial)
            base = {"name": t.name, "size": t.size, "sender": t.sender}
            if actual != t.sha256:
                t.partial.unlink(missing_ok=True)
                self._drop(tid)
                self._record(status="failed", reason="integrity check failed", **base)
                return 422, {"error": "integrity_check_failed"}
            final = unique_path(resolve_destination(self.save_dir, t.name))
            os.replace(t.partial, final)
            self._drop(tid)
            self._record(status="saved", saved_as=final.name, **base)
            return 200, {"saved_as": final.name, "sha256": actual}

    def status(self, tid: str) -> tuple[int, dict]:
        t = self._get(tid)
        if t is None:
            return 404, {"error": "unknown transfer"}
        return 200, {"name": t.name, "size": t.size, "received": _size(t.partial)}

    def cancel(self, tid: str) -> tuple[int, dict]:
        t = self._get(tid)
        if t is None:
            return 404, {"error": "unknown transfer"}
        self._drop(tid)   # partial file is kept so the transfer can resume
        self._record(status="cancelled", name=t.name, size=t.size, sender=t.sender)
        return 200, {"cancelled": True}

    # ----- dashboard state ------------------------------------------------
    def pairing_link(self) -> str | None:
        """Address of the browser sender with the live code and fingerprint in the fragment.

        The fragment (after #) is never sent to the server, so it stays out of logs.
        """
        code = self.pairing.current_code()
        if not self.advertise_url or code is None:
            return None
        return f"{self.advertise_url}/send#c={code}&f={self.fingerprint}"

    def pairing_qr_svg(self) -> str | None:
        link = self.pairing_link()
        if link is None:
            return None
        try:
            return to_svg(qr_encode(link))
        except QRTooLong:
            return None

    def revoke_device(self, session_id: str) -> bool:
        return self.pairing.revoke(session_id)

    def admin_state(self) -> dict:
        with self._tlock:
            active = [{"id": t.transfer_id, "name": t.name, "size": t.size,
                       "sender": t.sender, "received": _size(t.partial),
                       "started": t.started}
                      for t in self._transfers.values()]
            history = list(self._history)
        return {
            "device": self.device_name,
            "save_dir": str(self.save_dir),
            "advertise_url": self.advertise_url,
            "fingerprint": self.fingerprint,
            "discovery": self.discovery_name,
            "pairing": {"code": self.pairing.current_code(),
                        "seconds_left": self.pairing.code_seconds_left()},
            "pending": self.approvals.list(),
            "active": active,
            "history": history,
            "devices": self.pairing.list_sessions(),
        }


class _Handler(BaseHTTPRequestHandler):
    owner: ReceiverServer
    serves_peers: bool = True
    serves_dashboard: bool = False
    use_tls: bool = False
    server_version = "AirBridge/1"
    sys_version = ""
    timeout = 60  # seconds; stops a stalled peer from holding a thread forever

    def setup(self):
        super().setup()
        if self.use_tls:
            # Handshake here, in the per-connection thread, so a silent client
            # cannot stall the accept loop. The socket timeout bounds it.
            self.request.do_handshake()

    def log_message(self, fmt, *args):  # never log paths, headers or tokens
        return

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    # ----- plumbing --------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: dict) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json")

    def _content_length(self) -> int:
        try:
            n = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            raise ValueError("invalid Content-Length")
        if n < 0:
            raise ValueError("Content-Length required")
        return n

    def _read_json(self) -> dict:
        n = self._content_length()
        if n > MAX_JSON_BODY:
            raise ValueError("request body too large")
        obj = json.loads(self.rfile.read(n) or b"null")
        if not isinstance(obj, dict):
            raise ValueError("expected a JSON object")
        return obj

    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if self.owner.pairing.is_valid(token):
            return True
        self._json(401, {"error": "pairing required"})
        return False

    def _admin_host_ok(self) -> bool:
        port = self.server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        return self.client_address[0] in _LOOPBACK_ADDRS and self.headers.get("Host", "") in allowed

    def _admin_api_ok(self) -> bool:
        if self._admin_host_ok() and self.headers.get("X-AirBridge-Admin") == "1":
            return True
        self._json(403, {"error": "dashboard access only from this computer"})
        return False

    def _dispatch(self, method: str) -> None:
        url = urlsplit(self.path)
        parts = [p for p in url.path.split("/") if p]
        try:
            if self.serves_dashboard and (not parts or parts[0] in ("admin", "static")):
                return self._dashboard(method, parts)
            if self.serves_peers and (parts[:1] == ["send"] or parts[:1] == ["static"]):
                return self._sender_page(method, parts)
            if self.serves_peers and parts[:1] == ["v1"]:
                return self._route(method, parts, parse_qs(url.query))
            return self._json(404, {"error": "not found"})
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            self._json(500, {"error": "internal error"})

    def _route(self, method: str, parts: list[str], query: dict) -> None:
        if parts[:1] != ["v1"]:
            return self._json(404, {"error": "not found"})
        rest = parts[1:]
        if method == "GET" and rest == ["info"]:
            return self._json(200, {"device": self.owner.device_name,
                                    "protocol": PROTOCOL_VERSION,
                                    "capabilities": ["file-transfer"]})
        if method == "POST" and rest == ["pair"]:
            return self._pair()
        if method == "POST" and rest == ["offers"]:
            return self._offer()
        if len(rest) == 2 and rest[0] == "transfers":
            if method == "GET":
                return self._with_auth(lambda: self._json(*self.owner.status(rest[1])))
            if method == "DELETE":
                return self._with_auth(lambda: self._json(*self.owner.cancel(rest[1])))
        if len(rest) == 3 and rest[0] == "transfers":
            if method == "PUT" and rest[2] == "data":
                return self._put_data(rest[1], query)
            if method == "POST" and rest[2] == "complete":
                return self._with_auth(lambda: self._json(*self.owner.finalize(rest[1])))
        self._json(404, {"error": "not found"})

    def _with_auth(self, action) -> None:
        if self._authorized():
            action()

    # ----- peer endpoints --------------------------------------------------
    def _pair(self) -> None:
        body = self._read_json()
        raw_label = str(body.get("device", ""))
        label = "".join(ch for ch in raw_label if ch.isprintable()).strip()[:64] or "Unnamed device"
        try:
            token = self.owner.pairing.redeem(str(body.get("code", "")), label)
        except PairingError as exc:
            return self._json(403, {"error": str(exc)})
        self._json(200, {"token": token, "protocol": PROTOCOL_VERSION,
                         "device": self.owner.device_name})

    def _offer(self) -> None:
        if not self._authorized():
            return
        body = self._read_json()
        name = sanitize_filename(body.get("name"))
        size = body.get("size")
        sha = body.get("sha256")
        if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
            raise ValueError("invalid size")
        if not isinstance(sha, str) or not SHA256_RE.fullmatch(sha):
            raise ValueError("invalid sha256")
        offer = {"name": name, "size": size, "sha256": sha,
                 "sender": self.client_address[0]}
        if self.owner.approve is not None:
            try:
                accepted = bool(self.owner.approve(offer))
            except Exception:
                accepted = False
        else:
            accepted = self.owner.approvals.request(offer)
        if not accepted:
            self.owner._record(status="declined", name=name, size=size,
                               sender=offer["sender"])
            return self._json(403, {"error": "rejected"})
        self._json(200, self.owner.register_offer(offer))

    def _put_data(self, tid: str, query: dict) -> None:
        if not self._authorized():
            return
        try:
            offset = int(query.get("offset", [""])[0])
        except ValueError:
            raise ValueError("invalid offset")
        n = self._content_length()
        if offset < 0 or n < 0:
            raise ValueError("invalid range")
        if n > self.owner.max_chunk:
            # Drain a bounded amount so the client can read our reply instead
            # of hitting a broken pipe; refuse anything beyond that outright.
            drain = min(n, 2 * self.owner.max_chunk)
            while drain > 0:
                block = self.rfile.read(min(drain, _READ_BLOCK))
                if not block:
                    break
                drain -= len(block)
            return self._json(413, {"error": "chunk too large"})
        status, body = self.owner.write_chunk(tid, offset, n, self.rfile)
        self._json(status, body)

    # ----- browser sender page (peer listener, no secrets) ----------------
    def _sender_page(self, method: str, parts: list[str]) -> None:
        if method != "GET":
            return self._json(404, {"error": "not found"})
        if parts == ["send"]:
            body = (_WEB_DIR / "send.html").read_bytes()
            return self._send(200, body, "text/html; charset=utf-8", {
                "Content-Security-Policy": _SENDER_CSP,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            })
        if len(parts) == 2 and parts[0] == "static" and parts[1] in _SENDER_ASSETS:
            body = (_WEB_DIR / parts[1]).read_bytes()
            return self._send(200, body, _SENDER_ASSETS[parts[1]], {
                "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})
        self._json(404, {"error": "not found"})

    # ----- dashboard (loopback listener only) -------------------------------
    def _dashboard(self, method: str, parts: list[str]) -> None:
        if not self._admin_host_ok():
            return self._json(404, {"error": "not found"})
        if method == "GET" and parts == []:
            body = (_WEB_DIR / "index.html").read_bytes()
            return self._send(200, body, "text/html; charset=utf-8", {
                "Content-Security-Policy": _DASHBOARD_CSP,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            })
        if method == "GET" and len(parts) == 2 and parts[0] == "static" and parts[1] in _DASHBOARD_ASSETS:
            body = (_WEB_DIR / parts[1]).read_bytes()
            return self._send(200, body, _DASHBOARD_ASSETS[parts[1]], {
                "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})
        if parts[:1] != ["admin"]:
            return self._json(404, {"error": "not found"})
        if not self._admin_api_ok():
            return
        if method == "GET" and parts == ["admin", "state"]:
            return self._json(200, self.owner.admin_state())
        if method == "GET" and parts == ["admin", "qr"]:
            svg = self.owner.pairing_qr_svg()
            if svg is None:
                return self._json(404, {"error": "no active pairing code or address"})
            return self._send(200, svg.encode("utf-8"), "image/svg+xml", {
                "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})
        if method == "POST" and parts == ["admin", "code"]:
            code = self.owner.new_pairing_code()
            return self._json(200, {"code": code, "seconds_left": 300})
        if method == "POST" and len(parts) == 4 and parts[1] == "offers" and parts[3] in ("accept", "decline"):
            ok = self.owner.approvals.decide(parts[2], parts[3] == "accept")
            return self._json(200 if ok else 404, {"ok": ok})
        if method == "POST" and len(parts) == 4 and parts[1] == "devices" and parts[3] == "revoke":
            ok = self.owner.revoke_device(parts[2])
            return self._json(200 if ok else 404, {"ok": ok})
        self._json(404, {"error": "not found"})

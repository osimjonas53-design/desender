"""Command-line entry point: ``airbridge receive`` and ``airbridge send``."""
from __future__ import annotations

import argparse
import getpass
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path

from .client import Sender, TransferError
from .protocol import DEFAULT_CHUNK_SIZE
from .discovery import Advertisement, Responder, browse, clean_instance, search
from .server import ReceiverServer
from .qr import encode as qr_encode, to_text
from .tls import format_fingerprint, normalise_fingerprint
from .vault import Vault, VaultError, backend_for, default_backend_name

DEFAULT_PORT = 8765
_prompt_lock = threading.Lock()


def _lan_ip() -> str:
    """Best-effort LAN address (UDP connect sends no packets)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


PASSPHRASE_ENV = "AIRBRIDGE_PASSPHRASE"


def _key_backend(args: argparse.Namespace):
    """Choose how the receiver's secrets are protected, asking for a passphrase if needed."""
    directory = Path(args.identity_dir or Path.home() / ".airbridge" / "identity").expanduser()
    name = default_backend_name() if args.key_store == "auto" else args.key_store
    if name != "passphrase":
        return backend_for(name)
    passphrase = os.environ.get(PASSPHRASE_ENV)
    if passphrase is None:
        if not sys.stdin.isatty():
            raise VaultError(f"no terminal to ask for the vault passphrase; set {PASSPHRASE_ENV}")
        if Vault(directory).exists():
            passphrase = getpass.getpass("Vault passphrase: ")
        else:
            print("Creating the receiver's encrypted key store.")
            print("Choose a passphrase. It is needed every time the receiver starts,")
            print("and it cannot be recovered if lost.")
            passphrase = getpass.getpass("New passphrase: ")
            if getpass.getpass("Repeat passphrase: ") != passphrase:
                raise VaultError("the passphrases did not match")
    if not passphrase:
        raise VaultError("the passphrase cannot be empty")
    return backend_for("passphrase", passphrase)


def cmd_receive(args: argparse.Namespace) -> int:
    try:
        key_backend = _key_backend(args)
    except VaultError as exc:
        print(f"Cannot unlock the receiver's key store: {exc}", file=sys.stderr)
        return 3

    approve = None
    if args.yes:
        def approve(offer: dict) -> bool:
            print(f"[auto-accept] {offer['name']} ({offer['size']} bytes) from {offer['sender']}",
                  file=sys.stderr)
            return True

    shown_host = _lan_ip() if args.host == "0.0.0.0" else args.host
    try:
        server = ReceiverServer(args.dir, approve, host=args.host, port=args.port,
                                device_name=args.name,
                                advertise_url=f"https://{shown_host}:{args.port}",
                                identity_dir=args.identity_dir,
                                dashboard_port=args.dashboard_port,
                                key_backend=key_backend)
    except VaultError as exc:
        print(f"Cannot unlock the receiver's key store: {exc}", file=sys.stderr)
        return 3
    code = server.start()
    responder = _start_discovery(args, server, shown_host)
    print(f"AirBridge receiver '{args.name}' listening on https://{shown_host}:{server.port}")
    print(f"Pairing code: {code}  (valid 5 minutes, single use)")
    print(f"Device fingerprint: {format_fingerprint(server.fingerprint)}")
    print("Give the sender both the code and the fingerprint.")
    link = server.pairing_link()
    if link:
        print(f"Phone or browser: scan the code below, or open {link}")
        try:
            print(to_text(qr_encode(link)))
        except ValueError:
            print("(address too long to draw as a QR code; use the pairing code instead)")
    print(f"Saving to: {server.save_dir}")
    if not args.yes:
        print(f"Dashboard (on this computer only): http://127.0.0.1:{server.dashboard_port}/")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        if responder is not None:
            responder.stop()
        server.stop()
    return 0


def _start_discovery(args: argparse.Namespace, server: ReceiverServer, address: str):
    """Advertise this receiver on the LAN. Returns the responder, or None."""
    if args.no_discovery:
        print("Discovery: off (senders must use the address and code)")
        return None
    if args.host != "0.0.0.0":
        print("Discovery: off (listening on one interface only; use --host 0.0.0.0 to advertise)")
        return None
    ad = Advertisement(
        instance=clean_instance(args.name),
        host=f"airbridge-{server.fingerprint[:8]}.local",
        address=address,
        port=server.port,
        txt={"proto": "1", "id": server.fingerprint[:8], "caps": "file-transfer"},
    )
    responder = Responder(ad)
    try:
        responder.start()
    except OSError as exc:
        print(f"Discovery: could not start on UDP 5353 ({exc}); senders must use the address")
        return None
    server.discovery_name = ad.instance
    print(f"Discovery: visible to senders on this network as '{ad.instance}' (id {server.fingerprint[:8]})")
    return responder


def _looks_like_address(text: str) -> bool:
    if "://" in text or ":" in text:
        return True
    return bool(re.fullmatch(r"[0-9.]+|localhost|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", text))


def resolve_target(text: str, timeout: float = 3.0) -> tuple[str, dict | None]:
    """Return (address, discovered-record). Names are looked up on the LAN."""
    if _looks_like_address(text):
        return text, None
    found = search(browse(timeout=timeout), text)
    exact = [f for f in found if f.instance.lower() == text.strip().lower()]
    if len(exact) == 1:
        found = exact
    if not found:
        raise TransferError(f"no receiver named '{text}' found on this network. "
                            "Check that it is running and that both devices are on the same Wi-Fi.")
    if len(found) > 1:
        names = "; ".join(f"{f.instance} at {f.address}:{f.port} (id {f.txt.get('id', '?')})" for f in found)
        raise TransferError(f"'{text}' matches {len(found)} receivers: {names}. "
                            "Use one of the addresses above instead.")
    item = found[0]
    return f"{item.address}:{item.port}", {"instance": item.instance, "id": item.txt.get("id", "")}


def cmd_find(args: argparse.Namespace) -> int:
    found = search(browse(timeout=args.timeout), args.search or "")
    if not found:
        print("No receivers found. Check that the receiver is running and that both devices are on "
              "the same network. Guest Wi-Fi networks often block device-to-device traffic.")
        return 1
    print(f"{'Name':<28} {'Address':<22} ID")
    for f in found:
        print(f"{f.instance[:27]:<28} {f.address + ':' + str(f.port):<22} {f.txt.get('id', '?')}")
    print("Check the ID against the receiver's fingerprint before you pair.")
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    code = args.code or input("Pairing code: ").strip()
    fingerprint = args.fp or input("Device fingerprint: ").strip()
    try:
        address, discovered = resolve_target(args.to)
        if discovered:
            fp_norm = normalise_fingerprint(fingerprint)
            if discovered["id"] and not fp_norm.startswith(discovered["id"].lower()):
                raise TransferError(
                    f"the device named '{discovered['instance']}' on the network has id {discovered['id']}, "
                    "which does not match the fingerprint you entered. Do not pair with it.")
            print(f"Found '{discovered['instance']}' at {address} (id {discovered['id']})")
        sender = Sender(address, fingerprint=fingerprint, chunk_size=args.chunk_size)
        sender.pair(code, device_name=socket.gethostname())
    except (TransferError, ValueError) as exc:
        print(f"Pairing failed: {exc}", file=sys.stderr)
        return 2

    failures = 0
    for name in args.files:
        def progress(done: int, total: int, label: str = Path(name).name) -> None:
            pct = 100.0 * done / total if total else 100.0
            print(f"\r{label}: {pct:5.1f}%", end="", file=sys.stderr, flush=True)
        print(f"Waiting for approval on the receiver: {Path(name).name}", file=sys.stderr)
        try:
            result = sender.send_file(name, progress=progress)
        except TransferError as exc:
            print(f"\nFAILED {name}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"\nSaved on receiver as '{result['saved_as']}' "
              f"(sha256 {result['sha256'][:16]}...)")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="airbridge",
                                     description="Wi-Fi file transfer over the local network.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    recv = sub.add_parser("receive", help="accept files from devices on this network")
    recv.add_argument("--dir", default="~/AirBridge", help="folder to save into")
    recv.add_argument("--host", default="0.0.0.0", help="interface to listen on")
    recv.add_argument("--port", type=int, default=DEFAULT_PORT)
    recv.add_argument("--name", default=socket.gethostname(), help="display name")
    recv.add_argument("--identity-dir", default=None,
                      help="where the device certificate is stored (default ~/.airbridge/identity)")
    recv.add_argument("--dashboard-port", type=int, default=8766,
                      help="loopback port for the dashboard (0 = pick one)")
    recv.add_argument("--key-store", choices=["auto", "passphrase", "dpapi", "keychain"],
                      default="auto",
                      help="how the private key is protected (auto: DPAPI on Windows, "
                           "Keychain on macOS, passphrase elsewhere)")
    recv.add_argument("--no-discovery", action="store_true",
                      help="do not advertise this receiver on the local network")
    recv.add_argument("--yes", action="store_true",
                      help="accept every offer without prompting (trusted networks only)")

    send = sub.add_parser("send", help="send files to a receiver")
    send.add_argument("--to", required=True,
                      help="receiver name (found on the network) or address, e.g. 192.168.1.20:8765")
    send.add_argument("--code", help="pairing code shown by the receiver")
    send.add_argument("--fp", help="device fingerprint shown by the receiver (16 hex characters)")
    send.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    send.add_argument("files", nargs="+")

    find = sub.add_parser("find", help="list receivers on this network")
    find.add_argument("--search", default="", help="filter by name, id or address")
    find.add_argument("--timeout", type=float, default=3.0)

    args = parser.parse_args(argv)
    if args.cmd == "receive":
        return cmd_receive(args)
    if args.cmd == "find":
        return cmd_find(args)
    return cmd_send(args)

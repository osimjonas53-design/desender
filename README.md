# AirBridge

Local Wi-Fi file transfer. Files move directly between devices on the same
network, with no cloud upload.

**Status: v0.6.0.** Working and tested: the transfer engine, TLS with
fingerprint pinning, a receiver dashboard, QR pairing, trusted-device
revocation, a browser sender that works from a phone or any modern browser,
LAN discovery so senders can find receivers by name, and encryption at rest for
the receiver's private key and trusted-device store. Still missing: native
mobile and desktop apps, casting, installers, and platform key stores that
have been run on Windows and macOS. See "Not implemented".

## What works today

| Capability | Evidence |
|---|---|
| Pairing with a 6-digit single-use code (5 min, 5-attempt lockout) | `test_core.py`, `test_transfer.py` |
| TLS 1.2+ for all peer traffic, with certificate pinning by fingerprint | `test_tls.py`, CLI check |
| Chunked, resumable upload with SHA-256 verification before save | `test_transfer.py` |
| Atomic save; a failed hash discards the partial data | `test_transfer.py` |
| Accept and decline from the receiver dashboard, with a 2-minute timeout | `test_dashboard.py`, `scripts/ui_smoke.js` |
| QR pairing: the receiver shows a QR code that opens the browser sender with the code and fingerprint filled in | `test_qr.py` (decoded by an independent decoder), `scripts/sender_smoke.js` |
| Browser sender: pair, hash in the browser, send with approval, verify | `test_sender_and_devices.py`, `scripts/sender_smoke.js` |
| Browser SHA-256 matches the reference for every padding edge case | `test_sha256_js.py` (checked against Node's crypto) |
| Trusted devices persist across restarts, with revocation from the dashboard | `test_pairing_store.py`, `test_sender_and_devices.py` |
| Dashboard and sender pages run under strict Content-Security-Policy | `scripts/ui_smoke.js`, `scripts/sender_smoke.js` |
| LAN discovery over mDNS/DNS-SD: receivers advertise `_airbridge._tcp.local`; `find` lists them; `send --to "<name>"` resolves a name | `test_discovery.py`, cross-process check on the standard port 5353 |
| Name resolution refuses ambiguous names and any device whose ID does not match the fingerprint | `test_discovery.py` |
| Private key and trusted-device store sealed with AES-256-GCM; no plaintext secret left on disk | `test_vault.py`, `test_tls.py`, upgrade run from v0.5 |
| Tampered, renamed or truncated vault files are refused; a wrong passphrase is refused | `test_vault.py` |
| Plaintext key and sessions from v0.5 migrate in place with the same fingerprint | `test_tls.py`, `test_vault.py`, real upgrade from v0.5 |

## Test results

Python unit and integration tests:

```
PYTHONPATH=src python3 -m unittest discover -s tests -t .
Ran 158 tests in 80.5s
OK
```

Browser checks (need `playwright` and a Chromium it can launch):

```
node scripts/ui_smoke.js     <dir-with-airbridge-package> <port> <workdir>   # dashboard
node scripts/sender_smoke.js <dir-with-airbridge-package> <port> <workdir>   # QR pairing, browser upload, revocation
```

Both passed on the final build. Other browsers and phones were not tested.

Problems found and fixed in the discovery work: the responder first sent only
the PTR record, so browsers found nothing. Browse answers now include the SRV,
TXT and A records. Discovery was checked between two processes on this
machine, not between two physical devices.

Problems found and fixed during the QR and browser release: the browser sender cleared its
own progress rows after creating them; the dashboard's progress bars were
blocked by the Content-Security-Policy; a file edit in this release removed a
large part of the server module, which was restored from git and reapplied
with checks. The test suite would not have caught the first problem alone, so
the browser test was extended to cover it.

## Key store

The receiver's private TLS key and its trusted-device list are encrypted at
rest. They are sealed with AES-256-GCM under a random data key, stored in
`~/.airbridge/identity/`. The data key is protected by a backend:

| Backend | Used on | Status |
|---|---|---|
| `passphrase` | Linux, and any platform when chosen | Tested. scrypt derives a key from your passphrase, which wraps the data key. |
| `dpapi` | Windows (default) | **Written, not run.** Uses the Windows Data Protection API under your user account. |
| `keychain` | macOS (default) | **Written, not run.** Stores the data key in the macOS Keychain. The `security` tool gets the value as an argument, so other processes of the same user can briefly see it. |

The first run creates the vault and asks you to choose and repeat a passphrase.
Every later start asks for it. If you lose the passphrase, the receiver's key
cannot be recovered, and the device must be given a new identity, which changes
its fingerprint.

For unattended services, set `AIRBRIDGE_PASSPHRASE` in the service
environment. Anyone who can read that environment can unlock the receiver's
key, so protect the service definition as you would a password.

Choose the backend explicitly with `--key-store passphrase|dpapi|keychain`.
An existing vault keeps the backend it was created with. Switching needs a
new identity.

The private key is decrypted only while TLS is being set up. It is written to a
private temporary directory, loaded, and overwritten and deleted at once.
Overwriting is best effort on journaled file systems and on SSDs with wear
levelling, so the protection depends on the disk encryption of the machine too.

**Upgrading from v0.5.** Start the receiver with the new version and the same
`--identity-dir`. The plaintext key and trusted-device file are sealed and then
overwritten and deleted. The fingerprint does not change, and trusted devices
keep working. Tested with a real v0.5 receiver.

## Install

Python 3.12 is what the project was developed and tested on.

```bash
pip install -r requirements.txt        # cryptography: device certificate
pip install -r requirements-dev.txt    # optional: OpenCV decodes QR codes in the tests
```

## Receive

```bash
PYTHONPATH=src python3 -m airbridge receive --dir ~/AirBridge --name "Living room PC"
```

The receiver prints:

- a 6-digit pairing code, valid once for five minutes;
- a device fingerprint, 16 hex characters;
- a QR code in the terminal, and a link to the browser sender;
- the dashboard address, which works only on this computer.

Open the dashboard on the receiving computer to approve or decline each file,
to create a new code, to see paired devices, and to revoke them. The dashboard
does not answer requests from other devices.

## Find receivers by name

```bash
PYTHONPATH=src python3 -m airbridge find                 # list receivers on this network
PYTHONPATH=src python3 -m airbridge find --search living # filter by name, id or address
```

A receiver advertises itself while it runs, with its display name, port, and a
short fingerprint prefix called the ID. Pass `--no-discovery` to the receiver to
stay invisible. Discovery only works when `--host 0.0.0.0` is used, because the
receiver must advertise a LAN address.

Discovery finds addresses. It does not establish trust. Anyone on the network
can advertise any name. Before you pair, check that the ID the sender shows
matches the start of the receiver's fingerprint. The sender refuses to pair if
the ID doesn't match the fingerprint you enter.

## Send from the command line

```bash
PYTHONPATH=src python3 -m airbridge send --to 192.168.1.20:8765 \
    --code 784471 --fp ba75-20c5-5943-9499 photo.jpg movie.mp4

# or by name, when the receiver is discoverable
PYTHONPATH=src python3 -m airbridge send --to "Living room PC" \
    --code 784471 --fp ba75-20c5-5943-9499 photo.jpg
```

The sender refuses to send anything if the fingerprint doesn't match the
receiver's certificate.

## Send from a phone or browser

1. Scan the receiver's QR code with the phone's camera, or open the browser
   link the receiver prints.
2. The page fills in the code and fingerprint. Before you pair, open the
   browser's certificate details for the page. Check that its **SHA-256
   fingerprint** starts with the fingerprint on the receiver's screen, then tick
   the box and press Pair.
3. Choose files and press Send. Approve each one on the receiver.

The browser can't pin the certificate as the command-line sender does. The
fingerprint check is done by you, in the browser's certificate details. If you
skip it, a device that can intercept your Wi-Fi traffic could read the pairing
code and your files. Treat this as weaker than the command-line sender.

## Protocol (v1)

Full description in the module docstring of `src/airbridge/server.py`. All peer
traffic is TLS 1.2 or newer. The sender checks the receiver's fingerprint before
sending anything, including the pairing code.

1. `POST /v1/pair {code, device}` returns a bearer token. The code is consumed.
2. `POST /v1/offers {name, size, sha256}` waits for approval and returns a
   `transfer_id` and the byte `offset` to resume from.
3. `PUT /v1/transfers/{id}/data?offset=N` uploads one chunk. The server accepts
   only the offset it already holds.
4. `POST /v1/transfers/{id}/complete` hashes the partial file and saves it
   atomically, or returns 422 and discards it.
5. `GET /v1/transfers/{id}` reports progress; `DELETE` cancels and keeps the
   partial data for a later resume.

Partial files are named `<sha256>-<size>.part` in `.airbridge-partial/`. The
sender's file name never affects where bytes are written.

The browser sender page is served on the peer port at `/send`. It has no secrets
and no admin functions. The dashboard is on a second port bound to 127.0.0.1.

## Security model

- **Identity.** Each receiver has a self-signed certificate, created on first run.
  The certificate is public. The private key is sealed in the vault (see Key store).
- **Pinning.** The fingerprint is the first 64 bits of SHA-256 over the DER
  certificate. Command-line senders check it on every connection. Browser senders
  depend on the user doing the check described above.
- **Trusted devices.** A successful pairing creates a session that lasts eight
  hours. Only a hash of each session token is stored, in
  `~/.airbridge/identity/trusted-devices.enc`, sealed in the vault. Sessions survive
  restarts. The dashboard lists them and revokes them.
- **Consent.** Nothing is written to disk until the receiver approves the offer.
- **Path safety.** Names are reduced to a single safe component. Symlink escapes
  are refused. Collisions are renamed, never overwritten.
- **Dashboard.** Answers only the loopback address, only when the Host header
  names localhost (this blocks DNS rebinding), and only with a custom header that
  browsers won't send cross-site without a CORS preflight, which is never granted.
  Its policy forbids inline scripts and styles.
- **Limits.** Chunks, bodies and JSON have size caps. Sockets time out. Logs
  contain no tokens, file names or paths.

## Known limits

- The pairing code has 6 digits. Lockout and expiry make guessing unlikely, but
  a longer secret in the QR code would be stronger.
- Revocation takes effect on the next request from that device. It does not
  notify the device.
- Discovery advertises the receiver's display name, port, protocol version,
  capability list, and ID (the first 8 characters of its fingerprint). Anyone on
  the same network can see these while the receiver runs. Use `--no-discovery`
  if that is not acceptable.
- Discovery answers only queries from private, loopback or link-local addresses.
  It publishes one IPv4 address, so a receiver on several networks advertises
  just one of them.
- Browsers cannot browse mDNS. The browser sender therefore finds receivers only
  through the QR code or the address. Native apps would use Android NSD or
  Bonjour instead.
- On Windows, the firewall may block mDNS traffic on the private network. Native
  Android apps need a multicast lock to receive mDNS replies. Neither was tested
  on those platforms.
- The DPAPI and Keychain backends have not been run. Before relying on them,
  test a receiver on Windows and on macOS: first run, restart, and an upgrade
  from the passphrase store. Until then the passphrase backend is the one that
  is verified.
- Trusted sessions now persist across restarts. Stopping the receiver no longer
  signs out trusted devices. Sessions still expire after eight hours, and they
  can be revoked from the dashboard.
- Secure deletion of the temporary key and the old plaintext files is best
  effort. It is not a guarantee on SSDs or journaling file systems.
- Completion hashing and writes share one lock. A very large file blocks other
  transfers while it is hashed.
- The QR encoder supports byte mode, error-correction level M, versions 1 to 5
  (up to 84 bytes). Longer payloads fall back to typing the code.
- History and approvals are in memory. History is lost on restart. Trusted
  devices are kept.
- The browser sender has been tested in headless Chromium only. Phones were not
  tested. Browsers differ in how they show certificate details.
- TLS has been tested between this program and browsers. It has not been tested
  against other command-line TLS clients.

## Not implemented

- Native Android, iOS, Windows and macOS applications. The build environment has
  no Flutter, Android SDK, Xcode or Swift toolchain, so nothing for those
  platforms has been compiled or tested.
- Casting: Google Cast, AirPlay, DLNA/UPnP and the TV receiver. These need
  developer accounts, certified hardware or platform entitlements that are not
  available here.
- Sender pause and resume controls; a persistent transfer history; configurable
  save locations from the dashboard; notifications.
- Packaging, code signing and store submission.
- Android Keystore and iOS Keychain for the native apps, which do not exist yet.
- Browser discovery (a browser cannot browse mDNS).
- Packaging of the web assets: `src/airbridge/web/` must be shipped with the
  package. That is not configured yet, because there is no `pyproject.toml`.

## Recommended next steps, in order

1. Run the DPAPI and Keychain backends on real Windows and macOS machines and fix
   what they reveal.
2. Choose the mobile stack (Flutter is recommended in the brief). Port the
   protocol and pinning logic. Reuse the Python tests as conformance vectors for
   the new implementation, and reuse `scripts/sender_smoke.js` as a browser
   regression.
3. Add a `pyproject.toml` that packages the web assets.
4. Add a persistent transfer history and configurable save locations.

## Layout

```
src/airbridge/
  protocol.py   constants, filename sanitisation, destination confinement, collision policy
  integrity.py  streaming SHA-256
  vault.py      encrypted storage: AES-256-GCM sealed items under a data key; passphrase, DPAPI and Keychain backends
  pairing.py    pairing codes, revocable device sessions, persistence in the vault
  discovery.py  mDNS/DNS-SD: wire format, receiver responder, sender browser
  tls.py        device certificate, fingerprints, pinned client context
  qr.py         QR encoder (byte mode, EC level M, versions 1-5), SVG and terminal output
  server.py     receiver: TLS peer listener, loopback dashboard listener, transfer state
  client.py     command-line sender: pinned TLS, chunked resumable upload, retry
  cli.py        receive / send commands
  web/          dashboard (index.html, app.js) and browser sender (send.html, send.js, sha256.js)
tests/
  test_core.py            sanitisation, destinations, collisions, pairing basics
  test_transfer.py        end-to-end transfer tests over real sockets
  test_dashboard.py       dashboard access controls and approval flow
  test_tls.py             pinning, impostor rejection, listener separation
  test_pairing_store.py   sessions, revocation, persistence, expiry
  test_qr.py              QR encoder checked by an independent decoder
  test_sender_and_devices.py  browser sender page, QR endpoint, device revocation
  test_sha256_js.py       browser SHA-256 checked against Node's crypto
  test_discovery.py       wire format, hostile input, responder rules, name resolution
  test_vault.py           sealing, tamper and rename detection, lock state, no plaintext on disk, restart, upgrade
scripts/
  ui_smoke.js             dashboard in a real browser
  sender_smoke.js         QR pairing, browser upload, revocation in a real browser
```

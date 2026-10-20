"""Sender side: pair with a receiver and upload a file in resumable chunks."""
from __future__ import annotations

import http.client
import json
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .integrity import sha256_file
from .protocol import DEFAULT_CHUNK_SIZE, PROTOCOL_VERSION
from .tls import PinMismatch, check_pin, normalise_fingerprint, pinned_client_context


class TransferError(Exception):
    pass


class PinRejected(TransferError):
    """The receiver's certificate did not match the fingerprint provided."""


class _PinnedConnection(http.client.HTTPSConnection):
    """HTTPS connection that refuses to send anything unless the peer's certificate is pinned."""

    def __init__(self, host: str, port: int, timeout: float, fingerprint: str) -> None:
        super().__init__(host, port, timeout=timeout, context=pinned_client_context())
        self._fingerprint = fingerprint

    def connect(self) -> None:
        super().connect()
        try:
            check_pin(self.sock.getpeercert(binary_form=True), self._fingerprint)
        except PinMismatch as exc:
            self.sock.close()
            raise PinRejected(str(exc)) from None


class PairingRejected(TransferError):
    pass


class TransferRejected(TransferError):
    pass


class IntegrityError(TransferError):
    pass


class Sender:
    def __init__(
        self,
        base_url: str,
        *,
        fingerprint: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        timeout: float = 20.0,
        offer_timeout: float = 150.0,
        max_retries: int = 6,
        backoff: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        url = base_url if "://" in base_url else f"https://{base_url}"
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("receiver address must be https://host:port (or host:port)")
        self.host = parts.hostname
        self.port = parts.port or 8765
        self.fingerprint = normalise_fingerprint(fingerprint)
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.offer_timeout = offer_timeout  # receiver may wait for a human to approve
        self.max_retries = max_retries
        self.backoff = backoff
        self.sleep = sleep
        self.token: str | None = None
        self.put_offsets: list[int] = []   # offsets of every chunk PUT, for diagnostics

    # ----- HTTP helper -----------------------------------------------------
    def _request(self, method: str, path: str, body: bytes | None = None,
                 json_body: dict | None = None, timeout: float | None = None) -> tuple[int, dict]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn = _PinnedConnection(self.host, self.port, timeout or self.timeout, self.fingerprint)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        finally:
            conn.close()
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        return resp.status, payload

    # ----- public API ------------------------------------------------------
    def pair(self, code: str, device_name: str = "") -> None:
        status, body = self._request("POST", "/v1/pair",
                                     json_body={"code": code, "device": device_name})
        if status != 200:
            raise PairingRejected(body.get("error", f"pairing failed ({status})"))
        if body.get("protocol") != PROTOCOL_VERSION:
            raise TransferError("receiver speaks an incompatible protocol version")
        self.token = body["token"]

    def send_file(self, path: Path | str, progress: Callable[[int, int], None] | None = None) -> dict:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(str(path))
        if self.token is None:
            raise PairingRejected("not paired with a receiver")

        size = path.stat().st_size
        digest = sha256_file(path)
        try:
            status, body = self._request("POST", "/v1/offers",
                                         json_body={"name": path.name, "size": size, "sha256": digest},
                                         timeout=self.offer_timeout)
        except (OSError, http.client.HTTPException) as exc:
            raise TransferError("receiver did not answer the offer; is it still running?") from exc
        if status == 401:
            raise PairingRejected("session expired; pair again")
        if status == 403:
            raise TransferRejected("the receiver declined this file")
        if status != 200:
            raise TransferError(body.get("error", f"offer failed ({status})"))

        tid: str = body["transfer_id"]
        offset: int = body["offset"]
        step = min(self.chunk_size, int(body.get("max_chunk", self.chunk_size)))
        self.put_offsets = []
        failures = 0
        need_sync = False

        with path.open("rb") as fh:
            while offset < size:
                try:
                    if need_sync:
                        offset = self._sync_offset(tid)
                        need_sync = False
                        continue
                    fh.seek(offset)
                    chunk = fh.read(min(step, size - offset))
                    self.put_offsets.append(offset)
                    st, resp = self._request("PUT", f"/v1/transfers/{tid}/data?offset={offset}",
                                             body=chunk)
                    if st == 200:
                        offset = int(resp["received"])
                        failures = 0
                    elif st == 409:
                        offset = int(resp["expected_offset"])
                    elif st == 400 and "received" in resp:
                        raise ConnectionError("upload interrupted mid-chunk")
                    elif st == 404:
                        raise TransferError("receiver no longer knows this transfer")
                    else:
                        raise TransferError(resp.get("error", f"upload failed ({st})"))
                except (OSError, http.client.HTTPException) as exc:
                    failures += 1
                    if failures > self.max_retries:
                        raise TransferError("connection lost; the transfer can be resumed later") from exc
                    need_sync = True
                    self.sleep(min(self.backoff * (2 ** (failures - 1)), 30.0))
                    continue
                if progress:
                    progress(offset, size)

        return self._complete(tid, size, digest)

    # ----- internals -------------------------------------------------------
    def _sync_offset(self, tid: str) -> int:
        status, body = self._request("GET", f"/v1/transfers/{tid}")
        if status == 404:
            raise TransferError("receiver no longer knows this transfer")
        if status != 200:
            raise ConnectionError(f"status check failed ({status})")
        return int(body["received"])

    def _complete(self, tid: str, size: int, digest: str) -> dict:
        failures = 0
        while True:
            try:
                status, resp = self._request("POST", f"/v1/transfers/{tid}/complete")
            except (OSError, http.client.HTTPException) as exc:
                failures += 1
                if failures > self.max_retries:
                    raise TransferError("could not confirm completion; check the receiver") from exc
                self.sleep(min(self.backoff * (2 ** (failures - 1)), 30.0))
                continue
            if status == 200:
                return {"saved_as": resp["saved_as"], "sha256": resp["sha256"],
                        "bytes": size, "expected_sha256": digest}
            if status == 422:
                raise IntegrityError("receiver's hash check failed; the partial data was discarded")
            if status == 404:
                raise TransferError("transfer no longer exists on the receiver")
            raise TransferError(resp.get("error", f"completion failed ({status})"))

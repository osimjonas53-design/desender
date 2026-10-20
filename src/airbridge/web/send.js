(() => {
  "use strict";

  const { hashBlob } = window.AirBridgeSha256;
  const $ = (id) => document.getElementById(id);
  const CHUNK = 4 * 1024 * 1024;     // hashing slice
  const MAX_RETRIES = 4;
  let token = null;
  let queue = [];

  class SessionEnded extends Error {}
  class Declined extends Error {}

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (key === "text") node.textContent = value;
      else if (key === "className") node.className = value;
      else node.setAttribute(key, value);
    }
    for (const child of children) node.append(child);
    return node;
  }

  function fmtBytes(n) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let v = Number(n) || 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const authHeaders = () => ({ Authorization: `Bearer ${token}` });

  function showBanner(message) {
    const banner = $("banner");
    banner.textContent = message || "";
    banner.hidden = !message;
  }

  function updateConnectButton() {
    const ok = $("code").value.trim().length === 6 && $("fingerprint").value.replace(/[^0-9a-f]/gi, "").length === 16;
    $("pair").disabled = !(ok && $("verified").checked);
  }

  // ----- pairing -----------------------------------------------------------
  async function pair() {
    const code = $("code").value.trim();
    const res = await fetch("/v1/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, device: "Web browser" }),
      cache: "no-store",
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `Pairing failed (${res.status})`);
    }
    token = (await res.json()).token;
    $("session-state").textContent = "Paired";
    $("connect-card").hidden = true;
    $("send-card").hidden = false;
    $("progress-card").hidden = false;
    showBanner("");
  }

  // ----- sending -----------------------------------------------------------
  function rowFor(file) {
    const status = el("span", { className: "meta", text: "Waiting" });
    const bar = el("div", { className: "bar" });
    const fill = el("span");
    fill.style.width = "0%";
    bar.append(fill);
    const line = el("li", { className: "item" },
      el("div", { className: "item-head" },
        el("span", { className: "name", text: file.name }),
        status),
      bar);
    $("progress").append(line);
    return {
      setStatus(text, cls) {
        status.textContent = text;
        status.className = `meta ${cls || ""}`.trim();
      },
      setProgress(done, total) {
        fill.style.width = `${total ? (100 * done / total).toFixed(1) : 100}%`;
      },
    };
  }

  async function postJson(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }

  async function sendOne(file, row) {
    row.setStatus("Checking…");
    const digest = await hashBlob(file, CHUNK, (done, total) => row.setProgress(done, total));

    row.setStatus("Waiting for approval on the receiver…", "status-wait");
    const offer = await postJson("/v1/offers", { name: file.name, size: file.size, sha256: digest });
    if (offer.status === 401) throw new SessionEnded("The receiver ended this session. Pair again.");
    if (offer.status === 403) throw new Declined("The receiver declined this file.");
    if (offer.status !== 200) throw new Error(offer.body.error || `Offer failed (${offer.status})`);

    const { transfer_id: tid, max_chunk: maxChunk } = offer.body;
    const step = Math.min(8 * 1024 * 1024, maxChunk || 1024 * 1024);
    let offset = offer.body.offset;
    let fails = 0;
    row.setStatus("Sending", "status-wait");
    row.setProgress(offset, file.size);

    while (offset < file.size) {
      try {
        const res = await fetch(`/v1/transfers/${encodeURIComponent(tid)}/data?offset=${offset}`, {
          method: "PUT",
          headers: authHeaders(),
          body: file.slice(offset, offset + step),
          cache: "no-store",
        });
        if (res.status === 200) {
          offset = (await res.json()).received;
          fails = 0;
        } else if (res.status === 409) {
          offset = (await res.json()).expected_offset;
        } else if (res.status === 401) {
          throw new SessionEnded("The receiver ended this session. Pair again.");
        } else {
          throw new Error(`Upload failed (${res.status})`);
        }
      } catch (err) {
        if (err instanceof SessionEnded || err instanceof Declined) throw err;
        fails++;
        if (fails > MAX_RETRIES) throw new Error("Connection lost. Send the file again to resume.");
        row.setStatus(`Connection problem, retrying (${fails})…`, "status-wait");
        await sleep(1000 * fails);
        try {
          const st = await fetch(`/v1/transfers/${encodeURIComponent(tid)}`, { headers: authHeaders(), cache: "no-store" });
          if (st.ok) offset = (await st.json()).received;
        } catch (_) { /* keep retrying */ }
      }
      row.setProgress(offset, file.size);
    }

    row.setStatus("Verifying…", "status-wait");
    const done = await postJson(`/v1/transfers/${encodeURIComponent(tid)}/complete`, {});
    if (done.status === 422) throw new Error("The receiver's integrity check failed. Send the file again.");
    if (done.status !== 200) throw new Error(done.body.error || `Completion failed (${done.status})`);
    if (done.body.sha256 !== digest) throw new Error("The receiver reports a different checksum.");
    row.setProgress(file.size, file.size);
    row.setStatus(`Verified and saved as ${done.body.saved_as}`, "status-ok");
  }

  async function runQueue() {
    $("send").disabled = true;
    while (queue.length) {
      const { file, row } = queue.shift();
      try {
        await sendOne(file, row);
      } catch (err) {
        if (err instanceof SessionEnded) {
          row.setStatus(err.message, "status-bad");
          for (const rest of queue) rest.row.setStatus("Not sent: session ended", "status-bad");
          queue = [];
          token = null;
          $("session-state").textContent = "Session ended";
          $("connect-card").hidden = false;
          $("send-card").hidden = true;
          break;
        }
        row.setStatus(err.message, "status-bad");
      }
    }
    $("send").disabled = true;
  }

  // ----- wiring ------------------------------------------------------------
  function initFromFragment() {
    const params = new URLSearchParams(location.hash.slice(1));
    if (params.get("c")) $("code").value = params.get("c").slice(0, 6);
    if (params.get("f")) $("fingerprint").value = params.get("f");
    if (location.hash) history.replaceState(null, "", location.pathname);
    $("address").value = location.host;
    updateConnectButton();
  }

  ["code", "fingerprint"].forEach((id) => $(id).addEventListener("input", updateConnectButton));
  $("verified").addEventListener("change", updateConnectButton);

  $("pair").addEventListener("click", async () => {
    $("pair").disabled = true;
    try {
      await pair();
    } catch (err) {
      showBanner(err.message);
      updateConnectButton();
    }
  });

  $("files").addEventListener("change", () => {
    $("selected").replaceChildren(...[...$("files").files].map((f) =>
      el("li", { className: "item" },
        el("span", { className: "name", text: f.name }),
        el("span", { className: "meta", text: fmtBytes(f.size) }))));
    $("send").disabled = $("files").files.length === 0;
  });

  $("send").addEventListener("click", () => {
    const files = [...$("files").files];
    if (!files.length || !token) return;
    $("progress").replaceChildren();          // clear first, then create the new rows
    queue = files.map((file) => ({ file, row: rowFor(file) }));
    $("send").disabled = true;
    runQueue();
  });

  initFromFragment();
})();

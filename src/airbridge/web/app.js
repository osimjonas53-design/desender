(() => {
  "use strict";

  // Every name shown here comes from a remote peer. Only textContent is used,
  // never innerHTML, so a file or device name cannot inject markup.
  const ADMIN_HEADERS = { "X-AirBridge-Admin": "1" };
  const $ = (id) => document.getElementById(id);
  const lastRendered = {};
  let polling = false;
  let qrCode = null;      // code the current QR image was made for
  let qrUrl = null;       // blob URL for the QR image

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (key === "text") node.textContent = value;
      else if (key === "className") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
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

  function fmtTime(ts) {
    return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function fmtClock(seconds) {
    const m = Math.floor(seconds / 60);
    const s = String(seconds % 60).padStart(2, "0");
    return `${m}:${s}`;
  }

  async function api(path, method = "GET", asBlob = false) {
    const res = await fetch(path, { method, headers: ADMIN_HEADERS, cache: "no-store" });
    if (!res.ok) throw new Error(`${res.status}`);
    return asBlob ? res.blob() : res.json();
  }

  function setList(id, emptyId, items, build, key) {
    const sig = JSON.stringify(items);
    if (lastRendered[key] === sig) return;
    lastRendered[key] = sig;
    $(id).replaceChildren(...items.map(build));
    $(emptyId).hidden = items.length > 0;
  }

  function renderPairing(p, fingerprint) {
    if (p.code) {
      $("code").textContent = `${p.code.slice(0, 3)} ${p.code.slice(3)}`;
      $("code-timer").textContent = `Expires in ${fmtClock(p.seconds_left)}`;
    } else {
      $("code").textContent = "——  ——";
      $("code-timer").textContent = "Code used or expired. Create a new one.";
    }
    $("fingerprint").textContent = fingerprint ? fingerprint.replace(/(.{4})(?=.)/g, "$1 ") : "—";
  }

  async function refreshQr(code) {
    if (code === qrCode) return;
    qrCode = code;
    if (!code) {
      $("qr").hidden = true;
      $("qr-empty").hidden = false;
      return;
    }
    try {
      const blob = await api(`/admin/qr?v=${encodeURIComponent(code)}`, "GET", true);
      if (qrUrl) URL.revokeObjectURL(qrUrl);
      qrUrl = URL.createObjectURL(blob);
      $("qr").src = qrUrl;
      $("qr").hidden = false;
      $("qr-empty").hidden = true;
    } catch (_) {
      $("qr").hidden = true;
      $("qr-empty").hidden = false;
    }
  }

  function pendingItem(p) {
    const accept = el("button", { className: "btn primary", type: "button" }, "Accept");
    const decline = el("button", { className: "btn danger", type: "button" }, "Decline");
    const decide = (choice) => async () => {
      accept.disabled = decline.disabled = true;
      try { await api(`/admin/offers/${encodeURIComponent(p.id)}/${choice}`, "POST"); }
      catch (_) { /* request may have timed out already; the next poll shows the truth */ }
      poll();
    };
    accept.addEventListener("click", decide("accept"));
    decline.addEventListener("click", decide("decline"));
    return el("li", { className: "item" },
      el("div", { className: "item-head" },
        el("span", { className: "name", text: p.name }),
        el("span", { className: "meta", text: fmtBytes(p.size) })),
      el("div", { className: "meta", text: `From ${p.sender} · ${fmtTime(p.requested_at)}` }),
      el("div", { className: "actions" }, accept, decline));
  }

  function activeItem(t) {
    const pct = t.size ? Math.min(100, (100 * t.received) / t.size) : 100;
    const bar = el("div", { className: "bar", role: "progressbar",
      "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": Math.round(pct),
      "aria-label": `Progress for ${t.name}` });
    const fill = el("span");
    fill.style.width = `${pct.toFixed(1)}%`;   // CSSOM, not a style attribute: allowed by CSP
    bar.append(fill);
    return el("li", { className: "item" },
      el("div", { className: "item-head" },
        el("span", { className: "name", text: t.name }),
        el("span", { className: "meta", text: `${pct.toFixed(0)}%` })),
      bar,
      el("div", { className: "meta",
        text: `${fmtBytes(t.received)} of ${fmtBytes(t.size)} · from ${t.sender}` }));
  }

  function deviceItem(d) {
    const revoke = el("button", { className: "btn danger", type: "button" }, "Revoke");
    revoke.addEventListener("click", async () => {
      revoke.disabled = true;
      try { await api(`/admin/devices/${encodeURIComponent(d.id)}/revoke`, "POST"); }
      catch (_) { /* shown on next poll */ }
      poll();
    });
    return el("li", { className: "item" },
      el("div", { className: "item-head" },
        el("span", { className: "name", text: d.device }),
        el("span", { className: "meta", text: `paired ${fmtTime(d.created)}` })),
      el("div", { className: "meta", text: `last seen ${fmtTime(d.last_seen)} · expires ${fmtTime(d.expires)}` }),
      el("div", { className: "actions" }, revoke));
  }

  const STATUS_TEXT = {
    saved: "Saved", failed: "Failed", declined: "Declined", cancelled: "Cancelled",
  };

  function historyItem(h) {
    const label = h.saved_as || h.name;
    const detail = h.reason ? ` · ${h.reason}` : "";
    return el("li", { className: "item" },
      el("div", { className: "item-head" },
        el("span", { className: "name", text: label }),
        el("span", { className: `pill ${h.status}`, text: STATUS_TEXT[h.status] || h.status })),
      el("div", { className: "meta",
        text: `${fmtBytes(h.size)} · ${h.sender || "unknown sender"} · ${fmtTime(h.at)}${detail}` }));
  }

  function showBanner(message) {
    const banner = $("banner");
    banner.textContent = message || "";
    banner.hidden = !message;
  }

  async function poll() {
    if (polling) return;
    polling = true;
    try {
      const state = await api("/admin/state");
      showBanner("");
      const visible = state.discovery ? `visible as "${state.discovery}"` : "not discoverable";
      $("device").textContent = `${state.device} · ${visible} · ${state.advertise_url || "local only"}`;
      $("address").textContent = state.advertise_url || "—";
      $("save-dir").textContent = state.save_dir;
      renderPairing(state.pairing, state.fingerprint);
      refreshQr(state.pairing.code);
      const count = state.pending.length;
      $("pending-count").textContent = String(count);
      $("pending-count").hidden = count === 0;
      setList("pending", "pending-empty", state.pending, pendingItem, "pending");
      setList("active", "active-empty", state.active, activeItem, "active");
      setList("devices", "devices-empty", state.devices, deviceItem, "devices");
      setList("history", "history-empty", state.history.slice(0, 30), historyItem, "history");
    } catch (_) {
      showBanner("Lost contact with the receiver. Retrying…");
    } finally {
      polling = false;
    }
  }

  $("new-code").addEventListener("click", async () => {
    try { await api("/admin/code", "POST"); } catch (_) { showBanner("Could not create a code."); }
    lastRendered.pairing = undefined;
    poll();
  });

  poll();
  setInterval(poll, 1000);
})();

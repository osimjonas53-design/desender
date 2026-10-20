// End-to-end browser test for the browser sender.
// Starts a real receiver process, pairs a real Chromium from the QR link,
// uploads a file from the sender page, approves it on the dashboard, checks the
// saved file, then revokes the device and confirms the sender stops.
//
// Usage: node scripts/sender_smoke.js <dir-containing-airbridge-package> <peer-port> <workdir>
const { chromium } = require("playwright");
const { spawn, execFileSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const [, , srcDir, portArg, workArg] = process.argv;
const port = Number(portArg || 8851);
const work = path.resolve(workArg || "/tmp/sender-smoke");
const env = { ...process.env, PYTHONPATH: srcDir, AIRBRIDGE_PASSPHRASE: "browser-test-passphrase" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const exitOf = (proc) => new Promise((r) => proc.on("exit", r));
let failures = 0;
const check = (ok, msg) => { if (ok) console.log("ok  -", msg); else { failures++; console.error("FAIL -", msg); } };

(async () => {
  fs.rmSync(work, { recursive: true, force: true });
  fs.mkdirSync(path.join(work, "tx"), { recursive: true });
  const payload = crypto.randomBytes(2_500_000);
  const file = path.join(work, "tx", "trip-photo.jpg");
  fs.writeFileSync(file, payload);
  const second = path.join(work, "tx", "second.txt");
  fs.writeFileSync(second, "sent after revocation");

  const rx = spawn("python3", ["-m", "airbridge", "receive",
    "--dir", path.join(work, "rx"), "--host", "127.0.0.1", "--port", String(port),
    "--name", "Browser test PC", "--identity-dir", path.join(work, "identity"),
    "--dashboard-port", "0"], { env, stdio: ["ignore", "pipe", "pipe"] });
  let rxLog = "";
  rx.stdout.on("data", (d) => (rxLog += d));
  rx.stderr.on("data", (d) => (rxLog += d));
  await sleep(1500);

  const code = (rxLog.match(/Pairing code: (\d{6})/) || [])[1];
  const fp = ((rxLog.match(/Device fingerprint: ([0-9a-f ]+)/) || [])[1] || "").replace(/ /g, "");
  const dashUrl = (rxLog.match(/Dashboard .*?(http:\/\/127\.0\.0\.1:\d+\/)/) || [])[1];
  const qrLink = (rxLog.match(/open (https:\/\/\S+#c=\d{6}&f=[0-9a-f]{16})/) || [])[1];
  if (!code || fp.length !== 16 || !dashUrl || !qrLink) {
    console.error("receiver output missing code, fingerprint, dashboard or QR link");
    console.error(rxLog);
    rx.kill();
    process.exitCode = 1;
    return;
  }
  check(qrLink.includes(`c=${code}`) && qrLink.includes(`f=${fp}`), "QR link carries the live code and fingerprint");

  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: false });
  const sender = await context.newPage();
  const dash = await context.newPage();
  const problems = [];
  for (const [name, page] of [["sender", sender], ["dashboard", dash]]) {
    page.on("console", (m) => {
      // The browser logs every non-2xx response as "Failed to load resource". Those are
      // expected answers (401 after revocation, 409 on resume), so they are ignored here.
      // Policy refusals and script errors are still reported.
      const expectedStatus = /Failed to load resource: the server responded with a status of (401|403|404|409)/.test(m.text());
      if (expectedStatus) return;
      if (m.type() === "error" || /Refused to|violates|Content Security Policy/i.test(m.text())) {
        problems.push(`${name}: ${m.text()}`);
      }
    });
    page.on("pageerror", (e) => problems.push(`${name}: ${e}`));
  }

  // --- dashboard shows the QR while the code is still live ------------------
  await dash.goto(dashUrl);
  await dash.waitForFunction(() => {
    const img = document.querySelector("#qr");
    return img && !img.hidden && img.complete && img.naturalWidth > 0;
  }, null, { timeout: 15000 }).then(
    () => check(true, "dashboard renders the pairing QR code while the code is live"),
    () => check(false, "dashboard QR code did not load"));

  // --- sender page: prefilled from the QR fragment -----------------------
  const senderUrl = `https://127.0.0.1:${port}/send#c=${code}&f=${fp}`;
  await sender.goto(senderUrl);
  await sender.waitForSelector("#pair");
  check((await sender.inputValue("#code")) === code, "sender page fills the code from the QR link");
  check((await sender.inputValue("#fingerprint")) === fp, "sender page fills the fingerprint from the QR link");
  check(await sender.isDisabled("#pair"), "Pair stays disabled until the fingerprint is confirmed");
  await sender.check("#verified");
  await sender.click("#pair");
  await sender.waitForFunction(() => document.querySelector("#session-state").textContent === "Paired", null, { timeout: 15000 });
  check(true, "browser pairs with the receiver over TLS");

  // --- dashboard: device appears; the used code's QR is withdrawn -----------
  await dash.waitForSelector("#devices .item", { timeout: 15000 });
  const devName = await dash.textContent("#devices .item .name");
  check(devName === "Web browser", `dashboard lists the browser as "${devName}"`);
  await dash.waitForFunction(() => document.querySelector("#qr").hidden === true, null, { timeout: 15000 });
  check(true, "the QR is withdrawn once its single-use code has been used");

  // --- upload from the page, approve on the dashboard ----------------------
  await sender.setInputFiles("#files", file);
  await sender.click("#send");
  await dash.waitForSelector("#pending .item", { timeout: 30000 });
  check((await dash.textContent("#pending .item .name")) === "trip-photo.jpg", "incoming request shows the file name");
  await dash.click("#pending .btn.primary");
  await sender.waitForFunction(() => /Verified and saved/.test(document.querySelector("#progress").textContent), null, { timeout: 60000 });
  check(true, "sender page reports the file verified and saved");

  const saved = fs.readFileSync(path.join(work, "rx", "trip-photo.jpg"));
  const sameHash = crypto.createHash("sha256").update(saved).digest("hex") === crypto.createHash("sha256").update(payload).digest("hex");
  check(sameHash && saved.length === payload.length, "saved file is byte-identical to the file sent from the browser");
  await dash.waitForSelector("#history .pill.saved", { timeout: 15000 });

  // --- revoke the device from the dashboard; the sender must stop ----------
  await dash.click("#devices .btn.danger");
  await dash.waitForSelector("#devices-empty:not([hidden])", { timeout: 15000 });
  check(true, "dashboard removes the device after revocation");

  await sender.setInputFiles("#files", second);
  await sender.click("#send");
  await sender.waitForFunction(() => /ended|Pair again|Not sent/i.test(document.querySelector("#progress").textContent)
    || document.querySelector("#connect-card").hidden === false, null, { timeout: 30000 });
  const connectVisible = await sender.isVisible("#connect-card");
  check(connectVisible, "after revocation the sender returns to the pairing screen");
  check(!fs.existsSync(path.join(work, "rx", "second.txt")), "nothing was written after revocation");

  check(problems.length === 0, problems.length ? `console or CSP problems: ${problems.join(" | ")}` : "no CSP violations or console errors on either page");

  await browser.close();
  rx.kill();
  await exitOf(rx).catch(() => {});
  console.log(failures ? `\n${failures} CHECK(S) FAILED` : "\nALL BROWSER SENDER CHECKS PASSED");
  process.exitCode = failures ? 1 : 0;
})().catch((e) => {
  console.error("FAIL - unexpected error:", e.stack || e.message);
  process.exitCode = 1;
});

// End-to-end UI check: real receiver process, real sender process, real Chromium.
// Usage: node scripts/ui_smoke.js <dir-containing-airbridge-package> <peer-port> <workdir>
const { chromium } = require("playwright");
const { spawn, execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const [, , srcDir, portArg, workArg] = process.argv;
const port = Number(portArg || 8811);
const work = path.resolve(workArg || "/tmp/ui-smoke");
const env = { ...process.env, PYTHONPATH: srcDir, AIRBRIDGE_PASSPHRASE: "browser-test-passphrase" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const exitOf = (proc) => new Promise((r) => proc.on("exit", r));
const fail = (msg) => { console.error("FAIL:", msg); process.exitCode = 1; };
const pass = (msg) => console.log("ok  -", msg);

(async () => {
  fs.rmSync(work, { recursive: true, force: true });
  fs.mkdirSync(path.join(work, "tx"), { recursive: true });
  fs.writeFileSync(path.join(work, "tx", "holiday.jpg"), require("crypto").randomBytes(300000));
  fs.writeFileSync(path.join(work, "tx", "contract.pdf"), "declined content");

  const rx = spawn("python3", ["-m", "airbridge", "receive", "--dir", path.join(work, "rx"),
    "--host", "127.0.0.1", "--port", String(port), "--name", "UI test PC",
    "--identity-dir", path.join(work, "identity"), "--dashboard-port", "0"],
    { env, stdio: ["ignore", "pipe", "pipe"] });
  let rxLog = "";
  rx.stdout.on("data", (d) => (rxLog += d));
  rx.stderr.on("data", (d) => (rxLog += d));
  await sleep(1200);
  const code = (rxLog.match(/Pairing code: (\d{6})/) || [])[1];
  const fp = ((rxLog.match(/Device fingerprint: ([0-9a-f ]+)/) || [])[1] || "").replace(/ /g, "");
  const dashUrl = (rxLog.match(/Dashboard .*?(http:\/\/127\.0\.0\.1:\d+\/)/) || [])[1];
  if (!code || fp.length !== 16 || !dashUrl) { fail("receiver did not print code, fingerprint and dashboard URL"); rx.kill(); return; }

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  const consoleErrors = [];
  const cspViolations = [];
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  page.on("console", (m) => { if (/Content Security Policy/i.test(m.text())) cspViolations.push(m.text()); });

  await page.goto(dashUrl);
  await page.waitForSelector("#code");
  await page.waitForFunction(() => /\d{3} \d{3}/.test(document.querySelector("#code").textContent));
  const shownCode = (await page.textContent("#code")).replace(/\s/g, "");
  shownCode === code ? pass("dashboard shows the live pairing code") : fail(`code mismatch ${shownCode} vs ${code}`);

  // Send 1: accept
  const send1 = spawn("python3", ["-m", "airbridge", "send", "--to", `127.0.0.1:${port}`,
    "--code", code, "--fp", fp, path.join(work, "tx", "holiday.jpg")], { env, stdio: "pipe" });
  const send1Exit = exitOf(send1);
  await page.waitForSelector("#pending .item", { timeout: 15000 });
  const pendingName = await page.textContent("#pending .item .name");
  pendingName === "holiday.jpg" ? pass("incoming request appears with the file name") : fail(`pending name was ${pendingName}`);
  await page.screenshot({ path: path.join(work, "01-pending.png"), fullPage: true });
  await page.click("#pending .btn.primary");
  await page.waitForSelector("#history .pill.saved", { timeout: 30000 });
  pass("accepting marks the transfer saved in history");

  // Send 2 with the same pairing flow needs a new code, so generate one
  await page.click("#new-code");
  await page.waitForFunction((old) => {
    const digits = document.querySelector("#code").textContent.replace(/\s/g, "");
    return /^\d{6}$/.test(digits) && digits !== old;
  }, code);
  const code2 = (await page.textContent("#code")).replace(/\s/g, "");
  pass(`new code generated on request (${code2})`);
  const send2 = spawn("python3", ["-m", "airbridge", "send", "--to", `127.0.0.1:${port}`,
    "--code", code2, "--fp", fp, path.join(work, "tx", "contract.pdf")], { env, stdio: "pipe" });
  const send2Exit = exitOf(send2);
  await page.waitForSelector("#pending .item", { timeout: 15000 });
  await page.click("#pending .btn.danger");
  await page.waitForSelector("#history .pill.declined", { timeout: 30000 });
  pass("declining marks the request declined");

  const exit2 = await send2Exit;
  exit2 !== 0 ? pass(`sender reports failure after decline (exit ${exit2})`) : fail("sender should fail after decline");
  await send1Exit;

  await page.screenshot({ path: path.join(work, "02-history.png"), fullPage: true });

  const saved = fs.readdirSync(path.join(work, "rx"));
  saved.includes("holiday.jpg") && !saved.includes("contract.pdf")
    ? pass("only the accepted file was written to the save folder")
    : fail(`save folder contents: ${saved}`);
  const same = execFileSync("sha256sum", [path.join(work, "tx", "holiday.jpg"), path.join(work, "rx", "holiday.jpg")])
    .toString().trim().split("\n").map((l) => l.split(" ")[0]);
  same[0] === same[1] ? pass("received file matches the sent file (SHA-256)") : fail("hash mismatch");

  const pendingLeft = await page.$$eval("#pending .item", (n) => n.length);
  pendingLeft === 0 ? pass("no stale pending requests remain") : fail("stale pending request");
  cspViolations.length === 0 ? pass("no Content-Security-Policy violations") : fail(cspViolations.join("; "));
  consoleErrors.length === 0 ? pass("no console errors") : fail(consoleErrors.join("; "));

  await browser.close();
  rx.kill();
  console.log(process.exitCode ? "\nSOME CHECKS FAILED" : "\nALL UI CHECKS PASSED");
})().catch((e) => { fail(e.stack || e.message); process.exitCode = 1; });

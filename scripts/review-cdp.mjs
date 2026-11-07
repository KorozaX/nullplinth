// Captures true rendered screenshots of the running Tauri app through the WebView2
// DevTools protocol, at exact CSS viewport sizes, for every section.
// Usage: node scripts/review-cdp.mjs [port] [outDir]
import { writeFileSync, mkdirSync } from "node:fs";

const port = process.argv[2] ?? "9223";
const outDir = process.argv[3] ?? "review-cdp";
mkdirSync(outDir, { recursive: true });

const sizes = [
  [1024, 768],
  [1280, 720],
  [1366, 768],
  [1920, 1080],
];
const sections = [
  "Overview",
  "Event Explorer",
  "Network Analyzer",
  "Alerts",
  "Investigations",
  "Data Sources",
  "Settings",
];
const slug = (s) => s.toLowerCase().replace(/ /g, "-");

const list = await (await fetch("http://127.0.0.1:" + port + "/json")).json();
const page = list.find((t) => t.type === "page");
if (!page) throw new Error("no page target");

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  ws.addEventListener("open", resolve, { once: true });
  ws.addEventListener("error", reject, { once: true });
});

let nextId = 1;
const pending = new Map();
ws.addEventListener("message", (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  }
});
function send(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => {
    pending.set(id, (msg) => (msg.error ? reject(new Error(method + ": " + msg.error.message)) : resolve(msg.result)));
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await send("Page.enable");
await send("Runtime.enable");

// Wait for the app shell to render.
for (let i = 0; i < 40; i++) {
  const r = await send("Runtime.evaluate", { expression: "document.querySelectorAll('button[aria-label]').length", returnByValue: true });
  if ((r.result?.value ?? 0) > 0) break;
  await sleep(250);
}

const clickSection = async (label) => {
  const expr = "(() => { const target = " + JSON.stringify(label) + "; const hit = Array.from(document.querySelectorAll('button')).find(b => (b.getAttribute('aria-label') || '') === target || (b.textContent || '').trim() === target); if (hit) { hit.click(); return true; } return false; })()";
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true });
  if (!r.result?.value) throw new Error("could not click section " + label);
};

for (const [width, height] of sizes) {
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
  await sleep(700);
  for (const section of sections) {
    await clickSection(section);
    await sleep(900);
    const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
    const path = outDir + "/" + width + "x" + height + "-" + slug(section) + ".png";
    writeFileSync(path, Buffer.from(shot.data, "base64"));
    console.log("shot=" + path);
  }
  // Overflow audit per viewport.
  const audit = await send("Runtime.evaluate", {
    expression: "JSON.stringify({cw: document.documentElement.clientWidth, sw: document.documentElement.scrollWidth, offenders: [...document.querySelectorAll('*')].filter(e => e.getBoundingClientRect().right > window.innerWidth + 1).map(e => e.tagName + '.' + String(e.className).slice(0,40)).slice(0,8)})",
    returnByValue: true,
  });
  console.log("audit " + width + "x" + height + ": " + audit.result.value);
}
await send("Emulation.clearDeviceMetricsOverride");
ws.close();
console.log("done");
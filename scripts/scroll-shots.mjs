import { writeFileSync } from "node:fs";
const list = await (await fetch("http://127.0.0.1:9223/json")).json();
const page = list.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let id = 1; const pending = new Map();
ws.addEventListener("message", (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } });
const send = (method, params = {}) => { const i = id++; ws.send(JSON.stringify({ id: i, method, params })); return new Promise((res, rej) => pending.set(i, (m) => m.error ? rej(new Error(m.error.message)) : res(m.result))); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const evalJs = async (expression) => (await send("Runtime.evaluate", { expression, returnByValue: true })).result?.value;
const shot = async (name) => { const s = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false }); writeFileSync("review-cdp/" + name + ".png", Buffer.from(s.data, "base64")); console.log("shot=" + name); };
await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1366, height: 768, deviceScaleFactor: 1, mobile: false });
await sleep(800);
await evalJs("document.querySelector('.topology-graph__svg')?.scrollIntoView({ block: 'center' })");
await sleep(1200);
await shot("overview-graph");
// hover a node to show the tooltip
const node = await evalJs("(() => { const n = document.querySelector('.topology-graph__svg circle, .topology-graph__svg [data-node-id]'); if (!n) return null; const r = n.getBoundingClientRect(); return JSON.stringify({ x: Math.round(r.x + r.width/2), y: Math.round(r.y + r.height/2) }); })()");
if (node) {
  const { x, y } = JSON.parse(node);
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
  await sleep(700);
  await shot("overview-graph-hover");
}
ws.close();
console.log("done");

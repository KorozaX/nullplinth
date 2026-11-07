import { writeFileSync, mkdirSync } from "node:fs";
const outDir = "review-final";
mkdirSync(outDir, { recursive: true });
const list = await (await fetch("http://127.0.0.1:9223/json")).json();
const page = list.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let id = 1; const pending = new Map();
ws.addEventListener("message", (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } });
const send = (method, params = {}) => { const i = id++; ws.send(JSON.stringify({ id: i, method, params })); return new Promise((res, rej) => pending.set(i, (m) => m.error ? rej(new Error(m.error.message)) : res(m.result))); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const evalJs = async (expression) => (await send("Runtime.evaluate", { expression, returnByValue: true })).result?.value;
const click = async (label) => evalJs("(() => { const t = " + JSON.stringify(label) + "; const b = [...document.querySelectorAll('button')].find(x => (x.getAttribute('aria-label')||'') === t || (x.textContent||'').trim() === t); if (b) { b.click(); return true; } return false; })()");
const shot = async (name) => { const s = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false }); writeFileSync(outDir + "/" + name + ".png", Buffer.from(s.data, "base64")); console.log("shot=" + name); };

await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1366, height: 768, deviceScaleFactor: 1, mobile: false });
await sleep(900);

await click("Alerts"); await sleep(1100); await shot("1366-alerts");
await click("Investigations"); await sleep(1300); await shot("1366-investigations");
await click("Data Sources"); await sleep(1100); await shot("1366-data-sources");
await click("Overview"); await sleep(900);
await evalJs("document.querySelector('.topology-graph__svg')?.scrollIntoView({ block: 'center' })");
await sleep(1200); await shot("1366-graph");
// overflow audit
const audit = await evalJs("JSON.stringify({cw: document.documentElement.clientWidth, sw: document.documentElement.scrollWidth, offenders: [...document.querySelectorAll('*')].filter(e => e.getBoundingClientRect().right > window.innerWidth + 1).length })");
console.log("audit " + audit);
ws.close();
console.log("done");

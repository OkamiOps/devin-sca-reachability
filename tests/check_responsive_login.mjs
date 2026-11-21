// Local demo on :8006 with loopback origins enabled, Chromium CDP on :29229.
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";

const before = process.argv.includes("--before");
const phase = before ? "before" : "after";
const version = await (await fetch("http://localhost:29229/json/version")).json();
const socket = new WebSocket(version.webSocketDebuggerUrl);
await new Promise(resolve => socket.addEventListener("open", resolve, { once: true }));
let next = 0;
const pending = new Map();
socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (!message.id) return;
  const task = pending.get(message.id);
  pending.delete(message.id);
  message.error ? task.reject(new Error(JSON.stringify(message.error))) : task.resolve(message.result);
});
function send(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++next;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}
const { browserContextId } = await send("Target.createBrowserContext");
try {
  const { targetId } = await send("Target.createTarget", { url: "about:blank", browserContextId });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const call = (method, params) => send(method, params, sessionId);
  async function evaluate(expression) {
    const result = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function until(expression) {
    for (let count = 0; count < 100; count++) {
      if (await evaluate(expression)) return;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error("Browser condition timed out: " + expression);
  }
  async function resize(width) {
    await call("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
    await evaluate("new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))");
  }
  async function screenshot(view) {
    const { data } = await call("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
    const path = `/home/ubuntu/screenshots/sca-${view}-775-${phase}.png`;
    await writeFile(path, Buffer.from(data, "base64"));
    console.log(path);
  }
  const measure = `(() => {
    const rect = selector => {const n=document.querySelector(selector),r=n.getBoundingClientRect();return {width:r.width,left:r.left,right:r.right,scroll:n.scrollWidth,client:n.clientWidth};};
    const clippedText = [];
    for (const panel of document.querySelectorAll('.login-story,.login-form')) {
      const bounds=panel.getBoundingClientRect(), walker=document.createTreeWalker(panel,NodeFilter.SHOW_TEXT);
      while(walker.nextNode()) {
        if(!walker.currentNode.textContent.trim()) continue;
        const range=document.createRange();range.selectNodeContents(walker.currentNode);
        if([...range.getClientRects()].some(r=>r.left<bounds.left-1||r.right>bounds.right+1)) clippedText.push(walker.currentNode.textContent);
      }
    }
    return {viewport:innerWidth,available:document.documentElement.clientWidth,document:document.documentElement.scrollWidth,workspace:rect('.workspace'),header:rect('.topbar'),banner:rect('#environment-notice'),story:rect('.login-story'),form:rect('.login-form'),grid:getComputedStyle(document.querySelector('.app-shell')).gridTemplateColumns,clippedText};
  })()`;
  await call("Page.enable");
  await call("Page.navigate", { url: "http://127.0.0.1:8006/" });
  await until("!!document.querySelector('#access-token')");
  for (const width of [320, 390, 600, 640, 641, 700, 775, 850, 851, 860, 1000, 1200, 1201, 1440]) {
    await resize(width);
    const result = await evaluate(measure);
    console.log(`${phase} login ${width}: ${JSON.stringify(result)}`);
    if (width === 775) await screenshot("login");
    if (!before) {
      assert.ok(result.document <= width);
      assert.equal(result.workspace.width, result.available);
      assert.deepEqual(result.clippedText, [], `${width}: clipped login text`);
      for (const name of ["header", "banner", "story", "form"]) {
        assert.ok(result[name].width >= Math.min(260, width - 34), `${width} ${name}: ${JSON.stringify(result[name])}`);
        assert.ok(result[name].right <= width && result[name].left >= 0, `${width} ${name} outside viewport`);
        if (name !== "story") assert.ok(result[name].scroll <= result[name].client + 1, `${width} ${name} internal overflow`);
      }
    }
  }
  await resize(775);
  await evaluate("document.querySelector('[data-action=demo-login]').click()");
  await until("document.querySelector('#navigation')?.hidden === false");
  await screenshot("dashboard");
  const dashboard = await evaluate(`({width:innerWidth,scroll:document.documentElement.scrollWidth,workspace:document.querySelector('.workspace').getBoundingClientRect().width,grid:getComputedStyle(document.querySelector('.app-shell')).gridTemplateColumns,error:document.querySelector('#notification:not([hidden])')?.textContent || ''})`);
  console.log(`${phase} dashboard 775: ${JSON.stringify(dashboard)}`);
  if (!before) {
    assert.ok(dashboard.scroll <= 775);
    assert.ok(dashboard.workspace > 600);
    assert.equal(dashboard.error, "");
  }
  assert.equal(await evaluate(`fetch('/api/session',{method:'DELETE',headers:{'X-SCA-Request':'1'}}).then(r=>r.status)`), 204);
  console.log(`${phase.toUpperCase()}: responsive login widths and authenticated dashboard checked.`);
} finally {
  await send("Target.disposeBrowserContext", { browserContextId });
  socket.close();
}

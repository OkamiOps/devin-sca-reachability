// Local demo on :8000, Chromium CDP on :29229; no third-party packages.
import assert from "node:assert/strict";
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
      try { if (await evaluate(expression)) return; } catch {}
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error("Browser condition timed out: " + expression);
  }
  await call("Page.enable");
  await call("Page.navigate", { url: "http://127.0.0.1:8000" });
  await until("!!document.querySelector('#access-token')");
  assert.equal(await evaluate(`fetch('/api/session',{method:'POST',headers:{'Content-Type':'application/json','X-SCA-Request':'1'},body:JSON.stringify({token:'local-demo'})}).then(r=>r.status)`), 200);
  await call("Page.reload");
  await until("document.querySelector('#navigation')?.hidden === false");
  const scanId = await evaluate("fetch('/api/scans').then(r=>r.json()).then(r=>r.items.find(s=>s.status==='completed')?.id)");
  assert.ok(scanId, "A completed synthetic scan is required");
  for (const [width, height] of [[320, 640], [390, 844], [412, 844]]) {
    await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: true });
    for (const view of ["overview", "branches", "results", "activity"]) {
      await evaluate("location.hash=" + JSON.stringify(view));
      await until("document.querySelector('[data-view=" + view + "]').getAttribute('aria-current')==='page'");
      const result = await evaluate(`(() => {
        const selectors = ['#theme','#logout','[data-action="scan"]','.branch-row label','[data-action="detail"]'];
        const targets = selectors.flatMap(selector => [...document.querySelectorAll(selector)].filter(node => node.getClientRects().length).map(node => {
          const rect=node.getBoundingClientRect();return {selector,width:rect.width,height:rect.height};
        }));
        return {width:innerWidth,scrollWidth:document.documentElement.scrollWidth,targets,
          overflow:[...document.querySelectorAll('main *')].filter(n=>n.getBoundingClientRect().right>innerWidth+1).slice(0,5).map(n=>n.tagName+'.'+n.className)};
      })()`);
      console.log(`${width}x${height} ${view}: document=${result.scrollWidth}/${result.width}; min target=${Math.min(...result.targets.map(t=>t.width)).toFixed(1)}x${Math.min(...result.targets.map(t=>t.height)).toFixed(1)}`);
      assert.ok(result.scrollWidth <= result.width, JSON.stringify(result));
      for (const target of result.targets) assert.ok(target.width >= 44 && target.height >= 44, JSON.stringify(target));
    }
    await evaluate("location.hash='results'");
    await until("!!document.querySelector('[data-action=detail]')");
    await evaluate(`[...document.querySelectorAll('[data-action=detail]')].find(n=>n.dataset.id===${JSON.stringify(scanId)}).click()`);
    await until("document.querySelector('#detail-dialog').open && !!document.querySelector('#detail-title')");
    const result = await evaluate(`(() => {
      document.querySelectorAll('#detail-dialog details').forEach(n=>n.open=true);
      const dialog=document.querySelector('#detail-dialog');
      return {width:innerWidth,scrollWidth:document.documentElement.scrollWidth,dialogWidth:dialog.clientWidth,dialogScroll:dialog.scrollWidth,
        targets:[...dialog.querySelectorAll('button,summary')].map(n=>{const r=n.getBoundingClientRect();return {label:n.textContent,width:r.width,height:r.height}})};
    })()`);
    console.log(`${width}x${height} report expanded: document=${result.scrollWidth}/${result.width}; dialog=${result.dialogScroll}/${result.dialogWidth}; min target=${Math.min(...result.targets.map(t=>t.width)).toFixed(1)}x${Math.min(...result.targets.map(t=>t.height)).toFixed(1)}`);
    assert.ok(result.scrollWidth <= result.width && result.dialogScroll <= result.dialogWidth, JSON.stringify(result));
    for (const target of result.targets) assert.ok(target.width >= 44 && target.height >= 44, JSON.stringify(target));
    await evaluate("document.querySelector('#detail-dialog').close()");
  }
  console.log("PASS: 3 mobile widths, 4 views + expanded report; overflow and touch targets.");
} finally {
  await send("Target.disposeBrowserContext", { browserContextId });
  socket.close();
}

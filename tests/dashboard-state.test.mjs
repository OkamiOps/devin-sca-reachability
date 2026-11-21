import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const moduleSource = await readFile(new URL("../src/sca_reachability/static/model.js", import.meta.url), "utf8");
const model = await import(`data:text/javascript;base64,${Buffer.from(moduleSource).toString("base64")}`);
const appSource = (await readFile(new URL("../src/sca_reachability/static/app.js", import.meta.url), "utf8"))
  .replace(/^import .*?;\n/, "").replace(/await boot\(\);\s*$/, "");

// Exercise asynchronous session/scope behavior without a browser or third-party
// DOM library. Visual, focus, and layout checks belong to the integrated UI run.
function harness(responder) {
  const nodes = new Map();
  function node(selector) {
    if (!nodes.has(selector)) nodes.set(selector, {
      innerHTML: "", textContent: "", hidden: true, open: false,
      classList: { toggle() {} }, setAttribute() {}, addEventListener() {},
      contains() { return false; }, focus() {}, replaceChildren() {},
      close() { this.open = false; }, showModal() { this.open = true; },
    });
    return nodes.get(selector);
  }
  const calls = [];
  const sandbox = {
    ...model, e: model.escapeHTML, console, URLSearchParams, AbortController,
    setTimeout() { return 1; }, clearTimeout() {}, matchMedia() { return { matches: false }; },
    localStorage: { getItem() { return null; }, setItem() {} }, location: { hash: "" },
    window: { addEventListener() {} }, document: {
      querySelector: node, querySelectorAll() { return []; },
      addEventListener() {}, documentElement: { dataset: {} }, activeElement: null,
    },
    async fetch(path, options) {
      calls.push({ path, options });
      const result = await responder(path, options);
      return new Response(JSON.stringify(result.body ?? {}), { status: result.status ?? 200, headers: { "Content-Type": "application/json" } });
    },
  };
  vm.runInNewContext(`${appSource}\nglobalThis.testApp = { state, api, boot, saveBranches, loadScoped };`, sandbox);
  return { ...sandbox.testApp, nodes, calls };
}

test("unavailable backend never inserts synthetic inventory or a demo login", async () => {
  const app = harness(() => ({ status: 503 }));
  await app.boot();
  assert.match(app.nodes.get("#main").innerHTML, /Não foi possível/);
  assert.doesNotMatch(app.nodes.get("#main").innerHTML, /local-demo/);
  assert.equal(app.state.installations.length, 0);
  assert.equal(app.state.authenticated, false);
});

test("live login never advertises the public demo token", async () => {
  const app = harness(path => path === "/api/meta" ? { body: { mode: "live", github_configured: false, ai_configured: false } } : { status: 401 });
  await app.boot();
  assert.match(app.nodes.get("#main").innerHTML, /Token de acesso/);
  assert.doesNotMatch(app.nodes.get("#main").innerHTML, /local-demo/);
});

test("a rejected save retains the unsaved selection instead of claiming persistence", async () => {
  const app = harness(() => ({ status: 503 }));
  Object.assign(app.state, { authenticated: true, meta: { mode: "demo" }, view: "branches", installation: 1, repository: 2,
    branches: [{ name: "main", selected: false }], selected: new Set(["main"]) });
  await app.saveBranches();
  assert.equal(app.state.branches[0].selected, false);
  assert.equal(app.state.selected.has("main"), true);
  assert.match(app.nodes.get("#notification").textContent, /Não foi possível/);
  assert.equal(app.state.busy, false);
});

test("accepted selection uses server truth and installation-scoped mutation headers", async () => {
  const app = harness(() => ({ body: { items: [{ name: "main", selected: true }, { name: "removed", selected: false }] } }));
  Object.assign(app.state, { authenticated: true, meta: { mode: "demo" }, view: "branches", installation: 17, repository: 42,
    branches: [{ name: "main", selected: false }, { name: "removed", selected: false }], selected: new Set(["main", "removed"]) });
  await app.saveBranches();
  assert.equal(app.state.selected.has("removed"), false);
  assert.equal(app.state.selected.has("main"), true);
  assert.equal(app.calls[0].path, "/api/installations/17/repositories/42/branches");
  assert.equal(app.calls[0].options.headers["X-SCA-Request"], "1");
  assert.equal(app.calls[0].options.credentials, "same-origin");
});

test("expired session clears private data and releases a pending busy state", async () => {
  const app = harness(() => ({ status: 401 }));
  Object.assign(app.state, { authenticated: true, busy: true, meta: { mode: "live" }, scans: [{ id: "private" }], branches: [{ name: "private", selected: true }] });
  await assert.rejects(app.api("/api/dashboard"));
  assert.equal(app.state.authenticated, false);
  assert.equal(app.state.busy, false);
  assert.equal(app.state.scans.length, 0);
  assert.equal(app.state.branches.length, 0);
});

test("a late branch response cannot overwrite a more recent installation scope", async () => {
  let release;
  let branchesStarted;
  const started = new Promise(resolve => { branchesStarted = resolve; });
  const pending = new Promise(resolve => { release = resolve; });
  const app = harness(async path => {
    if (path === "/api/installations") return { body: { items: [{ id: 1, status: "active" }] } };
    if (path.endsWith("/repositories")) return { body: { items: [{ id: 2 }] } };
    if (path.endsWith("/branches")) { branchesStarted(); await pending; return { body: { items: [{ name: "old", selected: true }] } }; }
    return { body: { items: [] } };
  });
  Object.assign(app.state, { epoch: 1, installation: 1, repository: 2 });
  const loading = app.loadScoped(1);
  await started;
  Object.assign(app.state, { epoch: 2, installation: 3, repository: 4, branches: [{ name: "new", selected: false }] });
  release(); await loading;
  assert.equal(app.state.installation, 3);
  assert.equal(app.state.repository, 4);
  assert.equal(app.state.branches[0].name, "new");
});

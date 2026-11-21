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
  const events = new Map(), windowEvents = new Map(), timers = new Map();
  let timerId = 0;
  function node(selector) {
    if (!nodes.has(selector)) nodes.set(selector, {
      innerHTML: "", textContent: "", hidden: true, open: false,
      listeners: {}, classList: { toggle() {} }, setAttribute() {},
      addEventListener(name, handler) { this.listeners[name] = handler; },
      contains() { return false; }, focus(options) { this.focusOptions = options; }, replaceChildren() {},
      close() { this.open = false; this.listeners.close?.(); }, showModal() { this.open = true; },
    });
    return nodes.get(selector);
  }
  const calls = [];
  const sandbox = {
    ...model, e: model.escapeHTML, console, URLSearchParams, AbortController,
    setTimeout(fn, delay) { const id = ++timerId; timers.set(id, { fn, delay }); return id; },
    clearTimeout(id) { timers.delete(id); }, matchMedia() { return { matches: false }; },
    localStorage: { getItem() { return null; }, setItem() {} }, location: { hash: "" },
    window: { addEventListener(name, handler) { windowEvents.set(name, handler); }, scrollTo() {} }, document: {
      querySelector: node, querySelectorAll() { return []; },
      addEventListener(name, handler) { events.set(name, handler); }, documentElement: { dataset: {} }, activeElement: null,
    },
    async fetch(path, options) {
      calls.push({ path, options });
      const result = await responder(path, options);
      return new Response(JSON.stringify(result.body ?? {}), { status: result.status ?? 200, headers: { "Content-Type": "application/json" } });
    },
  };
  vm.runInNewContext(`${appSource}\nglobalThis.testApp = { state, api, boot, saveBranches, loadScoped, overview, activity, scanTable, branchRows, simulationControls, renderLogin, openDetail, focusMain };`, sandbox);
  return { ...sandbox.testApp, nodes, calls, events, windowEvents, timers,
    async tick(delay) {
      const entry = [...timers].find(([, timer]) => timer.delay === delay);
      assert.ok(entry, `No timer with delay ${delay}`);
      timers.delete(entry[0]); await entry[1].fn();
    },
  };
}

test("demo connection is neutral even with legacy configured metadata; live stays configured", () => {
  const app = harness(() => ({}));
  app.state.meta = { mode: "demo", github_configured: true };
  assert.match(app.overview(), /badge muted">Simulado/);
  assert.doesNotMatch(app.overview(), />Configurado</);
  app.state.meta.mode = "live";
  assert.match(app.overview(), /badge live">Configurado/);
});

test("activity separates webhook outcome from the linked scan state and handles no scan", () => {
  const app = harness(() => ({}));
  app.state.meta = { mode: "demo" };
  app.state.deliveries = [{ event: "push", status: "queued", scan_id: 'id"<', scan_status: "completed" }, { event: "push", status: "ignored" }];
  const html = app.activity();
  assert.match(html, /Análise enfileirada/);
  assert.match(html, /Análise: Concluída/);
  assert.match(html, /data-id="id&quot;&lt;"/);
  assert.equal((html.match(/data-action="detail"/g) || []).length, 1);
});

test("mobile table rows retain all labelled cells and the report action", async () => {
  const app = harness(() => ({}));
  app.state.meta = { mode: "demo" };
  const html = app.scanTable([{ repository: "repo", branch: "main", id: "1", status: "completed" }]);
  assert.match(html, /responsive-table/);
  assert.equal((html.match(/data-label=/g) || []).length, 5);
  assert.match(html, /data-label="Relatório"><button[^>]+data-action="detail"/);
  const css = await readFile(new URL("../src/sca_reachability/static/styles.css", import.meta.url), "utf8");
  assert.match(css, /@media \(max-width: 640px\)[\s\S]*\.responsive-table td \{ display: block; width: 100%; min-width: 0; \}/);
  assert.match(css, /\.responsive-table td::before \{ content: attr\(data-label\)/);
});

test("pending branch rows and simulation explain unsaved changes and offer all saved targets", () => {
  const app = harness(() => ({}));
  Object.assign(app.state, { meta: { mode: "demo" }, branches: [{ name: "main", selected: true }, { name: "release", selected: true }, { name: "new", selected: false }], selected: new Set(["release", "new"]) });
  assert.match(app.branchRows(), /A incluir ao salvar/);
  assert.match(app.branchRows(), /A remover ao salvar/);
  assert.match(app.simulationControls(), /Salve a seleção para simular/);
  app.state.selected = new Set(["main", "release"]);
  const html = app.simulationControls();
  assert.match(html, /option value="main"/);
  assert.match(html, /option value="release"/);
  assert.doesNotMatch(html, /option value="new"/);
});

test("simulation sends the visibly chosen saved target", async () => {
  const app = harness(() => ({ body: {} }));
  Object.assign(app.state, { authenticated: true, meta: { mode: "demo" }, repository: 2,
    branches: [{ name: "main", selected: true }, { name: "release", selected: true }], selected: new Set(["main", "release"]) });
  app.nodes.set("#simulation-branch", { value: "release" });
  await app.events.get("click")({ target: { closest() { return { dataset: { action: "simulate" } }; } } });
  assert.equal(JSON.parse(app.calls[0].options.body).branch, "release");
});

test("open pending report polls in place to completion, announces and stops", async () => {
  let status = "queued";
  const app = harness(() => ({ body: { status, findings: [], components: [], source: "demo" } }));
  app.state.authenticated = true;
  await app.openDetail("scan");
  assert.match(app.nodes.get("#detail-content").innerHTML, /Resultados ainda não calculados/);
  assert.doesNotMatch(app.nodes.get("#detail-content").innerHTML, /Nenhum achado disponível|Componentes analisados|APOIO À LEITURA/);
  status = "running"; await app.tick(2000);
  assert.match(app.nodes.get("#detail-content").innerHTML, /Em andamento/);
  status = "completed"; await app.tick(2000);
  assert.match(app.nodes.get("#detail-content").innerHTML, /não significa que o projeto está livre/);
  assert.equal(app.nodes.get("#detail-announcement").textContent, "Análise: Concluída.");
  assert.equal(app.timers.size, 0);
});

test("closing a report cancels polling and restores focus without scrolling navigation away", async () => {
  const app = harness(() => ({ body: { status: "queued" } }));
  app.state.authenticated = true;
  await app.openDetail("scan");
  app.nodes.get("#detail-dialog").close();
  assert.equal(app.timers.size, 0);
  assert.equal(app.nodes.get("#main").focusOptions.preventScroll, true);
});

test("failed or unavailable reports never poll or present empty calculated results", async () => {
  for (const result of [{ body: { status: "failed", error: "error" } }, { status: 503 }]) {
    const app = harness(() => result);
    app.state.authenticated = true;
    await app.openDetail("scan");
    assert.equal(app.timers.size, 0);
    assert.doesNotMatch(app.nodes.get("#detail-content").innerHTML, /Componentes analisados|Nenhum achado disponível/);
  }
});

test("demo login shows the single-line token hint and quick entry only in demo", async () => {
  const app = harness(() => ({}));
  app.state.meta = { mode: "demo" }; app.renderLogin();
  assert.match(app.nodes.get("#main").innerHTML, /class="demo-token">Use o token <code>local-demo/);
  let submitted = false;
  app.nodes.set("#login-form", { requestSubmit() { submitted = true; } });
  app.nodes.set("#access-token", { value: "" });
  await app.events.get("click")({ target: { closest() { return { dataset: { action: "demo-login" } }; } } });
  assert.equal(app.nodes.get("#access-token").value, "local-demo");
  assert.equal(submitted, true);
});

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

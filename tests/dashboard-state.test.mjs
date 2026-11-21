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
  const clipboard = { values: [], async writeText(text) { this.values.push(text); } };
  const sandbox = {
    ...model, e: model.escapeHTML, console, URLSearchParams, AbortController,
    setTimeout(fn, delay) { const id = ++timerId; timers.set(id, { fn, delay }); return id; },
    clearTimeout(id) { timers.delete(id); }, matchMedia() { return { matches: false }; },
    localStorage: { getItem() { return null; }, setItem() {} }, location: { hash: "" },
    navigator: { clipboard },
    window: { addEventListener(name, handler) { windowEvents.set(name, handler); }, scrollTo() {} }, document: {
      querySelector: node, querySelectorAll() { return []; },
      addEventListener(name, handler) { events.set(name, handler); }, documentElement: { dataset: {} }, activeElement: null, visibilityState: "visible",
    },
    async fetch(path, options) {
      calls.push({ path, options });
      const result = await responder(path, options);
      return new Response(JSON.stringify(result.body ?? {}), { status: result.status ?? 200, headers: { "Content-Type": "application/json" } });
    },
  };
  vm.runInNewContext(`${appSource}\nglobalThis.testApp = { state, api, boot, saveBranches, loadScoped, overview, activity, scanTable, branchRows, simulationControls, renderLogin, openDetail, focusMain, matchingScans, resultsList, refresh, selectFiltered, findingMarkup, advisoryLink, manifestLink, findingInstructions, copyInstructions, selectionSummary };`, sandbox);
  return { ...sandbox.testApp, nodes, calls, events, windowEvents, timers, clipboard, document: sandbox.document,
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

test("results search finds advisory IDs and package names, including clean inventories", () => {
  const app = harness(() => ({}));
  app.state.scans = [
    { id: "affected", status: "completed", advisory_ids: ["DEMO-0001"], package_names: ["fictional-demo-package"] },
    { id: "clean", status: "completed", advisory_ids: [], package_names: ["fictional-demo-package"] },
  ];
  app.state.filter = "demo-0001";
  assert.equal(app.matchingScans().length, 1);
  app.state.filter = "fictional-demo-package";
  assert.equal(app.matchingScans().length, 2);
  app.state.statusFilter = "failed";
  assert.equal(app.matchingScans().length, 0);
  app.state.meta = { mode: "demo" };
  assert.match(app.scanTable(app.state.scans), /DEMO-0001/);
});

const evidenceFinding = { advisory_id: "DEMO-0001", package_name: "fictional-demo-package", version: "1.0.0",
  ecosystem: "npm", purl: "pkg:npm/fictional-demo-package@1.0.0", reachability: "unknown", fixed_versions: ["1.1.0"] };
const evidenceScan = { status: "completed", source: "demo", repository: "fictional/repo", commit_sha: "a".repeat(40),
  findings: [evidenceFinding], components: [{ name: evidenceFinding.package_name, version: "1.0.0",
    ecosystem: "npm", purl: evidenceFinding.purl, manifest_path: "locks/package-lock.json" }] };

test("evidence explains exact-version provenance honestly in demo and live modes", () => {
  const app = harness(() => ({}));
  app.state.meta = { mode: "demo" };
  const html = app.findingMarkup(evidenceFinding, evidenceScan);
  assert.match(html, /fictional-demo-package@1.0.0/);
  assert.match(html, /locks\/package-lock.json/);
  assert.match(html, /aaaaaaa/);
  assert.match(html, /não houve consulta ao OSV/);
  assert.match(html, /Não foi feita análise de fluxo\/chamadas; por isso o alcance é desconhecido/);
  assert.match(html, /DEMO-0001 · fictício/);
  assert.doesNotMatch(html, /href="https:/);
  app.state.meta.mode = "live";
  const live = app.findingMarkup({ ...evidenceFinding, advisory_id: "CVE-2024-12345" }, { ...evidenceScan, source: "github" });
  assert.match(live, /Correspondência com o aviso por versão exata via OSV/);
  assert.match(live, /https:\/\/github.com\/fictional\/repo\/blob\/a{40}\/locks\/package-lock.json/);
  assert.match(live, /https:\/\/osv.dev\/vulnerability\/CVE-2024-12345/);
  assert.match(live, /rel="noopener noreferrer"/);
});

test("evidence links only known safe destinations and instructions escape untrusted metadata", () => {
  const app = harness(() => ({}));
  app.state.meta = { mode: "live" };
  for (const id of ["CVE-2024-12345", "GHSA-jfh8-c2jp-5v3q", "RUSTSEC-2024-0001"]) assert.match(app.advisoryLink(id), /https:\/\/osv.dev/);
  for (const id of ['CVE-2024-"><img>', "javascript:alert(1)", "DEMO-0001"]) assert.doesNotMatch(app.advisoryLink(id), /<a /);
  for (const path of ["../package-lock.json", "/package-lock.json"]) assert.doesNotMatch(app.manifestLink(path, { ...evidenceScan, source: "github" }), /<a /);
  assert.doesNotMatch(app.manifestLink("package-lock.json", { ...evidenceScan, source: "github", repository: "evil.invalid/repo/path" }), /<a /);
  const instruction = app.findingInstructions(evidenceFinding, evidenceScan);
  assert.match(instruction, /fictional-demo-package 1.1.0 em locks\/package-lock.json; atualize, teste e execute nova análise/);
  assert.match(app.findingInstructions({ ...evidenceFinding, fixed_versions: [] }, evidenceScan), /sem versão corrigida informada/);
  assert.match(app.findingInstructions(evidenceFinding, { components: [] }), /manifesto não informado/);
  const html = app.findingMarkup({ ...evidenceFinding, package_name: '"><img src=x onerror=x>' }, evidenceScan);
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /Copiar instruções/);
});

test("copy instructions uses the clipboard and announces a safe failure", async () => {
  const app = harness(() => ({}));
  assert.equal(await app.copyInstructions("instruções"), true);
  assert.deepEqual(app.clipboard.values, ["instruções"]);
  app.clipboard.writeText = async () => { throw new Error("private"); };
  assert.equal(await app.copyInstructions("instruções"), false);
  assert.match(app.nodes.get("#detail-announcement").textContent, /Selecione e copie/);
  assert.doesNotMatch(app.nodes.get("#detail-announcement").textContent, /private/);
});

test("report retains header and footer close actions with sticky compact styling", async () => {
  const app = harness(() => ({ body: evidenceScan }));
  Object.assign(app.state, { authenticated: true, meta: { mode: "demo" } });
  await app.openDetail("id");
  const html = app.nodes.get("#detail-content").innerHTML;
  assert.equal((html.match(/data-action="close-detail"/g) || []).length, 2);
  assert.match(html, /1 achado\./);
  const css = await readFile(new URL("../src/sca_reachability/static/styles.css", import.meta.url), "utf8");
  assert.match(css, /\.dialog-heading \{ position: sticky; top: 0/);
  assert.match(css, /#detail-title \{ font-size: 22px/);
});

test("switching away and back keeps a numeric demo repository ID and saved target", async () => {
  const app = harness(path => {
    if (path === "/api/installations") return { body: { items: [{ id: 9001, status: "active" }] } };
    if (path.endsWith("/repositories")) return { body: { items: [{ id: 9002 }, { id: 9003 }] } };
    if (path.endsWith("/branches")) return { body: { items: [{ name: path.includes("/9003/") ? "main" : "release", selected: true }] } };
    if (path.startsWith("/api/scans") || path === "/api/deliveries") return { body: { items: [] } };
    return { body: {} };
  });
  Object.assign(app.state, { authenticated: true, meta: { mode: "demo" }, installation: 9001, repository: 9002, view: "branches" });
  for (const value of ["9003", "9002"]) {
    await app.events.get("change")({ target: { matches() { return false; }, dataset: { control: "repository" }, value } });
  }
  assert.equal(app.state.repository, 9002);
  assert.equal(app.state.selected.has("release"), true);
  assert.equal(app.state.selected.has("main"), false);
  app.nodes.set("#simulation-branch", { value: "release" });
  await app.events.get("click")({ target: { closest() { return { dataset: { action: "simulate" } }; } } });
  const request = app.calls.find(call => call.path === "/api/demo/push");
  assert.deepEqual(JSON.parse(request.options.body), { repository_id: 9002, branch: "release" });
});

test("silent results polling updates matching rows without touching the focused search or caret", async () => {
  const app = harness(path => ({ body: path.startsWith("/api/scans") ? { items: [{ id: "new", status: "failed", branch: "stress/01" }] } : path === "/api/deliveries" ? { items: [] } : {} }));
  Object.assign(app.state, { authenticated: true, meta: { mode: "demo" }, view: "results", installation: 1, repository: 2, filter: "stress/01" });
  const search = { value: "stress/01", selectionStart: 3, selectionEnd: 3 };
  app.document.activeElement = search;
  app.nodes.set("#results-search", search);
  app.nodes.set("#main", { contains() { return true; } });
  await app.refresh({ full: false, silent: true });
  assert.match(app.nodes.get("#results-list").innerHTML, /Falhou/);
  assert.equal(app.nodes.get("#results-search"), search);
  assert.equal(search.selectionStart, 3);
  assert.equal(app.state.filter, "stress/01");
  assert.ok([...app.timers.values()].some(timer => timer.delay === 15000));
});

test("bulk selection respects the global limit, and the 21st checkbox is rejected inline", async () => {
  const app = harness(() => ({}));
  const branches = Array.from({ length: 23 }, (_, i) => ({ name: "stress/" + i, selected: false }));
  Object.assign(app.state, { meta: { mode: "demo" }, branches, selected: new Set(["hidden"]), filter: "stress/" });
  app.selectFiltered();
  assert.equal(app.state.selected.size, 20);
  assert.equal(app.state.selected.has("hidden"), true);
  assert.match(app.selectionSummary(), /20 de 20/);
  const target = { checked: true, dataset: { branch: "stress/22" }, matches() { return true; } };
  await app.events.get("change")({ target });
  assert.equal(target.checked, false);
  assert.equal(app.state.selected.size, 20);
  assert.match(app.nodes.get("#selection-error").textContent, /Limite de 20/);
  await app.events.get("click")({ target: { closest() { return { dataset: { action: "clear-selection" } }; } } });
  assert.equal(app.state.selected.size, 0);
});

test("known validation errors are localized; unknown diagnostics never reach the UI", async () => {
  const known = harness(() => ({ status: 400, body: { detail: "Select at most 20 distinct existing branch names." } }));
  await assert.rejects(known.api("/api/example"), /no máximo 20/);
  const unknown = harness(() => ({ status: 400, body: { detail: "private secret" } }));
  await assert.rejects(unknown.api("/api/example"), error => !error.message.includes("private") && /validar/.test(error.message));
});

test("clearing an empty results search restores the branch-selection shortcut", () => {
  const app = harness(() => ({}));
  app.state.meta = { mode: "demo" };
  app.state.filter = "missing";
  assert.match(app.resultsList(), /corresponde aos filtros/);
  app.events.get("input")({ target: { id: "results-search", value: "" } });
  assert.match(app.nodes.get("#results-list").innerHTML, /href="#branches"/);
});

test("empty login token receives inline Portuguese validation without a request", async () => {
  const app = harness(() => ({}));
  const field = { value: "", focus(options) { this.options = options; } };
  await app.events.get("submit")({ preventDefault() {}, target: { id: "login-form", elements: { token: field }, querySelector() { return {}; } } });
  assert.equal(app.calls.length, 0);
  assert.match(app.nodes.get("#login-error").textContent, /Informe o token/);
  assert.equal(field.options.preventScroll, true);
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
    assert.doesNotMatch(app.nodes.get("#detail-content").innerHTML, /Componentes analisados|Nenhum achado disponível|APOIO À LEITURA/);
  }
});

test("failed report retry posts the scoped scan ID and replaces failure with pending progress", async () => {
  const app = harness(path => ({ body: path.endsWith("/retry") ? { scan_id: "failed/scan" } : { status: "queued" } }));
  app.state.authenticated = true;
  const target = { dataset: { action: "retry-scan", id: "failed/scan" } };
  await app.events.get("click")({ target: { closest() { return target; } } });
  assert.equal(app.calls[0].path, "/api/scans/failed%2Fscan/retry");
  assert.equal(app.calls[0].options.method, "POST");
  assert.match(app.nodes.get("#detail-content").innerHTML, /Resultados ainda não calculados/);
  assert.equal(target.disabled, false);
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
  assert.match(app.state.saveError, /Não foi possível/);
  assert.match(app.nodes.get("#main").innerHTML, /id="save-error"[^>]*>Não foi possível/);
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

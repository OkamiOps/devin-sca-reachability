import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// No package.json or build is needed to exercise the browser's pure ES module.
const source = await readFile(new URL("../src/sca_reachability/static/model.js", import.meta.url), "utf8");
const { escapeHTML, count, isDirty, reachabilityLabel, explanationPresentation, scopedRepositoryPath, formatDate, reachabilityPresentation, evidenceSteps, sortFindings, reachabilityCounts } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
const { supportedMode, githubLink, advisoryURL, findingPage, findingScope, findingPresentation, scopeCounts, scopeSummary, dependencyPresentation, isTransitiveUnknown } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

test("public is a supported mode, but unknown modes are rejected", () => {
  for (const mode of ["demo", "live", "public"]) assert.equal(supportedMode(mode), true);
  for (const mode of [null, undefined, "PUBLIC", "__proto__", ""]) assert.equal(supportedMode(mode), false);
});
test("GitHub links use the exact commit and safely encoded source path and line", () => {
  const scan = { source: "github", repository: "owner/repo", commit_sha: "a".repeat(40) };
  const base = `https://github.com/owner/repo`;
  assert.equal(githubLink(scan), `${base}/commit/${scan.commit_sha}`);
  assert.equal(githubLink(scan, "src/a b#ç?.js", 129), `${base}/blob/${scan.commit_sha}/src/a%20b%23%C3%A7%3F.js#L129`);
  for (const path of ["../x", "/x", "a//b", "a/./b", "a\\b", "a\nx"]) assert.equal(githubLink(scan, path), null);
  for (const line of ["1", -1, 0, 1.5, Infinity]) assert.equal(githubLink(scan, "a.js", line), null);
  for (const change of [{ source: "demo" }, { repository: "javascript:alert(1)" }, { repository: "a/.." }, { repository: "a/b?x" }, { commit_sha: "main" }]) assert.equal(githubLink({ ...scan, ...change }), null);
  assert.equal(githubLink(null), null);
});
test("OSV links accept public identifiers without accepting active URLs or demo IDs", () => {
  assert.equal(advisoryURL("GHSA-fwr7-v2mv-hh25"), "https://osv.dev/vulnerability/GHSA-fwr7-v2mv-hh25");
  for (const id of [null, "", "DEMO-0001", "../x", "https://evil.invalid", "x\" onclick=\"x"]) assert.equal(advisoryURL(id), null);
});
test("large finding sets paginate in reachability order and preserve unknown", () => {
  const findings = Array.from({ length: 437 }, (_, i) => ({ id: i, reachability: i < 422 ? "unknown" : "reachable" }));
  const page = findingPage(findings);
  assert.equal(page.total, 437); assert.equal(page.pages, 44); assert.equal(page.items.length, 10);
  assert.ok(page.items.every(f => f.reachability === "reachable"));
  assert.equal(findingPage(findings, "unknown").total, 422);
  assert.equal(findingPage(findings, "unreachable").items.length, 0);
  assert.equal(findingPage(findings, "all", 999).items.length, 7);
  assert.equal(findingPage(findings, "all", -1).page, 0);
  assert.deepEqual(findingPage(undefined).items, []);
  assert.equal(findingPage([{ reachability: "safe" }], "unknown").total, 1);
  assert.equal(findings[0].id, 0);
});

test("untrusted GitHub and AI strings cannot become active HTML or attribute markup", () => {
  assert.equal(escapeHTML('<img src=x onerror="x()">&\''), "&lt;img src=x onerror=&quot;x()&quot;&gt;&amp;&#39;");
  assert.equal(escapeHTML(null), "");
});
test("unknown reachability is not rewritten as unreachable or interpreted from prose", () => {
  assert.equal(reachabilityLabel("unknown"), "Desconhecido");
  assert.equal(reachabilityLabel(undefined), "Não informado");
  assert.equal(reachabilityLabel("safe"), "Não informado");
});
test("AI provenance follows structured service metadata, not wording", () => {
  assert.equal(explanationPresentation({ status: "available", source: "deterministic", text: "AI says safe" }).ai, false);
  assert.equal(explanationPresentation({ status: "available", source: "ai", text: "Unknown" }).ai, true);
  assert.match(explanationPresentation({ status: "disabled", source: "ai", text: "Old text" }).text, /não está habilitada/);
  assert.equal(explanationPresentation({ status: "available", text: "No provenance" }).ai, false);
});
test("deterministic fallback is visible when AI is disabled or the provider is unavailable", () => {
  for (const status of ["disabled", "unavailable"]) {
    const result = explanationPresentation({ status, source: "deterministic", text: "Resumo local dos achados." });
    assert.equal(result.text, "Resumo local dos achados.");
    assert.equal(result.title, "Resumo determinístico · sem IA");
    assert.equal(result.ai, false);
    assert.ok(result.note);
  }
  assert.match(explanationPresentation({ status: "unavailable", source: "ai", text: "Stale output" }).text, /Não foi possível/);
});
test("branch edits preserve off-screen selections and detect a pause-all change", () => {
  const branches = [{ name: "main", selected: true }, { name: "release/v1", selected: true }, { name: "feature", selected: false }];
  assert.equal(isDirty(branches, new Set(["release/v1", "main"])), false);
  assert.equal(isDirty(branches, new Set()), true);
  assert.equal(isDirty(branches, new Set(["main", "feature"])), true);
});
test("installation and repository identities remain separate encoded path segments", () => {
  assert.equal(scopedRepositoryPath(123, 987), "/api/installations/123/repositories/987");
  assert.equal(scopedRepositoryPath("../1", "2?x=3"), "/api/installations/..%2F1/repositories/2%3Fx%3D3");
  assert.throws(() => scopedRepositoryPath(null, 987));
});
test("missing metrics and malformed timestamps are not displayed as real zero results", () => {
  assert.equal(count(null), "—"); assert.equal(count(undefined), "—");
  assert.equal(count(-1), "—"); assert.equal(count(0), "0");
  assert.equal(formatDate("invalid"), "Data indisponível");
});

test("each reachability state keeps a distinct caveat and unknown is never presented as safe", () => {
  assert.equal(reachabilityPresentation("reachable").tone, "reachable");
  assert.match(reachabilityPresentation("unknown").caveat, /não significa seguro/);
  assert.match(reachabilityPresentation("unreachable").caveat, /Não é garantia/);
  for (const status of ["safe", undefined, "__proto__"]) {
    assert.equal(reachabilityPresentation(status).tone, "unknown");
    assert.match(reachabilityPresentation(status).caveat, /não significa seguro/);
  }
});
test("evidence steps keep file, line and path and drop malformed entries", () => {
  const steps = evidenceSteps([
    { path: "src/server.js", line: 2, kind: "import", detail: "import 'pkg'", snippet: "import x from 'pkg';" },
    { path: "src/server.js", line: 7, kind: "call", detail: "renderTemplate()", snippet: "<b>x</b>" },
    { path: "src/x.js", line: "7", kind: "call" }, { line: 1 }, null, { path: "a.js", line: 3, kind: "<script>" },
  ]);
  assert.deepEqual(steps.map(step => [step.location, step.kind, step.kindLabel]), [
    ["src/server.js:2", "import", "Importa"], ["src/server.js:7", "call", "Chama"], ["a.js:3", "other", "Evidência"],
  ]);
  assert.deepEqual(evidenceSteps("not a list"), []);
});
test("findings are ordered reachable, unknown, unreachable and counted without trusting labels", () => {
  const findings = [{ id: "c", reachability: "unreachable" }, { id: "b", reachability: "unknown" }, { id: "a", reachability: "reachable" }, { id: "d", reachability: "safe" }];
  assert.deepEqual(sortFindings(findings).map(item => item.id), ["a", "b", "d", "c"]);
  assert.deepEqual(reachabilityCounts(findings), { reachable: 1, unknown: 2, unreachable: 1 });
});

test("reachable context is factual, ordered production-first and filterable without reclassification", () => {
  const findings = [
    { id: "test", reachability: "reachable", reachability_scope: "test_only" },
    { id: "unknown", reachability: "unknown", reachability_scope: "production" },
    { id: "tool", reachability: "reachable", reachability_scope: "dev_tooling" },
    { id: "legacy", reachability: "reachable" },
    { id: "prod", reachability: "reachable", reachability_scope: "production" },
    { id: "negative", reachability: "unreachable", reachability_scope: "test_only" },
  ];
  const original = JSON.stringify(findings);
  assert.deepEqual(sortFindings(findings).map(f => f.id), ["prod", "test", "tool", "legacy", "unknown", "negative"]);
  assert.deepEqual(findingPage(findings, "production").items.map(f => f.id), ["prod"]);
  assert.deepEqual(findingPage(findings, "nonproduction").items.map(f => f.id), ["test", "tool"]);
  assert.deepEqual(findingPage(findings, "unknown").items.map(f => f.id), ["unknown"]);
  assert.deepEqual(scopeCounts(findings), { production: 1, test_only: 1, dev_tooling: 1, unreported: 1 });
  assert.match(scopeSummary(scopeCounts(findings)), /1 alcançáveis em produção · 2 só em testes\/ferramentas · 1 alcançáveis sem contexto informado/);
  assert.equal(findingPresentation(findings[4]).label, "Alcançável em produção");
  assert.equal(findingPresentation(findings[0]).label, "Alcançável só em testes/ferramentas");
  assert.equal(findingPresentation(findings[2]).label, "Alcançável só em testes/ferramentas");
  assert.equal(findingPresentation(findings[1]).label, "Desconhecido");
  assert.match(findingPresentation(findings[1]).caveat, /não significa seguro/);
  assert.equal(JSON.stringify(findings), original);
});

test("empty and malformed scopes never invent production reachability", () => {
  assert.deepEqual(scopeCounts(null), { production: 0, test_only: 0, dev_tooling: 0, unreported: 0 });
  assert.equal(scopeSummary(null), "");
  assert.equal(findingScope({ reachability_scope: "__proto__" }), null);
  assert.equal(findingScope(null), null);
  assert.equal(findingScope({ reachability_analysis: { scope: "production" } }), "production");
  assert.equal(findingPresentation({ reachability: "safe", reachability_scope: "production" }).tone, "unknown");
  assert.equal(findingPage([], "nonproduction").total, 0);
  assert.equal(findingPage([{ reachability: "reachable" }], "production").total, 0);
});

test("dependency relation and imported-transitive bucket never imply safe or reachable", () => {
  const transitive = { id: "qs", reachability: "unknown", dependency_relation: "transitive",
    dependency_via: [["body-parser", "qs"], ["express", "body-parser", "qs"]],
    reachability_analysis: { transitive_imported_via: true } };
  assert.equal(dependencyPresentation(transitive), "Transitiva via body-parser, express");
  assert.equal(dependencyPresentation({ dependency_relation: "direct" }), "Direta");
  assert.equal(dependencyPresentation({ dependency_relation: "transitive", dependency_via: [null, [], [1]] }), "Transitiva · grafo não resolvido");
  assert.equal(dependencyPresentation(null), "Relação não informada");
  assert.equal(dependencyPresentation({ reachability_analysis: { dependency_relation: "direct" } }), "Direta");
  assert.equal(isTransitiveUnknown(transitive), true);
  assert.equal(isTransitiveUnknown({ reachability: "reachable", reachability_analysis: { transitive_imported_via: true } }), false);
  assert.equal(isTransitiveUnknown({ reachability: "unknown", reachability_analysis: { transitive_imported_via: "true" } }), false);
  const findings = [{ id: "other", reachability: "unknown" }, transitive, { id: "prod", reachability: "reachable", reachability_scope: "production" }];
  const original = JSON.stringify(findings);
  assert.deepEqual(findingPage(findings, "transitive_unknown").items.map(f => f.id), ["qs"]);
  assert.equal(findingPage([], "transitive_unknown").total, 0);
  assert.deepEqual(sortFindings(findings).map(f => f.id), ["prod", "qs", "other"]);
  assert.match(findingPresentation(transitive).caveat, /não significa seguro/);
  assert.equal(JSON.stringify(findings), original);
});

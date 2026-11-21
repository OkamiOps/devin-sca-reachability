import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// No package.json or build is needed to exercise the browser's pure ES module.
const source = await readFile(new URL("../src/sca_reachability/static/model.js", import.meta.url), "utf8");
const { escapeHTML, count, isDirty, reachabilityLabel, explanationPresentation, scopedRepositoryPath, formatDate } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

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

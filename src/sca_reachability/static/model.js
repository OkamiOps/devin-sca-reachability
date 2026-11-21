// Shared, side-effect-free display rules. Never infer reachability from AI prose.
export function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

export function formatDate(value) {
  if (!value) return "Ainda não registrada";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Data indisponível";
  return new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
}

export function count(value) {
  return Number.isFinite(value) && value >= 0 ? new Intl.NumberFormat("pt-BR").format(value) : "—";
}

export function supportedMode(mode) { return ["demo", "live", "public"].includes(mode); }

export function githubLink(scan, path = null, line = null) {
  if (scan?.source !== "github" || !/^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(scan.repository || "") ||
      !/^[a-f0-9]{40}$/i.test(scan.commit_sha || "")) return null;
  const base = `https://github.com/${scan.repository.split('/').map(encodeURIComponent).join('/')}`;
  if (path === null) return `${base}/commit/${scan.commit_sha}`;
  if (typeof path !== "string" || /[\\\x00-\x1f]/.test(path) || path.split('/').some(p => !p || p === '.' || p === '..') ||
      (line !== null && (!Number.isSafeInteger(line) || line < 1))) return null;
  return `${base}/blob/${scan.commit_sha}/${path.split('/').map(encodeURIComponent).join('/')}${line === null ? '' : `#L${line}`}`;
}

export function advisoryURL(id) {
  return typeof id === "string" && !id.startsWith("DEMO-") && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)
    ? `https://osv.dev/vulnerability/${encodeURIComponent(id)}` : null;
}

export function findingPage(findings, filter = "all", page = 0, size = 10) {
  const sorted = sortFindings(findings).filter(f => filter === "all" ||
    (filter === "transitive_decided" ? f.reachability_analysis?.transitive_decided === true && f.reachability !== "unknown" :
      filter === "transitive_unknown" ? isTransitiveUnknown(f) :
      filter === "production" ? f.reachability === "reachable" && findingScope(f) === "production" :
      filter === "nonproduction" ? f.reachability === "reachable" && ["test_only", "dev_tooling"].includes(findingScope(f)) :
        reachabilityPresentation(f.reachability).tone === filter));
  const pages = Math.max(1, Math.ceil(sorted.length / size));
  const current = Math.max(0, Math.min(page, pages - 1));
  return { items: sorted.slice(current * size, (current + 1) * size), total: sorted.length, page: current, pages };
}

export function scanLabel(status) {
  return ({ queued: "Na fila", running: "Em andamento", completed: "Concluída", failed: "Falhou" })[status] || "Estado desconhecido";
}

export function reachabilityLabel(status) {
  return ({ unknown: "Desconhecido", reachable: "Alcançável", unreachable: "Inalcançável" })[status] || "Não informado";
}

export function isDirty(branches, selected) {
  const saved = new Set(branches.filter(branch => branch.selected).map(branch => branch.name));
  return saved.size !== selected.size || [...saved].some(name => !selected.has(name));
}

export function scopedRepositoryPath(installation, repository) {
  if (installation == null || repository == null) throw new Error("Selecione uma instalação e um repositório.");
  return `/api/installations/${encodeURIComponent(installation)}/repositories/${encodeURIComponent(repository)}`;
}

export function explanationPresentation(explanation) {
  if (explanation?.source === "deterministic" && explanation.text) {
    return {
      title: "Resumo determinístico · sem IA", text: explanation.text, ai: false,
      note: explanation.status === "unavailable"
        ? "A IA não respondeu. Este resumo local continua disponível e não foi gerado por IA."
        : explanation.status === "disabled" ? "A explicação por IA está desabilitada neste ambiente." : null,
    };
  }
  if (explanation?.status !== "available" || !explanation.text) {
    return { title: "Explicação indisponível", text: explanation?.status === "disabled"
      ? "A explicação por IA não está habilitada neste ambiente. Os achados acima continuam disponíveis."
      : "Não foi possível obter uma explicação. Isso não altera os resultados da análise.", ai: false };
  }
  if (explanation.source === "ai") return { title: "Explicação gerada por IA", text: explanation.text, ai: true };
  return { title: "Explicação · origem não informada", text: explanation.text, ai: false };
}

const REACHABILITY = {
  reachable: { label: "Alcançável", tone: "reachable", order: 0, headline: "O código importa e chama o alvo do aviso.", caveat: "Priorize a correção: existe um caminho estático até o código vulnerável." },
  unknown: { label: "Desconhecido", tone: "unknown", order: 1, headline: "A análise estática não conseguiu decidir.", caveat: "Desconhecido não significa seguro. Trate como potencialmente alcançável." },
  unreachable: { label: "Inalcançável", tone: "unreachable", order: 2, headline: "Nenhuma chamada ao alvo foi encontrada neste commit.", caveat: "Não é garantia de segurança: vale apenas para este commit e dentro dos limites da análise." },
};
const UNREPORTED = { label: "Não informado", tone: "unknown", order: 1, headline: "O serviço não informou o alcance.", caveat: "Sem classificação, trate como desconhecido; isso não significa seguro." };
export function reachabilityPresentation(status) {
  return Object.hasOwn(REACHABILITY, status) ? REACHABILITY[status] : UNREPORTED;
}
const EVIDENCE_KINDS = { import: "Importa", entrypoint: "Entrada CLI", transitive_import: "Importa intermediária", transitive_entrypoint: "CLI intermediária", call: "Chama", dynamic: "Carga dinâmica", escape: "Uso indireto" };
export function evidenceSteps(evidence) {
  return (Array.isArray(evidence) ? evidence : [])
    .filter(item => item && typeof item.path === "string" && item.path && Number.isInteger(item.line) && item.line > 0)
    .slice(0, 6)
    .map(item => ({
      path: item.path, line: item.line, location: `${item.path}:${item.line}`,
      kind: Object.hasOwn(EVIDENCE_KINDS, item.kind) ? item.kind : "other",
      kindLabel: EVIDENCE_KINDS[item.kind] || "Evidência",
      detail: typeof item.detail === "string" ? item.detail : "",
      snippet: typeof item.snippet === "string" ? item.snippet : "",
    }));
}
export function sortFindings(findings) {
  const order = finding => reachabilityPresentation(finding?.reachability).order * 3 +
    (finding?.reachability === "reachable" ? findingScope(finding) === "production" ? 0 : findingScope(finding) ? 1 : 2 :
      reachabilityPresentation(finding?.reachability).tone === "unknown" && !isTransitiveUnknown(finding) ? 1 : 0);
  return (Array.isArray(findings) ? [...findings] : [])
    .sort((a, b) => order(a) - order(b));
}

export function findingScope(finding) {
  const scope = finding?.reachability_scope ?? finding?.reachability_analysis?.scope;
  return ["production", "test_only", "dev_tooling"].includes(scope) ? scope : null;
}

export function isTransitiveUnknown(finding) {
  return finding?.reachability === "unknown" && finding?.reachability_analysis?.transitive_imported_via === true;
}

export function dependencyPresentation(finding) {
  const relation = finding?.dependency_relation ?? finding?.reachability_analysis?.dependency_relation;
  if (relation === "direct") return "Direta";
  if (relation !== "transitive") return "Relação não informada";
  const chains = finding?.dependency_via ?? finding?.reachability_analysis?.dependency_via;
  const roots = [...new Set((Array.isArray(chains) ? chains : []).filter(chain => Array.isArray(chain) && typeof chain[0] === "string" && chain[0]).map(chain => chain[0]))];
  return roots.length ? `Transitiva via ${roots.slice(0, 3).join(", ")}${roots.length > 3 ? ` e mais ${roots.length - 3}` : ""}` : "Transitiva · grafo não resolvido";
}

export function findingPresentation(finding) {
  let presentation = reachabilityPresentation(finding?.reachability);
  const importLevel = finding?.reachability === "reachable" && finding?.reachability_analysis?.granularity === "import";
  if (importLevel) presentation = { ...presentation,
    headline: "Há um caminho estático de importações até o pacote.",
    caveat: "Alcance no nível de importação: não comprova chamada do símbolo vulnerável, execução ou exploração." };
  const scope = findingScope(finding);
  if (finding?.reachability !== "reachable" || !scope) return presentation;
  return { ...presentation, label: scope === "production" ? "Alcançável em produção" : "Alcançável só em testes/ferramentas",
    headline: importLevel || scope === "production" ? presentation.headline : "Chamada encontrada em contexto de testes ou ferramentas.",
    caveat: `${presentation.caveat} O contexto é inferido dos caminhos e do lockfile, não de execução em produção.` };
}

export function transitiveSteps(finding) {
  const path = finding?.reachability_analysis?.transitive_path;
  if (!Array.isArray(path)) return [];
  return path.filter(step => step && typeof step.file === "string" && step.file &&
    (step.line === null || Number.isInteger(step.line) && step.line > 0) && typeof step.specifier === "string")
    .slice(0, 64).map(step => ({ ...step,
      originLabel: step.kind === "grunt" ? "Gruntfile" : step.kind === "npm_script" ? `script npm · ${typeof step.label === "string" ? step.label : "scripts"}` : "Código do repositório",
      url: typeof step.package === "string" && typeof step.version === "string"
      ? `https://www.npmjs.com/package/${encodeURIComponent(step.package)}/v/${encodeURIComponent(step.version)}?activeTab=code` : null }));
}

export function scopeCounts(findings) {
  const counts = { production: 0, test_only: 0, dev_tooling: 0, unreported: 0 };
  for (const finding of Array.isArray(findings) ? findings : []) {
    if (finding?.reachability === "reachable") counts[findingScope(finding) || "unreported"] += 1;
  }
  return counts;
}

export function scopeSummary(counts) {
  if (!counts) return "";
  return `${count(counts.production)} alcançáveis em produção · ${count((counts.test_only || 0) + (counts.dev_tooling || 0))} só em testes/ferramentas${counts.unreported ? ` · ${count(counts.unreported)} alcançáveis sem contexto informado` : ""}`;
}
export function reachabilityCounts(findings) {
  const counts = { reachable: 0, unknown: 0, unreachable: 0 };
  for (const finding of Array.isArray(findings) ? findings : []) {
    counts[Object.hasOwn(REACHABILITY, finding?.reachability) ? finding.reachability : "unknown"] += 1;
  }
  return counts;
}

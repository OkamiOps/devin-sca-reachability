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
const EVIDENCE_KINDS = { import: "Importa", call: "Chama", dynamic: "Carga dinâmica", escape: "Uso indireto" };
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
  return (Array.isArray(findings) ? [...findings] : [])
    .sort((a, b) => reachabilityPresentation(a?.reachability).order - reachabilityPresentation(b?.reachability).order);
}
export function reachabilityCounts(findings) {
  const counts = { reachable: 0, unknown: 0, unreachable: 0 };
  for (const finding of Array.isArray(findings) ? findings : []) {
    counts[Object.hasOwn(REACHABILITY, finding?.reachability) ? finding.reachability : "unknown"] += 1;
  }
  return counts;
}

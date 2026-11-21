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

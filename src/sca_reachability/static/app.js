import { escapeHTML as e, formatDate, count, scanLabel, reachabilityLabel, isDirty, scopedRepositoryPath, explanationPresentation } from "/model.js";

const $ = selector => document.querySelector(selector);
const state = {
  meta: null, authenticated: false, view: "overview", dashboard: null,
  installations: [], installation: null, repositories: [], repository: null,
  branches: [], selected: new Set(), scans: [], deliveries: [],
  filter: "", statusFilter: "all", busy: false, operation: null, epoch: 0, detailEpoch: 0,
  lastUpdated: null, timer: null, noticeTimer: null, detailTimer: null,
  selectionError: "", saveError: "", connectionNotice: false,
};
const MAX_BRANCHES = 20;
class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; this.connection = status === 0 || status >= 500; }
}

async function api(path, { method = "GET", body } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(path, {
      method, credentials: "same-origin", cache: "no-store", signal: controller.signal,
      headers: { Accept: "application/json", ...(method !== "GET" ? { "Content-Type": "application/json", "X-SCA-Request": "1" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    if (response.status === 401) {
      if (state.authenticated) endSession();
      throw new ApiError(401, "Sua sessão não está ativa. Entre novamente.");
    }
    if (!response.ok) {
      if (response.status === 400) {
        const messages = {
          "Select at most 20 distinct existing branch names.": "Selecione no máximo 20 branches distintas.",
          "A selected branch does not exist in this repository.": "Uma branch selecionada não existe mais. Descarte a edição e atualize a lista.",
          "The branch is not selected for monitoring.": "Selecione e salve esta branch antes de iniciar a análise.",
          "An existing selected branch is required.": "Escolha uma branch monitorada para analisar.",
          "Select and save the demo branch before simulating a push.": "Salve a seleção desta branch para simular.",
          "The demo branch does not exist.": "A branch de demonstração não está disponível. Atualize a lista.",
          "A demo repository and existing branch are required.": "Escolha o repositório de demonstração e uma branch monitorada.",
        };
        let detail;
        try { detail = (await response.json()).detail; } catch { /* Keep unknown diagnostics private. */ }
        throw new ApiError(400, typeof detail === "string" && Object.hasOwn(messages, detail) ? messages[detail] : "Não foi possível validar a seleção. Confira os dados e tente novamente.");
      }
      // API errors can contain provider diagnostics. Do not echo them into the UI.
      throw new ApiError(response.status, ({
        403: "Você não tem permissão para esta ação.",
        404: "Este recurso não está disponível. Atualize a lista e tente novamente.",
        409: "Os dados mudaram. Atualize antes de tentar novamente.",
        422: "Não foi possível validar os dados. Confira a seleção.",
        429: "Muitas solicitações. Aguarde um momento e tente novamente.",
      })[response.status] || "Não foi possível concluir a solicitação. Tente novamente.");
    }
    if (response.status === 204) { if (state.connectionNotice) clearNotice(); return null; }
    const type = response.headers.get("content-type") || "";
    if (!type.includes("application/json")) throw new Error("O serviço retornou uma resposta inesperada.");
    const result = await response.json();
    if (state.connectionNotice) clearNotice();
    return result;
  } catch (error) {
    if (error.name === "AbortError") throw new ApiError(0, "O serviço demorou para responder. Tente novamente.");
    if (error instanceof TypeError) throw new ApiError(0, "Não foi possível conectar ao serviço. Verifique a conexão e tente novamente.");
    throw error;
  } finally { clearTimeout(timer); }
}

function items(response) {
  if (!Array.isArray(response?.items)) throw new Error("O serviço retornou uma lista inválida.");
  return response.items;
}
function demo() { return state.meta?.mode === "demo"; }
function repo() { return state.repositories.find(value => String(value.id) === String(state.repository)); }
function repositoryPath() { return scopedRepositoryPath(state.installation, state.repository); }
function badge(text, kind = "muted", dot = false) {
  const safeKind = ["muted", "live", "demo", "unknown", "failed", "completed", "queued", "running", "error"].includes(kind) ? kind : "muted";
  return `<span class="badge ${safeKind}">${dot ? '<span class="dot" aria-hidden="true"></span>' : ""}${e(text)}</span>`;
}
function notice(message, error = false, connection = false) {
  state.connectionNotice = error && connection;
  clearTimeout(state.noticeTimer);
  const node = $("#notification");
  node.textContent = message; node.classList.toggle("error", error); node.hidden = false;
  node.setAttribute("role", error ? "alert" : "status");
  if (!error) state.noticeTimer = setTimeout(() => { node.hidden = true; }, 8000);
}
function clearNotice() { $("#notification").hidden = true; state.connectionNotice = false; }
function focusMain() {
  $("#main").focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: "instant" });
}
function captureFocus() {
  const node = document.activeElement;
  if (!node || !$("#main").contains(node)) return null;
  return { id: node.id, action: node.dataset?.action, branch: node.dataset?.branch,
    item: node.dataset?.id, start: node.selectionStart, end: node.selectionEnd };
}
function restoreFocus(saved) {
  if (!saved || $("#detail-dialog").open) return;
  let node = saved.id ? document.getElementById(saved.id) : null;
  if (!node && saved.action) node = [...document.querySelectorAll("[data-action]")].find(candidate =>
    candidate.dataset.action === saved.action && candidate.dataset.branch === saved.branch && candidate.dataset.id === saved.item);
  if (!node || node.disabled) {
    if (state.view === "branches" && saved.action) $("#selection-summary")?.focus({ preventScroll: true });
    return;
  }
  node.focus({ preventScroll: true });
  if (typeof saved.start === "number" && node.setSelectionRange) node.setSelectionRange(saved.start, saved.end);
}
function empty(title, text, action = "") {
  return `<div class="empty"><h3>${e(title)}</h3><p>${e(text)}</p>${action}</div>`;
}
function button(text, action, style = "", disabled = false, attributes = "") {
  return `<button type="button" class="${style}" data-action="${action}" ${disabled ? "disabled" : ""} ${attributes}>${e(text)}</button>`;
}
function pageHeading(number, title, description, aside = "") {
  const names = { "01": "Visão geral", "02": "Branches monitoradas", "03": "Análises", "04": "Atividade" };
  return `<div class="page-heading"><div><span class="eyebrow">${number} / ${names[number]}</span><h1><span class="sr-only">${names[number]}: </span>${title}</h1><p>${e(description)}</p></div>${aside}</div>`;
}
function renderEnvironment() {
  if (!state.meta) return;
  $("#mode").outerHTML = `<span id="mode" class="badge ${demo() ? "demo" : "live"}"><span class="dot" aria-hidden="true"></span>${demo() ? "Demonstração · dados fictícios" : "Ambiente real"}</span>`;
  const node = $("#environment-notice");
  node.hidden = !demo();
  node.textContent = "Modo de demonstração. Repositórios, eventos e achados são sintéticos; nenhuma análise real do GitHub é representada aqui.";
  $("#navigation").hidden = !state.authenticated;
  $("#logout").hidden = !state.authenticated;
}

function renderLogin(message = "") {
  renderEnvironment();
  $("#main").innerHTML = `<section class="login-grid">
    <div><span class="eyebrow">VISIBILIDADE, SEM FALSAS CERTEZAS</span><h1>Seu código.<br>Seu contexto.<br><span class="accent">Seu próximo passo.</span></h1><p class="secondary">Acompanhe as branches que importam e revise vulnerabilidades com a origem de cada resultado à vista.</p>
      <div class="flow spaced"><span class="flow-number">01</span><div><h3>Escolha o que acompanhar</h3><p>Repositórios e branches, no escopo da sua instalação GitHub.</p></div></div>
      <div class="flow"><span class="flow-number">02</span><div><h3>Revise com evidência</h3><p>Achados técnicos separados de explicações geradas por IA.</p></div></div>
    </div>
    <form id="login-form" class="panel login-form" novalidate><span class="eyebrow">ACESSO PRIVADO</span><h2>Entre no seu painel.</h2>${demo() ? '<p class="demo-token">Use o token <code>local-demo</code></p>' : '<p>Use o token de acesso configurado pelo operador deste ambiente. Não é um token pessoal do GitHub.</p>'}
      <label for="access-token">Token de acesso</label><input id="access-token" name="token" type="password" required autocomplete="off" spellcheck="false" placeholder="Seu token de acesso">
      <p id="login-error" class="form-error" role="alert" ${message ? "" : "hidden"}>${e(message)}</p>
      <button class="primary" type="submit">Acessar painel <span aria-hidden="true">→</span></button>
      ${demo() ? button("Entrar na demonstração", "demo-login", "quiet") + '<p>Dados fictícios; não representam projetos reais.</p>' : '<p>O acesso é restrito ao operador. Nenhuma credencial é salva no navegador pela interface.</p>'}
    </form>
  </section>`;
}

function endSession() {
  clearTimeout(state.detailTimer);
  state.authenticated = false; state.busy = false; state.operation = null; state.epoch++; state.detailEpoch++;
  clearTimeout(state.timer);
  state.dashboard = null; state.installations = []; state.repositories = []; state.branches = [];
  state.scans = []; state.deliveries = []; state.selected = new Set();
  state.installation = null; state.repository = null;
  $("#detail-dialog").close(); $("#detail-content").replaceChildren();
  renderLogin("Sua sessão foi encerrada. Entre novamente para continuar.");
  focusMain();
}

function stat(label, value, caption, accent = false) {
  return `<div class="stat"><span class="eyebrow">${e(label)}</span><span class="stat-value${accent ? " accent" : ""}">${count(value)}</span><small>${e(caption)}</small></div>`;
}
function scanTable(scans) {
  if (!scans.length) return empty("Nenhuma análise por aqui, ainda.", "Selecione as branches que deseja monitorar. As análises aparecerão aqui após um envio de código ou uma execução manual.", '<a href="#branches" class="button">Selecionar branches <span aria-hidden="true">→</span></a>');
  return `<div class="table-wrap responsive-table"><table role="table"><caption class="eyebrow" style="text-align:left">${demo() ? "Análises sintéticas" : "Análises recebidas do serviço"}</caption><thead><tr><th scope="col">Repositório / branch</th><th scope="col">Estado</th><th scope="col">Achados</th><th scope="col">Atualização</th><th scope="col">Relatório</th></tr></thead><tbody>${scans.map(scan => `<tr>
    <td data-label="Repositório / branch"><strong class="break">${e(scan.repository)}</strong><span class="secondary mono">↳ ${e(scan.branch)} <span aria-hidden="true">·</span> ${e(scan.commit_sha?.slice(0, 7) || "sem commit")}</span>${scan.source === "demo" ? badge("Sintético", "demo") : scan.source === "github" ? "" : badge("Origem não informada")}</td>
    <td data-label="Estado">${badge(scanLabel(scan.status), scan.status)}</td><td data-label="Achados" class="mono">${scan.status === "completed" ? count(scan.finding_count) : "—"}${Array.isArray(scan.advisory_ids) ? scan.advisory_ids.map(id => `<span class="secondary">${e(id)}</span>`).join("") : ""}</td>
    <td data-label="Atualização" class="secondary">${e(formatDate(scan.completed_at || scan.created_at))}</td><td data-label="Relatório">${button("Ver análise →", "detail", "text-button", false, `data-id="${e(scan.id)}" aria-label="Ver análise de ${e(scan.repository)}, branch ${e(scan.branch)}"`)}</td>
  </tr>`).join("")}</tbody></table></div>`;
}
function overview() {
  const data = state.dashboard || {};
  return `${pageHeading("01", 'Cada branch.<br><span class="accent">O contexto que faltava.</span>', "Acompanhe a composição das suas dependências, os achados e o que ainda precisa ser investigado.", '<aside class="hero-aside"><span class="eyebrow">ESTADO DA ANÁLISE</span><p>Uma dependência presente não prova que o caminho vulnerável é executado.</p></aside>')}
    <div class="stats">${stat("Repositórios no escopo", data.repositories, "disponíveis na instalação")}${stat("Branches selecionadas", data.selected_branches, "acompanhadas por webhook")}${stat("Análises registradas", data.scans, demo() ? "execuções sintéticas" : "execuções do serviço")}${stat("Achados registrados", data.findings, "podem se repetir entre análises", true)}</div>
    <div class="toolbar"><div class="actions">${scopeControls()}</div><a href="#branches" class="button primary">Selecionar branches <span aria-hidden="true">→</span></a></div>
    <div class="overview-grid"><section><div class="section-heading"><div><span class="eyebrow">ÚLTIMAS EXECUÇÕES · REPOSITÓRIO SELECIONADO</span><h2>Do código à revisão.</h2></div><a href="#results" class="text-button">Ver todas →</a></div>${scanTable(state.scans.slice(0, 5))}</section>
    <aside class="panel panel-body"><span class="eyebrow">CONEXÕES DO AMBIENTE</span><div class="connection"><div class="inline"><h3>GitHub App</h3>${badge(demo() ? "Simulado" : state.meta.github_configured ? "Configurado" : "Não configurado", !demo() && state.meta.github_configured ? "live" : "muted")}</div><p>${demo() ? "Instalação e eventos simulados. Não há conexão real nesta demonstração." : state.meta.github_configured ? "A configuração está presente. A atividade abaixo confirma os eventos recebidos, não a saúde contínua da conexão." : "O operador precisa configurar o GitHub App no serviço para receber repositórios e eventos."}</p></div>
    <div class="connection"><div class="inline"><h3>Explicações por IA</h3>${badge(state.meta.ai_configured ? "Configurada" : "Desabilitadas", state.meta.ai_configured ? "live" : "muted")}</div><p>Quando disponíveis, ajudam na leitura. Não substituem evidência nem determinam o alcance.</p></div>
    <div class="connection"><span class="eyebrow">ÚLTIMA ANÁLISE</span><p>${e(formatDate(data.last_scan_at))}</p></div></aside></div>
    <div class="note spaced"><strong>Leia o resultado, não uma promessa de segurança.</strong><p>Sem achados nos dados analisados não significa ausência de vulnerabilidades. Alcance desconhecido permanece desconhecido.</p></div>`;
}

function scopeControls(includeRepository = true) {
  return `<label class="field" for="installation-select">Instalação GitHub<select id="installation-select" data-control="installation" ${state.busy ? "disabled" : ""}>${state.installations.length ? state.installations.map(installation => `<option value="${e(installation.id)}" ${String(installation.id) === String(state.installation) ? "selected" : ""} ${installation.status !== "active" ? "disabled" : ""}>${e(installation.account)}${installation.status !== "active" ? " · indisponível" : ""}</option>`).join("") : '<option value="">Nenhuma instalação</option>'}</select></label>
    ${includeRepository ? `<label class="field" for="repository-select">Repositório<select id="repository-select" data-control="repository" ${state.busy ? "disabled" : ""}>${state.repositories.length ? state.repositories.map(repository => `<option value="${e(repository.id)}" ${String(repository.id) === String(state.repository) ? "selected" : ""}>${e(repository.full_name)}</option>`).join("") : '<option value="">Nenhum repositório</option>'}</select></label>` : ""}`;
}
function scopeEmpty() {
  const sync = !demo() && state.meta.github_configured ? button("Sincronizar com GitHub", "sync", "primary", state.busy) : "";
  if (!state.installation) return empty("Nenhuma instalação ativa.", demo() ? "A instalação de demonstração ainda não está disponível. Atualize o painel para tentar novamente." : "Configure e instale o GitHub App para que os repositórios autorizados apareçam aqui. Instalações suspensas não permitem monitoramento.", sync);
  if (!state.repository) return empty("Nenhum repositório disponível.", "Autorize repositórios nesta instalação do GitHub App e sincronize a lista.", sync);
  return "";
}
function branchRows() {
  const visible = state.branches.filter(branch => branch.name.toLocaleLowerCase("pt-BR").includes(state.filter.toLocaleLowerCase("pt-BR")));
  if (!visible.length) return empty(state.branches.length ? "Nenhuma branch encontrada." : "Nenhuma branch disponível.", state.branches.length ? "Tente buscar por outro nome." : "Verifique se o repositório tem branches e atualize a lista.");
  return `<div class="panel">${visible.map((branch, index) => `<div class="branch-row"><label for="branch-${index}"><input type="checkbox" id="branch-${index}" data-branch="${e(branch.name)}" ${state.selected.has(branch.name) ? "checked" : ""} ${state.busy || (!state.selected.has(branch.name) && state.selected.size >= MAX_BRANCHES) ? "disabled" : ""}><span class="mono branch-name">${e(branch.name)}</span></label><div class="actions">${branch.name === repo()?.default_branch ? badge("Principal") : ""}<span data-branch-state="${e(branch.name)}">${branchBadge(branch)}</span>${button("Analisar", "scan", "text-button", state.busy || !branch.selected || isDirty(state.branches, state.selected), `data-branch="${e(branch.name)}" aria-label="Analisar branch ${e(branch.name)}"`)}<span class="secondary small" data-branch-blocked>${isDirty(state.branches, state.selected) ? "Salve a seleção para analisar." : !branch.selected ? "Selecione e salve para analisar." : ""}</span></div></div>`).join("")}</div>`;
}
function selectionSummary() {
  return `${state.selected.size} de ${MAX_BRANCHES} branches · ${isDirty(state.branches, state.selected) ? "Alterações não salvas" : "Seleção salva"}`;
}
function selectionMessage() {
  return state.selectionError || (state.selected.size >= MAX_BRANCHES ? "Limite de 20 branches atingido. Desmarque uma para incluir outra." : "");
}
function selectFiltered() {
  const visible = state.branches.filter(branch => branch.name.toLocaleLowerCase("pt-BR").includes(state.filter.toLocaleLowerCase("pt-BR")));
  for (const branch of visible) {
    if (state.selected.size >= MAX_BRANCHES) break;
    state.selected.add(branch.name);
  }
  state.selectionError = ""; state.saveError = ""; renderView();
}
function branchBadge(branch) {
  const selected = state.selected.has(branch.name);
  return selected !== branch.selected ? badge(selected ? "A incluir ao salvar" : "A remover ao salvar", "unknown") : branch.selected ? badge("Monitorada", "live") : badge("Fora do escopo");
}
function simulationControls() {
  const dirty = isDirty(state.branches, state.selected);
  const saved = state.branches.filter(branch => branch.selected);
  return `<label class="field" for="simulation-branch">Branch do push simulado<select id="simulation-branch" ${state.busy || dirty || !saved.length ? "disabled" : ""}>${saved.map(branch => `<option value="${e(branch.name)}">${e(branch.name)}</option>`).join("")}</select></label>${button("Simular push de demonstração", "simulate", "", state.busy || dirty || !saved.length)}<p id="simulation-help" class="secondary small">${dirty ? "Salve a seleção para simular" : saved.length ? "O push usa a branch indicada acima. Nenhum push real é enviado ao GitHub." : "Selecione e salve uma branch para simular."}</p>`;
}
function branches() {
  const dirty = isDirty(state.branches, state.selected);
  return `${pageHeading("02", 'Escolha o que<br><span class="accent">merece atenção.</span>', "Selecione as branches que devem iniciar uma análise quando novos commits chegarem pelo GitHub.")}
    <div class="toolbar"><div class="actions">${scopeControls()}</div><div class="actions">${!demo() && state.meta.github_configured ? button("Sincronizar com GitHub", "sync", "", state.busy) : ""}${button("Atualizar lista", "refresh", "", state.busy)}</div></div>
    ${scopeEmpty() || `<div class="branch-layout"><section><div class="section-heading"><div><span class="eyebrow">ESCOPO DO MONITORAMENTO</span><h2>Branches de ${e(repo()?.full_name?.split("/").pop() || "repositório")}</h2></div></div>
      <label class="field" for="branch-search">Buscar branch<input id="branch-search" type="search" placeholder="Filtrar pelo nome…" value="${e(state.filter)}" autocomplete="off"></label>
      <div class="actions spaced">${button("Selecionar filtradas", "select-filtered", "quiet", state.busy)}${button("Limpar seleção", "clear-selection", "quiet", state.busy || !state.selected.size)}</div><p class="secondary small">Selecionar filtradas inclui apenas as branches deste repositório que correspondem à busca, até 20 no total. Limpar seleção desmarca todas deste repositório, inclusive as ocultas pelo filtro.</p>
      <div class="save-bar"><p id="selection-summary" aria-live="polite" tabindex="-1">${selectionSummary()}</p><div class="actions">${button("Descartar", "discard", "quiet", !dirty || state.busy)}${button(state.operation === "save" ? "Salvando…" : "Salvar seleção", "save", "primary", !dirty || state.busy || state.selected.size > MAX_BRANCHES)}</div><p id="selection-error" class="form-error" role="status">${e(selectionMessage())}</p><p id="save-error" class="form-error" role="alert" tabindex="-1">${e(state.saveError)}</p></div>
      <div id="branch-list" class="spaced branch-list">${branchRows()}</div>
      <p class="secondary small spaced">Desmarcar todas pausa novas análises por webhook neste repositório. O histórico é preservado.</p></section>
      <aside class="panel panel-body"><span class="eyebrow">COMO FUNCIONA</span><div class="flow" style="border-top:0;padding-top:0"><span class="flow-number">01</span><div><h3>Selecione e salve</h3><p>A seleção só muda no serviço depois de salvar.</p></div></div><div class="flow"><span class="flow-number">02</span><div><h3>Envie código</h3><p>${demo() ? "Nesta demonstração, simule um push em uma branch salva." : "Um push em uma branch monitorada dispara a análise no serviço."}</p></div></div><div class="flow"><span class="flow-number">03</span><div><h3>Revise os achados</h3><p>Consulte os componentes, as evidências e as limitações de cada execução.</p></div></div><div id="simulation-controls">${demo() ? simulationControls() : ""}</div></aside></div>`}`;
}

function matchingScans() {
  const query = state.filter.toLocaleLowerCase("pt-BR");
  return state.scans.filter(scan => (state.statusFilter === "all" || scan.status === state.statusFilter) &&
    [scan.repository, scan.branch, scan.commit_sha, ...(Array.isArray(scan.advisory_ids) ? scan.advisory_ids : []), ...(Array.isArray(scan.package_names) ? scan.package_names : [])].join(" ").toLocaleLowerCase("pt-BR").includes(query));
}
function resultsList() {
  const filtered = matchingScans();
  if (filtered.length) return scanTable(filtered);
  return !state.filter.trim() && state.statusFilter === "all" ? scanTable([]) : empty("Nenhuma análise corresponde aos filtros.", "Tente outro termo ou escolha todos os estados.");
}
function results() {
  return `${pageHeading("03", 'Resultados com<br><span class="accent">origem e contexto.</span>', "Cada execução mantém seu commit, seus achados e os limites do que foi analisado.")}
    <div class="toolbar"><div class="actions">${scopeControls()}<label class="field" for="status-filter">Estado<select id="status-filter" data-control="status">${[["all", "Todos os estados"], ["queued", "Na fila"], ["running", "Em andamento"], ["completed", "Concluída"], ["failed", "Falhou"]].map(([value, label]) => `<option value="${value}" ${state.statusFilter === value ? "selected" : ""}>${label}</option>`).join("")}</select></label></div>${button("Atualizar", "refresh", "", state.busy)}</div>
    ${scopeEmpty() || `<label class="field" for="results-search">Buscar análises<input id="results-search" type="search" placeholder="Aviso, pacote, repositório, branch ou commit…" value="${e(state.filter)}" autocomplete="off"></label><div id="results-list" class="spaced">${resultsList()}</div>`}
    <p class="secondary small spaced"><span id="last-updated">${state.lastUpdated ? `Última atualização do painel: ${e(formatDate(state.lastUpdated))}.` : ""}</span> Atualização automática a cada 15 segundos; filtros e seleções em edição são preservados.</p>`;
}
function activity() {
  return `${pageHeading("04", 'A história começa<br><span class="accent">em um evento.</span>', "Confira os eventos recebidos pelo serviço e acompanhe o que entrou no fluxo de monitoramento.", `<div class="actions">${button("Atualizar", "refresh", "", state.busy)}</div>`)}
    ${state.deliveries.length ? `<div class="table-wrap responsive-table"><table role="table"><thead><tr><th scope="col">Evento</th><th scope="col">Repositório / branch</th><th scope="col">Resultado do evento / análise atual</th><th scope="col">Recebido em</th></tr></thead><tbody>${state.deliveries.map(delivery => `<tr><td data-label="Evento"><strong>${e(delivery.event)}</strong><span class="secondary mono">${e(delivery.delivery_id)}</span></td><td data-label="Repositório / branch"><span class="break">${e(delivery.repository || "—")}</span><span class="secondary mono">${e(delivery.branch || "—")}</span></td><td data-label="Resultado do evento / análise atual">${badge(deliveryLabel(delivery.status), delivery.status === "failed" ? "failed" : "muted")}${delivery.scan_id ? `<span class="secondary">Análise: ${e(scanLabel(delivery.scan_status))}</span>${button("Ver análise →", "detail", "text-button", false, `data-id="${e(delivery.scan_id)}"`)}` : ""}</td><td data-label="Recebido em">${e(formatDate(delivery.received_at))}</td></tr>`).join("")}</tbody></table></div>` : empty("Nenhum evento recebido ainda.", demo() ? "Selecione uma branch e use a simulação de push para explorar o fluxo de demonstração." : "Após configurar o webhook do GitHub App, os eventos recebidos aparecerão aqui.")}
    <div class="note spaced">${demo() ? "Eventos sintéticos, gerados no ambiente de demonstração. Nenhum webhook real é representado." : "Um evento recebido não significa uma análise concluída. Consulte o estado da execução em Análises."}</div>`;
}
function deliveryLabel(status) {
  return ({ accepted: "Aceito", queued: "Análise enfileirada", processed: "Processado", ignored: "Ignorado", failed: "Falhou", rejected: "Rejeitado", duplicate: "Duplicado", completed: "Concluído", received: "Recebido" })[status] || "Estado não reconhecido";
}

function renderView() {
  if (!state.authenticated) return;
  const focused = captureFocus();
  const scroll = { left: window.scrollX || 0, top: window.scrollY || 0, branches: $("#branch-list")?.scrollTop || 0 };
  renderEnvironment();
  document.querySelectorAll("[data-view]").forEach(link => {
    if (link.dataset.view === state.view) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });
  $("#main").setAttribute("aria-busy", String(state.busy));
  const operationLabel = ({ save: "Salvando a seleção de branches…", scan: "Enviando análise para a fila…", sync: "Consultando o inventário do GitHub…" })[state.operation] || "Atualizando dados do serviço…";
  $("#main").innerHTML = `${state.busy ? `<p class="loading-status" role="status">${operationLabel}</p>` : ""}${({ overview, branches, results, activity })[state.view]()}`;
  readableIdentifiers();
  restoreFocus(focused);
  if ($("#branch-list")) $("#branch-list").scrollTop = scroll.branches;
  window.scrollTo({ left: scroll.left, top: scroll.top, behavior: "instant" });
}
function readableIdentifiers() {
  document.querySelectorAll(".finding h3, [data-label='Evento'] .mono").forEach(node => {
    node.classList.add("id-chip"); node.title = node.textContent;
  });
}

function scansPath() {
  if (!state.installation || !state.repository) return null;
  return `/api/scans?${new URLSearchParams({ installation_id: state.installation, repository_id: state.repository })}`;
}
async function loadScoped(epoch) {
  const installations = items(await api("/api/installations"));
  if (epoch !== state.epoch) return false;
  const installation = installations.find(item => String(item.id) === String(state.installation) && item.status === "active")?.id ?? installations.find(item => item.status === "active")?.id ?? null;
  if (!installation) { Object.assign(state, { installations, installation: null, repositories: [], repository: null, branches: [], selected: new Set(), scans: [] }); return true; }
  const repositories = items(await api(`/api/installations/${encodeURIComponent(installation)}/repositories`));
  if (epoch !== state.epoch) return false;
  const repository = repositories.find(item => String(item.id) === String(state.repository))?.id ?? repositories[0]?.id ?? null;
  if (!repository) { Object.assign(state, { installations, installation, repositories, repository: null, branches: [], selected: new Set(), scans: [] }); return true; }
  const [branchesResponse, scansResponse] = await Promise.all([
    api(`${scopedRepositoryPath(installation, repository)}/branches`),
    api(`/api/scans?${new URLSearchParams({ installation_id: installation, repository_id: repository })}`),
  ]);
  if (epoch !== state.epoch) return false;
  const branches = items(branchesResponse), scans = items(scansResponse);
  Object.assign(state, { installations, installation, repositories, repository, branches, selected: new Set(branches.filter(branch => branch.selected).map(branch => branch.name)), scans });
  return true;
}
async function refresh({ full = true, silent = false } = {}) {
  if (state.busy || !state.authenticated) return;
  if (full && isDirty(state.branches, state.selected)) {
    notice("Salve ou descarte suas alterações antes de atualizar a lista.", true); return;
  }
  const epoch = ++state.epoch;
  const focused = captureFocus();
  if (!silent) { state.busy = true; renderView(); }
  try {
    const pollScope = silent && state.view === "branches" && !isDirty(state.branches, state.selected);
    const responses = await Promise.all([api("/api/dashboard"), api("/api/deliveries"), ...(full || pollScope ? [loadScoped(epoch)] : scansPath() ? [api(scansPath())] : [])]);
    if (epoch !== state.epoch || !state.authenticated) return;
    state.dashboard = responses[0]; state.deliveries = items(responses[1]);
    if (!full && responses[2]) state.scans = items(responses[2]);
    state.lastUpdated = new Date().toISOString();
    // Background polling must not destroy focus, search text, or edited branch choices.
    if (!silent) renderView();
    else if (state.view === "results") {
      const list = $("#results-list");
      if (list) list.innerHTML = resultsList();
      const updated = $("#last-updated");
      if (updated) updated.textContent = `Última atualização do painel: ${formatDate(state.lastUpdated)}.`;
    }
    else renderView();
  } catch (error) {
    if (epoch === state.epoch && state.authenticated) notice(`${error.message}${silent ? " Os dados exibidos podem estar desatualizados." : ""}`, true, error.connection);
  } finally {
    if (epoch === state.epoch) { state.busy = false; if (!silent) renderView(); }
    if (!silent && state.authenticated) restoreFocus(focused);
    scheduleRefresh();
  }
}
function scheduleRefresh() {
  clearTimeout(state.timer);
  if (state.authenticated) state.timer = setTimeout(async () => {
    if (document.visibilityState === "visible") await refresh({ full: false, silent: true });
    else scheduleRefresh();
  }, 15000);
}

function findingManifests(finding, scan) {
  return [...new Set((Array.isArray(scan.components) ? scan.components : [])
    .filter(component => (finding.purl && component.purl === finding.purl) ||
      (component.name === finding.package_name && component.version === finding.version && component.ecosystem === finding.ecosystem))
    .map(component => component.manifest_path).filter(path => typeof path === "string" && path))];
}
function advisoryLink(id) {
  if (typeof id !== "string") return "Identificador não informado";
  if (id.startsWith("DEMO-")) return `${e(id)} · fictício`;
  const valid = /^(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|[A-Z][A-Z0-9]*-\d{4}-[A-Za-z0-9.-]+)$/.test(id);
  return valid ? `<a href="https://osv.dev/vulnerability/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${e(id)}</a>` : e(id);
}
function manifestLink(path, scan) {
  const repository = scan.repository;
  const validRepository = typeof repository === "string" && /^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9_.-]+$/.test(repository) && ![".", ".."].includes(repository.split("/")[1]);
  const parts = path.split("/");
  if (demo() || scan.source !== "github" || !validRepository || !/^[0-9a-f]{40}$/i.test(scan.commit_sha || "") || parts.some(part => !part || part === "." || part === "..")) return e(path);
  const url = `https://github.com/${repository.split("/").map(encodeURIComponent).join("/")}/blob/${scan.commit_sha}/${parts.map(encodeURIComponent).join("/")}`;
  return `<a href="${e(url)}" target="_blank" rel="noopener noreferrer">${e(path)}</a>`;
}
function findingInstructions(finding, scan) {
  const versions = Array.isArray(finding.fixed_versions) ? finding.fixed_versions : [];
  const version = versions.length ? versions.join(" ou ") : "(sem versão corrigida informada)";
  const manifests = findingManifests(finding, scan).join(", ") || "manifesto não informado";
  return `Verifique a compatibilidade de ${finding.package_name || "componente não informado"} ${version} em ${manifests}; atualize, teste e execute nova análise. A presença da dependência não comprova alcance.`;
}
async function copyInstructions(text) {
  try {
    await navigator.clipboard.writeText(text);
    $("#detail-announcement").textContent = "Instruções copiadas.";
    return true;
  } catch {
    $("#detail-announcement").textContent = "Não foi possível copiar. Selecione e copie o texto do próximo passo.";
    return false;
  }
}
function findingMarkup(finding, scan) {
  const severity = ({ critical: "Crítica", high: "Alta", medium: "Média", moderate: "Moderada", low: "Baixa", unknown: "Não informada" })[finding.severity?.toLowerCase()] || "Não informada";
  const paths = findingManifests(finding, scan);
  const manifests = paths.length ? paths.map(path => manifestLink(path, scan)).join(", ") : "manifesto não informado";
  const instructions = findingInstructions(finding, scan);
  return `<article class="finding"><div class="section-heading"><h3>${e(finding.advisory_id || finding.id)}</h3>${badge(reachabilityLabel(finding.reachability), finding.reachability === "unknown" ? "unknown" : "muted")}</div><p><strong>${e(finding.package_name)}</strong> <span class="mono secondary">${e(finding.version)}</span> <span class="secondary">· Severidade: ${severity}</span></p><p class="secondary">${e(finding.summary || "O aviso não inclui um resumo.")}</p>
    <details><summary>Ver evidências e limites</summary><div class="evidence"><h4>Por que este achado apareceu?</h4><p><span class="mono">${e(finding.package_name)}@${e(finding.version)}</span> encontrado em ${manifests} no commit <span class="mono">${e(scan.commit_sha?.slice(0, 7) || "não informado")}</span>. ${scan.source === "demo" ? "Correlação sintética por versão exata com o aviso fictício; não houve consulta ao OSV." : "Correspondência com o aviso por versão exata via OSV."}</p><p>Não foi feita análise de fluxo/chamadas; por isso o alcance é desconhecido.</p><dl><dt>Identificador</dt><dd class="mono">${advisoryLink(finding.advisory_id || finding.id)}</dd><dt>Componente</dt><dd class="mono">${e(finding.purl || finding.package_name)}</dd><dt>Ecossistema</dt><dd>${e(finding.ecosystem || "Não informado")}</dd><dt>Correção informada</dt><dd>${e(finding.fixed_versions?.length ? finding.fixed_versions.join(", ") : "Nenhuma versão informada nos dados")}</dd><dt>Alcance</dt><dd>${e(reachabilityLabel(finding.reachability))}. A presença da dependência não prova que o caminho vulnerável é executado.</dd></dl></div></details>
    <section class="next-step"><h4>Próximo passo</h4><p>${e(instructions)}</p>${button("Copiar instruções", "copy-instructions", "quiet", false, `data-instructions="${e(instructions)}"`)}</section></article>`;
}
async function openDetail(id, polling = false) {
  clearTimeout(state.detailTimer);
  const epoch = ++state.detailEpoch;
  const dialog = $("#detail-dialog");
  if (!polling) $("#detail-content").innerHTML = `<div class="dialog-heading"><h2 id="detail-title">Carregando análise…</h2>${button("Fechar", "close-detail", "quiet")}</div><p class="secondary" role="status">Consultando o relatório e suas evidências.</p>`;
  if (!dialog.open) dialog.showModal();
  try {
    const scan = await api(`/api/scans/${encodeURIComponent(id)}`);
    if (!state.authenticated || !dialog.open || epoch !== state.detailEpoch) return;
    const explanation = explanationPresentation(scan.explanation);
    const findings = Array.isArray(scan.findings) ? scan.findings : [];
    const components = Array.isArray(scan.components) ? scan.components : [];
    const warnings = Array.isArray(scan.warnings) ? scan.warnings : [];
    const pending = ["queued", "running"].includes(scan.status);
    $("#detail-content").innerHTML = `<div class="dialog-heading"><div><span class="eyebrow">RELATÓRIO DA EXECUÇÃO</span><h2 id="detail-title">${scan.status === "completed" ? findings.length ? `${count(findings.length)} ${findings.length === 1 ? "achado" : "achados"}.` : "Sem achados nos dados." : e(scanLabel(scan.status))}</h2></div>${button("Fechar", "close-detail", "quiet")}</div>
      <div class="inline">${badge(scanLabel(scan.status), scan.status)}${badge(scan.source === "demo" ? "Demonstração · dados fictícios" : scan.source === "github" ? "Origem: GitHub" : "Origem não informada", scan.source === "demo" ? "demo" : "muted")}</div>
    <div class="dialog-meta"><span class="break">${e(scan.repository)} <span aria-hidden="true">/</span> ${e(scan.branch)}</span><span class="mono id-chip" title="${e(scan.commit_sha || "não informado")}">Commit ${e(scan.commit_sha || "não informado")}</span><span>${e(formatDate(scan.completed_at || scan.created_at))}</span></div>
      ${scan.source === "demo" ? '<p class="note">Este relatório é sintético. Não representa o estado de segurança de um projeto real.</p>' : ""}
      ${scan.status === "failed" ? `<p class="note form-error">A análise falhou e não produziu resultados. Nenhuma conclusão de segurança pode ser extraída.</p><p>Você pode tentar novamente com a mesma branch e o mesmo commit, se a branch continuar monitorada.</p>${button("Tentar novamente", "retry-scan", "quiet", false, `data-id="${e(id)}"`)}<p id="detail-action-error" class="form-error" role="alert"></p>` : ""}
      ${pending ? `<p class="note">Resultados ainda não calculados. Acompanhando automaticamente. ${button("Atualizar agora", "detail", "text-button", false, `data-id="${e(id)}"`)}</p>` : ""}
      ${warnings.length ? `<div class="note"><strong>Limitações informadas pelo serviço</strong><ul>${warnings.map(warning => `<li class="break">${e(warning)}</li>`).join("")}</ul></div>` : ""}
      ${scan.status === "completed" ? `
      <section class="spaced" aria-label="Achados técnicos"><span class="eyebrow">01 / RESULTADO TÉCNICO</span>${findings.length ? findings.map(finding => findingMarkup(finding, scan)).join("") : empty("Nenhum achado disponível.", "Nenhum aviso nos dados analisados. Isso não significa que o projeto está livre de vulnerabilidades.")}</section>
      <section class="explanation"><span class="eyebrow">02 / APOIO À LEITURA</span><div class="inline"><h3>${e(explanation.title)}</h3>${explanation.ai ? badge("IA · conteúdo não verificado", "unknown") : ""}</div>${explanation.note ? `<p class="secondary small">${e(explanation.note)}</p>` : ""}<p>${e(explanation.text)}</p><p class="secondary small">${explanation.ai ? "Texto gerado por IA, não uma evidência técnica. Pode conter erros. " : ""}A explicação não altera os achados nem comprova se um caminho vulnerável é executado.</p></section>
      <details class="spaced"><summary>Componentes analisados (${count(components.length)})</summary><div class="table-wrap spaced"><table><thead><tr><th scope="col">Componente</th><th scope="col">Versão</th><th scope="col">Ecossistema / manifesto</th></tr></thead><tbody>${components.map(component => `<tr><td class="break">${e(component.name)}<span class="secondary mono">${e(component.purl)}</span></td><td class="mono">${e(component.version)}</td><td>${e(component.ecosystem)}<span class="secondary mono">${e(component.manifest_path || "—")}</span></td></tr>`).join("")}</tbody></table></div></details>` : ""}<div class="dialog-footer">${button("Fechar relatório", "close-detail", "quiet")}</div>`;
    readableIdentifiers();
    $("#detail-announcement").textContent = `Análise: ${scanLabel(scan.status)}.`;
    if (pending) state.detailTimer = setTimeout(() => {
      if (dialog.open && epoch === state.detailEpoch) return openDetail(id, true);
    }, 2000);
  } catch (error) {
    if (epoch === state.detailEpoch && dialog.open) $("#detail-content").innerHTML = `<div class="dialog-heading"><h2 id="detail-title">Relatório indisponível.</h2>${button("Fechar", "close-detail", "quiet")}</div><p role="alert">${e(error.message)}</p>${button("Tentar novamente", "detail", "", false, `data-id="${e(id)}"`)}`;
  }
}

async function mutation(action, operation = null) {
  if (state.busy) return;
  const focused = captureFocus();
  state.busy = true; state.operation = operation; const epoch = ++state.epoch; renderView(); clearNotice();
  try {
    await action();
  } catch (error) {
    if (operation === "save") state.saveError = error.message;
    if (state.authenticated) notice(error.message, true, error.connection);
  }
  finally {
    if (epoch === state.epoch) {
      state.busy = false; state.operation = null; renderView();
      if (state.authenticated && operation === "save") $(state.saveError ? "#save-error" : "#selection-summary")?.focus({ preventScroll: true });
      else restoreFocus(focused);
    }
    scheduleRefresh();
  }
}
async function saveBranches() {
  state.saveError = "";
  if (state.selected.size > MAX_BRANCHES) { state.selectionError = "Selecione no máximo 20 branches."; renderView(); return; }
  const selection = [...state.selected];
  await mutation(async () => {
    const response = await api(`${repositoryPath()}/branches`, { method: "PUT", body: { branches: selection } });
    // Only mark as persisted after the server accepts the mutation.
    state.branches = items(response);
    state.selected = new Set(state.branches.filter(branch => branch.selected).map(branch => branch.name));
    const repository = repo(); if (repository) repository.selected_branches = [...state.selected];
    notice(state.selected.size ? "Seleção salva. Novos pushes nessas branches entrarão no monitoramento." : "Monitoramento por webhook pausado neste repositório. O histórico foi preservado.");
  }, "save");
}
async function queueScan(branch, simulate = false) {
  if (isDirty(state.branches, state.selected)) { notice("Salve ou descarte a seleção antes de iniciar uma análise.", true); return; }
  await mutation(async () => {
    const result = await api(simulate ? "/api/demo/push" : `${repositoryPath()}/scan`, { method: "POST", body: simulate ? { repository_id: Number(state.repository), branch } : { branch } });
    notice(simulate ? "Push sintético recebido. Acompanhe a análise de demonstração." : "Análise adicionada à fila. O resultado aparecerá quando a execução terminar.");
    const path = scansPath(); if (path) state.scans = items(await api(path));
    if (result?.scan_id) await openDetail(result.scan_id);
  }, "scan");
}

document.addEventListener("submit", async event => {
  if (event.target.id !== "login-form") return;
  event.preventDefault();
  const form = event.target; const submit = form.querySelector('button[type="submit"]');
  const field = form.elements.token; const token = field.value;
  if (!token.trim()) {
    $("#login-error").textContent = "Informe o token de acesso para entrar.";
    $("#login-error").hidden = false; field.focus({ preventScroll: true }); return;
  }
  submit.disabled = true; submit.textContent = "Entrando…"; $("#login-error").hidden = true;
  try {
    await api("/api/session", { method: "POST", body: { token } });
    field.value = ""; state.authenticated = true; clearNotice(); renderView(); await refresh(); focusMain();
  } catch (error) {
    field.value = ""; $("#login-error").textContent = error.status === 401 ? "Token inválido. Confira o token de acesso do ambiente." : error.message;
    $("#login-error").hidden = false; submit.disabled = false; submit.textContent = "Acessar painel →"; field.focus({ preventScroll: true });
  }
});

document.addEventListener("click", async event => {
  const target = event.target.closest("[data-action]");
  if (!target || target.disabled) return;
  const action = target.dataset.action;
  if (action === "skip-main") { event.preventDefault(); $("#main").focus({ preventScroll: true }); }
  else if (action === "demo-login" && demo()) {
    $("#access-token").value = "local-demo";
    $("#login-form").requestSubmit();
  }
  else if (action === "refresh") await refresh();
  else if (action === "sync") {
    if (isDirty(state.branches, state.selected)) { notice("Salve ou descarte suas alterações antes de sincronizar.", true); return; }
    await mutation(async () => {
      await api("/api/installations/sync", { method: "POST", body: {} });
      notice("Inventário do GitHub sincronizado. Atualizando repositórios…");
    }, "sync");
    await refresh();
  }
  else if (action === "discard") { state.selected = new Set(state.branches.filter(branch => branch.selected).map(branch => branch.name)); state.selectionError = ""; state.saveError = ""; renderView(); }
  else if (action === "select-filtered") selectFiltered();
  else if (action === "clear-selection") { state.selected.clear(); state.selectionError = ""; state.saveError = ""; renderView(); }
  else if (action === "save") await saveBranches();
  else if (action === "scan") await queueScan(target.dataset.branch);
  else if (action === "simulate" && demo()) {
    const branch = $("#simulation-branch").value;
    if (state.branches.some(value => value.name === branch && value.selected)) await queueScan(branch, true);
  }
  else if (action === "detail") await openDetail(target.dataset.id);
  else if (action === "copy-instructions") target.textContent = await copyInstructions(target.dataset.instructions) ? "Instruções copiadas" : "Não foi possível copiar; selecione o texto acima";
  else if (action === "retry-scan") {
    target.disabled = true;
    try {
      const result = await api(`/api/scans/${encodeURIComponent(target.dataset.id)}/retry`, { method: "POST", body: {} });
      await openDetail(result.scan_id);
    } catch (error) { $("#detail-action-error").textContent = error.message; }
    finally { target.disabled = false; }
  }
  else if (action === "close-detail") { clearTimeout(state.detailTimer); state.detailEpoch++; $("#detail-dialog").close(); }
  else if (action === "boot") await boot();
});

document.addEventListener("change", async event => {
  const target = event.target;
  if (target.matches('input[type="checkbox"][data-branch]')) {
    state.selectionError = ""; state.saveError = "";
    if (target.checked && !state.selected.has(target.dataset.branch) && state.selected.size >= MAX_BRANCHES) {
      target.checked = false;
      state.selectionError = "Limite de 20 branches. Desmarque uma antes de incluir outra.";
    }
    if (target.checked) state.selected.add(target.dataset.branch); else state.selected.delete(target.dataset.branch);
    // Preserve keyboard focus on the checkbox when updating the save controls.
    $("#selection-summary").textContent = selectionSummary();
    $("#selection-error").textContent = selectionMessage();
    $("#save-error").textContent = "";
    const dirty = isDirty(state.branches, state.selected);
    $('[data-action="save"]').disabled = !dirty; $('[data-action="discard"]').disabled = !dirty;
    $('[data-action="clear-selection"]').disabled = state.busy || !state.selected.size;
    document.querySelectorAll("[data-branch-state]").forEach(node => {
      const branch = state.branches.find(value => value.name === node.dataset.branchState);
      if (branch) node.innerHTML = branchBadge(branch);
    });
    document.querySelectorAll('[data-action="scan"]').forEach(node => {
      node.disabled = dirty || state.busy || !state.branches.some(branch => branch.name === node.dataset.branch && branch.selected);
    });
    document.querySelectorAll("[data-branch-blocked]").forEach(node => {
      node.textContent = dirty ? "Salve a seleção para analisar." : "";
    });
    document.querySelectorAll('input[type="checkbox"][data-branch]').forEach(node => {
      node.disabled = state.busy || (!node.checked && state.selected.size >= MAX_BRANCHES);
    });
    if (demo()) $("#simulation-controls").innerHTML = simulationControls();
    return;
  }
  if (target.dataset.control === "status") { state.statusFilter = target.value; $("#results-list").innerHTML = resultsList(); return; }
  if (target.dataset.control === "installation" || target.dataset.control === "repository") {
    if (isDirty(state.branches, state.selected)) {
      notice("Salve ou descarte suas alterações antes de mudar o escopo.", true); renderView(); return;
    }
    // Invalidate in-flight polls before changing scope. Never show another repo's rows under the new label.
    state.epoch++;
    if (target.dataset.control === "installation") { state.installation = target.value; state.repository = null; state.repositories = []; }
    else state.repository = target.value;
    state.branches = []; state.selected = new Set(); state.scans = []; state.filter = "";
    state.selectionError = ""; state.saveError = "";
    await refresh();
  }
});

document.addEventListener("input", event => {
  if (event.target.id === "branch-search") { state.filter = event.target.value; $("#branch-list").innerHTML = branchRows(); }
  if (event.target.id === "results-search") {
    state.filter = event.target.value;
    $("#results-list").innerHTML = resultsList();
  }
});

function readView() {
  const view = location.hash.slice(1);
  return ["overview", "branches", "results", "activity"].includes(view) ? view : "overview";
}
window.addEventListener("hashchange", () => { state.view = readView(); state.filter = ""; clearNotice(); renderView(); focusMain(); });
window.addEventListener("beforeunload", event => { if (state.authenticated && isDirty(state.branches, state.selected)) { event.preventDefault(); event.returnValue = ""; } });
$("#detail-dialog").addEventListener("close", () => { clearTimeout(state.detailTimer); state.detailEpoch++; focusMain(); });
$("#logout").addEventListener("click", async () => {
  if (isDirty(state.branches, state.selected)) { notice("Salve ou descarte suas alterações antes de sair.", true); return; }
  try { await api("/api/session", { method: "DELETE" }); endSession(); clearNotice(); }
  catch (error) { notice(error.message, true, error.connection); }
});
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("#theme").setAttribute("aria-label", theme === "dark" ? "Ativar tema claro" : "Ativar tema escuro");
}
try { applyTheme(localStorage.getItem("sca-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")); } catch { applyTheme("light"); }
$("#theme").addEventListener("click", () => {
  const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(theme); try { localStorage.setItem("sca-theme", theme); } catch { /* Theme still works when browser storage is blocked. */ }
});

async function boot() {
  state.view = readView();
  try {
    state.meta = await api("/api/meta");
    if (!["demo", "live"].includes(state.meta?.mode)) throw new Error("O serviço não informou um ambiente reconhecido.");
    renderEnvironment();
    try {
      state.dashboard = await api("/api/dashboard"); state.authenticated = true;
      renderView(); await refresh();
    } catch (error) {
      if (error.status === 401) renderLogin(); else throw error;
    }
  } catch (error) {
    $("#main").innerHTML = `<section class="initial-state"><span class="eyebrow">CONEXÃO INDISPONÍVEL</span><h1>Não foi possível<br><span class="accent">carregar o painel.</span></h1><p class="secondary" role="alert">${e(error.message)}</p><p class="secondary">Nenhum dado de demonstração substituiu uma resposta real.</p>${button("Tentar novamente", "boot", "primary")}</section>`;
  }
}
await boot();

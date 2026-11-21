import { escapeHTML as e, formatDate, count, scanLabel, reachabilityLabel, isDirty, scopedRepositoryPath, explanationPresentation, reachabilityPresentation, evidenceSteps, sortFindings, reachabilityCounts, supportedMode, githubLink, advisoryURL, findingPage, findingPresentation, scopeCounts, scopeSummary, dependencyPresentation, isTransitiveUnknown, transitiveSteps, validPublicRepository, publicErrorCopy, publicProgress } from "/model.js";

const $ = selector => document.querySelector(selector);
const state = {
  meta: null, authenticated: false, view: "overview", dashboard: null,
  installations: [], installation: null, repositories: [], repository: null,
  branches: [], selected: new Set(), scans: [], deliveries: [],
  filter: "", statusFilter: "all", busy: false, operation: null, epoch: 0, detailEpoch: 0,
  lastUpdated: null, timer: null, noticeTimer: null, detailTimer: null,
  selectionError: "", saveError: "", branchRefreshError: "", connectionNotice: false,
  simulationScope: null, simulationTarget: null, detailReturn: null,
  reportScan: null, findingFilter: "all", findingPage: 0,
  publicFlow: { url: "", phase: "idle", registration: null, scan: null, error: null }, publicTimer: null, publicEpoch: 0,
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
      let payload;
      try { payload = await response.json(); } catch { payload = {}; }
      if (typeof payload.code === "string") {
        const error = new ApiError(response.status, publicErrorCopy(payload.code));
        error.code = payload.code;
        throw error;
      }
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
        detail = payload.detail;
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

function reachSentence(scan) {
  if (!scan.finding_count) return "Nenhum achado correlacionado nesta análise.";
  const counts = scan.reachability_counts;
  if (!counts) return "Alcance não informado; trate como desconhecido.";
  const parts = [["reachable", "alcançável", "alcançáveis"], ["unknown", "desconhecido", "desconhecidos"], ["unreachable", "inalcançável", "inalcançáveis"]]
    .filter(([key]) => counts[key] > 0 && !(key === "reachable" && scan.reachability_scope_counts))
    .map(([key, one, many]) => `${counts[key]} ${counts[key] === 1 ? one : many}`);
  if (scan.reachability_scope_counts) parts.unshift(scopeSummary(scan.reachability_scope_counts));
  if (scan.transitive_imported_unknown_count) parts.push(`${scan.transitive_imported_unknown_count} desses desconhecidos são transitivos via importações/CLI`);
  if (scan.transitive_summary?.decided) parts.push(`${scan.transitive_summary.decided} decididos via caminho transitivo`);
  return parts.length ? `Alcance estático: ${parts.join(" · ")}.` : "Alcance não informado; trate como desconhecido.";
}

function items(response) {
  if (!Array.isArray(response?.items)) throw new Error("O serviço retornou uma lista inválida.");
  return response.items;
}
function demo() { return state.meta?.mode === "demo"; }
function publicMode() { return state.meta?.mode === "public"; }
function commitMarkup(scan) {
  const url = githubLink(scan);
  const label = `Commit ${scan.commit_sha?.slice(0, 7) || "não informado"}`;
  return url ? `<a class="commit-link mono" href="${e(url)}" target="_blank" rel="noopener noreferrer">${e(label)} ↗</a>` : e(label);
}
function repo() { return state.repositories.find(value => String(value.id) === String(state.repository)); }
function repositoryPath() { return scopedRepositoryPath(state.installation, state.repository); }
function badge(text, kind = "muted", dot = false) {
  const safeKind = ["muted", "live", "demo", "unknown", "failed", "completed", "queued", "running", "error", "reachable", "unreachable"].includes(kind) ? kind : "muted";
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
function detailOrigin() {
  return { focus: captureFocus(), view: state.view, installation: state.installation, repository: state.repository,
    left: window.scrollX || 0, top: window.scrollY || 0, branches: $("#branch-list")?.scrollTop || 0 };
}
function restoreDetailOrigin() {
  const origin = state.detailReturn;
  state.detailReturn = null;
  if (!state.authenticated || !origin || origin.view !== state.view ||
      String(origin.installation) !== String(state.installation) || String(origin.repository) !== String(state.repository)) {
    focusMain(); return;
  }
  restoreFocus(origin.focus);
  if (!origin.focus) $("#main").focus({ preventScroll: true });
  if ($("#branch-list")) $("#branch-list").scrollTop = origin.branches;
  window.scrollTo({ left: origin.left, top: origin.top, behavior: "instant" });
}
function empty(title, text, action = "") {
  return `<div class="empty"><span class="empty-icon" aria-hidden="true">↗</span><h3>${e(title)}</h3><p>${e(text)}</p>${action}</div>`;
}
function button(text, action, style = "", disabled = false, attributes = "") {
  return `<button type="button" class="${style}" data-action="${action}" ${disabled ? "disabled" : ""} ${attributes}>${e(text)}</button>`;
}
function pageHeading(number, title, description, aside = "") {
  const names = { "01": "Visão geral", "02": "Branches monitoradas", "03": "Análises", "04": "Atividade" };
  return `<div class="page-heading"><div><span class="eyebrow">WORKSPACE <span class="eyebrow-divider">/</span> ${names[number]}</span><h1>${title}</h1><p>${e(description)}</p></div>${aside}</div>`;
}
function renderEnvironment() {
  if (!state.meta) return;
  $("#mode").outerHTML = `<span id="mode" class="badge ${demo() ? "demo" : "live"}"><span class="dot" aria-hidden="true"></span>${demo() ? "Demonstração · dados fictícios" : publicMode() ? "GitHub público · somente leitura, sem credenciais" : "Ambiente real"}</span>`;
  const node = $("#environment-notice");
  node.hidden = !demo() && !publicMode();
  node.innerHTML = publicMode() ? '<strong>GitHub público + OSV real</strong><span>Somente leitura · análise estática no commit · nenhum código executado.</span>' : '<strong>Ambiente de demonstração</strong><span>Dados sintéticos. Sem conexão com GitHub, OSV ou IA reais.</span>';
  $("#navigation").hidden = !state.authenticated;
  $("#logout").hidden = !state.authenticated;
  $(".app-shell").classList.toggle("guest", !state.authenticated);
}

function renderLogin(message = "") {
  renderEnvironment();
  $("#main").innerHTML = `<section class="login-grid">
    <div class="login-story"><span class="eyebrow">CLAREZA PARA QUEM PROTEGE O CÓDIGO</span><h1>Da dependência<br>à <span class="accent">decisão.</span></h1><p class="secondary">Menos contexto perdido.<br>Mais evidência para o próximo passo.</p>
      <div class="login-diagram" aria-label="Fluxo do produto: GitHub, branches, dependências, evidências"><span class="diagram-node">GitHub <small>origem do código</small></span><span class="diagram-connector" aria-hidden="true"></span><div class="diagram-branches"><span>main</span><span>release</span><span>develop</span></div><span class="diagram-connector" aria-hidden="true"></span><span class="diagram-node diagram-result">Dependências → Evidências</span><p>Fluxo ilustrativo · não representa uma conexão ativa</p></div>
      <div class="login-principle"><span aria-hidden="true">◇</span><p>Presença não prova execução.<br><strong>Desconhecido nunca vira seguro.</strong></p></div>
    </div>
    <form id="login-form" class="panel login-form" novalidate><div class="login-mark" aria-hidden="true">↗</div><span class="eyebrow">SEU WORKSPACE DE SEGURANÇA</span><h2>${demo() ? "Conheça o fluxo completo." : "Bem-vindo ao workspace."}</h2><p>${demo() ? "Explore da seleção de branches até a revisão de um achado, sem conectar uma conta." : publicMode() ? "Repositórios públicos, avisos reais e evidência no código. Sem credenciais do GitHub." : "Acesse o monitoramento de dependências da sua instalação GitHub."}</p>
      ${demo() ? '<div class="demo-access">' + button("Entrar na demonstração →", "demo-login", "primary") + '<span>Ambiente isolado · somente dados fictícios</span></div><div class="login-divider"><span class="demo-token">Use o token <code>local-demo</code></span></div>' : publicMode() ? '<p>Use o token do operador configurado em <code>SCA_DASHBOARD_TOKEN</code>. Não é um token do GitHub.</p>' : '<p>Use o token configurado pelo operador. Não é um token pessoal do GitHub.</p>'}
      <label for="access-token">Token de acesso</label><input id="access-token" name="token" type="password" required autocomplete="off" spellcheck="false" placeholder="Seu token de acesso">
      <p id="login-error" class="form-error" role="alert" ${message ? "" : "hidden"}>${e(message)}</p>
      <button class="primary" type="submit">Acessar painel <span aria-hidden="true">→</span></button>
      <p class="login-footnote">${demo() ? "Nenhum repositório real é conectado nesta demonstração." : "Acesso privado do operador. O token não é salvo pela interface."}</p>
    </form>
  </section>`;
}

function endSession() {
  clearTimeout(state.publicTimer); state.publicEpoch++;
  state.publicFlow = { url: "", phase: "idle", registration: null, scan: null, error: null };
  clearTimeout(state.detailTimer);
  state.authenticated = false; state.busy = false; state.operation = null; state.epoch++; state.detailEpoch++;
  clearTimeout(state.timer);
  state.dashboard = null; state.installations = []; state.repositories = []; state.branches = [];
  state.scans = []; state.deliveries = []; state.selected = new Set();
  state.reportScan = null;
  state.installation = null; state.repository = null;
  $("#detail-dialog").close(); $("#detail-content").replaceChildren();
  renderLogin("Sua sessão foi encerrada. Entre novamente para continuar.");
  focusMain();
}

function stat(label, value, caption, accent = false) {
  return `<div class="stat${accent ? " stat-accent" : ""}"><span class="stat-label">${e(label)}</span><div class="stat-main"><span class="stat-value${accent ? " accent" : ""}">${count(value)}</span><span class="stat-symbol" aria-hidden="true">${accent ? "◇" : "↗"}</span></div><small>${e(caption)}</small></div>`;
}
function scanTable(scans) {
  if (publicMode()) scans = scans.map(scan => ({ ...scan, advisory_ids: Array.isArray(scan.advisory_ids) && scan.advisory_ids.length > 3 ? [...scan.advisory_ids.slice(0, 3), `+${scan.advisory_ids.length - 3} avisos no relatório`] : scan.advisory_ids }));
  if (!scans.length) return empty("Nenhuma análise por aqui, ainda.", publicMode() ? "Selecione e salve uma branch, depois use Analisar para consultar o commit público e o OSV." : "Selecione as branches que deseja monitorar. As análises aparecerão aqui após um envio de código ou uma execução manual.", '<a href="#branches" class="button">Selecionar branches <span aria-hidden="true">→</span></a>');
  return `<div class="table-wrap responsive-table"><table role="table"><caption class="sr-only">${demo() ? "Análises sintéticas" : "Análises recebidas do serviço"}</caption><thead><tr><th scope="col">Repositório / branch</th><th scope="col">Estado</th><th scope="col">Achados</th><th scope="col">Atualização</th><th scope="col">Relatório</th></tr></thead><tbody>${scans.map(scan => `<tr>
    <td data-label="Repositório / branch"><strong class="break">${e(scan.repository)}</strong><span class="secondary mono">↳ ${e(scan.branch)} <span aria-hidden="true">·</span> ${e(scan.commit_sha?.slice(0, 7) || "sem commit")}</span>${scan.source === "demo" ? badge("Sintético", "demo") : scan.source === "github" ? publicMode() ? badge("Origem: GitHub público", "live") + commitMarkup(scan) : "" : badge("Origem não informada")}</td>
    <td data-label="Estado">${badge(scanLabel(scan.status), scan.status, true)}</td><td data-label="Achados"><span class="finding-count ${scan.finding_count > 0 ? "has-findings" : ""}">${scan.status === "completed" ? count(scan.finding_count) : "—"}</span>${scan.status === "completed" && scan.finding_count > 0 && scan.reachability_counts ? `<span class="reach-mini">${["reachable", "unknown", "unreachable"].filter(key => scan.reachability_counts[key] > 0).map(key => `<span class="${key}"><i aria-hidden="true"></i>${count(scan.reachability_counts[key])} ${e(reachabilityPresentation(key).label.toLowerCase())}</span>`).join("")}</span>` : ""}${Array.isArray(scan.advisory_ids) ? scan.advisory_ids.map(id => `<span class="secondary mono">${e(id)}</span>`).join("") : ""}</td>
    <td data-label="Atualização" class="secondary">${e(formatDate(scan.completed_at || scan.created_at))}</td><td data-label="Relatório">${button("Ver análise →", "detail", "text-button", false, `data-id="${e(scan.id)}" aria-label="Ver análise de ${e(scan.repository)}, branch ${e(scan.branch)}"`)}</td>
  </tr>`).join("")}</tbody></table></div>`;
}
function overview() {
  const data = state.dashboard || {};
  const latest = state.scans.find(scan => scan.status === "completed");
  const monitored = state.branches.filter(branch => branch.selected).length;
  return `${pageHeading("01", 'Visão geral', "Dependências, branches e evidências. Um lugar para decidir o próximo passo.", button("Atualizar painel", "refresh", "", state.busy))}
    ${publicRepositoryCard()}
    <div class="section-kicker"><span>VISÃO DO AMBIENTE</span><span>Todas as instalações autorizadas</span></div>
    <div class="stats">${stat("Repositórios", data.repositories, "disponíveis no ambiente")}${stat("Branches monitoradas", data.selected_branches, "seleções salvas")}${stat("Análises registradas", data.scans, demo() ? "execuções sintéticas · histórico" : "execuções do serviço · histórico")}${stat("Achados atuais", data.findings, "última análise concluída por branch", true)}</div>
    <div class="toolbar scope-toolbar"><div class="actions">${scopeControls()}</div><div class="actions">${publicMode() && monitored ? button("Analisar agora →", "scan", "primary", state.busy, `data-branch="${e(state.branches.find(b => b.selected).name)}"`) : ""}<a href="#branches" class="button">Gerenciar monitoramento ↗</a></div></div>
    ${scopeEmpty() || `<section class="attention-card"><div class="attention-icon" aria-hidden="true">${latest?.finding_count ? "◇" : "↗"}</div><div><span class="eyebrow">PRÓXIMO PASSO · REPOSITÓRIO SELECIONADO</span><h2>${!monitored ? "Escolha suas primeiras branches." : latest ? latest.finding_count ? `${count(latest.finding_count)} ${latest.finding_count === 1 ? "achado para revisar" : "achados para revisar"}.` : "Uma análise pronta para sua revisão." : "Tudo pronto para a primeira análise."}</h2><p>${!monitored ? "Salve uma seleção para iniciar o acompanhamento deste repositório." : latest ? `${e(latest.branch)} · última análise concluída. ${e(reachSentence(latest))}` : publicMode() ? "Use Analisar agora ou escolha uma branch em Monitoramento. Nenhum webhook é necessário." : "Execute uma análise manual ou aguarde um push em uma branch monitorada."}</p></div>${latest && monitored ? button("Revisar última análise →", "detail", "primary", false, `data-id="${e(latest.id)}"`) : '<a href="#branches" class="button primary">Configurar branches →</a>'}</section>`}
    <div class="workflow-strip"><a href="#branches"><span>01</span><div><strong>Escolha as branches</strong><small>Defina o que acompanhar</small></div><b aria-hidden="true">→</b></a><a href="#results"><span>02</span><div><strong>Acompanhe análises</strong><small>Do commit ao resultado</small></div><b aria-hidden="true">→</b></a><a href="#activity"><span>03</span><div><strong>Confira a origem</strong><small>Eventos e execuções vinculados</small></div><b aria-hidden="true">↗</b></a></div>
    <div class="overview-grid"><section class="panel"><div class="section-heading panel-heading"><div><span class="eyebrow">REPOSITÓRIO SELECIONADO</span><h2>Análises recentes</h2></div><a href="#results" class="text-button">Ver todas →</a></div>${scanTable(state.scans.slice(0, 5))}</section>
    <aside class="panel panel-body"><span class="eyebrow">CONEXÕES DO AMBIENTE</span><div class="connection"><div class="inline"><h3>${publicMode() ? "GitHub público" : "GitHub App"}</h3>${badge(demo() ? "Simulado" : state.meta.github_configured ? "Configurado" : "Não configurado", !demo() && state.meta.github_configured ? "live" : "muted")}</div><p>${demo() ? "Instalação e eventos simulados. Não há conexão real nesta demonstração." : publicMode() ? "Sem GitHub App ou credenciais. Snapshots em memória e avisos reais do OSV. Inicie análises manualmente; webhooks desabilitados." : state.meta.github_configured ? "A configuração está presente. A atividade abaixo confirma os eventos recebidos, não a saúde contínua da conexão." : "O operador precisa configurar o GitHub App no serviço para receber repositórios e eventos."}</p></div>
    <div class="connection"><div class="inline"><h3>Explicações por IA</h3>${badge(state.meta.ai_configured ? "Configurada" : "Desabilitadas", state.meta.ai_configured ? "live" : "muted")}</div><p>Quando disponíveis, ajudam na leitura. Não substituem evidência nem determinam o alcance.</p></div>
    <div class="connection"><span class="eyebrow">ÚLTIMA ANÁLISE</span><p>${e(formatDate(data.last_scan_at))}</p></div></aside></div>
    <div class="trust-note"><span aria-hidden="true">◇</span><p><strong>Evidência, não promessa de segurança.</strong> Sem achados não significa ausência de vulnerabilidades. Alcance desconhecido permanece desconhecido.</p></div>`;
}

function publicRepositoryCard() {
  if (!publicMode()) return "";
  return `<section id="public-repository-card" class="panel public-repository-card" aria-labelledby="public-repository-title">${publicRepositoryContent()}</section>`;
}
function publicRepositoryContent() {
  const flow = state.publicFlow;
  const waiting = ["checking", "starting", "scanning"].includes(flow.phase);
  const registered = flow.registration;
  return `<div class="public-card-intro"><div><span class="eyebrow">GITHUB PÚBLICO · OSV REAL</span><h2 id="public-repository-title">Analisar repositório público</h2><p>Cole um endereço. Escolha a branch. Revise evidências reais, sem executar código.</p></div><span class="public-readonly">↗ Somente leitura</span></div>
    <form id="public-repository-form" novalidate><label for="public-repository-url">URL do repositório GitHub</label><div class="public-url-row"><input id="public-repository-url" name="repository" type="text" value="${e(flow.url)}" placeholder="https://github.com/owner/repo" autocomplete="off" spellcheck="false" maxlength="600" aria-describedby="public-repository-help public-repository-error" ${waiting ? "disabled" : ""}><button class="primary" type="submit" ${waiting ? "disabled" : ""}>${flow.phase === "checking" ? "Verificando…" : "Verificar →"}</button></div><p id="public-repository-help" class="secondary small">Sem conta GitHub, token pessoal ou instalação de dependências. Também aceita owner/repo e URLs de branch.</p></form>
    ${flow.error ? `<div id="public-repository-error" class="public-flow-error" role="alert"><strong>Não foi possível concluir</strong><p>${e(publicErrorCopy(flow.error))}</p>${button(flow.error === "network" ? "Tentar novamente" : "Escolher outro repositório", flow.error === "network" ? "public-retry" : "public-reset", "quiet")}</div>` : '<p id="public-repository-error" hidden></p>'}
    ${registered ? `<div class="public-branch-row"><div><span class="eyebrow">REPOSITÓRIO VERIFICADO</span><h3>${e(registered.repository.full_name)}</h3><span class="secondary small">${registered.branches.length} branches · padrão: ${e(registered.default_branch)}</span></div><label class="field" for="public-repository-branch">Branch<select id="public-repository-branch" ${waiting ? "disabled" : ""}>${registered.branches.map(branch => `<option value="${e(branch)}" ${branch === registered.selected_branch ? "selected" : ""}>${e(branch)}</option>`).join("")}</select></label>${button(flow.phase === "starting" ? "Iniciando…" : "Analisar →", "public-analyze", "primary", waiting || flow.phase === "completed")}</div>` : ""}
    ${flow.scan ? `<div class="public-progress" aria-live="polite"><div class="section-heading"><h3>${flow.phase === "completed" ? "Relatório pronto para revisão" : flow.phase === "error" ? "Análise interrompida" : "Análise em andamento"}</h3>${badge(flow.scan.status === "queued" ? "Na fila" : scanLabel(flow.scan.status), flow.scan.status)}</div><ol class="public-stage-list">${publicProgress(flow.scan).map((step, i) => `<li class="${step.status}" ${step.status === "active" ? 'aria-current="step"' : ""}><span>${step.status === "done" ? "✓" : String(i + 1).padStart(2, "0")}</span><strong>${e(step.label)}</strong></li>`).join("")}</ol>${flow.scan.progress?.total != null ? `<p class="secondary small">${e(flow.scan.progress.completed ?? 0)} / ${e(flow.scan.progress.total)} · contagem da etapa</p>` : ""}${flow.phase === "completed" ? `<p>${count(flow.scan.finding_count)} achados. Ausência de achados não significa segurança.</p>${button("Abrir relatório real →", "public-report", "primary")}` : '<p class="secondary small">Fontes lidos em memória. Desconhecido nunca significa seguro.</p>'}</div>` : ""}`;
}
function paintPublicRepository() {
  const card = $("#public-repository-card");
  if (card) card.innerHTML = publicRepositoryContent();
}
async function verifyPublicRepository() {
  const flow = state.publicFlow;
  const epoch = ++state.publicEpoch;
  clearTimeout(state.publicTimer);
  flow.registration = null; flow.scan = null;
  if (!validPublicRepository(flow.url)) { flow.error = "invalid_url"; flow.phase = "error"; paintPublicRepository(); return; }
  flow.phase = "checking"; flow.error = null; paintPublicRepository();
  try {
    const result = await api("/api/public/repositories", { method: "POST", body: { url: flow.url } });
    if (epoch !== state.publicEpoch || !state.authenticated) return;
    flow.registration = result; flow.phase = "ready";
    state.installation = result.installation_id; state.repository = result.repository.id;
    await refresh();
  } catch (error) { if (epoch === state.publicEpoch) { flow.phase = "error"; flow.error = error.code || "network"; } }
  if (epoch === state.publicEpoch) paintPublicRepository();
}
async function analyzePublicRepository(retry = false) {
  const flow = state.publicFlow, epoch = ++state.publicEpoch;
  clearTimeout(state.publicTimer);
  flow.phase = "starting"; flow.error = null; paintPublicRepository();
  try {
    if (retry && flow.scan && flow.scan.status !== "failed") {
      flow.phase = "scanning"; await pollPublicRepository(epoch); return;
    }
    const result = retry && flow.scan?.id
      ? await api(`/api/scans/${encodeURIComponent(flow.scan.id)}/retry`, { method: "POST", body: {} })
      : await api(`/api/public/repositories/${encodeURIComponent(flow.registration.repository.id)}/scan`, { method: "POST", body: { branch: flow.registration.selected_branch } });
    if (epoch !== state.publicEpoch || !state.authenticated) return;
    flow.scan = { id: result.scan_id, status: "queued" }; flow.phase = "scanning";
    paintPublicRepository(); await pollPublicRepository(epoch);
  } catch (error) { if (epoch === state.publicEpoch) { flow.error = error.code || "network"; flow.phase = "error"; paintPublicRepository(); } }
}
async function pollPublicRepository(epoch) {
  if (epoch !== state.publicEpoch || !state.authenticated) return;
  const flow = state.publicFlow;
  try {
    const scan = await api(`/api/scans/${encodeURIComponent(flow.scan.id)}`);
    if (epoch !== state.publicEpoch || !state.authenticated) return;
    flow.scan = scan;
    if (scan.status === "completed") { flow.phase = "completed"; await refresh(); }
    else if (["failed", "cancelled"].includes(scan.status)) { flow.phase = "error"; flow.error = scan.error_code || "analysis_failed"; }
    else state.publicTimer = setTimeout(() => pollPublicRepository(epoch), 1000);
  } catch (error) { if (epoch === state.publicEpoch) { flow.phase = "error"; flow.error = error.code || "network"; } }
  if (epoch === state.publicEpoch) paintPublicRepository();
}

function scopeControls(includeRepository = true) {
  return `<label class="field" for="installation-select">Instalação GitHub<select id="installation-select" data-control="installation" ${state.busy ? "disabled" : ""}>${state.installations.length ? state.installations.map(installation => `<option value="${e(installation.id)}" ${String(installation.id) === String(state.installation) ? "selected" : ""} ${installation.status !== "active" ? "disabled" : ""}>${e(installation.account)}${installation.status !== "active" ? " · indisponível" : ""}</option>`).join("") : '<option value="">Nenhuma instalação</option>'}</select></label>
    ${includeRepository ? `<label class="field" for="repository-select">Repositório<select id="repository-select" data-control="repository" ${state.busy ? "disabled" : ""}>${state.repositories.length ? state.repositories.map(repository => `<option value="${e(repository.id)}" ${String(repository.id) === String(state.repository) ? "selected" : ""}>${e(repository.full_name)}</option>`).join("") : '<option value="">Nenhum repositório</option>'}</select></label>` : ""}`;
}
function scopeEmpty() {
  const sync = !demo() && state.meta.github_configured ? button("Sincronizar com GitHub", "sync", "primary", state.busy) : "";
  if (!state.installation) return empty("Nenhuma instalação ativa.", demo() ? "A instalação de demonstração ainda não está disponível. Atualize o painel para tentar novamente." : publicMode() ? "Configure SCA_PUBLIC_REPOSITORIES no serviço e sincronize para listar os repositórios públicos. Não é necessário GitHub App." : "Configure e instale o GitHub App para que os repositórios autorizados apareçam aqui. Instalações suspensas não permitem monitoramento.", sync);
  if (!state.repository) return empty("Nenhum repositório disponível.", "Autorize repositórios nesta instalação do GitHub App e sincronize a lista.", sync);
  return "";
}
function branchRows() {
  const visible = state.branches.filter(branch => branch.name.toLocaleLowerCase("pt-BR").includes(state.filter.toLocaleLowerCase("pt-BR")));
  if (!visible.length) return empty(state.branches.length ? "Nenhuma branch encontrada." : "Nenhuma branch disponível.", state.branches.length ? "Tente buscar por outro nome." : "Verifique se o repositório tem branches e atualize a lista.");
  return `<div class="panel">${visible.map((branch, index) => `<div class="branch-row"><label for="branch-${index}"><input type="checkbox" id="branch-${index}" data-branch="${e(branch.name)}" ${state.selected.has(branch.name) ? "checked" : ""} ${state.busy || (!state.selected.has(branch.name) && state.selected.size >= MAX_BRANCHES) ? "disabled" : ""}><svg class="branch-glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="6" cy="5" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><path d="M6 7v10M18 7v2a5 5 0 0 1-5 5H6"/></svg><span class="branch-copy"><span class="mono branch-name">${e(branch.name)}</span><small>${branch.name === repo()?.default_branch ? "Branch principal" : "Branch do repositório"}</small></span></label><div class="actions"><span data-branch-state="${e(branch.name)}">${branchBadge(branch)}</span>${button("Analisar →", "scan", "", state.busy || !branch.selected || isDirty(state.branches, state.selected), `data-branch="${e(branch.name)}" aria-label="Analisar branch ${e(branch.name)}"`)}<span class="secondary small" data-branch-blocked>${isDirty(state.branches, state.selected) ? "Salve a seleção para analisar." : !branch.selected ? "Selecione e salve para analisar." : ""}</span></div></div>`).join("")}</div>`;
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
  const scope = `${state.installation ?? ""}:${state.repository ?? ""}`;
  if (state.simulationScope !== scope) {
    state.simulationScope = scope; state.simulationTarget = null;
  }
  const dirty = isDirty(state.branches, state.selected);
  const saved = state.branches.filter(branch => branch.selected);
  if (!saved.some(branch => branch.name === state.simulationTarget)) state.simulationTarget = saved[0]?.name ?? null;
  return `<label class="field" for="simulation-branch">Branch do push simulado<select id="simulation-branch" ${state.busy || dirty || !saved.length ? "disabled" : ""}>${saved.map(branch => `<option value="${e(branch.name)}" ${branch.name === state.simulationTarget ? "selected" : ""}>${e(branch.name)}</option>`).join("")}</select></label>${button("Simular push de demonstração", "simulate", "", state.busy || dirty || !saved.length)}<p id="simulation-help" class="secondary small">${dirty ? "Salve a seleção para simular" : saved.length ? "O push usa a branch indicada acima. Nenhum push real é enviado ao GitHub." : "Selecione e salve uma branch para simular."}</p>`;
}
function branches() {
  const dirty = isDirty(state.branches, state.selected);
  return `${pageHeading("02", 'Monitoramento', publicMode() ? "Selecione e salve as branches. Use Analisar para consultar GitHub e OSV reais, sem executar código." : "Você define o escopo. Cada push em uma branch salva pode iniciar uma análise.")}
    <div class="toolbar scope-toolbar"><div class="actions">${scopeControls()}</div><div class="actions">${!demo() && state.meta.github_configured ? button("Sincronizar com GitHub", "sync", "", state.busy) : ""}<div class="branch-refresh-action">${button("Atualizar lista", "refresh", "", state.busy)}<span id="branch-refresh-error" class="form-error" role="alert">${e(state.branchRefreshError)}</span></div></div></div>
    ${scopeEmpty() || `${demo() ? `<section class="execution-dock"><div><span class="eyebrow">TESTE O FLUXO</span><h3>Simule um push, veja o resultado.</h3><p>Primeiro selecione e salve uma branch. Depois envie um evento sintético.</p></div><div id="simulation-controls">${simulationControls()}</div></section>` : ""}<div class="branch-layout"><section><div class="section-heading"><div><span class="eyebrow">01 / ESCOLHA E SALVE</span><h2>Branches de ${e(repo()?.full_name?.split("/").pop() || "repositório")}</h2></div>${badge(`${state.branches.length} disponíveis`)}</div>
      <label class="field" for="branch-search">Buscar branch<input id="branch-search" type="search" placeholder="Filtrar pelo nome…" value="${e(state.filter)}" autocomplete="off"></label>
      <div class="actions bulk-actions">${button("Selecionar filtradas", "select-filtered", "quiet", state.busy)}${button("Limpar seleção", "clear-selection", "quiet", state.busy || !state.selected.size)}<span class="secondary small">Até 20 branches por repositório</span></div>
      <div class="save-bar"><p id="selection-summary" aria-live="polite" tabindex="-1">${selectionSummary()}</p><div class="actions">${button("Descartar", "discard", "quiet", !dirty || state.busy)}${button(state.operation === "save" ? "Salvando…" : "Salvar seleção", "save", "primary", !dirty || state.busy || state.selected.size > MAX_BRANCHES)}</div><p id="selection-error" class="form-error" role="status">${e(selectionMessage())}</p><p id="save-error" class="form-error" role="alert" tabindex="-1">${e(state.saveError)}</p></div>
      <div id="branch-list" class="branch-list">${branchRows()}</div>
      <p class="secondary small spaced">${publicMode() ? "Desmarcar todas pausa novas análises manuais." : "Desmarcar todas pausa novas análises por webhook neste repositório."} O histórico é preservado.</p></section>
      <aside class="panel panel-body"><span class="eyebrow">DO ESCOPO À EVIDÊNCIA</span><div class="flow"><span class="flow-number">01</span><div><h3>Selecione e salve</h3><p>Só a seleção salva é usada pelo serviço. Limpar seleção também desmarca branches ocultas pelo filtro.</p></div></div><div class="flow"><span class="flow-number">02</span><div><h3>Inicie uma análise</h3><p>Use Analisar para uma execução manual${demo() ? " ou simule um push acima" : publicMode() ? "; webhooks estão desabilitados" : " ou envie um push pelo GitHub"}.</p></div></div><div class="flow"><span class="flow-number">03</span><div><h3>Decida com contexto</h3><p>Revise pacote, versão, aviso e manifesto. A IA, quando disponível, não é evidência.</p><a href="#results" class="text-button">Abrir análises →</a></div></div></aside></div>`}`;
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
  return `${pageHeading("03", 'Análises', "Do commit à evidência. Revise o que foi encontrado e o que ainda não sabemos.")}
    <div class="toolbar"><div class="actions">${scopeControls()}<label class="field" for="status-filter">Estado<select id="status-filter" data-control="status">${[["all", "Todos os estados"], ["queued", "Na fila"], ["running", "Em andamento"], ["completed", "Concluída"], ["failed", "Falhou"]].map(([value, label]) => `<option value="${value}" ${state.statusFilter === value ? "selected" : ""}>${label}</option>`).join("")}</select></label></div>${button("Atualizar", "refresh", "", state.busy)}</div>
    ${scopeEmpty() || `<section class="panel results-panel"><div class="panel-heading"><label class="field" for="results-search">Buscar análises<input id="results-search" type="search" placeholder="Aviso, pacote, repositório, branch ou commit…" value="${e(state.filter)}" autocomplete="off"></label></div><div id="results-list">${resultsList()}</div></section>`}
    <p class="secondary small spaced"><span id="last-updated">${state.lastUpdated ? `Última atualização do painel: ${e(formatDate(state.lastUpdated))}.` : ""}</span> Atualização automática a cada 15 segundos; filtros e seleções em edição são preservados.</p>`;
}
function activity() {
  if (publicMode()) return `${pageHeading("04", "Atividade", "Execuções manuais sobre commits públicos. Este ambiente não recebe webhooks.", button("Atualizar", "refresh", "", state.busy))}<section class="panel panel-body"><span class="eyebrow">ORIGEM AUDITÁVEL</span><h2>Do GitHub ao relatório.</h2><p>Consulte o histórico de análises para revisar repositório, branch, commit exato e evidências. Nenhum push é simulado ou recebido neste modo.</p><a href="#results" class="button primary">Ver análises →</a></section>`;
  return `${pageHeading("04", 'Atividade', "A origem de cada execução. Confira o evento recebido e a análise que ele iniciou.", `<div class="actions">${button("Atualizar", "refresh", "", state.busy)}</div>`)}
    ${state.deliveries.length ? `<div class="table-wrap responsive-table"><table role="table"><thead><tr><th scope="col">Evento</th><th scope="col">Repositório / branch</th><th scope="col">Resultado do evento / análise atual</th><th scope="col">Recebido em</th></tr></thead><tbody>${state.deliveries.map(delivery => `<tr><td data-label="Evento"><strong>${e(delivery.event)}</strong><span class="secondary mono">${e(delivery.delivery_id)}</span></td><td data-label="Repositório / branch"><span class="break">${e(delivery.repository || "—")}</span><span class="secondary mono">${e(delivery.branch || "—")}</span></td><td data-label="Resultado do evento / análise atual"><div class="activity-status-group"><span class="eyebrow">O que o evento fez</span>${badge(deliveryLabel(delivery.status), delivery.status === "failed" ? "failed" : "muted")}</div>${delivery.scan_id ? `<div class="activity-status-group"><span class="eyebrow">Análise atual</span><span class="secondary">${e(scanLabel(delivery.scan_status))}</span>${button("Ver análise →", "detail", "text-button", false, `data-id="${e(delivery.scan_id)}"`)}</div>` : ""}</td><td data-label="Recebido em">${e(formatDate(delivery.received_at))}</td></tr>`).join("")}</tbody></table></div>` : empty("Nenhum evento recebido ainda.", demo() ? "Selecione uma branch e use a simulação de push para explorar o fluxo de demonstração." : "Após configurar o webhook do GitHub App, os eventos recebidos aparecerão aqui.")}
    <div class="note spaced">${demo() ? "Eventos sintéticos, gerados no ambiente de demonstração. Nenhum webhook real é representado." : "Um evento recebido não significa uma análise concluída. Consulte o estado da execução em Análises."}</div>`;
}
function deliveryLabel(status) {
  return ({ accepted: "Aceito", queued: "Encaminhou para análise", processed: "Processado", ignored: "Ignorado", failed: "Falhou", rejected: "Rejeitado", duplicate: "Duplicado", completed: "Concluído", received: "Recebido" })[status] || "Estado não reconhecido";
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
    const message = "Salve ou descarte as alterações antes de atualizar a lista.";
    if (state.view === "branches") {
      state.branchRefreshError = message;
      const inline = $("#branch-refresh-error");
      if (inline) { inline.textContent = message; inline.hidden = false; }
    }
    notice(message, true); return;
  }
  state.branchRefreshError = "";
  const epoch = ++state.epoch;
  const focused = captureFocus();
  if (!silent) { state.busy = true; renderView(); }
  try {
    const pollScope = silent && state.view === "branches" && !isDirty(state.branches, state.selected);
    const scanPath = !full && !pollScope ? scansPath() : null;
    const requests = [api("/api/dashboard"), api("/api/deliveries"), scanPath ? api(scanPath) : Promise.resolve(null)];
    if (full || pollScope) requests.push(loadScoped(epoch));
    const [dashboard, deliveries, scanResponse] = await Promise.all(requests);
    if (epoch !== state.epoch || !state.authenticated) return;
    state.dashboard = dashboard; state.deliveries = items(deliveries);
    if (scanResponse) state.scans = items(scanResponse);
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
    if (state.authenticated) restoreFocus(focused);
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
  const url = advisoryURL(id);
  return url ? `<a href="${e(url)}" target="_blank" rel="noopener noreferrer">${e(id)}</a>` : e(id);
}
function manifestLink(path, scan, line = null) {
  const label = line ? `${path}:${line}` : path;
  const url = demo() ? null : githubLink(scan, path, line);
  if (!url) return e(label);
  return `<a href="${e(url)}" target="_blank" rel="noopener noreferrer">${e(label)}</a>`;
}
function findingInstructions(finding, scan) {
  const versions = Array.isArray(finding.fixed_versions) ? finding.fixed_versions : [];
  const version = versions.length ? versions.join(" ou ") : "(sem versão corrigida informada)";
  const manifests = findingManifests(finding, scan).join(", ") || "manifesto não informado";
  const lead = ({
    reachable: `Prioridade: ${findingPresentation(finding).label.toLowerCase()}. ${finding.reachability_analysis?.granularity === "import" ? "Existe um caminho estático de importações; não comprova chamada vulnerável nem execução." : "O código chama o alvo do aviso neste contexto."}`,
    unreachable: "Nenhuma chamada encontrada, mas a dependência continua vulnerável.",
  })[finding.reachability] || "Alcance desconhecido: revise manualmente os pontos indicados e trate como potencialmente alcançável.";
  return `${lead} Atualize ${finding.package_name || "o componente"} para ${version} em ${manifests}, teste e execute nova análise.`;
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
  const reach = findingPresentation(finding);
  const steps = evidenceSteps(finding.reachability_evidence);
  const analysis = finding.reachability_analysis && typeof finding.reachability_analysis === "object" ? finding.reachability_analysis : {};
  const notes = evidenceSteps(analysis.notes);
  const transitive = transitiveSteps(finding);
  const transitivePath = transitive.length ? `<section class="transitive-trace" aria-label="Caminho transitivo"><div class="trace-heading"><span class="eyebrow">EVIDÊNCIA ENTRE PACOTES</span><span class="trace-chip">Importação estática</span></div><h4>Do repositório ao pacote.</h4><p class="secondary small">Fontes dos tarballs fixados no lockfile, lidos em memória. Não comprova chamada vulnerável nem execução.</p><ol>${transitive.map((step, index) => `<li><span class="trace-number" aria-hidden="true">${index + 1}</span><div class="trace-step"><strong>${e(step.package ? `${step.package}@${step.version}` : step.originLabel)}</strong>${step.url ? `<a class="trace-file mono" href="${e(step.url)}" target="_blank" rel="noopener noreferrer">${e(step.file)}${step.line ? `:${step.line}` : " · entrada"}<span aria-hidden="true">↗</span></a>` : manifestLink(step.file, scan, step.line)}<span class="trace-load mono">${step.specifier ? `importa ${e(step.specifier)}` : "Pacote do aviso alcançado"}</span></div></li>`).join("")}</ol></section>` : '';
  const contextNote = `<p class="secondary small dependency-context"><strong>${e(dependencyPresentation(finding))}</strong>${isTransitiveUnknown(finding) ? " · Desconhecido: revise os pacotes intermediários e os limites da análise antes de concluir alcance." : ""}</p>${analysis.dependency_dev ? '<p class="secondary small">Lockfile: dependência de desenvolvimento (<code>dev: true</code>).</p>' : ''}${notes.length ? `<p class="analysis-note small"><strong>Nota de análise · cargas locais</strong><br>${notes.map(note => manifestLink(note.path, scan, note.line)).join(" · ")}<br>Caminhos locais reconhecidos, não cargas de pacotes. Os arquivos locais são analisados dentro da cobertura registrada.</p>` : ''}`;
  const symbols = Array.isArray(analysis.symbols) ? analysis.symbols.filter(symbol => typeof symbol === "string") : [];
  const method = analysis.granularity === "import" ? "Caminho estático de importações entre pacotes. Os símbolos do aviso, quando informados, não foram comprovados como chamados. Nenhum código monitorado foi executado."
    : typeof analysis.language === "string" && Number.isInteger(analysis.files_scanned)
    ? `Análise estática de ${e(analysis.language)} em ${count(analysis.files_scanned)} ${analysis.files_scanned === 1 ? "arquivo" : "arquivos"}, ${symbols.length ? `procurando chamadas a <span class="mono">${symbols.map(e).join(", ")}</span>` : "no nível do pacote, porque o aviso não identifica a função vulnerável"}. O código monitorado foi apenas lido, nunca executado.`
    : "Nenhuma análise de chamadas foi registrada para este achado; o alcance permanece desconhecido.";
  const codePath = steps.length
    ? `<ol class="code-path" aria-label="Caminho no código">${steps.map(step => `<li class="step-${step.kind}"><div class="step-head"><span class="step-kind">${e(step.kindLabel)}</span><span class="mono step-location">${manifestLink(step.path, scan, step.line)}</span></div>${step.detail ? `<span class="step-detail mono">${e(step.detail)}</span>` : ""}${step.snippet ? `<pre><code>${e(step.snippet)}</code></pre>` : ""}</li>`).join("")}</ol>`
    : `<p class="secondary">Nenhum trecho de código foi registrado como evidência${finding.reachability === "unreachable" ? ": o pacote não é importado nos arquivos analisados" : ""}.</p>`;
  return `<article class="finding"><div class="section-heading"><h3>${publicMode() ? advisoryLink(finding.advisory_id || finding.id) : e(finding.advisory_id || finding.id)}</h3>${badge(reach.label, reach.tone, true)}</div><p><strong>${e(finding.package_name)}</strong> <span class="mono secondary">${e(finding.version)}</span> <span class="secondary">· Severidade: ${severity}</span></p><p class="secondary">${e(finding.summary || "O aviso não inclui um resumo.")}</p>
    <div class="reach-callout ${reach.tone}"><span class="eyebrow">ALCANCE ESTÁTICO · ${e(reach.label.toUpperCase())}</span><strong>${e(reach.headline)}</strong><p>${e(finding.reachability_reason || reach.caveat)}</p>${finding.reachability_reason && !finding.reachability_reason.includes(reach.caveat.split(".")[0]) ? `<p class="small">${e(reach.caveat)}</p>` : ""}</div>
    ${contextNote}${transitivePath}<details open><summary>Ver evidências e limites</summary><div class="evidence"><h4>Por que este achado apareceu?</h4><p><span class="mono">${e(finding.package_name)}@${e(finding.version)}</span> encontrado em ${manifests} no commit <span class="mono">${e(scan.commit_sha?.slice(0, 7) || "não informado")}</span>. ${scan.source === "demo" ? "Correlação sintética por versão exata com o aviso fictício; não houve consulta ao OSV." : "Correspondência com o aviso por versão exata via OSV."}</p><h4>Caminho no código</h4><p class="secondary">${method}</p>${codePath}<dl><dt>Identificador</dt><dd class="mono">${advisoryLink(finding.advisory_id || finding.id)}</dd><dt>Componente</dt><dd class="mono">${e(finding.purl || finding.package_name)}</dd><dt>Ecossistema</dt><dd>${e(finding.ecosystem || "Não informado")}</dd><dt>Correção informada</dt><dd>${e(finding.fixed_versions?.length ? finding.fixed_versions.join(", ") : "Nenhuma versão informada nos dados")}</dd><dt>Alcance</dt><dd>${e(reach.label)}. ${e(reach.caveat)}</dd></dl></div></details>
    <section class="next-step"><h4>Próximo passo</h4><p>${e(instructions)}</p>${button("Copiar instruções", "copy-instructions", "quiet", false, `data-instructions="${e(instructions)}"`)}</section></article>`;
}
function renderReportFindings() {
  const section = $("#report-findings");
  const scan = state.reportScan;
  if (!section || !scan || scan.status !== "completed") return;
  if (!publicMode()) return;
  const counts = reachabilityCounts(scan.findings);
  const scopes = scopeCounts(scan.findings);
  const filters = { all: ["Todos", scan.findings.length], reachable: ["Alcançáveis", counts.reachable], production: ["Em produção", scopes.production], nonproduction: ["Testes/ferramentas", scopes.test_only + scopes.dev_tooling], transitive_decided: ["Via caminho transitivo", scan.transitive_summary?.decided || 0], unknown: ["Desconhecidos", counts.unknown], transitive_unknown: ["Transitivas · import/CLI", scan.findings.filter(isTransitiveUnknown).length], unreachable: ["Inalcançáveis", counts.unreachable] };
  const page = findingPage(scan.findings, state.findingFilter, state.findingPage);
  state.findingPage = page.page;
  section.innerHTML = `<span class="eyebrow">01 / TRIAGEM DOS ACHADOS</span><h3>Priorize com evidências.</h3><p class="secondary">Alcançáveis em produção primeiro. Desconhecido exige revisão — nunca significa seguro.</p><p class="scope-summary">${e(scopeSummary(scopes))}</p>
    <div class="finding-filters" role="group" aria-label="Filtrar alcance e contexto">${Object.entries(filters).map(([key, [label, total]]) => `<button type="button" data-action="finding-filter" data-filter="${key}" aria-pressed="${state.findingFilter === key}">${e(label)} <span>${count(total)}</span></button>`).join("")}</div>
    <p class="secondary small" role="status">${page.total ? `${count(page.page * 10 + 1)}–${count(Math.min((page.page + 1) * 10, page.total))} de ${count(page.total)} achados` : "Nenhum achado neste filtro."} · ordem por alcance</p>
    ${page.items.map(f => findingMarkup(f, scan).replace('<details open>', '<details>')).join("")}
    <div class="finding-pagination">${button("← Anterior", "finding-prev", "quiet", page.page === 0)}<span class="secondary small">Página ${page.page + 1} de ${page.pages}</span>${button("Próxima →", "finding-next", "quiet", page.page + 1 === page.pages)}</div>`;
  readableIdentifiers();
}
function demoSourceMarkup(scan) {
  if (!demo() || scan.source !== "demo" || scan.status !== "completed") return "";
  const sources = Array.isArray(scan.demo_sources)
    ? scan.demo_sources.filter(source => source && typeof source.manifest_path === "string" &&
      typeof source.blob_sha === "string" && typeof source.content === "string")
    : [];
  if (!sources.length) {
    return '<section class="demo-source spaced"><h3>Registro sintético de origem</h3><p>Registro-fonte não armazenado nesta execução; simule uma nova análise.</p></section>';
  }
  return '<details class="demo-source spaced"><summary>Consultar registro sintético de origem</summary><p>Conteúdo gerado localmente para a demonstração; não é um arquivo obtido do GitHub.</p>' +
    sources.map(source => '<section class="demo-source-item"><p><strong>Manifesto sintético (caminho virtual):</strong> <code>' +
      e(source.manifest_path) + '</code></p><p class="secondary small">Hash do blob: <code>' + e(source.blob_sha) +
      '</code></p><pre class="demo-source-json"><code>' + e(source.content) + '</code></pre></section>').join("") +
    '</details>';
}
async function openDetail(id, polling = false, origin = null) {
  clearTimeout(state.detailTimer);
  const epoch = ++state.detailEpoch;
  const dialog = $("#detail-dialog");
  dialog.classList.toggle("public-report", publicMode());
  if (!dialog.open) state.detailReturn = origin || detailOrigin();
  if (!polling) $("#detail-content").innerHTML = `<div class="dialog-heading"><h2 id="detail-title">Carregando análise…</h2>${button("Fechar", "close-detail", "quiet")}</div><p class="secondary" role="status">Consultando o relatório e suas evidências.</p>`;
  if (!dialog.open) dialog.showModal();
  try {
    const scan = await api(`/api/scans/${encodeURIComponent(id)}`);
    if (!state.authenticated || !dialog.open || epoch !== state.detailEpoch) return;
    if (!polling) { state.findingFilter = "all"; state.findingPage = 0; }
    state.reportScan = scan;
    const explanation = explanationPresentation(scan.explanation);
    const findings = sortFindings(scan.findings);
    const reachCounts = reachabilityCounts(findings);
    const components = Array.isArray(scan.components) ? scan.components : [];
    const warnings = Array.isArray(scan.warnings) ? scan.warnings : [];
    const pending = ["queued", "running"].includes(scan.status);
    $("#detail-content").innerHTML = `<div class="dialog-heading"><div><span class="eyebrow">RELATÓRIO DA EXECUÇÃO</span><h2 id="detail-title">${scan.status === "completed" ? findings.length ? `${count(findings.length)} ${findings.length === 1 ? "achado" : "achados"}.` : "Sem achados nos dados." : e(scanLabel(scan.status))}</h2></div>${button("Fechar", "close-detail", "quiet")}</div>
      <div class="inline">${badge(scanLabel(scan.status), scan.status)}${badge(scan.source === "demo" ? "Demonstração · dados fictícios" : scan.source === "github" ? publicMode() ? "Origem: GitHub público" : "Origem: GitHub" : "Origem não informada", scan.source === "demo" ? "demo" : "muted")}</div>
    <div class="dialog-meta"><span class="break">${e(scan.repository)} <span aria-hidden="true">/</span> ${e(scan.branch)}</span><span class="mono id-chip" title="${e(scan.commit_sha || "não informado")}">${publicMode() ? commitMarkup(scan) : `Commit ${e(scan.commit_sha || "não informado")}`}</span><span>${e(formatDate(scan.completed_at || scan.created_at))}</span></div>
      <nav class="report-nav" aria-label="Seções do relatório"><button type="button" data-action="report-section" data-section="report-findings">Achados <span>${count(findings.length)}</span></button><button type="button" data-action="report-section" data-section="report-explanation">${explanation.ai ? "Leitura por IA" : "Resumo local"}</button><button type="button" data-action="report-section" data-section="report-components">Componentes <span>${count(components.length)}</span></button><button type="button" data-action="report-section" data-section="report-limits">Limites e origem</button></nav>
      ${scan.status === "completed" ? `<div class="report-summary"><div><span>Achados técnicos</span><strong>${count(findings.length)}</strong></div><div><span>Componentes</span><strong>${count(components.length)}</strong></div><div class="reach-summary"><span>Alcance estático</span><div class="reach-counts">${["reachable", "unknown", "unreachable"].map(key => `<b class="reach-count ${key}"><i aria-hidden="true"></i>${count(reachCounts[key])}<small>${e(reachabilityPresentation(key).label)}</small></b>`).join("")}</div></div></div>` : ""}
      ${scan.status === "completed" ? `<p class="scope-summary">${e(scopeSummary(scopeCounts(findings)))}</p>` : ""}
      <div id="report-limits" class="report-anchor" tabindex="-1">${scan.source === "demo" ? '<p class="note">Este relatório é sintético. Não representa o estado de segurança de um projeto real.</p>' : ""}${demoSourceMarkup(scan)}
      ${scan.status === "failed" ? `<p class="note form-error">A análise falhou e não produziu resultados. Nenhuma conclusão de segurança pode ser extraída.</p><p>Você pode tentar novamente com a mesma branch e o mesmo commit, se a branch continuar monitorada.</p>${button("Tentar novamente", "retry-scan", "quiet", false, `data-id="${e(id)}"`)}<p id="detail-action-error" class="form-error" role="alert"></p>` : ""}
      ${pending ? `<p class="note">Resultados ainda não calculados. Acompanhando automaticamente. ${button("Atualizar agora", "detail", "text-button", false, `data-id="${e(id)}"`)}</p>` : ""}
      ${warnings.length ? `<details class="report-warnings"><summary>Limitações informadas pelo serviço (${warnings.length})</summary><ul>${warnings.map(warning => `<li class="break">${e(warning)}</li>`).join("")}</ul></details>` : ""}</div>
      ${scan.status === "completed" ? `
      <section id="report-findings" class="spaced report-anchor" tabindex="-1" aria-label="Achados técnicos">${publicMode() ? "" : `<span class="eyebrow">01 / RESULTADO TÉCNICO</span>${findings.length ? findings.map(finding => findingMarkup(finding, scan)).join("") : empty("Nenhum achado disponível.", "Nenhum aviso nos dados analisados. Isso não significa que o projeto está livre de vulnerabilidades.")}`}</section>
      <section id="report-explanation" class="explanation report-anchor" tabindex="-1"><span class="eyebrow">02 / APOIO À LEITURA</span><div class="inline"><h3>${e(explanation.title)}</h3>${explanation.ai ? badge("IA · conteúdo não verificado", "unknown") : ""}</div>${explanation.note ? `<p class="secondary small">${e(explanation.note)}</p>` : ""}<p>${e(explanation.text)}</p><p class="secondary small">${explanation.ai ? "Texto gerado por IA, não uma evidência técnica. Pode conter erros. " : ""}A explicação não altera os achados nem comprova se um caminho vulnerável é executado.</p></section>
      <details id="report-components" class="spaced report-anchor" tabindex="-1"><summary>Componentes analisados (${count(components.length)})</summary><div class="table-wrap spaced"><table><thead><tr><th scope="col">Componente</th><th scope="col">Versão</th><th scope="col">Ecossistema / manifesto</th></tr></thead><tbody>${components.map(component => `<tr><td class="break">${e(component.name)}<span class="secondary mono">${e(component.purl)}</span></td><td class="mono">${e(component.version)}</td><td>${e(component.ecosystem)}<span class="secondary mono">${e(component.manifest_path || "—")}</span></td></tr>`).join("")}</tbody></table></div></details>` : ""}<div class="dialog-footer">${button("Fechar relatório", "close-detail", "quiet")}</div>`;
    renderReportFindings();
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
    notice(publicMode() ? "Seleção salva. Use Analisar nas branches selecionadas. O histórico foi preservado." : state.selected.size ? "Seleção salva. Novos pushes nessas branches entrarão no monitoramento." : "Monitoramento por webhook pausado neste repositório. O histórico foi preservado.");
  }, "save");
}
async function queueScan(branch, simulate = false) {
  if (isDirty(state.branches, state.selected)) { notice("Salve ou descarte a seleção antes de iniciar uma análise.", true); return; }
  const origin = detailOrigin();
  await mutation(async () => {
    const result = await api(simulate ? "/api/demo/push" : `${repositoryPath()}/scan`, { method: "POST", body: simulate ? { repository_id: Number(state.repository), branch } : { branch } });
    notice(simulate ? "Push sintético recebido. Acompanhe a análise de demonstração." : "Análise adicionada à fila. O resultado aparecerá quando a execução terminar.");
    const path = scansPath(); if (path) state.scans = items(await api(path));
    if (result?.scan_id) await openDetail(result.scan_id, false, origin);
  }, "scan");
}

document.addEventListener("submit", async event => {
  if (event.target.id === "public-repository-form") { event.preventDefault(); await verifyPublicRepository(); return; }
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
  if (action === "public-analyze") { await analyzePublicRepository(); return; }
  if (action === "public-retry") { if (state.publicFlow.scan) await analyzePublicRepository(true); else await verifyPublicRepository(); return; }
  if (action === "public-reset") { clearTimeout(state.publicTimer); state.publicEpoch++; state.publicFlow = { url: "", phase: "idle", registration: null, scan: null, error: null }; paintPublicRepository(); $("#public-repository-url")?.focus(); return; }
  if (action === "public-report") { await openDetail(state.publicFlow.scan.id); return; }
  if (action === "skip-main") { event.preventDefault(); $("#main").focus({ preventScroll: true }); }
  else if (action === "demo-login" && demo()) {
    $("#access-token").value = "local-demo";
    $("#login-form").requestSubmit();
  }
  else if (action === "refresh") await refresh();
  else if (["finding-filter", "finding-prev", "finding-next"].includes(action)) {
    if (action === "finding-filter") { state.findingFilter = target.dataset.filter; state.findingPage = 0; }
    else state.findingPage += action === "finding-next" ? 1 : -1;
    renderReportFindings();
    $("#report-findings").focus({ preventScroll: true });
    $("#report-findings").scrollIntoView({ block: "start" });
  }
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
    if (state.simulationScope === `${state.installation ?? ""}:${state.repository ?? ""}` &&
        branch === state.simulationTarget && state.branches.some(value => value.name === branch && value.selected)) await queueScan(branch, true);
  }
  else if (action === "detail") await openDetail(target.dataset.id);
  else if (action === "report-section") {
    const section = document.getElementById(target.dataset.section);
    if (section) { if (section.tagName === "DETAILS") section.open = true; section.scrollIntoView({ block: "start" }); section.focus({ preventScroll: true }); }
  }
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
  if (target.id === "public-repository-branch" && state.publicFlow.registration) {
    state.publicFlow.registration.selected_branch = target.value;
    state.publicFlow.phase = "ready"; state.publicFlow.scan = null; state.publicFlow.error = null;
    paintPublicRepository(); $("#public-repository-branch")?.focus();
  }
  if (target.id === "simulation-branch") {
    const saved = state.branches.find(value => value.name === target.value && value.selected);
    if (saved) {
      state.simulationScope = `${state.installation ?? ""}:${state.repository ?? ""}`;
      state.simulationTarget = saved.name;
    }
    return;
  }
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
  if (event.target.id === "public-repository-url") {
    state.publicFlow.url = event.target.value; state.publicFlow.registration = null; state.publicFlow.error = null;
    state.publicFlow.scan = null; state.publicFlow.phase = "idle";
    clearTimeout(state.publicTimer); state.publicEpoch++;
    const branch = $("#public-repository-card .public-branch-row"); if (branch) branch.hidden = true;
    const progress = $("#public-repository-card .public-progress"); if (progress) progress.hidden = true;
    const error = $("#public-repository-error"); if (error) error.hidden = true;
  }
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
$("#detail-dialog").addEventListener("close", () => { clearTimeout(state.detailTimer); state.detailEpoch++; restoreDetailOrigin(); });
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
    if (!supportedMode(state.meta?.mode)) throw new Error("O serviço não informou um ambiente reconhecido.");
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

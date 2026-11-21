# Backend de monitoramento de branches

## Repositório público por URL

`SCA_MODE=public` inicia sem lista de repositórios. `SCA_PUBLIC_REPOSITORIES` é apenas uma lista opcional de até dez presets; a sincronização também preserva os repositórios adicionados pelo operador. O dashboard oferece URL → verificar → escolher branch → analisar → acompanhar etapas → abrir relatório. A seleção de outra branch não exige configurar webhooks ou instalar um GitHub App. O token de acesso é somente o token do operador, nunca uma credencial GitHub.

`POST /api/public/repositories`, autenticado e protegido pelas regras existentes de Origin/CSRF, recebe `{ "url": "https://github.com/owner/repo" }`. Aceita também owner/repo, sufixo .git e /tree/branch (inclusive nomes com barras, validados contra os refs reais). Rejeita outros hosts, HTTP, credenciais, portas, query/fragment, caminhos de arquivos e branches inexistentes. Consulta smart HTTP, sem api.github.com, e retorna installation_id, repository, branches, default_branch e selected_branch. O catálogo persistido é restaurado no adaptador ao reiniciar. Há limite de 25 repositórios armazenados (rejeita novos, não apaga histórico nem análises em andamento) e oito verificações por sessão por minuto; Bearer compartilha o orçamento do operador.

`POST /api/public/repositories/{id}/scan` recebe `{ "branch": "main" }`, seleciona a branch verificada e usa a fila existente, com um worker global. O SHA completo é resolvido novamente ao enfileirar e o snapshot corresponde àquele commit. Nenhum código analisado é instalado, importado, executado ou gravado em disco.

`GET /api/scans/{id}` inclui progress (stage, completed, total, updated_at) e error_code. Etapas: fetching_snapshot, inventory, osv, reachability, persisting e completed/failed; queued representa a espera na fila. Contadores são de unidades da etapa quando disponíveis, não porcentagens estimadas nem prova de exploração. A UI consulta o progresso e oferece o relatório real apenas após conclusão. Erros têm mensagens e ações de recuperação; nunca são apresentados como relatórios vazios seguros.

Códigos estáveis: invalid_url, private_or_missing, network, too_large, unsupported_no_manifests, rate_limit e repository_cap. Sem manifesto suportado com versões exatas, a análise falha explicitamente. Os formatos atuais continuam package-lock.json v2/v3 e requirements.txt com pins exatos; não se infere suporte a Poetry/Pipfile. Content-Length acima do limite interrompe antes da leitura; sem ele, o stream é abortado ao exceder o orçamento. Limites do snapshot: 32 MiB transferidos, 64 MiB descompactados e 30.000 entradas; refs têm orçamento separado de 4 MiB. Há duas tabelas aditivas e idempotentes: scan_progress e public_registration_attempts. Sem mudança na classificação de alcance, nos modos demo/live ou na política de fontes npm.

Exemplo local, sem presets:

~~~sh
SCA_MODE=public SCA_DASHBOARD_TOKEN='<token-do-operador-com-pelo-menos-32-caracteres>' \
SCA_PUBLIC_ORIGIN=http://127.0.0.1:8012 SCA_DATABASE_PATH=./public-byurl.sqlite3 \
  .venv/bin/python -m sca_reachability.server.cli --port 8012
~~~

Piloto defensivo para um operador responsável pelas instalações explicitamente autorizadas. Não é autenticação SaaS multi-tenant. O CLI offline continua independente de FastAPI e de rede.

## Instalação e demonstração

Python 3.11 ou superior:

```sh
python -m venv .venv
.venv/bin/python -m pip install '.[server]'
SCA_MODE=demo SCA_DATABASE_PATH=./demo.sqlite3 .venv/bin/sca-reachability-serve --host 127.0.0.1 --port 8000
```

Entre com `local-demo`. Esse token é público, exclusivo de demonstração local e nunca aceito no modo live. A instalação 9001 e o repositório 9002 são fictícios. Main vem selecionada; develop e release são opções. A análise inicial usa o mesmo pipeline que os novos jobs. O pacote fictício npm 1.0.0 corresponde a DEMO-0001; release usa 1.1.0 e não corresponde. Não são vulnerabilidades reais. Simular push gera um payload local assinado e percorre a mesma validação HMAC, ingestão e fila; branch não selecionada é ignorada.

Demo não instancia provedor de IA, mesmo com variáveis de IA acidentalmente presentes, nem clientes externos GitHub/OSV. Nenhum push ou instalação de aplicativo real é realizado.

Para previews demo ou public acessados por um proxy local do desktop, habilite explicitamente `SCA_ALLOW_LOOPBACK_ORIGINS=1` junto com `SCA_MODE=demo` ou `SCA_MODE=public`. Além de `SCA_PUBLIC_ORIGIN`, login e mutações passam a aceitar origens HTTP/HTTPS com host exatamente `localhost`, `127.0.0.1` ou `[::1]`, em qualquer porta válida. A opção vem desabilitada; em live, habilitá-la impede a inicialização. Origin e `X-SCA-Request: 1` continuam obrigatórios no login e nas mutações por sessão, sem confiar em `X-Forwarded-*`. Não há CORS amplo. O cookie demo não tem Domain nem Secure (funciona em HTTP local); mantém HttpOnly, SameSite=strict e Path=/api. Os cookies live e public continuam Secure.

## Configuração live

Live é o padrão. O servidor inicia sem credenciais, mas sincronização e serviços indisponíveis retornam 503. Sem token válido não há acesso às APIs protegidas. A allowlist vazia nega todas as instalações. Exemplo com **placeholders, não credenciais**:

```sh
export SCA_MODE=live
export SCA_DATABASE_PATH=/private/sca/server.sqlite3
export SCA_DASHBOARD_TOKEN='<gere-um-token-aleatorio-com-pelo-menos-32-caracteres>'
export SCA_ALLOWED_INSTALLATION_IDS='<ids-numericos-autorizados-separados-por-virgula>'
export SCA_GITHUB_APP_ID='<id-do-seu-app>'
export SCA_GITHUB_PRIVATE_KEY_PATH='/private/sca/github-app.pem'
export SCA_GITHUB_WEBHOOK_SECRET='<segredo-aleatorio-do-webhook>'
export SCA_PUBLIC_ORIGIN='https://sca.example.invalid'
sca-reachability-serve --host 127.0.0.1 --port 8000
```

O operador deve criar/configurar e instalar seu próprio GitHub App somente nos repositórios autorizados. Permissões: **Metadata: read** e **Contents: read**, sem escrita. Eventos: `installation`, `installation_repositories`, `push`. Webhook: `POST /api/webhooks/github`, content type JSON, mesmo segredo configurado no servidor. Este projeto não cria nem instala apps automaticamente.

Use HTTPS com proxy confiável em live. Configure SCA_PUBLIC_ORIGIN com a origem pública exata, inclusive porta se aplicável; isto atende também proxies autenticados. O cookie live tem Secure e não funciona em HTTP simples. O padrão de bind é loopback. Não há CORS amplo. Não confie em headers de proxy vindos diretamente da internet.

## Sessões e API

### Repositórios públicos sem GitHub App

```sh
export SCA_MODE=public
export SCA_PUBLIC_REPOSITORIES='OWASP/NodeGoat'
export SCA_DASHBOARD_TOKEN='<token-aleatorio-com-pelo-menos-32-caracteres>'
export SCA_PUBLIC_ORIGIN='http://127.0.0.1:8010'
export SCA_DATABASE_PATH='./public.sqlite3'
.venv/bin/sca-reachability-serve --port 8010
```

Após login, sincronize instalações e dispare a análise da branch padrão (selecionada inicialmente). A instalação sintética 9003, “Repositórios públicos”, contém somente os nomes configurados. `SCA_PUBLIC_REPOSITORIES` aceita até dez entradas estritas `owner/name`; vazio deixa GitHub não configurado. IDs sintéticos de repositório são estáveis. O token segue a regra live; nenhuma credencial GitHub é necessária. IA permanece desabilitada neste modo. `/api/meta` informa `public` e configuração real; os scans usam source `github` por compatibilidade com SQLite. Webhooks e `/api/demo/push` retornam 404. Para proxies locais do desktop, public também aceita a opção explícita `SCA_ALLOW_LOOPBACK_ORIGINS=1`; live continua rejeitando-a na inicialização.

Não há chamadas a api.github.com: branches, HEAD simbólico e SHA vêm do anúncio smart HTTP de refs; o snapshot vem de codeload no SHA exato. Download máximo de 32 MiB comprimidos; tar descomprimido (inclusive headers) de até 64 MiB e 30.000 entradas. Tudo permanece em memória: nenhum arquivo monitorado é gravado, executado, instalado ou importado. Apenas um commit fica no cache; blobs recebem SHA Git real. Symlinks/hardlinks não são seguidos e viram entradas 120000, sinalizadas como lacuna pelo pipeline. Caminhos inseguros, arquivos especiais, limites excedidos e snapshots inválidos falham explicitamente, nunca geram resultado “seguro”. Redirects HTTPS são aceitos somente para github.com/codeload.github.com, no máximo três saltos. Rede pública pode falhar ou limitar tráfego; não há garantia de disponibilidade. Reachability e evidências seguem o mesmo worker estático; unknown nunca significa seguro e IA não altera classificação.

O cookie public mantém Secure, HttpOnly, SameSite=strict e Path=/api, como live, sem atributo Domain. Com a opção de loopback habilitada, o Chrome armazenou o cookie Secure em `http://localhost:8011` (contexto seguro) e o enviou automaticamente em leitura autenticada e logout. Não foi necessário remover Secure. O TestClient/HTTPX não implementa essa exceção de localhost: o teste HTTP repassa o cookie explicitamente para validar a proteção do servidor; a aceitação automática foi conferida no Chrome. Use HTTPS fora do ambiente local.

O dashboard identifica GitHub público, oferece Analisar agora, links OSV e links de commit/arquivo/linha fixados no SHA. Relatórios públicos têm filtros por alcance com contagens e páginas de dez achados, alcançáveis primeiro; evidências começam recolhidas.

As cargas `require(path.resolve(__dirname + "/../config/env/..."))` do NodeGoat são reconhecidas como caminhos locais, inclusive com seleção dinâmica de ambiente. Elas geram notas visíveis, não incerteza sobre nomes de pacotes. Isso não resolve o ambiente de execução nem analisa código transitivo de dependências: inalcançável continua limitado aos fontes coletados naquele commit, nunca é um selo de segurança.

A ausência de importação direta não prova que uma dependência transitiva é inalcançável: por exemplo, body-parser é importado em server.js:5 e pode usar qs internamente. Esses casos exigem revisão e permanecem desconhecidos; o código dos pacotes intermediários não foi analisado.

`GET /api/meta` é público e revela somente modo e booleanos de configuração. Login `POST /api/session` recebe `{"token":"..."}`, requer Origin da própria origem e `X-SCA-Request: 1`, responde 200 `{"authenticated":true}`. O cookie opaco é HttpOnly, SameSite=strict, expira em oito horas e só seu SHA-256 é persistido. Logout `DELETE /api/session` responde 204 e revoga o hash. Todas as demais APIs, exceto webhook, exigem bearer token ou sessão. Mutações por cookie exigem o mesmo header e validação de Origin; bearer não substitui a allowlist.

Principais rotas (listas usam `{"items":[...]}`):

- GET /api/installations; POST /api/installations/sync.
- GET /api/installations/{id}/repositories.
- GET/PUT /api/installations/{id}/repositories/{repo_id}/branches. PUT recebe `{"branches":["main"]}`; nomes existentes exatos, máximo 20; lista vazia pausa o monitoramento.
- POST /api/installations/{id}/repositories/{repo_id}/scan recebe `{"branch":"main"}`, resolve o SHA atual e retorna 202 com scan_id e status queued.
- GET /api/scans (filtros installation_id/repository_id, até 100 recentes) inclui advisory_ids e package_names distintos para busca local; GET /api/scans/{id} inclui componentes, achados, avisos e explicação salva.
- POST /api/scans/{id}/retry reenfileira somente uma análise falha autorizada, no mesmo commit e branch ainda monitorada. A tentativa explícita usa um novo job, com até três tentativas automáticas, sem duplicar o scan.
- GET /api/deliveries inclui o resultado imutável do evento e scan_id/scan_status atual quando associado; GET /api/dashboard. Achados do dashboard consideram a análise completa mais recente de cada branch, sem somar repetições históricas.
- POST /api/demo/push recebe repository_id numérico/branch salva e selecionada, exige autenticação/CSRF e existe somente em demo. Meta informa github_configured:false; a conexão é simulada.

## Processamento, armazenamento e limites

HMAC SHA-256 é comparado em tempo constante sobre bytes originais. Headers, assinatura e formato são validados antes de persistir. Delivery ID único com o mesmo digest é duplicata; com digest diferente retorna 409. Delivery e enqueue são atômicos. Instalação ativa/allowlisted, associação real repo/instalação, ref de branch, SHA de 40 hex e seleção exata são revalidados. Tags, exclusões e branches não selecionadas ficam ignoradas com motivo de auditoria. Um SHA por instalação/repositório/branch gera somente um scan.

SQLite guarda metadados, seleções, hashes de sessões/deliveries, fila e resultados, não tokens GitHub, chave privada, manifests ou payloads completos. O diretório novo usa permissão 0700 e o arquivo 0600. Proteja backups e volumes; permissões do SO não equivalem a criptografia. Arquivos .sqlite3 e .env estão ignorados no Git. A fila usa transações, leases renovadas, recuperação de leases expiradas, até três tentativas para erros transitórios e backoff de 2/4 segundos. Um worker em thread atende o piloto; não é um serviço distribuído de alta disponibilidade. Revogação/suspensão/remoção apaga seleção, cancela jobs e nega histórico fora de escopo; o worker revalida antes de buscar e salvar.

Limite de request: 64 KiB (webhook 1 MiB, contado durante leitura). Rate limit em memória por endereço/minuto: 120 APIs, 10 logins, 600 webhooks. Não é rate limit distribuído. Clientes externos têm timeouts, limites de resposta/paginação e não seguem redirects. Tokens GitHub ficam apenas em memória e são limpos em revogação.

O inventário resolve commit/tree por SHA fixado, rejeita tree truncada e lê somente blobs package-lock.json npm v2/v3 e requirements.txt com um pin == exato. Máximos: 50 manifests, 2 MiB cada, 5000 componentes. Symlinks/submodules não são seguidos; entradas URL/VCS/opções pip e versões não fixadas são ignoradas com avisos. Marcadores Python não são avaliados: pins são incluídos conservadoramente com aviso. Ausência de manifests ou cobertura parcial nunca é apresentada como projeto seguro.

OSV recebe somente nome/ecossistema/versão exatos, em batches de até 100 (sem enviar PURL versionado junto da versão). Detalhes vêm de /v1/vulns/{id}; correções são extraídas somente do pacote correspondente. Erros, contagem desalinhada ou paginação pendente falham explicitamente em vez de produzir resultado limpo. Reachability permanece unknown. Nenhum código monitorado é instalado, clonado, executado ou explorado.

## IA opcional e verificação

`pip install '.[server,ai]'` instala o SDK opcional OpenAI >=1.68.2,<3. Somente live com SCA_AI_ENABLED=true, SCA_AI_API_KEY e SCA_AI_MODEL cria provedor no startup. O worker calcula e salva explicação uma vez por scan; leitura não faz requests. Falhas mantêm fallback determinístico e não alteram achados. Somente IDs públicos CVE/GHSA validados, contagens e enums limitados atravessam o sanitizer; nomes/versões/caminhos/prosa de pacotes não são enviados. O provedor é fechado no shutdown. Ver docs/ai-explanations.md.

```sh
python -m pip install '.[server]'
python -m unittest discover -s tests -v
python -m pip install build==1.6.1
python -m build
```

Testes backend usam banco temporário, adapters fake e httpx.MockTransport; bloqueiam transporte HTTP externo. A demonstração não valida credenciais nem instalação GitHub reais. Limitações deliberadas: dois formatos de manifest, sem análise estática de alcance, sem execução de código, sem publicação de alertas, sem garantias empresariais ou conclusão “seguro”.

## Static reachability

After correlation, the worker reads (never executes, installs, or imports) up to a bounded number of `.js/.jsx/.mjs/.cjs/.ts/.tsx` and `.py` blobs from the scanned commit and runs `sca_reachability.static_reachability`:

- **reachable**: the package is imported and the advisory's vulnerable symbol (OSV `affected_functions`/`imports[].symbols`) is called, or the package is called when the advisory names no symbol.
- **unreachable**: sources cover the manifest and the package is never imported, or it is imported but the vulnerable symbol is never called. npm additionally requires the lockfile graph checks below. Valid only for that commit and the analyzer's coverage, never a guarantee of safety.
- **unknown**: dynamic `import()`/`require()`/`importlib`/`getattr`, indirect references, parse errors, star imports, or incomplete coverage (limits, symlinks, non-UTF-8, unavailable blobs). Unknown is never presented as safe.

Each finding stores up to 6 evidence items (`path`, `line`, `kind`, `detail`, `snippet`) in `reachability_evidence` plus `reachability_analysis` (files scanned, language, granularity, symbols). Existing databases migrate automatically.

### Contexto e cargas locais

`reachability_scope` na API é `production`, `test_only` ou `dev_tooling`. É um contexto inferido, não comprovação de execução/deploy: considera primeiro os caminhos das chamadas (senão, importações; sem ambas, contexto do manifesto). Diretórios test/tests/__tests__/spec, arquivos *.test.*/*.spec.* e convenções Python test_*.py/*_test.py identificam testes; Gruntfile/gulpfile/webpack e scripts/build/configurações de ferramentas identificam tooling. Uma chamada de produção prevalece sobre chamadas de teste, mas `dev: true` na entrada package-lock impede rotulá-la como dependência de produção. Isso não muda reachable/unreachable/unknown. Evidências de produção são priorizadas antes do limite de seis itens.

O contexto, a flag `dependency_dev` e até seis notas `local_load` ficam no JSON `reachability_analysis` já persistido pelo worker, sem nova coluna ou migração. Relatórios antigos sem esse contexto continuam não informados, nunca são promovidos a produção. Listagens incluem `reachability_scope_counts` apenas de alcançáveis; `unreported` conta os legados. Dashboard, próximos passos e filtros separam produção de testes/ferramentas; desconhecido continua exigindo revisão.

No JavaScript, concatenações/templates com prefixo local fixo (`./`, `../`, `/`, `__dirname`, `__filename`) e path.resolve com base local fixa não bloqueiam prova negativa por si sós. path.join aceita bases absolutas ou que preservem `../`: `path.join("./config", nome)` normaliza para um possível nome de pacote e **continua desconhecido**. Prefixos contendo node_modules, bases variáveis, expressões condicionais/operadores não comprovados e outras cargas dinâmicas continuam incerteza. Lacunas de cobertura ainda impedem inalcançável; notas não as suprimem. Python mantém o tratamento conservador anterior de importações dinâmicas.

### Dependências npm diretas e transitivas

As declarações dependencies/devDependencies/optionalDependencies/peerDependencies de `packages[""]` identificam as entradas diretas, resolvidas no node_modules da raiz. Outra versão aninhada do mesmo nome continua transitiva. Para cada pacote, o grafo lê dependencies e também optionalDependencies/peerDependencies, resolvendo cada nome pelo node_modules mais próximo e subindo os diretórios. Não usa devDependencies dos pacotes intermediários. Todo pin requirements.txt permanece direto, sem inferir grafo Python.

Uma transitiva só recebe inalcançável se o grafo estiver completo e todos os ancestrais diretos, por qualquer caminho, não forem importados com cobertura completa e sem incerteza bloqueante; a própria transitiva também não pode ter uso/importação ou incerteza nos fontes. Uma declaração direta também não permite ignorar seu uso por outro ancestral direto importado. Grafo ausente, órfãos, dependências não resolvidas, entradas não suportadas ou limites excedidos produzem desconhecido, nunca uma prova negativa. Limites: 5.000 nós, 50.000 arestas/visitas e 32 nomes por caminho. Ciclos são tratados com conjuntos de visitados; guarda-se um caminho curto por ancestral direto, sem perder ancestrais que chegam por outras rotas.

Não se infere alcançável por transitividade. Uma importação direta do ancestral gera desconhecido com nota visível e evidência da importação; fontes que citam a própria transitiva também não comprovam sua versão instalada. `dependency_relation` e `dependency_via` são expostos no achado e persistidos no JSON de análise, junto de `lock_path`, `dependency_graph_complete`, `dependency_note` e `transitive_imported_via`. Sem migração adicional. Dados legados sem relação ficam não informados. O filtro “Transitivas · import/CLI” e `transitive_imported_unknown_count` nas listagens tornam esse subconjunto dos desconhecidos legível; ele não significa seguro.

A auditoria manual também identificou entradas de ferramentas que não usam require: `grunt.loadNpmTasks("pacote")` conta como importação estática; nome dinâmico bloqueia prova negativa. O coletor lê package.json em memória apenas como metadado de scripts (não instala nem executa nada). Na análise inicial, referências nos scripts aos nomes dos pacotes ou aliases bin do lockfile geram desconhecido e evidência `entrypoint`/`transitive_entrypoint`, nunca alcançável por si sós. A etapa pública de fontes npm descrita abaixo pode decidir entradas determinísticas com evidência adicional. O subconjunto transitive_imported_via inclui essas entradas CLI, explicitamente distintas de importações nas notas. Scripts dinâmicos, referências npm run/exec/npx não resolvidas e JSON inválido também bloqueiam prova negativa. Ausência de uso continua limitada aos fontes e entradas estáticas modeladas, não ao que alguém pode executar externamente.

Validação de NodeGoat no SHA `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`: 437 achados, 13 alcançáveis em produção, 1 só em testes, 0 inalcançáveis diretos, 11 inalcançáveis transitivos, 407 desconhecidos transitivos via importação/CLI e 5 outros desconhecidos. Async@2.6.1 passou de teste-alcançável para desconhecido porque é transitivo e a resolução da versão citada pelos fontes não foi comprovada. O contexto test_only foi preservado.

### Fontes npm e caminhos transitivos (modo public)

Depois da análise do repositório, o worker público pode decidir transitivas usando os tarballs `resolved` do lockfile. Somente HTTPS em registry.npmjs.org, sem credenciais, query, porta alternativa ou redirecionamentos. Valida SRI sha512 ou sha1 quando presente (prefere sha512); sem integrity, registra/cacheia o conteúdo pelo SHA-512 calculado, sem afirmar verificação contra um hash esperado. Confere nome e versão do package.json. O cache é somente em memória e por análise, indexado pelo conteúdo/integrity validada, nunca instala nem importa código.

Limites por análise: 150 downloads tentados, 64 MiB transferidos, 128 MiB de conteúdo extraído. Por pacote: 4 MiB comprimidos, 16 MiB descompactados, 3.000 entradas; arquivos de código até 512 KiB. Reutiliza a validação de tarballs do adaptador público, com limites menores: caminhos relativos seguros, raiz única, rejeição de entradas especiais e duplicadas; links não são seguidos e impedem prova negativa. Não escreve os arquivos analisados em disco.

O specifier original do pai escolhe o subpath. Sem subpath usa exports (condições require/import, node/default) ou main/index.js. Exports curinga/arrays e entradas não resolvidas permanecem desconhecidos. Segue requires/imports relativos estáticos a partir dessa entrada e registra arquivo/linha de cada salto; um caminho completo pode produzir **reachable no nível de importação**, inclusive quando o aviso informa símbolos. Isso não significa que um símbolo vulnerável foi chamado, nem comprova execução ou exploração. O contexto vem da evidência raiz, com prioridade para produção.

Para uma nova prova negativa, examina todos os fontes do pacote, não só os alcançados pela entrada, e todos os caminhos ancestrais do grafo. Qualquer carga dinâmica, arquivo omitido, importação fora da entrada, bin/scripts, lacuna do repositório, ciclo/limite ou ancestral Grunt/CLI não modelado mantém desconhecido. Entradas Grunt/CLI não são presumidas equivalentes a main; não inventa uma entrada para elas. Limites adicionais: 16 pacotes por caminho, 512 caminhos por componente, 800 arquivos alcançados e 64 etapas de evidência. Provas negativas anteriores também são reavaliadas quando novas entradas ou ambiguidades impedem comprovar cobertura completa.

`reachability_analysis` persiste `transitive_path` (package/version/file/line/specifier/kind/url), `transitive_decided`, `transitive_unknown_reason` e granularity=import, sem alteração de esquema. Hops de entrada têm line=null, pois não são uma chamada inventada na linha 1. API de detalhe e listagem incluem `transitive_summary` com decided/reachable/unreachable e unknown_reasons. Links npm abrem o código da versão exata, sem alegar um permalink de linha que o site não oferece. O dashboard mostra uma sequência vertical responsiva e o filtro “Via caminho transitivo”. Demo/live e requirements Python não consultam o registry nem mudam de semântica.

Nova validação pública do mesmo commit NodeGoat: 437 achados, 25 alcançáveis em produção, 37 só em testes, 11 inalcançáveis e 364 desconhecidos. Foram decididos 48 achados transitivos (12 produção + 36 testes), todos por importação; nenhuma nova prova negativa. Restaram 348 transitivos desconhecidos por entradas CLI/Grunt ou ancestrais sem importação literal modelada, 9 por cargas dinâmicas/cobertura de pacote e 2 por limite de bytes, além de 5 outros desconhecidos. Exemplo: server.js:5 → body-parser@1.18.3/index.js:151 → lib/types/urlencoded.js:225 → qs@6.5.2/lib/index.js. A linha 225 contém o require dentro de uma função: o caminho é uma afirmação estática de importação, não execução dessa função. Uma primeira execução revelou retrocesso exponencial na detecção de regex; a análise agora usa repetição possessiva e tem regressão com prazo limitado em subprocesso.

### Entradas determinísticas Grunt e npm

Comportamento conferido em `grunt@1.0.3/lib/grunt/task.js`, funções `loadNpmTasks`/`loadTasks`: uma chamada literal no Gruntfile.js resolve o diretório tasks do pacote e carrega cada JS de primeiro nível, não o main nem subdiretórios. Cada arquivo é uma entrada independente com contexto dev_tooling. CoffeeScript, coleções gruntcollection recursivas, pacotes ausentes e chamadas não literais continuam bloqueando provas negativas; comentários/regex não criam entradas. Não modela execução de configurações ou despacho de tarefas pelo Grunt.

Scripts do package.json do repositório aceitam invocações simples e separação conservadora por &&/;. Expansões, pipes, redirecionamentos, atribuições shell, quoting ambíguo e outros comandos não modelados não viram entradas positivas. Resolve o bin declarado por um único pacote direto/hoisted no lockfile e confirma seu destino no package.json do tarball: bin string ou objeto, inclusive entradas Node sem extensão. Também aceita node node_modules/... quando corresponde exatamente a um bin declarado. Não adivinha vencedores de colisões em .bin nem interpreta wrappers como execução automática dos seus argumentos. Apenas scripts de nome test herdam test_only; os demais recebem dev_tooling. Os primeiros hops persistem kind/label e são exibidos como “Gruntfile” ou “script npm · scripts.nome”.

Validação do mesmo NodeGoat: **437 achados, 25 alcançáveis em produção, 41 só em testes, 73 em ferramentas, zero inalcançáveis e 298 desconhecidos**. Agora 125 achados transitivos têm caminho positivo, contra 48 anteriormente: 77 decisões adicionais, sem nova prova negativa. Onze antigas negativas passaram a desconhecido: o Gruntfile referencia grunt-nodemon, ausente do lockfile, e scripts.precommit tem um bin grunt declarado por grunt e grunt-cli; essas entradas não modeladas invalidam a cobertura necessária para ausência de uso.

Motivos primários dos 293 desconhecidos transitivos: 119 archive, 69 host, 57 CLI/ancestral sem import literal modelado, 29 carga dinâmica/cobertura, 11 entrada ambígua/não resolvida e 8 limite de arquivo; mais 5 outros desconhecidos. A verificação direta encontrou npm@3.10.10 acima de 3.000 entradas do tarball e grunt-if@0.2.0 com resolved em github.com, host não permitido. Limites e política de hosts não foram relaxados. Exemplo Grunt: Gruntfile.js:151 → grunt-retire@0.3.12/tasks/retire.js:13 → request@2.67.0/index.js. Exemplo npm: package.json scripts.dev → cross-env@7.0.2/src/bin/cross-env.js:3 → src/index.js:1 → cross-spawn@7.0.3/index.js. Continuam sendo caminhos estáticos de importação, não execução ou exploração.

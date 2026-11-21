# Backend de monitoramento de branches

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

Para previews demo acessados por um proxy local do desktop, habilite explicitamente `SCA_ALLOW_LOOPBACK_ORIGINS=1` junto com `SCA_MODE=demo`. Além de `SCA_PUBLIC_ORIGIN`, login e mutações passam a aceitar origens HTTP/HTTPS com host exatamente `localhost`, `127.0.0.1` ou `[::1]`, em qualquer porta válida. A opção vem desabilitada; em live, habilitá-la impede a inicialização. Origin e `X-SCA-Request: 1` continuam obrigatórios no login e nas mutações por sessão, sem confiar em `X-Forwarded-*`. Não há CORS amplo. O cookie demo não tem Domain nem Secure (funciona em HTTP local); mantém HttpOnly, SameSite=strict e Path=/api. O cookie live continua Secure.

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

Após login, sincronize instalações e dispare a análise da branch padrão (selecionada inicialmente). A instalação sintética 9003, “Repositórios públicos”, contém somente os nomes configurados. `SCA_PUBLIC_REPOSITORIES` aceita até dez entradas estritas `owner/name`; vazio deixa GitHub não configurado. IDs sintéticos de repositório são estáveis. O token segue a regra live; nenhuma credencial GitHub é necessária. IA permanece desabilitada neste modo. `/api/meta` informa `public` e configuração real; os scans usam source `github` por compatibilidade com SQLite. Webhooks e `/api/demo/push` retornam 404. A opção de origens loopback continua exclusiva de demo.

Não há chamadas a api.github.com: branches, HEAD simbólico e SHA vêm do anúncio smart HTTP de refs; o snapshot vem de codeload no SHA exato. Download máximo de 32 MiB comprimidos; tar descomprimido (inclusive headers) de até 64 MiB e 30.000 entradas. Tudo permanece em memória: nenhum arquivo monitorado é gravado, executado, instalado ou importado. Apenas um commit fica no cache; blobs recebem SHA Git real. Symlinks/hardlinks não são seguidos e viram entradas 120000, sinalizadas como lacuna pelo pipeline. Caminhos inseguros, arquivos especiais, limites excedidos e snapshots inválidos falham explicitamente, nunca geram resultado “seguro”. Redirects HTTPS são aceitos somente para github.com/codeload.github.com, no máximo três saltos. Rede pública pode falhar ou limitar tráfego; não há garantia de disponibilidade. Reachability e evidências seguem o mesmo worker estático; unknown nunca significa seguro e IA não altera classificação.

O cookie public mantém Secure, HttpOnly, SameSite=strict e Path=/api, como live. Login e envio do cookie Secure foram verificados no Chrome via `http://127.0.0.1:8010`; não foi necessário remover Secure. Use HTTPS fora do ambiente local.

O dashboard identifica GitHub público, oferece Analisar agora, links OSV e links de commit/arquivo/linha fixados no SHA. Relatórios públicos têm filtros por alcance com contagens e páginas de dez achados, alcançáveis primeiro; evidências começam recolhidas.

As cargas `require(path.resolve(__dirname + "/../config/env/..."))` do NodeGoat são reconhecidas como caminhos locais, inclusive com seleção dinâmica de ambiente. Elas geram notas visíveis, não incerteza sobre nomes de pacotes. Isso não resolve o ambiente de execução nem analisa código transitivo de dependências: inalcançável continua limitado aos fontes coletados naquele commit, nunca é um selo de segurança.

Nova validação de OWASP/NodeGoat, master no SHA `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`: 1.479 componentes, 437 achados — 13 alcançáveis em produção, 2 só em testes, 418 inalcançáveis e 4 desconhecidos. Os 15 alcançáveis anteriores continuam alcançáveis; 418 desconhecidos deixaram de ser bloqueados pelas duas cargas locais. Os quatro restantes são entradas de underscore importado sem chamada reconhecida e sem símbolo vulnerável no aviso. Exemplo de produção: body-parser@1.18.3, GHSA-27r3-jxmh-p828, importado em server.js:5 e chamado em server.js:71–72. É evidência no nível do pacote, não prova de exploração.

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
- **unreachable**: sources cover the manifest and the package is never imported, or it is imported but the vulnerable symbol is never called. Valid only for that commit and the analyzer's coverage.
- **unknown**: dynamic `import()`/`require()`/`importlib`/`getattr`, indirect references, parse errors, star imports, or incomplete coverage (limits, symlinks, non-UTF-8, unavailable blobs). Unknown is never presented as safe.

Each finding stores up to 6 evidence items (`path`, `line`, `kind`, `detail`, `snippet`) in `reachability_evidence` plus `reachability_analysis` (files scanned, language, granularity, symbols). Existing databases migrate automatically.

### Contexto e cargas locais

`reachability_scope` na API é `production`, `test_only` ou `dev_tooling`. É um contexto inferido, não comprovação de execução/deploy: considera primeiro os caminhos das chamadas (senão, importações; sem ambas, contexto do manifesto). Diretórios test/tests/__tests__/spec, arquivos *.test.*/*.spec.* e convenções Python test_*.py/*_test.py identificam testes; Gruntfile/gulpfile/webpack e scripts/build/configurações de ferramentas identificam tooling. Uma chamada de produção prevalece sobre chamadas de teste, mas `dev: true` na entrada package-lock impede rotulá-la como dependência de produção. Isso não muda reachable/unreachable/unknown. Evidências de produção são priorizadas antes do limite de seis itens.

O contexto, a flag `dependency_dev` e até seis notas `local_load` ficam no JSON `reachability_analysis` já persistido pelo worker, sem nova coluna ou migração. Relatórios antigos sem esse contexto continuam não informados, nunca são promovidos a produção. Listagens incluem `reachability_scope_counts` apenas de alcançáveis; `unreported` conta os legados. Dashboard, próximos passos e filtros separam produção de testes/ferramentas; desconhecido continua exigindo revisão.

No JavaScript, concatenações/templates com prefixo local fixo (`./`, `../`, `/`, `__dirname`, `__filename`) e path.resolve com base local fixa não bloqueiam prova negativa por si sós. path.join aceita bases absolutas ou que preservem `../`: `path.join("./config", nome)` normaliza para um possível nome de pacote e **continua desconhecido**. Prefixos contendo node_modules, bases variáveis, expressões condicionais/operadores não comprovados e outras cargas dinâmicas continuam incerteza. Lacunas de cobertura ainda impedem inalcançável; notas não as suprimem. Python mantém o tratamento conservador anterior de importações dinâmicas.

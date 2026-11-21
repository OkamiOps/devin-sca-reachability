# Painel do SCA Reachability

Interface em português, sem dependências de runtime ou etapa de build. Os arquivos
fonte em `src/sca_reachability/static/` são servidos pelo backend no mesmo domínio:
`/`, `/app.js`, `/model.js` e `/styles.css`. Não há CDNs, fontes remotas, tokens
embutidos ou dados fictícios de fallback no frontend.

## Fluxo humano

1. O painel lê `/api/meta` para identificar o ambiente e pede o token **do painel**,
   não um token pessoal do GitHub. A sessão usa um cookie HttpOnly do serviço.
2. O usuário escolhe uma instalação ativa e um repositório autorizado.
3. Seleciona branches, revisa o contador de alterações e salva. Desmarcar todas
   pausa novas análises por webhook sem apagar o histórico.
4. Pode iniciar uma análise manual de uma branch salva, ou aguardar um push.
   No ambiente de demonstração, há um botão explicitamente sintético de simulação.
5. Consulta as execuções por repositório, estado, branch ou commit; abre o relatório
   para revisar achados, componentes, limitações e uma explicação separada.
6. Consulta a atividade de webhook para distinguir evento recebido de análise
   efetivamente concluída. Pode encerrar a sessão com “Sair”.

## Contrato de integração

- `GET /api/meta`: `{mode: 'demo'|'live', github_configured, ai_configured}`.
- `POST /api/session`: `{token}`; `DELETE /api/session` encerra o cookie.
- `GET /api/dashboard`: contadores globais, `last_scan_at`, `mode`.
- `GET /api/installations`: `{items: [{id, account, status}]}`.
- `POST /api/installations/sync`: sincronização de inventário, somente modo real.
- `GET /api/installations/{id}/repositories`: `{items: [{id, full_name,
  default_branch, selected_branches, last_scan_at}]}`.
- `GET /api/installations/{id}/repositories/{repo}/branches`:
  `{items: [{name, selected}]}`; `PUT` recebe `{branches: string[]}`.
- `POST /api/installations/{id}/repositories/{repo}/scan`: `{branch}`;
  retorna `{scan_id, status}`.
- `GET /api/scans?installation_id=...&repository_id=...`: `{items: [...]}`.
- `GET /api/scans/{id}`: execução com `components`, `findings`, `warnings`,
  `explanation: {status, text, source}` conforme contrato do backend.
- `GET /api/deliveries`: `{items: [...]}`.
- `POST /api/demo/push`: `{repository_id, branch}`, apenas em demonstração.

Todas as chamadas usam `credentials: 'same-origin'`. Mutações levam
`X-SCA-Request: 1`. Os caminhos são codificados e nunca incluem tokens.
Erros HTTP não expõem diagnósticos internos do provedor na interface.

## Estados e limites

- **Demonstração:** identificada no cabeçalho, no aviso de ambiente, nas tabelas e
  no relatório. O token público `local-demo` só é sugerido quando o serviço declara
  explicitamente `mode: 'demo'`. Dados vêm da API, inclusive a simulação.
- **Real:** sem fallback para amostras se a conexão falhar. A interface não afirma
  saúde contínua do GitHub apenas porque há configuração presente.
- **IA:** texto simples escapado, nunca HTML/Markdown executável, apresentado
  separadamente dos achados. Resumo determinístico não é rotulado como IA.
- **Alcance:** usa o campo técnico do serviço. Desconhecido não é inalcançável;
  zero achados não é um atestado de segurança.
- **Atualização:** consulta automática a cada 15 segundos com a aba visível.
  Preserva a edição das branches e não destrói o foco de controles ativos.
- **Falhas:** sem sucesso otimista em salvamento; seleção permanece em edição
  após falha. Respostas atrasadas de outro escopo não substituem os dados atuais.
- **Acessibilidade:** controles nativos rotulados, navegação por teclado, foco
  visível, diálogo modal com Escape, status anunciados, link de salto e tema claro/
  escuro. Layout responsivo sem dependência de fontes externas.

## Verificação local

O backend é responsável por servir assets e configurar `setuptools.package-data`.
Apenas abrir `index.html` como arquivo não conecta a interface à API.

Testes puros de apresentação e segurança de saída (Node 20 ou superior, somente
desenvolvimento):

```sh
node --test tests/dashboard-model.test.mjs
node --input-type=module --check < src/sca_reachability/static/app.js
```

Os testes de integração/browser devem usar o serviço real no modo de demonstração,
claramente identificado. Não são prova de conexão ao GitHub nem a um provedor de IA.

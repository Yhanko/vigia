# Vigia — Plano de Tarefas, Segurança e Progresso

> **Versionado no Git** (o histórico mostra quem marcou cada tarefa e quando). Espelho operacional do [README.md](./README.md): cada tarefa aponta para a secção (`§`) que a origina. Serve para acompanhar o progresso e a **blindagem de segurança obrigatória** em cada fase até cobrir toda a plataforma.
>
> **Regra de manutenção:** quando o README mudar, este ficheiro muda no mesmo commit de trabalho; quando uma tarefa revelar uma decisão nova, ela vai para um ADR (§24) e o README é actualizado.

**Equipa:** CEO (decisões de produto, negócio, custos e legais) · CTO/Tech Lead: Claude (arquitectura, prioridades, revisão) · Desenvolvedor: Gemini (execução das tarefas).

**Como o desenvolvedor trabalha com este ficheiro:**
1. Pegar **sempre a primeira tarefa `[ ]` da fase activa** (ver "Próximos passos"), nunca saltar fases.
2. Todas as tarefas são feitas na branch **`development`**, em commits pequenos e com testes; só se publica no GitHub depois da aprovação do CTO, e o código segue `development → staging → main` (fluxo no [GEMINI.md](./GEMINI.md) §6). Marcar `[~]` ao começar e `[x]` só quando o **Security Gate** e a **DoD** estiverem cumpridos e o CI verde.
3. Tarefas marcadas **🧭 CTO** precisam de revisão do CTO antes do merge (segurança, contratos públicos, dinheiro). Tarefas marcadas **👔 CEO** são decisões ou acções do CEO, não de código.
4. Se uma tarefa estiver ambígua ou em conflito com o README, **parar e perguntar** em vez de adivinhar.
5. Antes de cada tarefa, reler a secção **"👨‍💻 Padrão de engenharia exigido"** abaixo; antes de cada PR, cumprir a **checklist pré-PR**.
6. As regras permanentes do desenvolvedor (leitura obrigatória, relatório diário) estão no [GEMINI.md](./GEMINI.md).

---

## 🚦 Fase activa e porta de fase

> **FASE ACTIVA: 1 — Fundação do Backend** *(aberta em 2026-11-26: porta da Fase 0 aprovada pelo CTO e autorizada pelo CEO)*
> *(só o CTO, com autorização do CEO, muda esta linha)*

**Regras:**
1. O desenvolvedor só trabalha em tarefas da **fase activa**. Tarefas de fases seguintes não se começam, mesmo que pareçam fáceis.
2. A fase seguinte só começa quando a **porta de fase** abre:
   - todas as tarefas `[ ]`/`[~]` da fase estão `[x]`, incluindo as de segurança 🔒;
   - o critério de saída da fase (tabela "📊 Estado por fase") foi demonstrado, com comandos e resultados no relatório;
   - todos os commits da fase foram aprovados pelo CTO e estão em `development`, `staging` e `main`, com o CI verde nas três;
   - o CTO reviu e o CEO autorizou.
3. **ADRs:** um ADR com *"antes da Fase N"* conta para a porta da fase **N−1** (ex.: ADR-003 *antes da Fase 2* tem de estar aprovado para fechar a Fase 1). Os restantes ADRs não bloqueiam a fase actual.
4. **Tarefas 👔 do CEO dentro da fase:** o desenvolvedor prepara o documento com as perguntas e opções; a porta só abre quando o CEO responder.
5. **Ritmo:** uma sessão de trabalho por dia na fase activa. Não há prazo de "uma fase por dia": as fases têm tamanhos muito diferentes (a Fase 2 é o produto inteiro). Se a fase não terminar, continua no dia seguinte. Qualidade e segurança antes de velocidade.
6. **Trabalho já feito fora de ordem:** as tarefas 1.0 e 1.1 marcadas `[x]` foram feitas pelo CTO antes desta regra existir; mantêm-se, e o que falta delas é feito agora, na Fase 1.

**Porta da Fase 0 — o que tem de estar `[x]` para abrir a Fase 1:**
- 0.2: template, ADR-001, ADR-002, ADR-005, ADR-008, ADR-013, ADR-014, ADR-015 (os que dizem *antes da Fase 1* ou *antes da 1.2*);
- 0.3: todas as tarefas (a das perguntas da §24.2 depende de respostas do CEO 👔).

---

## 👨‍💻 Padrão de engenharia exigido — aplica-se a TODAS as tarefas de TODAS as fases

**Em cada fase e em cada tarefa, o desenvolvedor actua como Desenvolvedor de Software Sénior com mais de 30 anos de experiência.** Espera-se profissionalismo, rigor, eficiência e código limpo, fácil de entender e de manter, com os princípios **SOLID** aplicados sempre. Isto não é um estilo opcional: é o critério com que cada PR é revisto pelo CTO, e um PR que não o cumpra é devolvido.

### Princípios obrigatórios

**Profissionalismo e rigor**
- Ler a tarefa, a secção do README referida (`§`) e o código existente **antes** de escrever código. Perceber o porquê, não só o quê.
- **Honestidade no estado das tarefas:** `[x]` só quando está feito, testado e verificado. Nunca marcar como concluído o que está parcial, nunca declarar "testado" o que não correu. Na dúvida, `[~]` com nota do que falta.
- Verificar o próprio trabalho a correr o código (testes, `go vet`, `golangci-lint`, e quando aplicável `docker compose up`) — não assumir que funciona.
- Tratar todos os erros; nada de `_ = err` sem justificação escrita; erros embrulhados com contexto (`fmt.Errorf("...: %w", err)`).
- Pensar nos casos-limite e nos casos maliciosos antes do caso feliz: input vazio, gigante, concorrente, repetido, de outro tenant.

**Código limpo**
- Nomes que dizem a intenção; funções curtas que fazem uma coisa; sem números mágicos (constantes com nome e comentário do porquê).
- Comentários explicam **porquê**, não o quê; toda a API exportada tem doc comment.
- Sem código morto, sem duplicação (extrair quando há a segunda repetição real, não antes), sem abstrações especulativas ("vai ser útil um dia").
- Seguir as convenções do Go (Effective Go, `gofmt`, `goimports`) e o estilo já existente no repositório; consistência vale mais do que preferência pessoal.
- Preferir a stdlib; cada dependência nova precisa de justificação no PR (§11.6).

**SOLID aplicado ao Go deste projecto**
- **S — Responsabilidade única:** cada pacote, tipo e função tem uma razão para mudar. Handlers HTTP só fazem fronteira (decode, validar, chamar o serviço, responder); regras de negócio vivem em serviços; SQL vive em repositórios/`sqlc`.
- **O — Aberto/fechado:** novos comportamentos por extensão, não por `switch` crescente espalhado. Ex.: um canal de notificação novo (Telegram, WhatsApp) é um novo adaptador que implementa a interface de canal, sem mexer no dispatcher.
- **L — Substituição de Liskov:** qualquer implementação de uma interface tem de respeitar o mesmo contrato (erros, timeouts, idempotência). Um adaptador falso nos testes comporta-se como o real.
- **I — Segregação de interfaces:** interfaces pequenas, definidas **do lado de quem as consome** (regra Go e §4.5). Nada de interfaces "Repository" com 20 métodos.
- **D — Inversão de dependências:** dependências entram por construtor (injecção explícita, sem globals nem `init()` com efeitos); relógio (`clock.Clock`), BD, fila e fornecedores externos são injectados para poderem ser testados.

**Eficiência**
- Correcto primeiro, depois rápido — mas sem desperdício óbvio: sem queries N+1, sem goroutines sem limite, sem ler bodies inteiros sem limite, sem alocações desnecessárias no hot path da ingestão.
- Optimizar só com medição (`pprof`, benchmarks) (§13).
- PRs pequenos e focados: uma tarefa por PR, fácil de rever.

### Erros já cometidos que não se podem repetir
| Erro | Regra que o evita |
|---|---|
| Tarefas marcadas `[x]` sem estarem concluídas (config "completa" que aceitava produção sem segredos; `sqlc` "configurado" sem queries) | Honestidade no estado das tarefas; `[x]` só com verificação |
| Ordem de middlewares errada (panics em CORS/limite de body não eram apanhados) | Pensar no fluxo completo de um pedido e testar no router real, não só a função isolada |
| Limite de body da ingestão aplicado a toda a API | Cada limite e regra no âmbito certo (grupo de rotas), nunca global por conveniência |
| Dependências entre fases ignoradas (webhooks precisavam do cliente SSRF de uma fase posterior) | Ler as dependências da tarefa antes de começar; se faltar algo, avisar o CTO |
| README desactualizado face ao código | Documentação actualizada no mesmo PR que muda o comportamento |
| Comando que nunca correu documentado como funcional | Só documentar o que foi executado e verificado |

### ✅ Checklist pré-PR (obrigatória, copiar para a descrição do PR)
- [ ] Li a tarefa, a secção do README e o código afectado; a solução cumpre os critérios de aceitação
- [ ] SOLID respeitado; handler fino, lógica em serviço, dependências injectadas, interfaces pequenas do lado do consumidor
- [ ] Código limpo: nomes claros, funções curtas, sem duplicação, sem código morto, comentários do porquê
- [ ] Erros todos tratados e com contexto; nenhum segredo ou detalhe interno em respostas ou logs
- [ ] Testes: caso feliz, casos-limite, casos maliciosos/negativos e cross-tenant quando aplicável
- [ ] `gofmt`, `go vet`, `golangci-lint run ./...`, `go test -race ./...` e `govulncheck ./...` verdes **localmente**
- [ ] Security Gate e Definition of Done cumpridos
- [ ] README/OpenAPI/ADR/runbooks actualizados se o comportamento mudou
- [ ] Estado no TASKS.md actualizado com honestidade (`[x]` ou `[~]` com o que falta)

**Legenda:** `[x]` Concluído (cumpre o Security Gate **e** a DoD) · `[~]` Em curso / parcial · `[ ]` Pendente · `⚠` dependência ou risco · 🧭 CTO revê · 👔 decisão/acção do CEO

**Última revisão:** 2026-11-26 — roadmap reordenado por decisão do CEO: o primeiro produto é **error tracking compatível com SDKs Sentry + alertas + notificações (email, Telegram, WhatsApp)**.

---

## 🧭 Registo de decisões do CTO

| Data | Decisão | Motivo |
|---|---|---|
| 2026-11-26 | **MVP (Fase 2) = error tracking + alertas de erro + notificações email/Telegram/WhatsApp.** Métricas, incidentes completos, SSE, webhooks, Web Push, collectors e uptime passam para depois | Pedido do CEO: é onde dói mais e há menos oferta acessível localmente |
| 2026-11-26 | **Ingestão compatível com o protocolo dos SDKs Sentry** (envelope + store, `X-Sentry-Auth`, DSN). O cliente migra mudando só o DSN | Remove a maior barreira de adopção (modelo GlitchTip) |
| 2026-11-26 | **SDK Node próprio cancelado no MVP** (adiado para a Fase 10, só se houver necessidade). Os clientes usam os SDKs oficiais Sentry (MIT), em qualquer linguagem | Poupa semanas e dá logo suporte a JS, Python, PHP/Laravel, Java, .NET, Go, mobile |
| 2026-11-26 | **SDK Go próprio logo a seguir ao go-live do MVP** (tarefa 2.10), por decisão do CEO (pergunta 12). O MVP lança com os SDKs Sentry, incluindo `sentry-go`, sem atraso | Decisão de produto do CEO; não atrasa o lançamento |
| 2026-11-26 | **Respostas do CEO às 12 perguntas da §24.2** registadas em `docs/decisions/perguntas-ceo.md`: startups/PMEs, SaaS primeiro, plano único no beta, VPS, região única fora de Angola com parecer jurídico da APD, SLOs aprovados | Fecha a última tarefa 👔 da porta da Fase 0 |
| 2026-11-26 | **Nunca copiar código do servidor Sentry** (licença FSL) nem usar a marca no branding. Implementamos o protocolo a partir da documentação pública; "compatível com SDKs Sentry" é uso nominativo aceitável | Risco legal |
| 2026-11-26 | **WhatsApp só por API oficial** (WhatsApp Business Platform/Cloud API da Meta ou BSP). Proibido usar bibliotecas não oficiais (Baileys, whatsapp-web.js…) | Violação dos termos da Meta → banimento do número e risco de dados |
| 2026-11-26 | **No MVP o "acknowledge" é o estado do issue** (`resolved`/`ignored`), sem entidade Incident; os incidentes completos chegam com os alertas de métricas (Fase 4) | Reduz o MVP sem perder o essencial |
| 2026-11-26 | **O MVP inclui um go-live mínimo** (2.9): não se dá acesso a clientes sem TLS, backups com restore testado, monitorização externa e runbooks essenciais | Os dados de erros dos clientes são sensíveis desde o primeiro dia |

---

## 📊 Estado por fase

| Fase | Tema | Estado | Critério de saída |
|---|---|---|---|
| 0 | Discovery, arquitectura e contratos | `[x]` (porta aprovada em 2026-11-26) | Scope aprovado, ADRs da fase seguinte escritos, riscos listados |
| 1 | Fundação do backend (auth, orgs, projectos, credenciais, CI) | `[~]` **← fase activa** (1.0 e 1.1 quase completas) | Auth + isolamento de tenant em E2E; pipeline verde; backup/restore testado |
| **2** | **MVP: Error tracking compatível Sentry + alertas + email/Telegram/WhatsApp + UI mínima + go-live** | `[ ]` | SDKs Sentry de ≥ 5 plataformas enviam erros só com troca de DSN; alerta → notificação nos 3 canais com falhas simuladas; go-live mínimo aprovado |
| 3 | Métricas e ingestão de telemetria | `[ ]` | Load test base aprovado; sobrecarga documentada; retenção validada |
| 4 | Alertas de métricas, incidentes e tempo real (SSE) | `[ ]` | E2E ingest → alerta → incidente → notificação |
| 5 | Canais adicionais: webhooks e Web Push | `[ ]` | Suite SSRF base aprovada; assinatura HMAC verificável |
| 6 | Pull collectors | `[ ]` | Suite SSRF completa; revisão de segurança dedicada |
| 7 | Uptime e dashboards | `[ ]` | Falha/recuperação provadas; SSRF coberto |
| 8 | Hardening e escala | `[ ]` | Checklist de produção (§22) aprovado; riscos residuais aceites por escrito |
| 9 | Logs e traces (pós-V1) | `[ ]` | Só se houver necessidade real |
| 10 | Expansão (pós-V1) | `[ ]` | Orientada por uso |

**A V1 = fases 0–8 (§3).** As fases executam-se pela ordem da tabela; não implementar módulos em paralelo (§20.1).

---

## 🎯 Próximos passos imediatos (ordem recomendada)

**👔 CEO (começar já — têm prazos externos que não dependem do código):**
1. **WhatsApp:** criar o Meta Business Manager da Yhanko e iniciar a **verificação da empresa** (pode levar dias a semanas); escolher o número de telefone dedicado (não pode estar em uso noutra conta WhatsApp) e o nome de exibição. Decidir orçamento mensal para mensagens (a Meta cobra por mensagem de template).
2. **Email:** escolher o domínio de envio (ex.: `alerts.<domínio>`) para configurar SPF/DKIM/DMARC.
3. **Legal:** termos de serviço, política de privacidade e enquadramento na lei angolana de protecção de dados (Lei n.º 22/11) antes do go-live (2.9).
4. Responder às perguntas da §24.2 (público inicial, SaaS vs self-hosted, retenção default, volume esperado).

**Desenvolvedor (Gemini) — Fase 1 (activa), sempre na branch `development`:**
1. O que falta da 1.1, pela ordem da lista (`ADMIN_PORT`, pool da BD, testes de integração com `testcontainers-go`, `oapi-codegen`, lint da spec).
2. 1.2 → 1.3 → 1.4, pela ordem; o `internal/platform/crypto` (ADR-015) é a primeira tarefa da 1.2.
3. Em paralelo, só documentos: os ADRs que contam para a porta da Fase 1 (003, 004, 009, 017) 🧭.
4. Relatório no fim de cada sessão, com os commits por rever; nada é publicado sem aprovação do CTO.

**👔 CEO, no GitHub:** branch protection em `staging` e `main` (4 jobs do CI obrigatórios, sem push directo excepto o fast-forward aprovado).

---

## 🔒 Regra de Ouro — Security Gate obrigatório por funcionalidade

**Nenhuma funcionalidade é `[x]` sem cumprir, no momento da entrega:**

1. **Isolamento multi-tenant (zero BOLA/IDOR):** toda a query/repositório exige `organization_id` vindo da sessão/credencial validada (nunca do body/query do cliente); não existe "find by id" sem tenant; teste negativo cross-tenant (§11.1).
2. **Validação estrita na fronteira:** schema rigoroso, tipos, limites de tamanho/profundidade/body, rejeição de campos inesperados (`DisallowUnknownFields`) — **excepto** na ingestão compatível Sentry, onde campos desconhecidos são ignorados por contrato com os SDKs (TASKS 2.2) —, queries 100% parametrizadas (zero SQLi) (§11.5).
3. **Zero fuga de segredos ou internals:** segredos sempre via `*_FILE` + tipo `Secret`, zero stack traces/erros internos em respostas HTTP, redacção de PII/credenciais em logs (§11.4, §14.2).
4. **Controlo de acesso e anti-abuso:** RBAC verificado no backend em cada endpoint, rate limit e quotas aplicados, timeouts explícitos, protecção contra DoS (§10.5, §11.3).
5. **Testes de regressão de segurança:** testes negativos (acesso não autorizado, cross-tenant, payloads maliciosos, XSS/SSRF/injecção conforme aplicável) + `go vet` / `gosec` / `govulncheck` verdes no CI (§15.1).
6. **Auditoria:** acções administrativas e de segurança do módulo geram registo em `audit_logs` sem segredos (§7.10).

## ✅ Definition of Done (§21) — aplica-se a cada funcionalidade

- [ ] Endpoint/schema descrito em `api/openapi.yaml` e código gerado sem diferenças (`oapi-codegen`, `sqlc`)
- [ ] Testes unit + integração (`//go:build integration`, `testcontainers-go`) + E2E se for fluxo crítico (§15.2)
- [ ] Logging estruturado, métricas e tracing do módulo (§14.1)
- [ ] Erros mapeados para códigos do catálogo de erros; rate limits e quotas considerados
- [ ] Migrations seguras (expand/contract, §16.3) e com `Down` revisto
- [ ] UI com estados de loading/erro/vazio (a partir da Fase 2)
- [ ] Documentação e runbooks actualizados; feature flag/rollback considerados
- [ ] Deploy em staging + smoke test (a partir do go-live da Fase 2; antes disso, ambiente Compose)

---

## Fase 0 — Discovery, Arquitectura e Contratos

### 0.1 Feito
- [x] Visão, objectivos, princípios de engenharia e escopo V1 (§§1–3)
- [x] Estrutura de pastas do monorepo (§6)
- [x] Esqueleto inicial do backend Go (`cmd/vigia`, `config`, `httpserver`) (§26.1)
- [x] Ambiente Docker endurecido (`Dockerfile` distroless, `compose.yaml`, `compose.dev.yaml`, `redis.conf`, `secrets/`) (§26.1–26.3)
- [x] Roadmap reordenado: MVP de error tracking + notificações (registo de decisões acima; README §3 e §20 actualizados)

### 0.2 ADRs obrigatórios em `docs/adr/` (§24.1)
> Formato: contexto, alternativas, decisão, consequências, riscos, data, responsável; protótipo/benchmark quando técnico. O texto em *itálico* diz que fase fica bloqueada sem o ADR. Todos os ADRs são 🧭.

- [x] Template `docs/adr/000-template.md` — *aprovado pelo CTO (2026-11-26) e fundido na `main`*
- [x] ADR-001: Monorepo e monólito modular — *antes da Fase 1; aceite (2026-11-26) e fundido na `main`*
- [x] ADR-002: PostgreSQL para metadata — *antes da Fase 1; aceite (2026-11-26) e fundido na `main`*
- [ ] ADR-003: TimescaleDB vs ClickHouse para telemetria (**incl. revisão da Timescale License**, §5.3) e onde vivem os `issue_events` — *antes da Fase 2*
- [ ] ADR-004: Asynq vs River vs RabbitMQ/NATS; semântica de entrega (at-least-once + dedup) — *antes da Fase 2*
- [x] ADR-005: Autenticação (sessões, cookies, CSRF) e formato/hash das API keys, **incluindo o tipo "DSN key" pública** (2.1) — *antes da 1.2; aceite (2026-11-26) e fundido na `main`*
- [ ] ADR-006: Ingestão OpenTelemetry — *antes da Fase 9*
- [ ] ADR-007: Modelo de métricas e cardinalidade — *antes da Fase 3*
- [x] ADR-008: Isolamento de tenant (aplicação + RLS) — *antes da 1.2; aceite (2026-11-26) e fundido na `main`*
- [ ] ADR-009: Retenção e quotas (eventos de erro/dia, mensagens WhatsApp/mês) — *antes da Fase 2*
- [ ] ADR-010: Estratégia de deploy — *antes do go-live da Fase 2 (2.9)*
- [ ] ADR-011: SSE vs WebSocket; autenticação do stream; fan-out entre réplicas — *antes da Fase 4*
- [ ] ADR-012: Segurança dos collectors pull (BD e endpoints) — *antes da Fase 6*
- [x] ADR-013: Go como linguagem do backend — *aceite (2026-11-26) e fundido na `main`*
- [x] ADR-014: Acesso a dados (`sqlc` + `pgx` vs ORM) — *aceite (2026-11-26) e fundido na `main`*
- [x] ADR-015: Gestão de chaves de encriptação (envelope encryption, KEK/DEK, rotação) — *antes da 1.2; aceite (2026-11-26) e fundido na `main`*
- [ ] ADR-016: Armazenamento de "events" genéricos (`/ingest/events`) — *antes da Fase 3*
- [ ] **ADR-017: Compatibilidade com o protocolo de ingestão dos SDKs Sentry** — *antes da Fase 2*. Tem de fixar:
  - versão do protocolo (`sentry_version=7`), endpoints (`/api/<project_id>/envelope/` e `/store/`) e formatos de autenticação (`X-Sentry-Auth`, query `sentry_key`);
  - tipos de item suportados no MVP (`event`) e os aceites-e-descartados (`transaction`, `session(s)`, `client_report`, `attachment`, `replay_*`, `profile`, `check_in`, `span`, `log`, `statsd`), sempre com `200` para não partir os SDKs;
  - limites (envelope, evento, descomprimido, frames, breadcrumbs) e compressões aceites (`gzip`, `deflate`, `br`, `zstd`?);
  - algoritmo de agrupamento (fingerprint) e suporte ao campo `fingerprint` com `{{ default }}`;
  - matriz de SDKs suportados e versões mínimas testadas;
  - notas legais: protocolo implementado a partir da documentação pública (develop.sentry.dev), sem código do servidor Sentry; política de nome/branding.
- [ ] **ADR-018: Fornecedor de WhatsApp** — *antes de 2.7*. Comparar Meta WhatsApp Cloud API directa vs BSP (Twilio, 360dialog, Infobip) em custo por mensagem para números `+244`, prazo de activação, SLA e suporte; templates necessários (categoria *utility*); janela de 24 h; opt-in e opt-out; o que fazer se a verificação da Meta atrasar (lançar com email + Telegram). 👔 o CEO aprova o custo
- [ ] **ADR-019: Fornecedor de email transaccional em produção** (Resend, Postmark, Amazon SES ou SMTP próprio) — *antes de 2.9*

### 0.3 Segurança, requisitos e convenções
- [x] Threat model formal em `docs/security/threat-model.md` (activos e ameaças da §11.7, STRIDE por fronteira de confiança) (§11.7)
- [x] Classificação de dados (público / interno / confidencial / segredo) e **lista de dados proibidos** de ingestão (§17.3, §20.1) — `docs/security/data-classification.md`
- [x] SLOs iniciais e metas de capacidade documentados (§14.4, §25.2), incl. **RPO/RTO** por classe de dado (§16.6) — `docs/architecture/slos-capacity.md`
- [x] Respostas escritas às 12 perguntas da §24.2 (público-alvo, modelo SaaS/self-hosted, volume, retenção default, alvo de deploy…) — `docs/decisions/perguntas-ceo.md` (respondido pelo CEO em 2026-11-26)
- [x] Valores concretos da §25.3: política de passwords, duração de sessão, expiração padrão das keys, valores de rate limit, definição de severidades, regras de reabertura (incidente/issue) — `docs/decisions/business-defaults.md`
- [x] **Catálogo de códigos de erro da API** + política de versionamento/depreciação (§25.3, §9.1) — `docs/api/error-catalog.md`
- [x] Personas, user journeys e lista numerada de requisitos (`RF-001…`) com critério de aceitação (§25.1) — `docs/product/requirements.md`
- [x] Fluxos completos: convite, recuperação de conta, eliminação de organização/projecto, **transferência de ownership** (§25.1) — `docs/product/critical-flows.md`
- [x] Convenções Go escritas (erros com `%w`, `context` em toda a I/O, concorrência limitada, nomes de pacotes, testes table-driven) (§23) — `docs/engineering/go-conventions.md`
- [x] Diagramas de arquitectura e fluxo actualizados em `docs/` (§20.1) — `docs/architecture/diagrams.md`

---

## Fase 1 — Fundação do Backend

### 1.0 CI mínimo (antecipado — pré-requisito do Security Gate) (§16.1)
> ⚠ O TASKS original punha o CI na 1.4, mas a Regra de Ouro exige `gosec`/`govulncheck` em **cada** módulo. Tem de existir antes da 1.2.

- [~] `.github/workflows/ci.yml`: `gofmt -l`, `go vet`, `go mod tidy` sem diferenças, `golangci-lint` v2.15.0, `go test -race`, `govulncheck`, `gitleaks` (histórico completo), testes no container, build da imagem, `docker compose config` — *lint e govulncheck verdes localmente; falta a primeira execução no GitHub*
- [x] `.golangci.yml`: `gosec`, `errcheck`, `bodyclose`, `noctx`, `errorlint`, `rowserrcheck`, `sqlclosecheck`, `forbidigo` (`http.Get`/`http.DefaultClient`/`fmt.Print` proibidos fora do CLI), `goimports`
- [x] Fronteiras (§4.5): `depguard` impede `internal/platform` de importar `internal/modules` e proíbe `math/rand`, `log`, `io/ioutil`, `github.com/pkg/errors`. Entre módulos, a regra é estrutural: o código privado de cada módulo vive em `internal/modules/<x>/internal/` e o compilador do Go impede outros módulos de o importar
- [x] Dependabot (`gomod`, `github-actions`, `docker`) com `cooldown` de 7 dias (§11.6)
- [ ] **Branch protection** em `staging` e `main`: 5 jobs (`lint`, `test`, `integration`, `security`, `docker`) obrigatórios, bloquear force-push e eliminação; **não** activar "Require a pull request" (o fluxo é por fast-forward de commits já verdes em `development`, e o GitHub aceita o push porque o mesmo SHA já tem os checks) — *acção manual 👔 no GitHub*
- [ ] `sqlc diff` e `oapi-codegen` sem diferenças no CI (quando houver código gerado; ver 1.1)

### 1.1 Fundação da plataforma (`platform/` + CLI)
- [x] `internal/platform/config`: validação de env + segredos via `*_FILE` (§5.1, §26.4)
  - [x] Parsing/validação de `APP_ENV`, `PORT`, `APP_URL`, `LOG_LEVEL`, `DATABASE_URL`, limites, `*_FILE`
  - [x] **Fail-fast fora de `development`:** `staging`/`production` exigem `DATABASE_URL`, `REDIS_ADDR`, `SESSION_SECRET_FILE`, `API_KEY_PEPPER_FILE`, `ENCRYPTION_KEY_FILE` (≥ 32 caracteres); `production` exige `APP_URL` e origens CORS em `https`
  - [x] `CORS_ORIGINS`: só origens exactas (`*`, caminhos, query e credenciais rejeitados); `SMTP_URL` validado (`smtp`/`smtps`); `API_MAX_BODY_BYTES` novo
  - [x] Caminho do ficheiro de segredo nas mensagens de erro: avaliado e mantido (só aparece no log de arranque, não é segredo; o valor nunca é incluído — coberto por teste)
- [x] `internal/platform/telemetry`: `log/slog` JSON + `LOG_LEVEL` (§14.2) + testes
- [x] `internal/platform/clock`: relógio injectável (`System`/`Fake`) para testes determinísticos (§15.5)
- [x] `internal/platform/database`: pool `pgx`, `WithTx` e `Ping` (§5.1)
  - [x] Pool configurável por env (`DATABASE_MAX_CONNS`) e `statement_timeout` por defeito na ligação (§13.9)
  - [x] Teste de integração com `testcontainers-go` (Timescale) para `NewPool`, `WithTx` e migrations up/down (`//go:build integration` + job no CI)
- [x] `internal/platform/queue`: cliente Redis com password via `REDIS_PASSWORD_FILE` + `Ping` (§5.1)
- [x] `migrations/` + `vigia migrate <up|down|status|version>` com `goose` embutido (§5.1, §26.5)
- [x] `internal/platform/httpserver`: `chi`, `X-Request-Id`, logging JSON, recovery, CORS, security headers, envelope de erro (§9.1), `GET /health/ready` (§9.3)
  - [x] Ordem dos middlewares: RequestID → SecurityHeaders → Recoverer → Logger → CORS → MaxBytes (panics em qualquer camada seguinte são apanhados e a resposta mantém request id e headers) + teste
  - [x] `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'…` em todas as respostas e `Strict-Transport-Security` quando `APP_ENV=production` + testes
  - [x] Limite de body da API de produto separado do de ingestão (`API_MAX_BODY_BYTES`, 256 KiB); a ingestão aplicará o seu no grupo de rotas (Fase 2)
  - [x] `DecodeJSON` estrito (Content-Type, `DisallowUnknownFields`, um único objecto, 413 em excesso, sem eco de campos) + testes
  - [x] Recoverer deixa passar `http.ErrAbortHandler` + teste
  - [ ] Paginação por cursor (`?limit=&cursor=`), middleware `Idempotency-Key`, headers `RateLimit-*`/`Retry-After` (§9.1) — *fazer com o primeiro endpoint que precisa deles (1.2)*
  - [x] `/health/ready` e futuro `/metrics` num **listener interno separado** (`ADMIN_PORT`) em vez da porta pública (§9.3)
- [~] Configuração do `sqlc` (`sqlc.yaml` + `queries/`) (§5.1)
  - [ ] `queries/` ainda está vazio: primeira query real na 1.2 + `//go:generate sqlc generate` + `sqlc diff` no CI
- [x] Contrato base `api/openapi.yaml` (§5.1, §9)
  - [x] Configurar `oapi-codegen` (tipos + interface de servidor `chi`) para `internal/api` com `go generate` e verificação "sem diferenças" no CI (§5.1, §16.1)
  - [x] Lint da spec (`redocly/cli:1.34.5`) no CI
- [x] `Dockerfile`, `.dockerignore` e `compose.yaml` (secrets montados na API, `migrations/` incluídas)
  - [x] Docker secrets `session_secret`, `api_key_pepper`, `encryption_key` + `secrets/README.md` (geração idempotente em bash e PowerShell)
  - [x] Serviço `migrate` one-shot; a `api` espera por `service_completed_successfully`
- [x] README §26 actualizado (rotas reais, pacotes, CI, arranque com `migrate`, variáveis)
- **🔒 Blindagem de Segurança (1.1):**
  - [x] Tipo `Secret` com redacção em `fmt` e `slog` + teste (`TestSecretRedaction`)
  - [x] Timeouts HTTP explícitos contra Slowloris
  - [x] Limite de body (`MaxBytesMiddleware`) + teste negativo `413`
  - [x] Sanitização de `X-Request-Id` contra header/log injection + teste negativo
  - [x] Recovery sem vazar stack trace + teste negativo (unitário e no router real)
  - [x] `/health/ready` sem expor erros internos + CORS estrito por allowlist + testes
  - [x] Arranque fora de `development` falha sem segredos obrigatórios ou com chaves curtas, sem expor o valor (`TestLoadFromFailFastOutsideDevelopment`)
  - [x] Healthcheck do CLI com `context` e timeout (sem `client.Get` sem contexto)

### 1.2 Identity, Organizations, RBAC e Audit
- [~] `internal/platform/crypto`: envelope encryption AES-256-GCM (DEK por registo, KEK de `ENCRYPTION_KEY_FILE`, `key_id` para rotação) conforme ADR-015 *(implementado, testado com fuzzing 30s e ligado no arranque; aguarda revisão do CTO 🧭)* 🧭
- [ ] Migration: `users`, `sessions`, `organizations`, `memberships`, `invitations`, `teams`, `team_members`, `audit_logs` (§8.2) com índices a começar pelo tenant e `UNIQUE` da §8.6
- [ ] Padrão de repositório tenant-scoped (tipo `TenantID` obrigatório nas assinaturas) (§11.1)
- [ ] `identity`: `POST /auth/register|login|logout|refresh`, sessões revogáveis, Argon2id, cookies `HttpOnly`/`Secure`/`SameSite` (§9.2, §10.3)
- [ ] `identity`: `/auth/verify-email`, `/auth/password/forgot|reset`, `/auth/mfa/setup|verify` (TOTP) + códigos de recuperação (§10.3)
- [ ] **MFA obrigatório para `owner`/`admin`** antes de produção (§10.3, §22)
- [ ] **Re-autenticação** em operações de alto risco (criar/revogar keys, mudar roles, apagar org/projecto) (§10.3)
- [ ] Envio de email transaccional mínimo (verificação/reset) via adaptador SMTP → Mailpit em dev (§7.7); o mesmo adaptador é reutilizado pelo canal de email da Fase 2
- [ ] `organizations`: CRUD, memberships, convites (`/invitations/:token/accept`), teams (§9.2)
- [ ] Transferência de ownership e eliminação de organização (soft delete + período de graça) (§25.1)
- [ ] RBAC (`owner`, `admin`, `member`, `viewer`) com as permissões explícitas da §10.5, verificadas por middleware em cada request
- [ ] `audit`: registo append-only (login/logout, MFA, roles, convites…) + `GET /organizations/:id/audit-logs` com `audit:read` e paginação por cursor (§7.10, §9.2)
- **🔒 Blindagem de Segurança (1.2):**
  - [ ] Argon2id com salt CSPRNG + parâmetros documentados; comparação em tempo constante
  - [ ] Anti-enumeração de contas em login/registo/recuperação (respostas genéricas e timing consistente)
  - [ ] Rate limit + lockout progressivo em `/auth/login`, `/auth/password/*`, `/auth/mfa/*`
  - [ ] CSRF para cookie-auth (`SameSite` + token CSRF ou verificação de `Origin`) e rotação do ID de sessão no login/elevação de privilégio
  - [ ] Tokens de convite/reset/verificação: CSPRNG ≥ 256 bits, guardados como hash, expiração curta, uso único
  - [ ] Testes negativos de escalada de privilégios (`viewer`/`member` → acções de `admin`/`owner`; `admin` não remove `owner`) e cross-tenant
  - [ ] `audit_logs` sem passwords, tokens, cookies nem segredos; tabela sem `UPDATE`/`DELETE` para o utilizador da aplicação

### 1.3 Projects, Environments e API Credentials
- [ ] Migration: `projects`, `environments`, `api_credentials` (§8.2)
- [ ] `projects`: CRUD projects e environments (`is_protected`) (§9.2)
- [ ] `credentials`: CSPRNG ≥ 256 bits (`vg_ing_<prefix>_<secret>`, `vg_cli_<prefix>_<secret>`), HMAC-SHA256 com pepper, lookup por prefixo, tempo constante, scopes, expiração, rotação com overlap e revogação imediata (§10.1–10.2)
- [ ] Middleware de autenticação por credencial que injecta `organization_id`/`project_id`/`environment_id` no contexto (§4.3)
- [ ] Cache de credenciais validadas (Redis, TTL curto, prefixo de tenant) com invalidação na revogação
- [ ] `last_used_at` (actualização assíncrona/agrupada, sem escrita por pedido) (§10.2)
- [ ] Detecção de uso anómalo de keys (picos, IPs novos) → evento de auditoria (alerta real na Fase 4) (§10.2)
- **🔒 Blindagem de Segurança (1.3):**
  - [ ] Segredo mostrado **uma única vez**; nunca devolvido nem gravado em plaintext
  - [ ] `vg_ing_` impedida de aceder a rotas administrativas ou de leitura; `vg_cli_` só leitura (testes negativos)
  - [ ] Revogação imediata com invalidação de cache + teste de rejeição imediata
  - [ ] `is_protected` protege contra eliminação/alteração não autorizada
  - [ ] Testes cross-tenant em todos os endpoints de projects, environments e credentials

### 1.4 Validação e saída da Fase 1
- [ ] Suite automatizada **cross-tenant** para todos os recursos sensíveis (`tests/security/`) (§11.1, §11.9)
- [ ] Testes de revogação imediata e de não-exposição de segredos em logs/respostas (§11.9)
- [ ] **E2E** (`tests/e2e/`): signup/login/MFA, organização + membros, projecto + ambiente, criar/revogar key, trilha de auditoria, negativo cross-tenant (§15.2 #1–4, #12–13)
- [ ] CI completo: `sqlc diff`, `oapi-codegen` sem diferenças, testes de integração, validação de migrations (up → down → up) (§16.1)
- [ ] Backup e restore encriptado do PostgreSQL testado (`pg_dump`/`pgBackRest`) + runbook (§16.6)
- [ ] Decisão e aplicação de **RLS** como defesa em profundidade (`SET LOCAL app.organization_id` dentro de `WithTx`) (§8.6, §11.1)
- [ ] **Revisão de segurança antes de iniciar a ingestão** (§20.2 passo 12) — a primeira ingestão é a compatível Sentry da Fase 2 🧭

---

## Fase 2 — MVP: Error Tracking compatível com Sentry + Alertas + Notificações

> **Objectivo de produto:** um developer em Angola troca o DSN do SDK Sentry que já usa (ou instala um SDK Sentry pela primeira vez), vê os erros agrupados no Vigia e recebe o alerta no **WhatsApp, Telegram ou email** em menos de 1 minuto.
>
> **Fora do MVP (não implementar aqui):** métricas, dashboards, SSE, incidentes com timeline, webhooks de saída, Web Push, collectors, uptime, performance/tracing, replays, profiling, SDK próprio.
>
> **Pré-requisitos:** Fase 1 concluída (auth, orgs, RBAC, projectos, credenciais, audit, CI); ADR-003, 004, 009, 015, 017 aprovados.

### 2.0 Fundações partilhadas do MVP
- [ ] Fila durável (Asynq ou River, conforme ADR-004) + subcomando `vigia worker` com graceful shutdown, concorrência limitada e filas/limites **por tenant** (§4.4, §13.6)
- [ ] Subcomando `vigia scheduler` (jobs periódicos: detecção de picos, digests, retenção) com lock distribuído (§4.4)
- [ ] `internal/platform/redaction`: regras partilhadas de scrubbing (lista da §2.3) e lista de dados proibidos (§11.4, §17.3) + testes
- [ ] `quotas` (mínimo do MVP): eventos de erro/dia por organização, mensagens WhatsApp/mês por organização, projectos e membros; contadores em Redis + `usage_aggregates`; `GET /organizations/:id/usage` e `/quotas` (§17.1, §9.2)
- [ ] Serviços `worker` e `scheduler` no `compose.yaml`

### 2.1 Projectos e DSN compatível com Sentry
- [ ] `projects.public_id`: identificador **numérico** do projecto para o DSN (vários SDKs Sentry, ex. Python, exigem `project_id` inteiro). Gerar aleatório de 53 bits (nunca sequencial: não revelar o número de projectos) com `UNIQUE`
- [ ] Novo tipo de credencial `dsn` em `api_credentials` (ADR-005): chave pública de 32 hex, presa a projecto/ambiente, **só escrita de erros**, revogável e rotativa; várias por projecto
- [ ] Formato do DSN: `https://<public_key>@<host>/<public_id>` (ex.: `https://3f2a…@ingest.vigia.ao/4817263`); `GET /projects/:id/credentials` mostra o DSN pronto a copiar
- [ ] Por chave DSN: `allowed_origins` (para SDKs de browser), rate limit próprio, estado activa/desactivada
- **🔒 Segurança:** a chave DSN é **pública por natureza** (vai no JavaScript do browser) → nunca dá leitura nem acesso administrativo; abuso controlado por rate limit, quotas, `allowed_origins` e revogação imediata. Teste negativo: chave DSN rejeitada em todas as rotas `/api/v1/*`

### 2.2 Ingestão compatível com os SDKs Sentry 🧭
> Implementar a partir da documentação pública do protocolo (develop.sentry.dev → SDK development). **Não copiar código do servidor Sentry.**

- [ ] Rotas fora de `/api/v1` (contrato dos SDKs): `POST /api/{public_id}/envelope/` e `POST /api/{public_id}/store/` (legacy), com e sem barra final; grupo de rotas próprio com **limite de body e CORS próprios**. ⚠ Hoje `CORSMiddleware` e `MaxBytesMiddleware` estão no router global (`httpserver.NewHandler`): mover para o grupo `/api/v1` antes de montar estas rotas, senão o preflight dos SDKs de browser falha
- [ ] Autenticação por `X-Sentry-Auth: Sentry sentry_key=…, sentry_version=7, sentry_client=…`, header `Authorization: Sentry …` e query `?sentry_key=&sentry_version=` (browsers); a chave tem de pertencer ao `public_id` do path; `401`/`403` com corpo JSON `{"detail": "..."}`
- [ ] Descompressão por `Content-Encoding` (`gzip`, `deflate`, `br`; `zstd` conforme ADR-017) com **limite do tamanho descomprimido** (protecção zip-bomb) e leitura em streaming
- [ ] Parser de envelopes: linha de header (`event_id`, `dsn`, `sent_at`, `sdk`), itens com header (`type`, `length` opcional, `content_type`), itens separados por `\n`; tolerante a campos desconhecidos (o protocolo evolui)
- [ ] Itens `event` (e o corpo do `/store/`) normalizados para o modelo interno; restantes tipos **aceites e descartados com `200`** e contados numa métrica interna (`sentry_items_dropped_total{type}`)
- [ ] Normalização do evento: `event_id`, `timestamp` (float epoch ou ISO-8601), `platform`, `level`, `logger`, `message`/`logentry`, `exception.values[]` (type, value, module, mechanism, `stacktrace.frames[]` com filename, abs_path, function, module, lineno, colno, in_app, context_line), `threads`, `release`, `dist`, `environment`, `server_name`, `transaction`, `tags`, `contexts` (os, runtime, browser, device, app), `user`, `request`, `breadcrumbs`, `sdk`, `fingerprint`, `extra`; truncagem de campos grandes
- [ ] Resposta `200 {"id":"<event_id>"}`; dedup por `event_id` (Redis `SET NX EX` + `UNIQUE` na BD) para retries dos SDKs
- [ ] Rate limit e quotas **no formato que os SDKs entendem**: `429` + `Retry-After` + `X-Sentry-Rate-Limits: <segundos>:error:organization:quota_exceeded`, para os SDKs pararem de enviar em vez de martelar o servidor
- [ ] CORS para SDKs de browser nestas rotas: `Access-Control-Allow-Origin` conforme `allowed_origins` da chave (ou `*` sem credenciais se a lista estiver vazia), headers `Content-Type, X-Sentry-Auth, sentry-trace, baggage`, preflight `OPTIONS`
- [ ] Ingestão rápida: validar, redigir, enfileirar e responder; agrupamento e persistência no `worker`
- [ ] Sem request body por defeito: descartar `request.data` e cookies enviados pelos SDKs, salvo opt-in explícito do projecto (§7.8, §17.3)
- [ ] Inbound filters por projecto (como os clientes esperam): ignorar erros de extensões de browser, de `localhost`, de crawlers conhecidos e por `release`/mensagem configurável
- **🔒 Segurança (2.2):**
  - [ ] Fuzzing (`go test -fuzz`) do parser de envelopes e do parser de `X-Sentry-Auth`
  - [ ] Testes negativos: zip-bomb, envelope com `length` mentiroso, item gigante, JSON profundo, milhares de frames/breadcrumbs, `public_id` de outra organização, chave revogada, chave de outro projecto
  - [ ] Scrubbing no servidor **antes** de enfileirar (2.3), independentemente do `send_default_pii` do SDK
  - [ ] Tenant/projecto/ambiente derivados **só** da chave DSN validada, nunca do payload

### 2.3 Processamento: issues, agrupamento e privacidade
- [ ] Migrations `issues` e `issue_events` (§8.2); `issue_events` em hypertable/particionado por tempo com retenção por plano (ADR-003/009)
- [ ] Fingerprint por defeito: tipo de excepção + frames `in_app` normalizados (module/filename sem paths absolutos, nomes de função sem endereços/números/hashes, **sem** números de linha); fallback para mensagem normalizada (IDs, números, UUIDs, emails substituídos); suporte ao campo `fingerprint` do SDK incluindo `{{ default }}` (§7.8)
- [ ] Lifecycle `unresolved | resolved | ignored` com **regressão** (issue `resolved` que volta a ocorrer reabre e marca `regressed`) (§7.8)
- [ ] Contadores (`occurrence_count`, utilizadores afectados aproximados), `first_seen`/`last_seen`, últimos releases e ambientes, tags mais frequentes
- [ ] Scrubbing por defeito (equivalente ao que os utilizadores Sentry esperam): chaves `password`, `passwd`, `secret`, `api_key`, `apikey`, `token`, `access_token`, `auth`, `authorization`, `credentials`, `cookie`, `set-cookie`, `session`, `private_key`, `mysql_pwd`; números de cartão (Luhn) e padrões de documentos; headers `Authorization`/`Cookie`; query strings sanitizadas; IP do utilizador guardado só se o projecto o permitir (§7.8, §17.3)
- [ ] Endpoints: `GET /projects/:id/issues` (filtros: status, ambiente, release, nível, pesquisa; paginação por cursor), `GET /issues/:id`, `GET /issues/:id/events`, `POST /issues/:id/resolve|ignore|unresolve|assign` (§9.2)
- [ ] Eliminação de issues/eventos (direito do titular) e retenção automática (§17.2)
- [ ] Testes de agrupamento com fixtures reais de vários SDKs (mesmo erro em linhas diferentes → 1 issue; erros diferentes → issues diferentes)
- **🔒 Segurança (2.3):**
  - [ ] Regex só RE2 (`regexp` do Go) com limites de entrada (anti-ReDoS)
  - [ ] Testes de regressão de fuga de PII/credenciais em `issue_events` com dados sintéticos
  - [ ] Cross-tenant em todos os endpoints de issues

### 2.4 Source maps e releases (MVP+, logo a seguir ao núcleo) 🧭
> Sem source maps, os stack traces de JavaScript minificado são inúteis e os clientes de frontend não migram. Fazer **depois** de 2.2–2.8 estarem verdes, mas **antes** do lançamento público.

- [ ] Spike (1–2 dias): compatibilidade do `sentry-cli`/plugins de bundler com um subconjunto da API de upload (`/api/0/…` releases, artifact bundles, chunk upload) vs upload próprio com instruções; decisão registada no ADR-017
- [ ] Armazenamento dos artefactos (S3-compatível/MinIO ou disco) com quota por organização
- [ ] Desminificação dos frames no `worker` (debug IDs e/ou release + nome do ficheiro)
- [ ] Releases: lista por projecto, `first_seen` por release, regressão por release

### 2.5 Alertas de erro
- [ ] Migrations `alert_rules` (versão simplificada para erros) e estado por regra/issue
- [ ] Tipos de regra no MVP: **novo issue**, **regressão**, **pico** (N eventos em M minutos para um issue ou projecto); filtros por ambiente, nível mínimo e tags (§7.8)
- [ ] "Novo issue" e "regressão" avaliados no `worker` na mesma transacção que cria/reabre o issue, com escrita na **outbox** (§4.3); "pico" avaliado pelo `scheduler` com janela deslizante
- [ ] Anti-ruído obrigatório (o WhatsApp custa dinheiro): cooldown por issue e regra, máximo de notificações por destino por hora, digest para picos repetidos, issues `ignored` nunca notificam (§7.5)
- [ ] CRUD `GET|POST /projects/:id/alert-rules`, `GET|PATCH|DELETE /alert-rules/:id`, `POST /alert-rules/:id/test` (envia notificação de teste)
- [ ] Regras por defeito criadas com o projecto: "novo issue em produção → email ao owner"
- [ ] Testes com relógio injectável (`clock.Fake`) para janelas e cooldowns

### 2.6 Motor de notificações
- [ ] Migrations `notification_policies`, `notification_destinations`, `notification_subscriptions`, `notifications`, `notification_outbox` (§8.2)
- [ ] Subcomando `vigia dispatcher`: lê a outbox, backoff exponencial + jitter, máximo de tentativas, DLQ, idempotency key por notificação, timeout e circuit breaker por canal; estados `pending | sent | failed | suppressed` (§7.7)
- [ ] Interface de canal (adapter) única: `Send(ctx, destination, message) (providerMessageID, error)` com classificação de erros (retentável / permanente / destino inválido)
- [ ] Destinos por utilizador e por equipa/grupo; preferências por utilizador (canal, severidade, projectos, horário de silêncio opcional)
- [ ] Templates versionados por canal (texto curto: projecto, ambiente, tipo de erro, mensagem truncada, contagem, link autenticado para o issue); **sem PII nem stack trace completo** na mensagem
- [ ] Documentar que "tentativa de envio" ≠ "recebido no dispositivo": nenhum fornecedor garante entrega fim-a-fim (§7.7)
- [ ] Histórico de entregas visível na UI (enviado/falhado/suprimido e motivo redigido)
- [ ] Testes de falha simulada (provider em baixo, 429, timeout), retries, DLQ e idempotência (nenhum duplicado após retry)

### 2.7 Canais: Email, Telegram e WhatsApp
**Email**
- [ ] Adaptador SMTP (Mailpit em dev) + adaptador do fornecedor de produção (ADR-019); tratamento de bounces/complaints (desactivar destino); HTML e texto; templates acessíveis
- [ ] Guia de SPF/DKIM/DMARC para o domínio de envio 👔 (DNS do domínio)

**Telegram** (Bot API — gratuito, sem aprovação; primeiro canal de mensagens a entregar)
- [ ] Bot da Yhanko criado no `@BotFather`; token em Docker secret `telegram_bot_token` (`TELEGRAM_BOT_TOKEN_FILE`)
- [ ] Ligação de conta: botão "Ligar Telegram" gera link `https://t.me/<bot>?start=<token>` (token CSPRNG, uso único, expira em 10 min, guardado como hash) → o webhook recebe `/start <token>` e associa o `chat_id` ao utilizador
- [ ] Suporte a grupos: adicionar o bot ao grupo e usar `/link <token>` para associar o grupo a um projecto (permissão `notification_policy:manage`)
- [ ] Webhook `POST /integrations/telegram/webhook` com validação do header `X-Telegram-Bot-Api-Secret-Token` (segredo próprio, comparação em tempo constante)
- [ ] Erros: `403` (bot bloqueado/removido do grupo) → destino desactivado e utilizador avisado por email; `429` → respeitar `retry_after`; limites globais do Telegram (≈ 30 msg/s) no dispatcher
- [ ] Mensagens com `parse_mode=HTML` e **escape** de todo o conteúdo vindo dos eventos (`<`, `>`, `&`) — é conteúdo não confiável
- [ ] `chat_id` encriptado em repouso; `/stop` desliga o destino

**WhatsApp** (WhatsApp Business Platform via fornecedor do ADR-018; bloqueado pela verificação Meta 👔)
- [ ] Adaptador para o fornecedor escolhido; credenciais em Docker secrets
- [ ] Templates de categoria *utility* submetidos e aprovados (ex.: `vigia_alerta_erro`, `vigia_codigo_verificacao`) em português; variáveis truncadas aos limites da Meta e sem PII
- [ ] **Opt-in obrigatório:** o utilizador introduz o número (normalizado para E.164, ex. `+244…`), recebe um código de verificação por WhatsApp e confirma na UI; só números verificados recebem alertas (impede enviar mensagens pagas para números de terceiros)
- [ ] Opt-out: responder "PARAR"/"STOP" ou desligar na UI → destino desactivado de imediato
- [ ] Webhook de estados (`sent`, `delivered`, `read`, `failed`) com verificação de assinatura (`X-Hub-Signature-256` HMAC-SHA256 no caso da Cloud API) e handshake de verificação; actualiza o histórico de entregas
- [ ] Quota mensal de mensagens por organização (2.0) e custo estimado visível ao owner; ao atingir 80 % e 100 %, aviso por email e fallback para Telegram/email
- [ ] Números de telefone encriptados em repouso e mascarados na UI (`+244 9•• ••• 123`)
- **🔒 Segurança (2.7):**
  - [ ] Webhooks de entrada (Telegram, WhatsApp) com verificação de segredo/assinatura, limite de body e rate limit; testes negativos com assinatura inválida e replay
  - [ ] Pedidos de saída só para hosts fixos dos fornecedores (`api.telegram.org`, host do ADR-018, SMTP), com `http.Client` com timeouts (nunca `http.DefaultClient`, já imposto pelo lint)
  - [ ] Tokens de ligação (Telegram) e códigos de verificação (WhatsApp) com CSPRNG, uso único, expiração curta, tentativas limitadas
  - [ ] Prevenção de header injection em emails e de injecção de markup em Telegram/WhatsApp

### 2.8 Frontend mínimo (`web/`)
- [ ] Bootstrap: Vite + React + TypeScript + Tailwind + TanStack Query + React Hook Form + Zod, `pnpm` com lockfile, tipos gerados do OpenAPI (`openapi-typescript`), CI do frontend (format, lint, type-check, testes) (§5.1, §16.1)
- [ ] Serviço `web` no `compose.yaml` (§16.5)
- [ ] Autenticação (registo, login, MFA, recuperação), organization switcher, membros e convites
- [ ] Projectos: criar projecto, mostrar o DSN e **guia de instalação por plataforma** (Node, browser/React, Python/Django, PHP/Laravel, Java/Spring, .NET, Go, React Native/Flutter) com snippets dos SDKs Sentry apontados ao Vigia
- [ ] Ecrã "a aguardar o primeiro evento" que detecta o primeiro erro recebido (polling)
- [ ] Issues: lista com filtros e pesquisa; detalhe com stack trace (frames `in_app` destacados), breadcrumbs, tags, contexto, utilizador, releases, gráfico simples de ocorrências; acções resolver/ignorar/atribuir
- [ ] Alertas: regras por projecto, teste de regra
- [ ] Notificações: ligar Telegram, verificar WhatsApp, email; preferências; histórico de entregas
- [ ] Teams (criar, membros) e gestão de API Credentials (DSN keys, ingest keys, client tokens: criar, rotar, revogar, segredo mostrado uma vez)
- [ ] Uso e quotas da organização; audit log
- [ ] Padrões de UX da §18.4 (loading/erro/vazio, teclado, contraste, timezone do utilizador) e português como idioma da UI
- **🔒 Segurança (2.8):**
  - [ ] Stack traces, mensagens, tags e breadcrumbs são **conteúdo não confiável**: renderizar sempre como texto; proibir `dangerouslySetInnerHTML` (regra de lint)
  - [ ] CSP estrita (sem `unsafe-inline`/`unsafe-eval`), cookies `HttpOnly`/`Secure`/`SameSite`, nunca tokens em `localStorage`
  - [ ] Permissões impostas no backend (a UI só reflecte); `pnpm audit` no CI

### 2.9 Compatibilidade, testes e go-live do MVP
- [ ] **Matriz de compatibilidade automatizada** (`tests/contract/sentry/`): apps mínimas em containers com os SDKs oficiais (`@sentry/node`, `@sentry/browser`, `sentry-python`, `sentry/sentry-laravel`, `sentry-java`, `sentry-dotnet`, `sentry-go`) enviam erros reais para o Vigia e os testes verificam issue criado, stack trace e agrupamento; corre no CI (nightly se for lento)
- [ ] Fixtures de envelopes reais gravados por SDK/versão para testes de regressão do parser
- [ ] E2E: SDK envia erro → issue → regra "novo issue" → notificação por email, Telegram e WhatsApp (sandbox) → resolver → regressão → nova notificação
- [ ] Load test da ingestão Sentry (rajadas de um SDK em loop de erros) com backpressure `429` + `X-Sentry-Rate-Limits` comprovado
- [ ] Documentação pública: "Migrar do Sentry em 2 minutos" (só trocar o DSN) e limitações conhecidas (sem performance/replays/profiling no MVP)
- [ ] **Go-live mínimo** (subconjunto da Fase 8, ADR-010):
  - [ ] Servidor de produção com Docker Compose, TLS 1.2+ automático (Caddy/Traefik), firewall, BD e Redis sem portas públicas
  - [ ] Graceful shutdown e resource limits (CPU/memória/processos) em todos os processos: `api`, `worker`, `scheduler`, `dispatcher` (§22)
  - [ ] Pipeline de deploy com imagem por SHA, staging com dados sintéticos e smoke test; rollback ensaiado
  - [ ] Backups automáticos encriptados + **restore testado**
  - [ ] `/metrics` e `/health/*` só na rede interna; monitorização mínima da ingestão, fila, dispatcher e entregas por canal
  - [ ] **Canal de alerta externo independente** para a própria plataforma (§14.3)
  - [ ] Runbooks: API em baixo, BD em baixo, backlog da fila, falha de fornecedor de notificação, abuso de ingestão, compromisso de credencial, exposição de dados de tenant
  - [ ] Revisão de segurança 🧭 + scan de imagem (Trivy) e SBOM
  - [ ] 👔 Termos de serviço, política de privacidade e processo de pedidos de eliminação de dados publicados
  - [ ] 👔 Parecer jurídico sobre a transferência de dados para fora de Angola (autorização da APD, Lei n.º 22/11) e, se necessário, pedido de autorização feito (pergunta 10)

### 2.10 SDK Go próprio (logo a seguir ao go-live, por decisão do CEO) 🧭
> Só começa depois de a 2.9 estar fechada; não bloqueia o lançamento. Os clientes Go continuam a poder usar o `sentry-go` com o DSN do Vigia.

- [ ] ADR curto: âmbito do SDK Go (só erros e mensagens no início; métricas quando a Fase 3 existir), protocolo de envio (envelope compatível com a ingestão da 2.2) e o que o distingue do `sentry-go`
- [ ] `sdks/go/` como módulo Go separado (`go.mod` próprio, sem depender de `internal/`): `Init(dsn)`, `CaptureException`, `CaptureMessage`, `Recover` (middleware `net/http`), `Flush`, `Close`
- [ ] Redacção local, fila limitada em memória, batching, retry com backoff e respeito por `429` + `X-Sentry-Rate-Limits`; nunca bloqueia nem derruba a aplicação do cliente
- [ ] Testes de contrato contra a ingestão real (`tests/contract/`), testes de resiliência (plataforma em baixo, lenta, 429) e `-race`
- [ ] Publicação com versionamento semântico (tags `sdks/go/vX.Y.Z`), documentação e exemplos

---

## Fase 3 — Métricas e Ingestão de Telemetria

> ⚠ §17: retenção, privacidade e quotas de métricas definidas **antes** de abrir esta ingestão (ADR-007, ADR-009). Reutiliza fila, worker, redaction e quotas da Fase 2.

- [ ] Hypertable `metrics` + índices + continuous aggregate `metrics_1m` **com `add_continuous_aggregate_policy`** + retenção + compressão com `segmentby` por tenant/série (§8.3)
- [ ] Armazenamento de `events` conforme ADR-016 (§7.1)
- [ ] Camada de acesso à telemetria abstraída (interface `TelemetryStore`) para permitir ClickHouse no futuro (§8.5)
- [ ] Quotas de métricas: séries activas, eventos/minuto, payload/batch/profundidade/descomprimido, política de cardinalidade (§7.1, §17.1)
- [ ] Rate limit por key, por tenant e por IP na ingestão de telemetria (§7.1)
- [ ] `ingestion`: `POST /api/v1/ingest/metrics` e `/events` com `vg_ing_` key, envelope comum (`event_id`, `schema_version`, `received_at`, `source`) (§8.4), dedup, `202 Accepted`, backpressure `429`/`503` + `Retry-After` (§7.1)
- [ ] Escrita em lote (`COPY` / multi-row) no worker (§13.4)
- [ ] `metrics`: `GET /api/v1/metrics/query`, `/metrics/history`, `/metrics/names` com limites de intervalo/step/séries/pontos/timeout (§9.2)
- [ ] Cache de leitura Redis com prefixo de tenant e TTL curto (§13.7)
- [ ] Métricas de host/aplicação/BD/infra da §7.4: exemplos de envio (script/exporter) (§7.4, §24.2 #7)
- [ ] Load test base + comportamento sob sobrecarga + validação da retenção (§15.4, §20.1)
- [ ] E2E: ingerir métricas (§15.2 #5)
- **🔒 Blindagem de Segurança (Fase 3):**
  - [ ] Gzip-bomb, profundidade de JSON e itens por batch + testes negativos
  - [ ] Anti-explosão de cardinalidade (rejeitar `user_id`, `email`, `request_id`, UUIDs arbitrários; limite de séries activas por tenant)
  - [ ] Validação de `occurredAt` (futuro > 5 min ou fora da janela → rejeitar) + `received_at`
  - [ ] Redacção antes de enfileirar/persistir + testes de regressão com segredos/PII sintéticos; tenant derivado só da `vg_ing_` key
  - [ ] Anti-DoS nas queries de leitura (intervalo máximo, `step` mínimo, limites, `statement_timeout`, nomes validados)
  - [ ] Defesa contra *queue poisoning* e fuzzing dos parsers (`go test -fuzz`)
  - [ ] Isolamento de *noisy neighbors*: quotas e limites por tenant, nenhum tenant consegue degradar a ingestão dos outros (§11.3)

---

## Fase 4 — Alertas de Métricas, Incidentes e Tempo Real (SSE)

- [ ] Migrations: `alert_state` completo, `incidents`, `incident_events`, `silences`, `maintenance_windows` (§8.2)
- [ ] Regras de métricas: query versionada, dry-run, máquina de estados (`Normal → Pending → Firing → Resolved`), `last_evaluation_error`/`consecutive_errors`, `noDataBehavior` (§7.5)
- [ ] Subcomando `vigia evaluator` com lock distribuído por `(rule_id, scope_key)` e detecção de schedules perdidos (§4.4, §7.5)
- [ ] Anti-ruído completo: dedup, grouping, repeat interval, limites por destino, digest (§7.5)
- [ ] Consistência eventual do motor de alertas documentada (§7.5)
- [ ] Silences e maintenance windows (§9.2) — aplicáveis também aos alertas de erro da Fase 2
- [ ] **Meta-alerta** sobre falhas do próprio alert engine (§7.5)
- [ ] `incidents`: `open → acknowledged → resolved`, reabertura por política, timeline append-only, `acknowledge|resolve|assign|notes`; issues da Fase 2 podem ser ligados a incidentes (§7.6, §7.8)
- [ ] Stream SSE (`GET /api/v1/stream`, `POST /api/v1/stream/ticket`) com heartbeat, `Last-Event-ID` e fan-out via Redis Pub/Sub `org:<id>:*` (§10.4)
- [ ] Notificações in-app via SSE + `GET /notifications`, `PATCH /notifications/:id/read`, `POST /notifications/read-all` (§9.2)
- [ ] Eventos "notificação enviada/falhada" na timeline do incidente (§7.6)
  - [ ] ⚠ O `WriteTimeout` global de 15 s corta streams SSE: usar `http.ResponseController.SetWriteDeadline` por rota
  - [ ] Clientes máquina-a-máquina via `fetch` + `Authorization: Bearer vg_cli_…`
- [ ] Testes de propriedade/fuzz da máquina de estados com relógio injectável (§15.5)
- [ ] E2E: ingestão → regra → `pending → firing` → incidente (dedup) → notificação → ack → resolução → SSE (§15.2 #6–11)
- **🔒 Blindagem de Segurança (Fase 4):**
  - [ ] Tickets SSE ≤ 30 s, uso único, CSPRNG; nunca tokens de longa duração na URL
  - [ ] Ownership/permissões em cada subscrição + teste cross-tenant de SSE; limite de ligações por utilizador/tenant
  - [ ] Validação estrita de `query_definition` (zero SQL; timeout e custo limitados)
  - [ ] Timeline append-only, transições auditadas

---

## Fase 5 — Canais Adicionais: Webhooks e Web Push

- [ ] `internal/platform/ssrf`: cliente HTTP seguro (resolução DNS + validação de IP antes de ligar, ligar ao IP validado, bloqueio de loopback/RFC1918/link-local/multicast/metadata/IPv6/ofuscados, revalidação por redirect, limites) + suite SSRF base (§11.2)
- [ ] Webhooks de saída: Challenge-Echo, HMAC-SHA256 (`timestamp + "." + body`), `X-Vigia-Event-Id`/`X-Vigia-Timestamp`/`X-Vigia-Signature`, segredo encriptado com rotação; Slack/Discord/Teams documentados como destinos webhook (§7.7)
- [ ] Endpoints `POST /notification-destinations/:id/verify` e `/test` para webhooks (§9.2)
- [ ] Web Push (VAPID via `webpush-go`) com service worker no frontend; remoção de subscriptions inválidas (§7.7)
- [ ] SMS (opcional, se o CEO decidir) via fornecedor local, com quota (§12)
- **🔒 Blindagem de Segurança (Fase 5):**
  - [ ] Todos os webhooks pelo cliente `ssrf`; subscriptions Web Push encriptadas; previews sem PII; rate limit por destino

---

## Fase 6 — Pull Collectors (`http_get_json` e `db_readonly`)

- [ ] ADR-012 aprovado antes de começar
- [ ] Migration: `collectors` (§8.2)
- [ ] `collectors`: `http_get_json` (mapping JSONPath) e `db_readonly` (queries nomeadas pré-aprovadas, read-only, `LIMIT`, `statement_timeout`, cursor incremental) (§7.2)
- [ ] Motores suportados em `db_readonly` na V1 (ex.: só PostgreSQL) documentados
- [ ] Execução pelo scheduler com concorrência e janela por tenant; mesmo pipeline de validação/redacção/dedup/quotas (§7.2)
- [ ] Endpoints `GET|POST /projects/:id/collectors`, `GET|PATCH|DELETE /collectors/:id`, `/test`, `/run` (§9.2)
- [ ] Métrica e alerta interno `collector_failures` + atraso do cursor (§7.2, §14.1)
- [ ] E2E: collector pull com cursor incremental (§15.2 #14)
- **🔒 Blindagem de Segurança (Fase 6 — Alto Risco):**
  - [ ] Suite SSRF completa: loopback, RFC1918, link-local, `169.254.169.254`, IPv4-mapped IPv6, octal/hex/decimal, DNS rebinding, redirects
  - [ ] `db_readonly`: nunca SQL arbitrário; transacção `READ ONLY`, views dedicadas; host da BD externa validado contra SSRF
  - [ ] Credenciais externas encriptadas, nunca devolvidas nem logadas; egress policy nos containers
  - [ ] Redacção e política de dados proibidos aplicadas aos dados importados **antes** de entrarem no pipeline (§7.2, §17.3)
  - [ ] Limites de concorrência, tamanho de resposta e timeout por tenant (§7.2)
  - [ ] **Revisão de segurança dedicada** (critério de saída)

---

## Fase 7 — Uptime Checks e Dashboards

- [ ] Migrations: `monitors`, `monitor_check_results` (retenção própria) (§8.2)
- [ ] `monitors`: HTTP/HTTPS (`GET`/`HEAD`) via cliente `ssrf`, `expectedStatuses`/`expectedContent`, retries, N falhas / M sucessos, uptime com timezone e exclusão de manutenção (§7.3)
- [ ] Monitor em falha gera incidente e notificação (§7.6)
- [ ] Limitação de região única de probe documentada (§7.3)
- [ ] Endpoints `/projects/:id/monitors`, `GET|PATCH|DELETE /monitors/:id`, `/test`, `/results` (§9.2)
- [ ] Persistência de dashboards/widgets (tabela `dashboards` com config JSONB versionada; actualizar §8.2)
- [ ] UI: overview (§18.2), vista de projecto (§18.3), os 8 dashboards da §7.4 com `uPlot`/`ApexCharts`, monitors, alert rules de métricas, incidents (timeline, ack/resolve), silences
- [ ] E2E de UI (Playwright) para os fluxos críticos
- **🔒 Blindagem de Segurança (Fase 7):**
  - [ ] Uptime checks obrigatoriamente pelo cliente `ssrf`
  - [ ] Sanitização de Markdown de alertas (DOMPurify/allowlist)

---

## Fase 8 — Hardening e Escala

> O go-live mínimo já aconteceu na 2.9. Esta fase leva a plataforma ao nível do Checklist de Produção completo (§22).

- [ ] OpenTelemetry Go SDK + `GET /metrics` com todas as métricas da §14.1; dogfooding (erros do Vigia enviados para o próprio Vigia via SDK Sentry Go) (§14.3)
- [ ] Dashboard de SLOs e alertas internos (§14.4)
- [ ] Rolling/canary, feature flags para mudanças de risco (§16.2)
- [ ] PgBouncer e limites de pool por processo; réplicas de leitura se necessário (§13.7, §13.9)
- [ ] Separação de processos conforme medições (ingestion → worker → evaluator → dispatcher) (§4.4)
- [ ] Restantes runbooks da §14.5 + processo de resposta a incidentes e template de postmortem (§14.6)
- [ ] Workflows completos de export e delete, retenção por plano, retenção de audit logs separada (§17.2)
- [ ] Resiliência/chaos: worker morto, Redis/Postgres fora, failover, poison messages, backlog, relógio dessincronizado, rate limit de fornecedores (§15.3)
- [ ] Performance e baseline de capacidade com `pprof`/benchmarks (§13, §15.4)
- [ ] Revisão integral do isolamento de tenants (§20.1)
- [ ] Quotas por plano aplicadas a todos os recursos da §17.1 (monitores, regras, projectos, membros, destinos, collectors, concorrência de queries…)
- [ ] Requisitos legais documentados e revistos (lei angolana de protecção de dados, residência de dados) (§17.3)
- **🔒 Blindagem de Segurança (Fase 8 — Auditoria Final):**
  - [ ] DAST/pentest em staging (OWASP API Top 10: BOLA, BOPLA, BFLA, SSRF, rate limiting, misconfiguration)
  - [ ] TLS 1.2+ verificado em todos os pontos de entrada; rotação de segredos ensaiada (pepper, KEK, tokens de fornecedores); backups encriptados com acesso restrito
  - [ ] Scan de imagens (Trivy/Docker Scout), SBOM, `govulncheck`, `gosec` e secret scanning verdes
  - [ ] Checklist de Produção (§22) aprovado e **riscos residuais aceites por escrito** 👔🧭

---

## Fase 9 — Logs Estruturados e Traces (Pós-V1)

- [ ] ADR-006 aprovado
- [ ] Hypertable `logs` + `POST /api/v1/ingest/logs` com pesquisa limitada por tempo e resultado (§7.9, §8.3)
- [ ] Ingestão OpenTelemetry (`POST /api/v1/ingest/otel` / OTLP-HTTP) (§7.9, §9.2)
- [ ] Aceitar `transaction`/`span` dos SDKs Sentry (hoje descartados na 2.2) e logs Sentry, se fizer sentido de produto
- [ ] Traces/spans, sampling, service map e correlação logs ↔ erros ↔ métricas (§7.9)
- [ ] Escalation policies e on-call (§3.2)
- **🔒 Blindagem de Segurança (Fase 9):**
  - [ ] Redacção obrigatória em payloads OTLP/logs + limites por query + exports auditados

---

## Fase 10 — Expansão (Pós-V1)

- [ ] SDKs próprios adicionais (Node ou outros; o de Go está na 2.10) **só se** surgir necessidade que os SDKs Sentry não cobrem; se for feito: redacção local, fila limitada, batching, retry/backoff, non-blocking, testes de resiliência e publicação no npm com provenance (§19); host agent em Go (§3.3)
- [ ] Session replay, profiling e performance compatíveis com SDKs Sentry, se houver procura
- [ ] Evolução para ClickHouse se as medições provarem os limites do TimescaleDB (§4.2, §8.5)
- [ ] SSO/OIDC/SAML enterprise; push mobile (FCM/APNs) com apps nativas; integrações nativas Slack/Teams (§3.3, §12)
- **🔒 Blindagem de Segurança (Fase 10):**
  - [ ] Validação rigorosa de assinaturas/claims OIDC/SAML; mTLS opcional para agents; isolamento de tenant no ClickHouse

---

## 📝 Lacunas encontradas no README (a corrigir lá)

- [x] §26 desactualizada face ao código (corrigido)
- [x] §3 e §20 reflectem o novo roadmap com o MVP de error tracking (corrigido)
- [ ] §8.3 sem `add_continuous_aggregate_policy` para `metrics_1m` (sem ela o agregado não é actualizado)
- [ ] §8.2 sem tabela para `events` genéricos nem para `dashboards`; sem `projects.public_id` nem `api_credentials.kind = dsn`
- [ ] §7.8 e §9.2 sem a especificação da ingestão compatível Sentry (fica no ADR-017; resumir no README quando aprovado)
- [ ] §26.4 sem `ADMIN_PORT`, parâmetros de pool da BD, `TELEGRAM_BOT_TOKEN_FILE` e credenciais do WhatsApp
- [ ] §5.1 indica `caarlos0/env` mas o código usa parsing manual — decidir e alinhar

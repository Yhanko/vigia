# Threat Model — Vigia

- **Versão:** 1.1 (Fase 0 — Discovery; correcções da revisão do CTO aplicadas)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini) · Revisão: CTO (Claude)
- **Referências:** README §10, §11.1–11.9, §17.3; ADR-005, ADR-008, ADR-015; TASKS 0.3

> Documento vivo. Deve ser revisto **antes** de cada funcionalidade de alto risco (1.2 Auth/RBAC, 2.2 Ingestão Sentry, 2.7 Telegram/WhatsApp, 5/6 SSRF e Collectors).

---

## 1. Activos a proteger (§11.7)

| ID | Activo | Sensibilidade | Impacto de compromisso |
|---|---|---|---|
| A1 | Dados de telemetria e `issue_events` (stack traces, contexto, breadcrumbs, source maps) | Confidencial | Exposição de código proprietário, PII acidental ou vulnerabilidades dos clientes |
| A2 | Credenciais e API keys (`vg_ing_`, `vg_cli_`, `dsn`, segredos de sessão/pepper/KEK) | Segredo | Ingestão fraudulenta, leitura não autorizada ou tomada de conta |
| A3 | Identidades de utilizadores (passwords Argon2id, sessões, segredos TOTP/MFA, emails) | Segredo / PII | Account takeover, escalada para `owner`/`admin` |
| A4 | Metadata dos tenants (organizações, projectos, membros, regras, audit logs) | Confidencial | Fuga cross-tenant, violação legal (Lei n.º 22/11) |
| A5 | Segredos de canais e integrações (token bot Telegram, credenciais WhatsApp/SMTP, webhooks HMAC, credenciais de collectors) | Segredo | Abuso financeiro (WhatsApp pago), envio de phishing em nome da Yhanko, acesso a BDs de clientes |
| A6 | Contactos e subscriptions de notificação (números de telefone E.164, `chat_id` Telegram, Web Push keys) | Confidencial / PII | Spam, assédio, fuga de dados pessoais |
| A7 | Dados de incidentes, alertas e `audit_logs` | Confidencial / Integridade | Ocultação de intrusão, perda de rasto forense |
| A8 | Metadata de infraestrutura (rede interna, containers, Docker secrets, backups) | Segredo | Movimento lateral, acesso directo a PostgreSQL/Redis |
| A9 | Disponibilidade e integridade da plataforma | Operacional | Cegueira operacional dos clientes durante incidentes reais |

---

## 2. Fronteiras de confiança (Trust Boundaries)

```mermaid
flowchart LR
  subgraph Internet["Zona Não Confiável (Internet)"]
    Browser["Browser / UI (Utilizadores)"]
    SDKs["SDKs Sentry / Scripts / Servidores"]
    ExtProviders["Telegram / Meta WhatsApp / SMTP / Destinos Webhook"]
  end

  subgraph Edge["TB-1 / TB-2 / TB-5: Edge (Reverse Proxy TLS + vigia api)"]
    API["Product API (/api/v1/*)"]
    Ingest["Ingestion (/api/{public_id}/envelope|store, /ingest/*)"]
    InWebhooks["Webhooks Entrada (Telegram / WhatsApp)"]
  end

  subgraph Core["TB-3: Rede Interna Backend (internal: true)"]
    Workers["Workers / Scheduler / Evaluator / Dispatcher"]
    PG[("PostgreSQL + TimescaleDB")]
    Redis[("Redis (Queue, Locks, Cache)")]
  end

  subgraph Ops["TB-6: Rede Interna Operação"]
    Admin["/health/* e /metrics (ADMIN_PORT)"]
  end

  Browser -->|TB-1: HTTPS + Cookie HttpOnly + CSRF| API
  SDKs -->|TB-2: HTTPS + DSN / vg_ing_| Ingest
  ExtProviders -->|TB-5: HTTPS + Secret/HMAC| InWebhooks
  API --> PG
  API --> Redis
  Ingest --> Redis
  Workers --> PG
  Workers --> Redis
  Workers -->|TB-4: Egress controlado / SSRF client| ExtProviders
```

- **TB-1 (Browser → Product API `/api/v1/*`):** tráfego autenticado por cookie `HttpOnly` + CSRF ou `vg_cli_`.
- **TB-2 (SDKs/Clientes → Ingestão):** tráfego não confiável de alto volume; chaves `dsn` são públicas em browsers.
- **TB-3 (Processos Vigia → PostgreSQL/Redis):** rede Docker `backend` (`internal: true`), sem acesso à internet nem portas públicas.
- **TB-4 (Vigia → Serviços Externos):** notificações (Telegram, WhatsApp, SMTP, Webhooks) e futuros collectors/monitors (vector principal de SSRF).
- **TB-5 (Telegram/Meta → Webhooks de Entrada):** pedidos vindos da internet que alteram estado (ligação de conta, opt-out, estados de entrega).
- **TB-6 (Operação Interna):** `/health/live`, `/health/ready` e `/metrics` (Prometheus), nunca expostos publicamente.

---

## 3. Análise STRIDE completa por fronteira de confiança

### TB-1 — Product API (`/api/v1/*`) e Frontend (`web/`)
| Categoria | Ameaça concreta | Controlo obrigatório | Fase |
|---|---|---|---|
| **S** (Spoofing) | Brute-force em login/MFA, roubo de sessão via XSS, session fixation, enumeração de contas | Argon2id (`m=19 MiB, t=2, p=1`) + timing constante; cookies `HttpOnly`/`Secure`/`SameSite=Lax`; rotação de sessão; rate limit **antes** do hash + lockout; MFA obrigatório para `owner`/`admin` (ADR-005) | 1.2 |
| **T** (Tampering) | CSRF em acções destrutivas; manipulação de `organizationId` no body; mass assignment | `Origin` + `X-CSRF-Token`; `DecodeJSON` com `DisallowUnknownFields`; `organization_id` derivado só da sessão/credencial (ADR-008) | 1.1 / 1.2 |
| **R** (Repudiation) | Utilizador nega ter alterado roles, revogado keys ou apagado projecto | `audit_logs` append-only (`SELECT`/`INSERT` apenas para `vigia_app`) com `request_id`, actor, recurso e diff sanitizado | 1.2 |
| **I** (Info Disclosure) | BOLA/IDOR cross-tenant; fuga de segredos em logs ou respostas de erro; XSS em stack traces/Markdown | `TenantID` obrigatório + PostgreSQL RLS *fail-closed* (ADR-008); `404` em acesso cross-tenant; `config.Secret`; zero stack traces em respostas; renderização como texto + CSP estrita na UI | 1.1 / 1.2 / 2.8 |
| **D** (DoS) | Slowloris, bodies gigantes, exaustão de RAM por Argon2id concorrente, queries pesadas | Timeouts HTTP explícitos + `MaxBytesMiddleware` (`API_MAX_BODY_BYTES`); semáforo Argon2id (ex.: 4) + rate limit antes do hash; paginação por cursor; `statement_timeout` | 1.1 / 1.2 |
| **E** (Elevation) | `viewer`/`member` executa acções de `admin`/`owner`; `vg_ing_`/`dsn` acede a `/api/v1/*` | Middleware RBAC por permissão em cada endpoint; separação rígida por `credential_kind` + testes negativos | 1.2 / 1.3 / 2.1 |

### TB-2 — Ingestão (Sentry `/api/{public_id}/envelope|store` e Telemetria `/ingest/*`)
| Categoria | Ameaça concreta | Controlo obrigatório | Fase |
|---|---|---|---|
| **S** (Spoofing) | Uso de chave `dsn` de outro projecto ou chave revogada; spoofing de `occurredAt` | Validar `(public_key, public_id)` em conjunto; parsing por posição; revogação imediata com invalidação Redis (`cred:dsn:<public_key>` para `dsn`, `cred:<kind>:<prefix>` para `ingest`/`client`); guardar `received_at` do servidor e rejeitar timestamps absurdos | 2.1 / 2.2 / 3 |
| **T** (Tampering) | Envelopes malformados com `length` mentiroso; queue poisoning; injecção de HTML/markup que chega a Telegram/UI | Parser streaming com limites estritos + `go test -fuzz`; escape HTML no Telegram; renderização como texto na UI | 2.2 / 2.7 / 2.8 |
| **R** (Repudiation) | Cliente ou atacante nega envio de rajadas/eventos ou uso anómalo de chave | Registo estruturado com `event_id`, `received_at`, `credential_id`/`prefix` mascarado (nunca `public_key` completa) e auditoria de uso anómalo de keys (§10.2) | 1.3 / 2.2 |
| **I** (Info Disclosure) | SDK envia passwords, cookies, cartões ou request bodies (PII) para o Vigia | Descartar `request.data`/cookies por defeito; scrubbing no servidor **antes** de enfileirar (independente de `send_default_pii`) | 2.2 / 2.3 |
| **D** (DoS) | Zip-bomb (`gzip`/`br`/`deflate`), loop infinito de erros num SDK (flood), JSON profundo, explosão de cardinalidade, *noisy neighbor* | Limite do tamanho **descomprimido**; profundidade máxima JSON; rate limit + `429` + `X-Sentry-Rate-Limits`; quotas diárias por org; filas/concorrência por tenant; allowlist de labels na Fase 3 | 2.0 / 2.2 / 3 |
| **E** (Elevation) | Uso de chave `dsn` pública ou `vg_ing_` para ler eventos/issues ou aceder a endpoints administrativos | Separação rígida por `credential_kind`; `dsn` e `vg_ing_` rejeitadas em todas as rotas de leitura/admin `/api/v1/*` + testes negativos obrigatórios | 1.3 / 2.1 |

### TB-3 — Rede Interna (`api`, `worker`, `scheduler`, `dispatcher`, PostgreSQL, Redis)
| Categoria | Ameaça concreta | Controlo obrigatório | Fase |
|---|---|---|---|
| **S** (Spoofing) | Acesso não autenticado a PostgreSQL ou Redis | `SCRAM-SHA-256` em Postgres; ACL obrigatória em Redis (`users.acl` em `tmpfs`); rede `backend` com `internal: true` | 0 / 1.1 |
| **T** (Tampering) | `FLUSHALL`/`CONFIG` no Redis; `UPDATE`/`DELETE` em `audit_logs`; container comprometido modifica filesystem | Comandos `@admin`, `FLUSHALL`, `FLUSHDB` bloqueados no Redis; role `vigia_app` sem `UPDATE`/`DELETE` em tabelas append-only; containers `read_only`, `cap_drop: ALL`, `no-new-privileges`, `distroless` não-root | 0 / 1.2 |
| **R** (Repudiation) | Alteração de schema ou acesso indevido à BD sem rasto | PostgreSQL regista autenticações, desconexões, DDL (`log_statement=ddl`) e queries lentas (> 500 ms); `audit_logs` append-only | 0 / 1.2 |
| **I** (Info Disclosure) | Fuga de Docker secrets via `docker inspect` ou logs; exposição de backups | Segredos apenas em ficheiros (`*_FILE`), nunca em env vars; `config.Secret`; envelope encryption AES-256-GCM para segredos em BD (ADR-015); backups encriptados com acesso restrito | 0 / 1.1 / 1.2 |
| **D** (DoS) | Saturação de ligações PostgreSQL, evicção silenciosa de jobs no Redis ou esgotamento de CPU/RAM | Pool `DATABASE_MAX_CONNS` + `statement_timeout`; `maxmemory-policy noeviction` no Redis; limites de CPU, memória e PIDs em todos os containers no `compose.yaml` | 0 / 1.1 |
| **E** (Elevation) | Processo de runtime liga como `SUPERUSER` (`vigia`) e contorna RLS; escalada de privilégios no container | Role `vigia_app` (`NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`) com secret próprio (`postgres_app_password`) + teste de integração obrigatório (ADR-008); `no-new-privileges` e utilizador não-root `65532` | 0 / 1.2 |

### TB-4 — Saída para Fornecedores e Destinos Externos (Notificações, Webhooks, Collectors, Monitors)
| Categoria | Ameaça concreta | Controlo obrigatório | Fase |
|---|---|---|---|
| **S** (Spoofing) | Receptor de webhook não consegue validar que o pedido veio do Vigia; abuso de WhatsApp pago para números de terceiros | Assinatura HMAC-SHA256 (`timestamp + "." + body`) + Challenge-Echo (Fase 5); **opt-in obrigatório por código** no WhatsApp + quota mensal (Fase 2.7) | 2.7 / 5 |
| **T** (Tampering) | Alteração em trânsito ou replay de payloads de webhook | TLS 1.2+ obrigatório; assinatura HMAC-SHA256 sobre payload canonicalizado + header `X-Vigia-Timestamp` (janela de 5 min) + `X-Vigia-Event-Id` idempotente | 5 |
| **R** (Repudiation) | Divergência sobre se uma notificação foi enviada ou falhou | Histórico persistido em `notifications` (`pending | sent | failed | suppressed`, `attempt_count`, `providerMessageID`, erro redigido); documentação explícita de que "tentativa ≠ recepção no dispositivo" (§7.7) | 2.6 |
| **I** (Info Disclosure / SSRF) | Fuga de PII/stack traces em previews; SSRF para rede interna (`127.0.0.1`, `169.254.169.254`, `db:5432`/`redis:6379`) via DNS rebinding ou redirects | Previews só com resumo curto + link autenticado; na Fase 2.7 apenas hosts fixos dos fornecedores (`api.telegram.org`, API Meta/BSP, SMTP); nas Fases 5–7 cliente `internal/platform/ssrf` obrigatório + egress policy | 2.6 / 2.7 / 5–7 |
| **D** (DoS) | Fornecedor externo lento/indisponível bloqueia o dispatcher ou estoura custos de WhatsApp | Timeouts explícitos (`http.Client` dedicado), retries com backoff exponencial + jitter, DLQ, circuit breaker por canal, rate limit por destino e quota mensal de WhatsApp com fallback | 2.6 / 2.7 |
| **E** (Elevation) | N/A — fronteira de saída para terceiros: destinos externos não recebem credenciais nem privilégios internos da plataforma; qualquer tentativa de atingir serviços internos é tratada como SSRF em **I** acima | Garantir que headers/credenciais internos nunca são encaminhados para destinos externos (§11.2) | 5–7 |

### TB-5 — Webhooks de Entrada (Telegram e WhatsApp)
| Categoria | Ameaça concreta | Controlo obrigatório | Fase |
|---|---|---|---|
| **S** (Spoofing) | Atacante envia payloads falsos para `/integrations/telegram/webhook` ou webhook WhatsApp para associar contas ou forjar estados | Telegram: validar `X-Telegram-Bot-Api-Secret-Token` em tempo constante. WhatsApp: validar `X-Hub-Signature-256` (HMAC-SHA256). Tokens de ligação `/start <token>` CSPRNG, uso único, expiram em 10 min | 2.7 |
| **T** (Tampering) | Modificação em trânsito ou replay de callbacks de estado (`sent`/`delivered`/`failed`) | TLS 1.2+ + verificação HMAC/secret token + idempotência por ID do evento do fornecedor | 2.7 |
| **R** (Repudiation) | Contestação de opt-out ("PARAR"/"STOP") ou associação/desassociação de conta | Registo auditável de cada ligação (`/start`, `/link`), opt-out e mudança de estado de destino | 2.7 |
| **I** (Info Disclosure) | N/A — endpoints de webhook de entrada apenas ingerem callbacks dos fornecedores e respondem `200` com corpo vazio/mínimo, sem devolver dados de utilizadores ou tenants | Nunca ecoar payloads nem detalhes internos em respostas de erro de webhooks | 2.7 |
| **D** (DoS) | Flood nos endpoints públicos de webhook | Limite de body estrito + rate limit por IP | 2.7 |
| **E** (Elevation) | Utilizador sem permissão tenta associar grupo Telegram a projecto via `/link <token>` | O token de `/link` só é emitido mediante verificação RBAC (`notification_policy:manage`) na API autenticada; webhooks nunca concedem sessão nem privilégios | 2.7 |

### TB-6 — Operação Interna e Cadeia de Fornecimento
| Categoria | Ameaça concreta | Controlo obrigatório | Fase |
|---|---|---|---|
| **S** (Spoofing) | Acesso não autorizado aos endpoints de operação (`/metrics`, `/health/ready`) | Isolamento em listener interno separado (`ADMIN_PORT`), não exposto no reverse proxy público | 1.1 / 2.9 |
| **T** (Tampering) | Dependência comprometida em Go/npm ou imagem Docker reescrita no registry | `go.sum` e `pnpm-lock.yaml` fixos; imagens base fixadas por **digest SHA-256**; Dependabot com cooldown de 7 dias; `govulncheck`, `gosec`, `gitleaks`, `pnpm audit`, Trivy e SBOM no CI | 1.0 / 2.9 |
| **R** (Repudiation) | Deploy de código não rastreável em produção | Artefactos imutáveis etiquetados pelo SHA do commit (`VERSION`/`COMMIT` injectados via `-ldflags` e visíveis em `/api/v1/status` e `vigia version`) | 1.0 / 2.9 |
| **I** (Info Disclosure) | Exposição pública de métricas internas ou detalhes de erro de BD/Redis em `/health/ready` | `ADMIN_PORT` apenas na rede interna; `/health/ready` devolve apenas `"ok"`/`"error"` sem mensagens internas (coberto por `TestReadinessChecks`) | 1.1 / 2.9 |
| **D** (DoS) | N/A — endpoints internos não são expostos à internet; os healthchecks internos aplicam timeouts curtos (2–3 s) para não bloquear workers | Manter `ADMIN_PORT` fora da rede pública e `context.WithTimeout` nos checks | 1.1 / 2.9 |
| **E** (Elevation) | Compromisso de pipeline CI ou acção GitHub maliciosa altera imagem/código | Branch protection na `main` com jobs obrigatórios; acções GitHub fixadas; revisão obrigatória do CTO 🧭 | 1.0 |

---

## 4. Mapeamento completo das ameaças da §11.7 do README

| Ameaça (README §11.7) | Fronteira | Controlo principal | Teste / Verificação |
|---|---|---|---|
| Acesso cross-tenant / BOLA | TB-1, TB-2, TB-3 | `TenantID` + RBAC + PostgreSQL RLS *fail-closed* com `vigia_app` (ADR-008) | `tests/security/` cross-tenant + teste `rolsuper`/`rolbypassrls` |
| Roubo de credenciais / fuga de API key | TB-1, TB-2 | Argon2id (`m=19 MiB, t=2, p=1`) / HMAC-SHA256 + pepper, scope mínimo, MFA, revogação imediata (ADR-005) | Testes de revogação imediata e scope negativo |
| SSRF via collectors/monitors/webhooks | TB-4 | Hosts fixos na Fase 2.7; `internal/platform/ssrf` nas Fases 5–7 + egress policy | Suite SSRF (DNS rebinding, redirects, IPs ofuscados) |
| DoS / abuso de ingestão e login | TB-1, TB-2 | Rate limit antes de Argon2id + semáforo; quotas, `MaxBytesReader`, limite descomprimido, `429`/`503` | Load test + testes zip-bomb/payload gigante/login concorrente |
| Abuso de queries de telemetria | TB-1 | Intervalo máximo, `step` mínimo, limite de séries/pontos, `statement_timeout` | Testes negativos de query |
| Injecção / payloads maliciosos | TB-1, TB-2, TB-5 | `sqlc` parametrizado, `DecodeJSON` estrito, `go test -fuzz` nos parsers | Fuzzing + `gosec` |
| XSS via logs/erros/Markdown | TB-1 | Renderização como texto na UI, proibição de `dangerouslySetInnerHTML`, DOMPurify em Markdown, CSP estrita | Lint frontend + testes XSS |
| CSRF (cookie-auth) | TB-1 | `SameSite=Lax` + `Origin` + `X-CSRF-Token` | Testes negativos sem header/origin |
| Replay/duplicação de eventos e webhooks | TB-2, TB-4, TB-5 | `event_id` dedup (Redis + `UNIQUE`), HMAC + janela de timestamp | Testes de replay |
| Queue poisoning | TB-2, TB-3 | Validação/scrubbing antes de enfileirar, limites de tamanho, DLQ | Testes de poison message |
| Escalada de privilégios | TB-1, TB-3 | RBAC por permissão no backend, `audit_logs`, re-autenticação, `vigia_app` mínimo | Testes negativos por role |
| Segredos em logs | TB-1, TB-2, TB-3 | `config.Secret`, mascaramento de `dsn`, redacção, testes de regressão | `TestSecretRedaction` + `gitleaks` |
| Explosão de cardinalidade | TB-2 | Allowlist de labels e limite de séries activas por tenant (Fase 3) | Testes de quota/cardinalidade |
| Compromisso de worker | TB-3, TB-4 | `distroless` não-root, `read_only`, `cap_drop: ALL`, `vigia_app` mínimo, egress | `docker compose config` + revisão |
| Fuga em notificações | TB-4 | Previews sem PII/stack trace completo; link autenticado | Testes de template/scrubbing |
| Cadeia de fornecimento | TB-6 | Digests, lockfiles, Dependabot cooldown 7d, `govulncheck`, Trivy, SBOM | CI `security` job |
| Backup exposto | TB-3 | Backups encriptados, acesso restrito, restore ensaiado | Runbook + teste de restore |

---

## 5. Riscos residuais conhecidos na Fase 0

1. **Abuso de chaves `dsn` públicas:** como a chave `dsn` é pública por natureza (visível em browsers), um actor externo pode tentar gerar flood ou consumir a quota de um projecto. **Importante:** `allowed_origins` trava apenas abuso proveniente de browsers (via CORS); scripts fora do browser forjam trivialmente o header `Origin`. Por isso, **a defesa real contra flood com DSN é rate limit + quotas + revogação/rotação imediata** (complementada por inbound filters).
2. **Garantia fim-a-fim de notificações externas:** email, Telegram e WhatsApp dependem de terceiros; o Vigia garante entrega até ao fornecedor com retries/DLQ e regista o estado de entrega, mas não controla a recepção no dispositivo final (§7.7).
3. **Protecção de dados pessoais (Lei n.º 22/11):** requer enquadramento jurídico (termos, política de privacidade e workflow de eliminação) antes do go-live da Fase 2.9 (acção 👔 CEO).

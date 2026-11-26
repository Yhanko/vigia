# Diagramas de Arquitectura e Fluxo — Vigia (§20.1)

- **Versão:** 1.0 (Fase 0 — Discovery; reflecte o MVP Error Tracking + evolução V1)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Referências:** README §3.0, §4.1–4.5, §20.1; ADR-001, ADR-005, ADR-008, ADR-015; TASKS 0.3

---

## 1. Arquitectura do MVP (Fases 1 e 2 — Error Tracking compatível Sentry + Notificações)

```mermaid
flowchart TD
  subgraph Clients["Apps dos Clientes (Qualquer Linguagem)"]
    SDK["SDKs Oficiais Sentry (JS/Node, Python, PHP, Go, Java, .NET, Mobile)"]
    BrowserUI["Browser — UI Vigia (web/)"]
  end

  subgraph Edge["Edge / Proxy TLS 1.2+"]
    Proxy["Caddy / Traefik (TLS automático)"]
  end

  subgraph Backend["Binário Único Go (vigia)"]
    API["vigia api\n• /api/v1/* (Product API)\n• /api/{public_id}/envelope|store (Sentry)\n• /integrations/telegram|whatsapp/webhook"]
    Worker["vigia worker\n• Fingerprint & Issues\n• Source maps\n• Alertas novo/regressão → Outbox"]
    Scheduler["vigia scheduler\n• Detecção de picos\n• Digests & Retenção"]
    Dispatcher["vigia dispatcher\n• Polling Outbox\n• Retries + Backoff + DLQ"]
  end

  subgraph Data["Rede Interna (backend: internal)"]
    PG[("PostgreSQL 18 + TimescaleDB\n• Metadata + RLS (vigia_app)\n• issues & issue_events\n• notification_outbox & audit_logs")]
    Redis[("Redis 8 (ACL + noeviction)\n• Fila de jobs + Dedup\n• Rate limit + Cache credenciais")]
    ObjStore[("Object Storage / Volume\n• Source maps")]
  end

  subgraph Channels["Canais de Notificação (Hosts Fixos)"]
    Email["SMTP / Fornecedor Email"]
    Telegram["Telegram Bot API"]
    WhatsApp["Meta WhatsApp Cloud API / BSP"]
  end

  SDK -->|HTTPS + DSN key| Proxy
  BrowserUI -->|HTTPS + Cookie HttpOnly + CSRF| Proxy
  Proxy --> API
  API -->|Valida + Scrubbing + Enfileira| Redis
  API -->|WithTenantTx| PG
  Redis --> Worker
  Worker -->|WithTenantTx + Outbox atómica| PG
  Worker --> ObjStore
  Scheduler -->|SECURITY DEFINER → WithTenantTx| PG
  PG -->|Outbox| Dispatcher
  Dispatcher --> Email
  Dispatcher --> Telegram
  Dispatcher --> WhatsApp
  Telegram -.->|Webhook entrada| Proxy
  WhatsApp -.->|Webhook estados/opt-out| Proxy
```

---

## 2. Fluxo de Ingestão Sentry → Issue → Alerta → Notificação (MVP)

```mermaid
sequenceDiagram
  autonumber
  participant SDK as SDK Sentry (Cliente)
  participant API as vigia api (Ingestão)
  participant Redis as Redis (Cache / Rate / Fila)
  participant Worker as vigia worker
  participant PG as PostgreSQL (RLS: vigia_app)
  participant Disp as vigia dispatcher
  participant Canal as Email / Telegram / WhatsApp

  SDK->>API: POST /api/{public_id}/envelope/ (X-Sentry-Auth + gzip)
  API->>Redis: Lookup cred:dsn:<public_key> + Rate limit / Quota
  alt Quota ou Rate Limit excedido
    API-->>SDK: 429 + Retry-After + X-Sentry-Rate-Limits
  end
  API->>API: Descomprime (limite) + Parse streaming + Scrubbing PII/segredos
  API->>Redis: Dedup event_id (SET NX EX) + Enfileira job (tenant-scoped)
  API-->>SDK: 200 {"id": "<event_id>"}

  Redis->>Worker: Consome job (organization_id, project_id, evento)
  Worker->>PG: BEGIN + set_config('app.organization_id', orgID, true)
  Worker->>PG: Upsert issue (fingerprint) + Insert issue_event
  alt Novo issue ou Regressão com regra activa (fora de cooldown)
    Worker->>PG: Insert notification_outbox (mesma transacção!)
  end
  Worker->>PG: COMMIT

  Disp->>PG: claim_pending_outbox_batch() [SECURITY DEFINER]
  Disp->>PG: WithTenantTx(orgID): carrega destino (decifra ADR-015) + template
  Disp->>Canal: Envia resumo curto (sem PII/stack trace) + link autenticado
  Disp->>PG: WithTenantTx(orgID): regista estado (sent / retry / DLQ)
```

---

## 3. Fluxo de Isolamento Multi-Tenant e Roles PostgreSQL (ADR-008)

```mermaid
flowchart LR
  subgraph Migrate["Job One-Shot (vigia migrate)"]
    MigRole["Role: vigia (SUPERUSER)\nSecret: postgres_password\n• Executa migrations goose\n• Sincroniza vigia_app e vigia_definer"]
  end

  subgraph Runtime["Runtime (api, worker, scheduler, dispatcher)"]
    AppRole["Role: vigia_app\nNOSUPERUSER · NOBYPASSRLS\nSecret: postgres_app_password"]
    Definer["Role: vigia_definer\nNOLOGIN · NOSUPERUSER · BYPASSRLS\nOwner das funções SECURITY DEFINER"]
  end

  subgraph DB["PostgreSQL"]
    RLS["Tabelas Tenant-Scoped\nENABLE + FORCE ROW LEVEL SECURITY\nPolicy: organization_id = app.organization_id"]
    AppendOnly["audit_logs / incident_events\nGRANT apenas SELECT, INSERT"]
  end

  MigRole -->|DDL / Migrations| DB
  AppRole -->|1. Lookup inicial / batch cross-tenant| Definer
  Definer -->|GRANT mínimo de colunas| RLS
  AppRole -->|2. WithTenantTx: set_config(..., true)| RLS
  AppRole -->|Append-only| AppendOnly
```

---

## 4. Evolução V1 Completa (Fases 3–8)

```mermaid
flowchart LR
  F1["Fase 1\nFundação: Auth, Orgs, RBAC,\nProjects, Credentials, RLS, Crypto"] --> F2["Fase 2 (MVP)\nSentry Ingest, Issues, Source Maps,\nAlertas Erro, Email/Telegram/WhatsApp, UI"]
  F2 --> F3["Fase 3\nMétricas Push + TimescaleDB\nQuery API + Cardinalidade"]
  F3 --> F4["Fase 4\nAlertas Métricas, Incidentes,\nTimeline, Silences, SSE"]
  F4 --> F5["Fase 5\nCliente SSRF + Webhooks HMAC\n+ Web Push (VAPID)"]
  F5 --> F6["Fase 6\nPull Collectors\n(http_get_json, db_readonly)"]
  F6 --> F7["Fase 7\nUptime Checks\n+ 8 Dashboards"]
  F7 --> F8["Fase 8\nHardening, OTel/Prometheus,\nPgBouncer, Chaos, DAST"]
```

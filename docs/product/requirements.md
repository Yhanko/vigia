# Personas, User Journeys e Requisitos Funcionais (RF-001…)

- **Versão:** 1.0 (Fase 0 — Discovery; alinhado com o roadmap MVP Error Tracking + V1)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Referências:** README §1, §3, §7, §18, §20, §25.1; TASKS 0.3

---

## 1. Personas

| Persona | Perfil | Dor principal | O que espera do Vigia |
|---|---|---|---|
| **P1 — Developer (Backend/Frontend)** | Trabalha numa startup/PME (Node, Python, PHP/Laravel, Go, React) | Descobre bugs em produção pelos clientes; Sentry pago em USD é caro e disperso dos alertas | Colar um DSN no SDK Sentry em 2 minutos, ver stack trace desminificado e resolver/ignorar issues sem ruído |
| **P2 — Tech Lead / Ops** | Gere 3–15 projectos e ambientes (`production`, `staging`) | Tem Grafana + scripts + emails perdidos; não sabe quem assumiu um incidente | Receber alertas críticos no **WhatsApp/Telegram** em < 1 min, com anti-ruído, histórico de entregas e regras claras |
| **P3 — Gestor / Owner (PME)** | Fundador ou CTO que aprova custos e acessos | Receio de custos imprevisíveis, fugas de dados de clientes e falta de auditoria | Controlo de acessos (RBAC + MFA), quotas previsíveis (especialmente WhatsApp), audit log e conformidade com a Lei n.º 22/11 |

---

## 2. User Journeys principais (MVP — Fases 1 e 2)

1. **Onboarding até ao 1.º erro (< 5 min):** `P2` cria conta → verifica email → cria Organização → cria Projecto (`production`) → copia o DSN + snippet do SDK Sentry → dispara erro de teste → ecrã "a aguardar o primeiro evento" detecta o issue → `P2` liga Telegram/WhatsApp → recebe o primeiro alerta.
2. **Investigação e regressão:** `P1` clica no link do alerta → abre o issue com stack trace `in_app`, breadcrumbs, release e tags → resolve o issue (`resolved`) → num deploy posterior o erro volta → Vigia reabre automaticamente como regressão e alerta a equipa.
3. **Gestão de equipa e segurança:** `P3` convida `P1` como `member` e um auditor como `viewer` → activa MFA obrigatório para `admin`/`owner` → revoga imediatamente a chave de um servidor antigo → consulta `audit_logs` para verificar todas as acções.

---

## 3. Requisitos Funcionais (V1)

### 3.1 Identidade, Organizações, RBAC e Auditoria (Fase 1)
| ID | Requisito | Critério de aceitação verificável | Fase |
|---|---|---|---|
| **RF-001** | Registo, login, logout e gestão de sessões revogáveis | Password ≥ 12 chars com Argon2id (`m=19 MiB, t=2, p=1`); cookie `HttpOnly`/`Secure`/`SameSite=Lax`; logout revoga a sessão imediatamente; anti-enumeração verificada em teste | 1.2 |
| **RF-002** | Verificação de email, recuperação de password e MFA (TOTP) | Tokens CSPRNG de uso único; reset revoga todas as sessões; TOTP encriptado (ADR-015) com códigos de recuperação; `owner`/`admin` exigem MFA antes de produção | 1.2 |
| **RF-003** | Gestão de organizações, memberships, convites e teams | CRUD completo; convites expiram em 7 dias; transferência de ownership e eliminação com re-autenticação | 1.2 |
| **RF-004** | Controlo de acesso por papéis (RBAC) e isolamento multi-tenant | 4 roles (`owner`, `admin`, `member`, `viewer`) verificados no backend; acesso cross-tenant devolve `404`; PostgreSQL RLS activo com `vigia_app` | 1.2 / 1.4 |
| **RF-005** | Gestão de projectos, ambientes e API credentials (`vg_ing_`, `vg_cli_`, `dsn`) | Segredos mostrados 1 vez (excepto `dsn` pública); revogação imediata invalida cache Redis; `is_protected` protege ambientes críticos; testes negativos de scope | 1.3 / 2.1 |
| **RF-006** | Audit logs append-only da plataforma | Acções de segurança/admin registadas sem segredos; `vigia_app` sem `UPDATE`/`DELETE`; listagem paginada por cursor com permissão `audit:read` | 1.2 |

### 3.2 MVP: Error Tracking compatível Sentry + Alertas + Notificações (Fase 2)
| ID | Requisito | Critério de aceitação verificável | Fase |
|---|---|---|---|
| **RF-007** | Ingestão compatível com SDKs oficiais Sentry (`/api/{public_id}/envelope/` e `/store/`) | ≥ 5 SDKs oficiais (Node, Browser, Python, PHP/Laravel, Go/Java/.NET) enviam erros mudando apenas o DSN; itens não suportados aceites e descartados com `200`; `429` + `X-Sentry-Rate-Limits` sob quota | 2.2 / 2.9 |
| **RF-008** | Agrupamento de erros (fingerprint), lifecycle de issues e regressões | Mesmo erro em linhas diferentes agrupa num só issue; suporte a `fingerprint` com `{{ default }}`; `resolved` reabre como regressão em nova ocorrência; `ignored` não notifica | 2.3 |
| **RF-009** | Scrubbing de privacidade e dados proibidos | Credenciais, cookies, `request.data`, cartões (Luhn) e BI redigidos no servidor antes de enfileirar; testes de regressão com dados sintéticos | 2.2 / 2.3 |
| **RF-010** | Source maps e releases | Upload de source maps com quota por org; desminificação de frames JS no `worker`; lista de releases e regressões por release | 2.4 |
| **RF-011** | Regras de alerta de erro com anti-ruído | Regras para novo issue, regressão e pico (N em M min), dry-run/test, cooldown por issue e máximo por destino/hora | 2.5 |
| **RF-012** | Motor de notificações fiável (Outbox + Dispatcher) | Outbox na mesma transacção; retries com backoff exponencial + jitter; DLQ; idempotência comprovada; previews sem PII/stack trace completo | 2.6 |
| **RF-013** | Canais de notificação MVP: Email, Telegram e WhatsApp | Email (SMTP/fornecedor + bounces); Telegram (ligação `/start`, grupos `/link`, webhook validado, escape HTML); WhatsApp (API oficial, opt-in por código, opt-out `PARAR`/`STOP`, quota mensal, número mascarado) | 2.7 |
| **RF-014** | Interface Web mínima (`web/`) | Auth, org switcher, projectos + guia DSN, lista/detalhe de issues com stack trace `in_app`, regras, canais, teams, credentials, quotas e audit log; renderização como texto (anti-XSS) | 2.8 |

### 3.3 Expansão V1 (Fases 3–8)
| ID | Requisito | Critério de aceitação verificável | Fase |
|---|---|---|---|
| **RF-015** | Ingestão e consulta de métricas + eventos (`vg_ing_`) | `POST /api/v1/ingest/metrics\|events` (`202`), TimescaleDB + `metrics_1m`, `GET /metrics/query\|history\|names` com limites e anti-cardinalidade | 3 |
| **RF-016** | Motor de alertas de métricas, incidentes com timeline e SSE | Máquina de estados `Normal → Pending → Firing → Resolved`; incidentes `open → acknowledged → resolved` com timeline append-only; SSE com ticket ≤ 30 s e isolamento de tenant | 4 |
| **RF-017** | Canais adicionais: Webhooks (HMAC + Challenge-Echo) e Web Push (VAPID) | Todos os webhooks via cliente `ssrf`; assinatura verificável; Challenge-Echo obrigatório | 5 |
| **RF-018** | Pull collectors (`http_get_json` e `db_readonly`) | Queries nomeadas read-only com cursor incremental; suite SSRF completa + revisão de segurança dedicada | 6 |
| **RF-019** | Uptime checks HTTP/HTTPS e dashboards de métricas | Confirmação N falhas / M sucessos via cliente `ssrf`; cálculo de uptime com timezone/manutenção; 8 dashboards da §7.4 | 7 |
| **RF-020** | Auto-observabilidade, backups/restore, export/delete e hardening | `/metrics` interno, canal de alerta externo, restore ensaiado, workflows de eliminação e Checklist de Produção (§22) aprovado | 2.9 / 8 |

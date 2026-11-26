# SLOs Iniciais, Metas de Capacidade e RPO/RTO

- **Versão:** 1.0 (Fase 0 — Discovery; baseline inicial para o MVP, a validar com load tests na Fase 2.9 e Fase 3)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Referências:** README §13, §14.4, §16.6, §25.2; TASKS 0.3, 2.9

> **Nota:** estes valores constituem a proposta técnica inicial para uma infraestrutura modesta de MVP (VPS único ou 2 nós com Docker Compose). Devem ser revistos após as respostas do CEO em `docs/decisions/perguntas-ceo.md` e validados com benchmarks reais antes do go-live (Fase 2.9).

---

## 1. SLOs iniciais (Service Level Objectives)

| Serviço / Fluxo | SLI (Indicador) | SLO Inicial (MVP) | Janela | Notas |
|---|---|---|---|---|
| **Product API (`/api/v1/*`)** | Pedidos válidos (não-4xx de cliente) com resposta 2xx/3xx | **99,5%** (meta V1 madura: **99,9%**) | 30 dias | Exclui janelas de manutenção anunciadas |
| **Latência Product API** | Duração P95 dos endpoints core (`GET /issues`, `GET /projects`, etc.) | **≤ 300 ms** (P99 ≤ 800 ms) | 30 dias | Login (Argon2id) tem alvo próprio: P95 ≤ 400 ms |
| **Ingestão Sentry (`/api/{id}/envelope\|store`)** | Eventos válidos aceites de forma durável (`200` após enfileirar; exclui `429` por quota do cliente) | **99,9%** | 30 dias | Hot path prioritário; latência P95 ≤ 100 ms |
| **Processamento de erros (`worker`)** | Atraso entre `received_at` e persistência do `issue`/`issue_event` | **P95 ≤ 10 s** (P99 ≤ 30 s) | 30 dias | Sob carga normal (fora de rajadas acima de quota) |
| **Alertas de erro (novo issue / regressão)** | Atraso entre persistência do evento e escrita na `notification_outbox` | **P95 ≤ 15 s** | 30 dias | Transacção atómica no `worker` |
| **Alertas de pico / métricas (Fase 2.5 / 4)** | Atraso entre condição atingida e avaliação/disparo | **≤ 2× intervalo de avaliação** | 30 dias | Conforme README §14.4 |
| **Dispatcher de notificações** | Atraso entre registo na `notification_outbox` e **1.ª tentativa de envio** ao fornecedor (email/Telegram/WhatsApp) | **P95 ≤ 15 s** (P99 ≤ 45 s) | 30 dias | Mede a **tentativa**, não a recepção no dispositivo (§7.7) |
| **UI Web (`web/`)** | Disponibilidade dos assets estáticos + `/api/v1/status` | **99,5%** (meta V1: **99,9%**) | 30 dias | — |

**Objectivo combinado do MVP (TASKS Fase 2):** do erro ocorrer na app do cliente até a 1.ª tentativa de entrega no Telegram/WhatsApp/Email em **< 60 segundos** (orçamento: ~10 s worker + ~15 s outbox/dispatcher + latência do fornecedor).

---

## 2. Metas de capacidade alvo (MVP — Fase 2.9)

Pressupostos iniciais para um servidor VPS dedicado de entrada (ex.: 4 vCPU, 8–16 GB RAM, SSD NVMe):

| Dimensão | Alvo MVP (Fase 2) | Alvo V1 Completa (Fases 3–8) | Controlo |
|---|---|---|---|
| Organizações activas | Até **50** | Até **250** | Isolamento RLS + quotas por org |
| Projectos activos | Até **200** | Até **1 000** | Quota por plano |
| Ingestão de erros sustentada | **50 eventos/s** (~4,3 M/dia) | **200 eventos/s** | Workers concorrentes + batching |
| Ingestão de erros em rajada (burst) | **250 eventos/s** durante 5 min | **1 000 eventos/s** | Fila Redis como amortecedor + `429`/`X-Sentry-Rate-Limits` |
| Ingestão de métricas (Fase 3) | N/A no MVP | **1 000 pontos/s** (burst 5 000/s) | Escrita em lote (`COPY`) + TimescaleDB |
| Notificações (email + Telegram + WhatsApp) | Até **5 000/dia** (com quota mensal de WhatsApp por org) | Até **25 000/dia** | Dispatcher com rate limit por canal/destino |
| Armazenamento por evento de erro | ≤ **16 KB** médio após truncagem/scrubbing | Comprimido em TimescaleDB | Retenção default (ex.: 30 dias) |

---

## 3. RPO e RTO por classe de dado (§16.6)

| Classe de dado | Exemplos | RPO (Perda máxima aceitável) | RTO (Tempo máximo de recuperação) | Estratégia de backup |
|---|---|---|---|---|
| **Metadata crítica** | `users`, `organizations`, `memberships`, `projects`, `api_credentials`, `alert_rules`, `notification_destinations`, `audit_logs` | **≤ 1 hora** (MVP: backup diário + WAL archiving contínuo ou dumps horários encriptados) | **≤ 2 horas** | `pg_dump` / `pgBackRest` encriptado fora do servidor (S3/object storage) + teste periódico de restore |
| **Issues e estado operacional** | `issues`, `incidents`, `notifications` | **≤ 1 hora** | **≤ 2 horas** | Mesma instância PostgreSQL da metadata |
| **Telemetria e eventos de alto volume** | `issue_events`, `metrics`, `monitor_check_results` | **≤ 24 horas** | **≤ 4 horas** | Incluído no backup diário; dados efémeros com retenção curta (30 dias) |
| **Source maps / artefactos** | Ficheiros em object storage / volume | **≤ 24 horas** | **≤ 4 horas** | Sincronização diária encriptada (clientes também podem reenviar no CI) |
| **Fila Redis / cache** | Jobs em trânsito, rate limits, cache | **Best-effort** (AOF `appendfsync everysec` já activo em `redis.conf`) | **≤ 15 minutos** | Sem backup de cache; `notification_outbox` em PostgreSQL garante zero perda de notificações |
| **Segredos e KEKs (`secrets/`)** | `ENCRYPTION_KEY_FILE`, `API_KEY_PEPPER_FILE`, tokens | **0 (zero perda)** | **≤ 30 minutos** | Cópias encriptadas offline / secret manager **separadas** dos backups da BD |

---

## 4. Critérios de validação

- **Fase 2.9 (go-live MVP):** executar load test sintético atingindo 50 eventos/s sustentados e 250 eventos/s em rajada, verificando P95 ≤ 100 ms na ingestão e `429` + `X-Sentry-Rate-Limits` sob sobrecarga; ensaiar 1 restore completo de backup cronometrado para comprovar RTO ≤ 2 h.
- **Fase 3 (métricas):** load test de 1 000 pontos/s com escrita em lote e verificação da política de retenção/compressão do TimescaleDB.

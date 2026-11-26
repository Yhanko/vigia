# Valores Concretos de Regras de Negócio (§25.3)

- **Versão:** 1.0 (Fase 0 — Discovery; valores padrão para implementação na Fase 1 e Fase 2)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini) · Revisão: CTO (Claude)
- **Referências:** README §7.5–7.8, §10.2–10.3, §25.3; ADR-005; TASKS 0.3

> Estes valores eliminam números mágicos no código: cada parâmetro deve viver como constante nomeada ou configuração validada em `internal/platform/config`.

---

## 1. Política de passwords (§10.3)

- **Comprimento mínimo:** **12 caracteres** (NIST SP 800-63B); máximo **128 caracteres** (evita DoS no hashing).
- **Sem regras arbitrárias de composição** (não obrigar símbolos específicos que incentivam padrões fracos); aceitar todos os caracteres Unicode imprimíveis e espaços.
- **Bloqueio de passwords comprometidas:** rejeitar uma lista mínima embutida das 10 000 passwords mais comuns + rejeitar passwords que contenham o próprio email ou nome da organização.
- **Sem expiração forçada periódica** (apenas reset obrigatório em caso de suspeita de compromisso).
- **Hashing:** Argon2id (`m=19 MiB, t=2, p=1`), conforme ADR-005.

---

## 2. Duração de sessões e tokens efémeros (§10.3, ADR-005)

| Tipo | Duração padrão | Renovação / Limite absoluto | Notas |
|---|---|---|---|
| **Sessão de utilizador** (`vigia_session`) | **7 dias** de inactividade (*sliding* a cada 24 h) | **30 dias** máximo absoluto | Revogável imediatamente; roda ID no login/MFA/reset |
| **Janela de re-autenticação** (acções de alto risco) | **10 minutos** após último login/MFA | Não renovável automaticamente | Exigida para criar/revogar keys, mudar roles, apagar org/projecto, transferir ownership |
| **Token de verificação de email** | **24 horas** | Uso único | Hash na BD |
| **Token de reset de password** | **30 minutos** | Uso único | Revoga todas as sessões activas do utilizador após uso |
| **Convite de organização** (`invitations`) | **7 dias** | Uso único | Revogável por `admin`/`owner` antes de aceite |
| **Token de ligação Telegram** (`/start`, `/link`) | **10 minutos** | Uso único | CSPRNG, hash na BD |
| **Código de verificação WhatsApp** (opt-in) | **10 minutos** (6 dígitos) | Uso único, máx. **5 tentativas** | Invalida após 5 falhas |
| **Ticket SSE** (Fase 4) | **30 segundos** | Uso único | Nunca token longo na URL |

---

## 3. Expiração padrão das API Credentials (§10.2, ADR-005)

| Tipo (`kind`) | Expiração padrão | Máximo permitido | Rotação (overlap) |
|---|---|---|---|
| **Ingest key (`vg_ing_`)** | **1 ano** (365 dias) | Sem expiração apenas se escolhido explicitamente por `owner`/`admin` | Overlap opcional até **7 dias** |
| **Client token (`vg_cli_`)** | **90 dias** | Máximo **1 ano** (365 dias) | Overlap opcional até **24 horas** |
| **DSN key (`dsn`)** | **Sem expiração por defeito** (vive em apps/browsers distribuídos) | Configurável | Múltiplas chaves activas por projecto para rotação sem downtime |

---

## 4. Valores padrão de Rate Limiting (§10.3, §11.3)

Algoritmo: *sliding window* ou *token bucket* em Redis com headers `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` e `Retry-After` em `429`.

| Grupo de endpoints | Chave de contagem | Limite padrão | Lockout / Acção adicional |
|---|---|---|---|
| `POST /api/v1/auth/login` | Por IP **e** por email normalizado | **10 req / 15 min** por IP; **5 falhas / 15 min** por conta | Aplicado **antes** do Argon2id (ADR-005); backoff progressivo após 5 falhas (1 min → 5 min → 15 min) |
| `POST /api/v1/auth/register` | Por IP | **5 req / hora** por IP | — |
| `POST /api/v1/auth/password/forgot\|reset` | Por IP **e** por email | **3 req / 15 min** por email; **10 req / 15 min** por IP | Resposta sempre genérica (anti-enumeração) |
| `POST /api/v1/auth/mfa/verify` | Por sessão **e** por IP | **5 tentativas / 15 min** | Invalida desafio MFA após 5 falhas |
| Product API autenticada (`/api/v1/*`) | Por utilizador / `vg_cli_` token | **120 req / min** (burst 240) | `429` + `Retry-After` |
| Ingestão Sentry (`/api/{id}/envelope\|store`) | Por chave `dsn` **e** por organização | **100 eventos / min** (Free), **1 000 / min** (Pro), **5 000 / min** (Business) | `429` + `Retry-After` + `X-Sentry-Rate-Limits` |
| Ingestão de telemetria (`/api/v1/ingest/*`, Fase 3) | Por `vg_ing_` key, por org e por IP | Conforme quota do plano (default **600 req / min** por org) | `429` / `503` + `Retry-After` |
| Webhooks de entrada (Telegram / WhatsApp) | Por IP | **120 req / min** por IP | `429` + registo de abuso |
| Notificações de saída (anti-ruído) | Por destino (email/Telegram/WhatsApp) | **10 notificações / hora** por destino (WhatsApp: também quota mensal da org) | Suprime excedentes com estado `suppressed` + digest |

---

## 5. Definição de severidades (§7.5, §7.7, §25.3)

| Severidade | Significado operacional | Exemplos | Comportamento padrão de notificação |
|---|---|---|---|
| **`critical`** | Serviço indisponível, perda de dados, erro bloqueante em produção ou regressão de alto impacto | Excepção `fatal`/`error` com pico em `production`, monitor DOWN confirmado, CPU > 95% sustentada | Notifica de imediato por todos os canais activos (WhatsApp, Telegram, Email) |
| **`warning`** | Degradação relevante ou erro novo sem indisponibilidade total | Novo issue em `production`, erro em `staging`, latência P95 elevada, 80% da quota atingida | Notifica por Telegram e Email (WhatsApp apenas se o utilizador optar explicitamente) |
| **`info`** | Evento informativo ou mudança de estado de baixa urgência | Recuperação de incidente, resumo/digest diário, novo deploy/release | In-app / Email digest (nunca WhatsApp) |

---

## 6. Regras de reabertura (Issues e Incidentes)

### 6.1 Issues (Error Tracking — Fase 2)
- **`unresolved` → `resolved`:** acção manual do utilizador (ou na próxima release, futuro).
- **`resolved` → `unresolved` (regressão):** **reabre automaticamente** assim que chega um novo evento com o mesmo `fingerprint` cujo `occurred_at` (ou `received_at`) seja posterior a `resolved_at` (ou de uma release diferente da que resolveu). Marca `is_regression = true` e dispara regras do tipo **regressão**.
- **`ignored`:** **não reabre** automaticamente e **nunca dispara notificações** até ser manualmente alterado para `unresolved` (ou expirar uma condição de ignore futura).

### 6.2 Incidentes (Alertas de métricas e uptime — Fase 4)
- **`open` → `acknowledged`:** manual; **não resolve** nem pára o estado `firing` do alerta.
- **`open` / `acknowledged` → `resolved`:** automático quando o alerta volta a `Normal` (configurável por regra, activo por defeito) ou manual.
- **Política de reabertura de incidente:** um incidente `resolved` **não é reaberto** por padrão; se a condição voltar a disparar depois de resolvida (fora da janela de cooldown de **10 minutos**), cria-se um **novo incidente** ligado à mesma regra para preservar métricas limpas de MTTR e timeline independente. Se voltar a disparar dentro de 10 minutos (flapping), a regra pode ser configurada para reabrir o mesmo incidente registando evento `reopened` na timeline append-only.

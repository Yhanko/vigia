# ADR-008: Isolamento multi-tenant (aplicação + PostgreSQL RLS)

- **Estado:** Proposto (em segunda revisão do CTO)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Em revisão (decisão dos dois roles aprovada; correcções aplicadas em 2026-11-26)
- **Fase bloqueada:** Antes da 1.2
- **Referências:** README §2, §8.1, §8.6, §11.1, §11.9, §24.1; ADR-003, ADR-005; TASKS 1.2, 1.4

---

## 1. Contexto

O Vigia é uma plataforma multi-tenant onde organizações distintas partilham a mesma infraestrutura, armazenando dados altamente sensíveis: stack traces, contexto de erros, regras de alerta, credenciais encriptadas, contactos de equipa e audit logs. Uma única falha de isolamento (*Broken Object Level Authorization* — BOLA/IDOR) que exponha dados da Organização A à Organização B compromete irreversivelmente a confiança no produto e acarreta responsabilidade legal.

## 2. Alternativas consideradas

### Opção A — Base de dados partilhada com `organization_id` obrigatório + camada de aplicação tipada + PostgreSQL RLS como defesa em profundidade (escolhida)
- **Prós:**
  - Custo operacional e complexidade baixos (uma instância PostgreSQL, um único conjunto de migrations, pooling simples).
  - **Duas barreiras independentes:** se um programador esquecer `WHERE organization_id = $1` numa query, o PostgreSQL RLS bloqueia o acesso (*fail-closed*) e devolve 0 registos / erro de escrita.
  - Compatível com `pgxpool` e com `PgBouncer` em modo transacção usando `SELECT set_config('app.organization_id', $1, true)` (`LOCAL` à transacção).
- **Contras:**
  - Requer separação estrita de roles na BD (o utilizador `vigia` do `compose.yaml` é `SUPERUSER` e contorna RLS mesmo com `FORCE`) e um mecanismo controlado e auditável para operações legítimas que cruzam tenants.

### Opção B — Apenas isolamento na camada de aplicação (sem RLS)
- **Prós:** Mais simples de configurar na BD.
- **Contras:** Ponto único de falha humano: um único `SELECT ... WHERE id = $1` sem `AND organization_id = $2` que escape ao code review expõe dados cross-tenant em produção. Rejeitada como barreira única.

### Opção C — Um schema ou uma base de dados por tenant (silo)
- **Prós:** Isolamento físico/lógico forte na BD.
- **Contras:** Explosão operacional de migrations (correr migrations em N schemas/BDs), saturação de pools de ligação e caches do PostgreSQL, inviável para o modelo de "servidor leve e escalável" com dezenas/centenas de PMEs. Rejeitada para V1 (pode ser oferecida como deploy *self-hosted* dedicado em enterprise futuro).

## 3. Decisão

Adoptar **isolamento multi-tenant em duas camadas (Aplicação + PostgreSQL RLS)** com comportamento *fail-closed*:

### 3.1 Camada 1 — Aplicação (barreira primária)
1. **Derivação segura do tenant:** o `organization_id` vem **exclusivamente** da sessão autenticada (verificada contra `memberships` activa) ou da credencial validada (`vg_ing_`, `vg_cli_`, `dsn`). Nunca é aceite a partir do body JSON ou de query params sem verificação de posse.
2. **Tipo forte `TenantID`:** os repositórios exigem `TenantID` explicitamente na assinatura de cada método tenant-scoped. É proibido existir `FindByID(ctx, id)` sem `tenantID`.
3. **Respostas sem enumeração de IDs:** quando um recurso existe noutro tenant, a API responde `404 RESOURCE_NOT_FOUND` (nunca `403`), evitando revelar a existência de IDs de terceiros.
4. **Isolamento fora da BD:**
   - **Redis (cache, dedup, rate limit, Pub/Sub SSE):** todas as chaves usam prefixo `org:<organization_id>:...`.
     - **Excepções documentadas (ADR-005):** a cache de credenciais usa **`cred:<kind>:<prefix>`** para `ingest`/`client` e **`cred:dsn:<public_key>`** (32 hex, `UNIQUE`) para `dsn`, pois o lookup ocorre antes de se conhecer o tenant; o valor armazenado inclui `organization_id` e é invalidado directamente na revogação.
   - **Filas/Workers:** todo o job carrega `organization_id` no payload e é processado sob `WithTenantTx`; quotas e concorrência aplicadas por tenant.
   - **Object storage (source maps, exports):** prefixo `<organization_id>/<project_id>/...`.

### 3.2 Camada 2 — PostgreSQL Row-Level Security (defesa em profundidade)
1. **Separação estrita de roles na BD (aprovada pelo CTO para implementação desde a Fase 1.2):**
   - `vigia` (`POSTGRES_USER` no `compose.yaml`): é **`SUPERUSER`** (ignora RLS mesmo com `FORCE ROW LEVEL SECURITY`). Por isso, **`vigia` é usado exclusivamente pelo job one-shot `vigia migrate`** (DDL e migrations) e **nunca** pelos processos de runtime.
   - `vigia_app`: role de runtime usado por `api`, `worker`, `scheduler`, `evaluator` e `dispatcher`, criado explicitamente com:
     ```sql
     CREATE ROLE vigia_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
     ```
     - **Credencial própria:** password num Docker secret separado (`postgres_app_password`, montado em `/run/secrets/postgres_app_password` via `DATABASE_PASSWORD_FILE` nos serviços de runtime; `postgres_password` fica restrito ao `db` e ao serviço `migrate`).
     - **Criação e sincronização via `vigia migrate`:** `vigia_app` (e `vigia_definer` abaixo) são criados e sincronizados de forma **idempotente** exclusivamente pelo comando `vigia migrate`, lendo `postgres_app_password` do ficheiro de secret e aplicando quoting seguro de literais (`format('ALTER ROLE vigia_app WITH PASSWORD %L', $1)` / `pgx.Identifier`, nunca concatenação directa de strings em SQL). Não se usam scripts em `/docker-entrypoint-initdb.d/`, pois só correm na primeira inicialização de um volume vazio e não funcionam em BDs já existentes.
     - **Privilégios mínimos:** `SELECT`, `INSERT`, `UPDATE`, `DELETE` nas tabelas de domínio; apenas `SELECT` e `INSERT` em tabelas append-only (`audit_logs`, `incident_events`); `EXECUTE` apenas nas funções `SECURITY DEFINER` listadas em §3.3.
   - `vigia_definer`: role dedicado, sem login e sem privilégios de superuser, owner exclusivo das funções `SECURITY DEFINER` de §3.3:
     ```sql
     CREATE ROLE vigia_definer NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
     ```
     Recebe `GRANT` apenas nas tabelas e colunas exactas que cada função de §3.3 acede. Nunca se atribui ownership destas funções ao superuser `vigia`.
2. **Política RLS *fail-closed* uniforme em todas as tabelas tenant-scoped:**
   ```sql
   ALTER TABLE <tabela> ENABLE ROW LEVEL SECURITY;
   ALTER TABLE <tabela> FORCE ROW LEVEL SECURITY;

   CREATE POLICY tenant_isolation ON <tabela>
     USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
     WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
   ```
   Se `app.organization_id` não for definido na transacção, `NULLIF(..., '')` devolve `NULL` e nenhuma linha é lida nem gravada (*fail-closed*).
3. **Helper transaccional `database.WithTenantTx`:**
   - Abre transacção via `pgxpool`, executa `SELECT set_config('app.organization_id', $1, true)` (escopo estritamente local à transacção, seguro com pooling e `PgBouncer`), executa a função de domínio e faz commit/rollback.

### 3.3 Operações legítimas cross-tenant (mecanismo único)

Para manter as políticas RLS das tabelas 100% uniformes (apenas `organization_id`, sem cláusulas `OR` complexas) e evitar conceder privilégios globais a `vigia_app`, **todas** as operações que precisam de cruzar tenants usam o mesmo mecanismo: **funções SQL `SECURITY DEFINER` de âmbito mínimo**, com as seguintes regras obrigatórias:

1. **Owner dedicado (nunca `SUPERUSER`):** cada função pertence a `vigia_definer` (`NOLOGIN NOSUPERUSER BYPASSRLS`), com `GRANT` estrito apenas nas colunas/tabelas que a função usa — nunca ao superuser `vigia`.
2. **Revogação de `PUBLIC`:** como o PostgreSQL concede `EXECUTE` a `PUBLIC` por defeito em funções novas, a migration executa explicitamente para cada função:
   ```sql
   REVOKE EXECUTE ON FUNCTION <assinatura> FROM PUBLIC;
   GRANT EXECUTE ON FUNCTION <assinatura> TO vigia_app;
   ```
3. **`search_path` fixo:** toda a função define `SET search_path = pg_catalog, public, pg_temp` (`pg_temp` sempre em último).
4. **Revisão e reentrada em `WithTenantTx`:** cada função é revista pelo CTO 🧭 e devolve apenas identificadores mínimos de encaminhamento; **todo o processamento subsequente entra imediatamente em `WithTenantTx(ctx, pool, tenantID, fn)`**.

| Operação cross-tenant | Função `SECURITY DEFINER` (âmbito mínimo) | O que devolve / Regra seguinte |
|---|---|---|
| **Listar as minhas organizações** (`GET /api/v1/organizations`, `memberships`/`organizations`) | `list_user_organizations(p_user_id uuid)` | Apenas `(organization_id, name, slug, role, status)` das memberships activas de `p_user_id` (derivado da sessão autenticada). Qualquer operação sobre uma organização específica entra em `WithTenantTx(orgID)`. |
| **Lookup de credencial secreta** (`vg_ing_`, `vg_cli_`) | `lookup_credential_by_prefix(p_kind text, p_prefix text)` | Metadados mínimos + `organization_id` + `secret_hash`; o pedido entra em `WithTenantTx(orgID)`. |
| **Lookup de chave DSN** (ingestão Sentry) | `lookup_dsn_credential(p_public_id bigint, p_public_key text)` | `organization_id`, `project_id`, `environment_id`, `allowed_origins`, estado; o enfileiramento/worker entra em `WithTenantTx(orgID)`. |
| **Dispatcher — polling da outbox** (`notification_outbox`) | `claim_pending_outbox_batch(p_limit int)` | Bloqueia (`FOR UPDATE SKIP LOCKED`) e devolve apenas `(id, organization_id)` pendentes; o processamento e actualização de cada item correm em `WithTenantTx(item.OrganizationID)`. |
| **Scheduler — detecção de picos** (alertas de erro, Fase 2.5) | `list_active_spike_rules()` | Devolve `(organization_id, rule_id)` elegíveis; cada avaliação corre isolada em `WithTenantTx(orgID)`. |
| **Scheduler — digests de notificação** (Fase 2.5/2.6) | `list_due_digest_tenants()` | Devolve `organization_id` com digests por enviar; agregação e escrita na outbox correm em `WithTenantTx(orgID)`. |
| **Scheduler — retenção por plano** (Fase 2.0/2.3) | `list_tenant_retention_targets()` | Devolve `(organization_id, retention_days)`; eliminação lógica por tenant corre em `WithTenantTx(orgID)` (drops de chunks globais ficam sob política nativa do TimescaleDB). |

*(Nota: tabelas globais sem `organization_id` — `users` e `sessions` — são acedidas por `user_id`/`token_hash` fora de RLS de tenant.)*

### 3.4 Índices compostos
- Todos os índices de tabelas tenant-scoped começam por `organization_id` (ex.: `(organization_id, project_id, created_at DESC)`), garantindo eficiência tanto nas queries da aplicação como nos filtros do RLS.

## 4. Consequências

### Positivas
- Elimina a classe de falhas em que um `WHERE` incompleto expõe todos os tenants.
- `vigia_app` sem `SUPERUSER` nem `BYPASSRLS` torna impossível contornar RLS em runtime.
- Inventário explícito e auditável de todas as funções `SECURITY DEFINER` que cruzam tenants.
- Seguro com `pgxpool` e `PgBouncer` em modo transacção porque `set_config(..., true)` é limpo automaticamente no fim da transacção.

### Negativas / Trade-offs aceites
- Obriga a gerir dois roles PostgreSQL (`vigia` e `vigia_app`) e dois Docker secrets (`postgres_password` e `postgres_app_password`) desde a Fase 1.2.
- Operações de leitura tenant-scoped correm dentro de `WithTenantTx` (overhead mínimo em PostgreSQL, mas exige disciplina para nunca manter transacções abertas durante chamadas HTTP externas).

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Runtime ligar com `vigia` (`SUPERUSER`) por erro de configuração | Média / Crítico | Teste de integração obrigatório que falha se `rolsuper` ou `rolbypassrls` for `true` na ligação de runtime + `compose.yaml` só monta `postgres_app_password` na `api`/`worker` |
| Função `SECURITY DEFINER` demasiado permissiva ou vulnerável a `search_path` hijacking | Baixa / Crítico | Owner `vigia_definer` (não `SUPERUSER`), `REVOKE EXECUTE ... FROM PUBLIC`, `GRANT EXECUTE ... TO vigia_app`, `SET search_path = pg_catalog, public, pg_temp`, âmbito mínimo e revisão obrigatória do CTO 🧭 |
| Transacção mantida aberta durante I/O externo (HTTP/SMTP/Telegram) | Média / Alto | Regra: nunca fazer chamadas de rede externas dentro de `WithTenantTx`; usar outbox |
| Fuga em cache Redis ou canais SSE (onde o RLS não actua) | Média / Crítico | Prefixos `org:<id>:` obrigatórios por helper centralizado (únicas excepções: `cred:<kind>:<prefix>` para `ingest`/`client` e `cred:dsn:<public_key>` para `dsn`) + testes negativos cross-tenant |

## 6. Validação / Protótipo / Benchmark

- **Validação obrigatória na Fase 1.2 / 1.4 (`testcontainers-go`):**
  - **Teste de role de runtime:** executar `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user` na pool da aplicação e **falhar o teste** se `rolsuper = true` ou `rolbypassrls = true`.
  - **Teste *fail-closed*:** executar `SELECT * FROM projects` sem `set_config('app.organization_id', ...)` com `vigia_app` → deve devolver 0 linhas.
  - **Suite cross-tenant (`tests/security/`):** criar Org A e Org B e tentar ler, alterar e apagar **cada** recurso da Org B com sessão, `vg_cli_`, `vg_ing_` e `dsn` da Org A → 100% rejeitados (`404`/`401`/`403`).
- **Protótipo obrigatório no ADR-003 (antes da Fase 2):**
  - Validar explicitamente a compatibilidade entre **PostgreSQL RLS e hypertables comprimidas do TimescaleDB** (`issue_events`, e futuramente `metrics`), incluindo políticas de compressão, `SELECT`, `INSERT` em chunks comprimidos e `DELETE`/retenção. Se o TimescaleDB apresentar restrições ou incompatibilidades com RLS em chunks comprimidos, documentar no ADR-003 a alternativa (ex.: isolamento por `TenantID` + vistas tenant-scoped, compressão apenas após janela de escrita ou separação de storage).

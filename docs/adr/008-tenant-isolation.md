# ADR-008: Isolamento multi-tenant (aplicação + PostgreSQL RLS)

- **Estado:** Proposto (aguarda revisão do CTO)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Pendente
- **Fase bloqueada:** Antes da 1.2
- **Referências:** README §2, §8.1, §8.6, §11.1, §11.9, §24.1; TASKS 1.2, 1.4

---

## 1. Contexto

O Vigia é uma plataforma multi-tenant onde organizações distintas partilham a mesma infraestrutura, armazenando dados altamente sensíveis: stack traces, contexto de erros, regras de alerta, credenciais encriptadas, contactos de equipa e audit logs. Uma única falha de isolamento (*Broken Object Level Authorization* — BOLA/IDOR) que exponha dados da Organização A à Organização B compromete irreversivelmente a confiança no produto e acarreta responsabilidade legal.

## 2. Alternativas consideradas

### Opção A — Base de dados partilhada com `organization_id` obrigatório + camada de aplicação tipada + PostgreSQL RLS como defesa em profundidade (escolhida)
- **Prós:**
  - Custo operacional e complexidade baixos (uma instância PostgreSQL, um único conjunto de migrations, pooling simples).
  - **Duas barreiras independentes:** se um programador esquecer `WHERE organization_id = $1` numa query, o PostgreSQL RLS bloqueia o acesso (*fail-closed*) e devolve 0 registos / erro de escrita.
  - Compatível com `pgxpool` e com `PgBouncer` em modo transacção usando `set_config('app.organization_id', $1, true)` (`LOCAL` à transacção).
- **Contras:**
  - Requer disciplina no modelo de roles da BD (separar role de migrations com ownership de role da aplicação sem `BYPASSRLS`) e cuidado em jobs de background que iteram entre tenants.

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
   - **Filas/Workers:** todo o job carrega `organization_id` no payload e é processado sob `WithTenantTx`; quotas e concorrência aplicadas por tenant.
   - **Object storage (source maps, exports):** prefixo `<organization_id>/<project_id>/...`.

### 3.2 Camada 2 — PostgreSQL Row-Level Security (defesa em profundidade)
1. **Separação de roles na BD:**
   - `vigia` (owner): usado apenas pelo subcomando `vigia migrate` (DDL e migrations).
   - `vigia_app` (sem `SUPERUSER`, sem `BYPASSRLS`): usado em runtime por `api`, `worker`, `scheduler`, `evaluator` e `dispatcher`, com privilégios mínimos (`SELECT`, `INSERT`, `UPDATE`, `DELETE` — e apenas `SELECT`/`INSERT` em tabelas append-only como `audit_logs` e `incident_events`).
2. **Política RLS *fail-closed* em todas as tabelas tenant-scoped:**
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
4. **Excepções explícitas (tabelas não tenant-scoped ou lookup inicial):**
   - Tabelas globais de identidade (`users`, `sessions`) não têm `organization_id` e são acedidas por `user_id`/`token_hash`.
   - Lookup inicial de credencial (`api_credentials` por `prefix`/`public_key` antes de conhecer o tenant) e polling da `notification_outbox` pelo `dispatcher` são feitos por funções/views `SECURITY DEFINER` com escopo mínimo ou queries dedicadas revistas pelo CTO, e o processamento subsequente entra imediatamente em `WithTenantTx(tenantID)`.

### 3.3 Índices compostos
- Todos os índices de tabelas tenant-scoped começam por `organization_id` (ex.: `(organization_id, project_id, created_at DESC)`), garantindo eficiência tanto nas queries da aplicação como nos filtros do RLS.

## 4. Consequências

### Positivas
- Elimina a classe de falhas em que um `WHERE` incompleto expõe todos os tenants.
- Privilégio mínimo na BD impede que a aplicação faça `UPDATE`/`DELETE` em `audit_logs` mesmo em caso de bug.
- Seguro com `pgxpool` e `PgBouncer` em modo transacção porque `set_config(..., true)` é limpo automaticamente no fim da transacção.

### Negativas / Trade-offs aceites
- Obriga a manter dois roles PostgreSQL (`vigia` para migrations, `vigia_app` para runtime) no `compose.yaml` e em produção.
- Operações de leitura tenant-scoped passam a correr dentro de `WithTenantTx` (overhead mínimo em PostgreSQL, mas requer cuidado para não manter transacções abertas durante chamadas HTTP externas).

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Aplicação correr com o role `vigia` (owner) por engano e contornar RLS | Média / Crítico | `FORCE ROW LEVEL SECURITY` + teste de integração que valida que a ligação de runtime não tem `BYPASSRLS` |
| Transacção mantida aberta durante I/O externo (HTTP/SMTP/Telegram) | Média / Alto | Regra: nunca fazer chamadas de rede externas dentro de `WithTenantTx`; usar outbox |
| Fuga em cache Redis ou canais SSE (onde o RLS não actua) | Média / Crítico | Prefixos `org:<id>:` obrigatórios por helper centralizado + testes negativos cross-tenant em Redis/SSE |

## 6. Validação / Protótipo / Benchmark

- **Validação obrigatória na Fase 1.4:**
  - Suite `tests/security/` cria dois tenants (Org A e Org B) e tenta ler, alterar e apagar **cada** recurso da Org B com sessão, `vg_cli_`, `vg_ing_` e `dsn` da Org A → 100% rejeitados (`404`/`401`/`403`).
  - Teste de integração directo em PostgreSQL (`testcontainers-go`): executar `SELECT * FROM projects` sem `app.organization_id` usando `vigia_app` → deve devolver 0 linhas.

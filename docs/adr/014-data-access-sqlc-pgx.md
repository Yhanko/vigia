# ADR-014: Acesso a dados com `sqlc` + `pgx/v5` em vez de ORM

- **Estado:** Aceite
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Aprovado (2026-11-26)
- **Fase bloqueada:** Antes da Fase 1 (já decidido; formalizar)
- **Referências:** README §5.1, §8.6, §11.1, §11.5, §24.1

---

## 1. Contexto

O acesso à base de dados no Vigia exige três garantias simultâneas: (1) **segurança multi-tenant e anti-SQLi**, onde toda a query é parametrizada e filtra explicitamente por `organization_id`; (2) **controlo fino sobre SQL PostgreSQL/TimescaleDB** (hypertables, `time_bucket`, `COPY`, `ON CONFLICT`, `JSONB`, transacções com `SET LOCAL` para RLS, paginação por cursor); e (3) **segurança de tipos em tempo de compilação** e performance previsível sem queries N+1 escondidas.

## 2. Alternativas consideradas

### Opção A — `pgx/v5` + `sqlc` (escolhida)
- SQL escrito à mão em `queries/` validado contra o schema de `migrations/`; `sqlc` gera código Go fortemente tipado usando `pgx/v5`.
- **Prós:**
  - Zero magia em runtime: o SQL executado em produção é exactamente o SQL revisto no PR.
  - Erros de sintaxe SQL, nomes de colunas ou tipos são detectados em tempo de geração/compilação, não em produção.
  - Suporte nativo e sem fricção a funcionalidades específicas do PostgreSQL/TimescaleDB (`COPY`, CTEs, `JSONB`, `FOR UPDATE SKIP LOCKED`, `time_bucket`, RLS).
  - Parâmetros 100% bindados pelo driver (`$1`, `$2`), eliminando SQL injection por construção.
  - Facilita impor em code review que toda a query tenant-scoped inclui `WHERE organization_id = $1`.
  - Performance de referência em Go (`pgxpool` nativo, sem reflexão).
- **Contras:**
  - Queries altamente dinâmicas (ex.: filtros opcionais combinados em listagens) exigem padrões explícitos em SQL (`sqlc.narg(...)`) ou query builder pontual parametrizado.
  - Passo extra de geração (`go generate ./...` / `sqlc generate`), verificado no CI com `sqlc diff`.

### Opção B — ORM (GORM)
- **Prós:** Rapidez inicial em CRUD simples e convenções familiares.
- **Contras:** Reflexão pesada, geração implícita de SQL difícil de auditar, risco frequente de queries N+1 e *lazy loading* acidental, suporte fraco a TimescaleDB/CTEs complexas e abstrações que escondem falhas de isolamento de tenant.

### Opção C — `ent` (entity framework gerado)
- **Prós:** Type-safe, bom para grafos relacionais.
- **Contras:** Curva de aprendizagem própria, código gerado extenso, fricção com SQL específico de PostgreSQL/TimescaleDB e migrations geridas externamente (`goose`).

### Opção D — `database/sql` + `pgx` manual sem `sqlc`
- **Prós:** Sem ferramenta de geração.
- **Contras:** Muito boilerplate repetitivo de `rows.Scan(...)`, propenso a erros silenciosos quando o schema muda.

## 3. Decisão

Adoptar **`pgx/v5` (`pgxpool`) + `sqlc`** como camada padrão de acesso a dados:

1. **Schema e queries:** migrations SQL (`goose`) em `migrations/` são o schema de entrada do `sqlc`; queries ficam organizadas por módulo em `queries/`.
2. **Geração controlada:** `sqlc.yaml` gera código em `internal/platform/database/sqlcgen` (ou por módulo, conforme a fronteira da Fase 1.2) com `sql_package: "pgx/v5"`, `emit_interface: true` e `emit_empty_slices: true`. O CI falha se houver diferenças não geradas (`sqlc diff`).
3. **Transacções e RLS:** todas as operações multi-query e de outbox usam `database.WithTx` sobre `pgxpool.Pool` com `pgx.Tx`, permitindo `SELECT set_config('app.organization_id', $1, true)` (ADR-008) e commit atómico.
4. **Queries dinâmicas excepcionais:** se uma pesquisa futura (ex.: `/metrics/query`) exigir construção condicional que `sqlc.narg` não cubra com clareza, é permitida apenas com allowlist estrita de identificadores e valores 100% parametrizados via `pgx`, mediante revisão do CTO.
5. **Escrita em lote:** pipelines de alto volume podem usar `pgx.CopyFrom` directamente sobre o pool.

## 4. Consequências

### Positivas
- Total visibilidade e auditabilidade de todo o SQL executado contra PostgreSQL e TimescaleDB.
- Detecção precoce de desalinhamentos entre migrations e código Go.
- Desempenho e consumo de memória óptimos (sem reflexão).

### Negativas / Trade-offs aceites
- Developers precisam de escrever SQL idiomático de PostgreSQL.
- Alterações a migrations exigem correr `sqlc generate` no mesmo PR.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Código gerado ficar desactualizado face às queries/migrations | Média / Médio | `sqlc diff` obrigatório no CI (TASKS 1.0/1.4) |
| Query tenant-scoped esquecer `organization_id` | Média / Crítico | Assinatura obrigatória com `TenantID` no repositório + revisão de PR + RLS em PostgreSQL (ADR-008) + testes cross-tenant |
| Queries lentas por falta de índice | Média / Médio | `log_min_duration_statement=500` activo em dev + `EXPLAIN ANALYZE` em queries críticas |

## 6. Validação / Protótipo / Benchmark

- `pgxpool` + `WithTx` + `goose` já implementados em `internal/platform/database/database.go`; `sqlc.yaml` criado na raiz.
- Validação completa (primeiras queries reais + `sqlc generate` + `sqlc diff` no CI + testes de integração com `testcontainers-go`) na Fase 1.1/1.2.

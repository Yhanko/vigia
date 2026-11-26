# ADR-002: PostgreSQL para metadata transaccional

- **Estado:** Proposto (aguarda revisão do CTO)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Pendente
- **Fase bloqueada:** Antes da Fase 1
- **Referências:** README §2, §5.1, §8.2, §8.6, §11.1, §24.1

---

## 1. Contexto

O Vigia precisa de armazenar dados transaccionais críticos com garantias ACID estritas: utilizadores, sessões, organizações, memberships, teams, projectos, ambientes, credenciais (`api_credentials`), regras de alerta, estado de alertas (`alert_state`), issues, incidentes, outbox transaccional (`notification_outbox`), destinos de notificação, audit logs e quotas. A integridade referencial, o isolamento multi-tenant e a atomicidade entre mudança de estado e outbox são requisitos inegociáveis.

## 2. Alternativas consideradas

### Opção A — PostgreSQL 18 (escolhida)
- **Prós:**
  - Garantias ACID maduras, chaves estrangeiras, `UNIQUE` compostos, `CHECK` constraints e índices parciais/compostos tenant-first.
  - Suporte nativo a **Row-Level Security (RLS)** como camada de defesa em profundidade para isolamento multi-tenant (ADR-008).
  - Suporte a `JSONB` validado/indexável (regras versionadas, payloads de auditoria, tags/contexto de issues) sem perder esquema relacional forte.
  - Ecossistema sólido em Go (`pgx/v5`, `sqlc`, `goose`) e compatibilidade directa com TimescaleDB na mesma instância na V1 (evitando operar dois SGBDs desde o dia 1).
  - Ferramentas maduras de backup/PITR (`pg_dump`, `pgBackRest`) e autenticação `SCRAM-SHA-256`.
- **Contras:**
  - Telemetria de altíssimo volume (milhões de pontos/min) exigirá particionamento/TimescaleDB e, numa fase futura de escala, eventual migração da telemetria para ClickHouse (ADR-003), mantendo a metadata em PostgreSQL.

### Opção B — MySQL / MariaDB
- **Prós:** Amplamente conhecido e estável.
- **Contras:** Sem RLS nativo equivalente ao PostgreSQL; sem extensão equivalente ao TimescaleDB; menor riqueza em tipos (`uuid`, `jsonb`, índices parciais) e transacções DDL menos seguras para migrations.

### Opção C — SQLite (ficheiro local)
- **Prós:** Zero configuração em single-node.
- **Contras:** Limitação de escrita concorrente, inviável para múltiplos processos (`api`, `worker`, `scheduler`, `dispatcher`) e réplicas stateless atrás de load balancer; sem RLS nativo.

### Opção D — Base de dados NoSQL (MongoDB / DynamoDB)
- **Prós:** Esquema flexível.
- **Contras:** Modelo de domínio do Vigia é fortemente relacional (org → project → environment → credential / issue / rule / membership); maior risco de inconsistência em transacções multi-entidade e outbox; lock-in (DynamoDB).

## 3. Decisão

Adoptar **PostgreSQL 18** como base de dados canónica de toda a metadata transaccional do Vigia:

1. **Segurança da instância:** autenticação `SCRAM-SHA-256` na rede, nunca exposta publicamente (rede interna `backend` no Docker), registo de DDL e queries lentas (> 500 ms).
2. **Convenções de schema (§8.6):**
   - IDs opacos (`uuid`), timestamps sempre em `timestamptz` (UTC).
   - Todo recurso tenant-scoped contém `organization_id` (ou ligação inequívoca) e índices compostos começam por `organization_id`.
   - Paginação por cursor em listas que crescem; chaves estrangeiras e políticas `ON DELETE` explícitas.
   - `audit_logs` e `incident_events` são append-only (sem `UPDATE`/`DELETE` para o utilizador da aplicação).
3. **Atomicidade da outbox:** transições de estado (novo issue, regressão, alerta `firing`) e inserção em `notification_outbox` ocorrem na **mesma transacção PostgreSQL**.
4. **Separação lógica:** telemetria de alto volume nunca é gravada em tabelas transaccionais comuns sem particionamento/retenção (decisão detalhada no ADR-003).

## 4. Consequências

### Positivas
- Uma única tecnologia de base de dados operacional para metadata e séries temporais/eventos iniciais.
- Defesa em profundidade disponível via RLS, constraints e transacções ACID.
- Migrations SQL versionadas e reprodutíveis via `goose` + `sqlc`.

### Negativas / Trade-offs aceites
- Exige gestão cuidadosa de ligações (`MaxConns` por processo e `PgBouncer` quando o número de réplicas crescer).
- Migrations têm de seguir o padrão expand/contract (§16.3) para não causar downtime nem locks prolongados.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Esgotamento de ligações com múltiplos processos | Média / Alto | Limite explícito de pool por processo (`DATABASE_MAX_CONNS`), `statement_timeout` e `PgBouncer` na Fase 8 |
| Contenção entre telemetria e metadata na mesma instância | Média / Alto | Isolar acesso à telemetria atrás de interface (`TelemetryStore`), retenção/compressão e migração para instância/ClickHouse se medido (ADR-003) |
| Perda de dados ou migration destrutiva | Baixa / Crítico | Backups automáticos encriptados com restore testado periodicamente (§16.6) e padrão expand/contract |

## 6. Validação / Protótipo / Benchmark

- Container `timescale/timescaledb:2.32.1-pg18` endurecido já operacional em `compose.yaml` com `SCRAM-SHA-256` e `migrations/00001_enable_extensions.sql`.
- **Sinal para rever:** nunca para metadata (permanece em PostgreSQL); para telemetria/eventos de alto volume, ver critérios do ADR-003.

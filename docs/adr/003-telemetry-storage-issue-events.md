# ADR-003: Armazenamento da telemetria e dos `issue_events` (TimescaleDB vs ClickHouse)

- **Estado:** Aceite
- **Data:** 2026-11-27
- **Responsável:** CTO (Claude)
- **Revisão CTO:** Aprovado (2026-11-27); **emendado (2026-11-28)** — sem columnstore, ver §7
- **Fase bloqueada:** Antes da Fase 2
- **Referências:** README §5.1, §5.3, §8.2, §8.3, §8.5, §13, §17.2; TASKS 2.3; ADR-002, ADR-008, ADR-009, ADR-014; `docs/decisions/perguntas-ceo.md` (perguntas 3, 4 e 5)

---

## 1. Contexto

A Fase 2 começa a guardar o primeiro volume grande de dados do Vigia: os eventos de erro enviados pelos SDKs Sentry. Cada evento tem stack trace, breadcrumbs, contexto e tags, normalmente entre 2 e 20 KiB depois de normalizado e redigido.

Restrições fixadas pelo CEO:

- **Volume do MVP (pergunta 3):** até 50 organizações e 1–5 milhões de eventos/mês; média de ~2 eventos/s, picos de 10–20/s e rajadas até **250 eventos/s**.
- **Retenção do beta (pergunta 4):** **30 dias** de `issue_events` e quota de 100 000 eventos/mês por organização.
- **Infraestrutura (pergunta 5):** um **VPS** (4 vCPU, 8–16 GB RAM, 160–250 GB NVMe) com Docker Compose. Não há equipa de operações dedicada.

O PostgreSQL já é a base de dados de metadata (ADR-002) e a imagem em uso é `timescale/timescaledb:2.32.1-pg18`, com a extensão `timescaledb` activada na migration `00001`. Toda a segurança multi-tenant assenta em RLS fail-closed e em `WithTenantTx` (ADR-008).

Sem esta decisão não se pode escrever a migration de `issues`/`issue_events` (TASKS 2.3) nem dimensionar o disco do go-live.

## 2. Alternativas consideradas

### Opção A — TimescaleDB no mesmo PostgreSQL (escolhida)
- **Prós:**
  - Um só motor de base de dados para operar, fazer backup (runbook `postgres-backup-restore.md`), monitorizar e proteger.
  - O mesmo modelo de segurança da Fase 1: RLS fail-closed, `WithTenantTx`, `sqlc` + `pgx` (ADR-014) e os testes-guarda do catálogo.
  - Transacções reais entre `issues` (agregado) e `issue_events` (detalhe): criar ou reabrir um issue e guardar o evento é atómico, e a fila de jobs (ADR-004) pode entrar na mesma transacção.
  - Hypertables com partição por tempo, compressão em colunas e remoção barata de partições antigas (`drop_chunks`) resolvem a retenção de 30 dias sem `DELETE` em massa.
  - O volume do MVP (≤ 5 M eventos/mês, ≤ 250 ev/s em rajada) está muito abaixo dos limites conhecidos do PostgreSQL num NVMe.
- **Contras:**
  - Partilha CPU, RAM e I/O com a metadata: uma rajada de ingestão pode afectar o login e a API. Mitiga-se com o processamento assíncrono no `worker` (ADR-004), limites de concorrência e quotas (ADR-009).
  - Compressão, continuous aggregates e políticas automáticas estão sob a **Timescale License (TSL)**, não Apache 2.0 (ver §3.6).
  - Pesquisa analítica de texto em grandes volumes é mais lenta do que num motor colunar.

### Opção B — ClickHouse para `issue_events`
- **Prós:** motor colunar desenhado para este tipo de dado; compressão e agregações muito rápidas; TTL nativo; escala a centenas de milhões de linhas.
- **Contras:** segundo motor de base de dados para operar, fazer backup e proteger no mesmo VPS; sem transacções com a metadata (o issue e o evento podem divergir); sem RLS equivalente, o isolamento entre clientes fica só no código; consumo de memória elevado para um VPS de 8–16 GB; o volume do MVP não o justifica. **Rejeitada para o MVP**; é o caminho de evolução (§3.7).

### Opção C — PostgreSQL com particionamento nativo (sem Timescale)
- **Prós:** 100 % licença PostgreSQL; RLS e transacções iguais à opção A.
- **Contras:** sem compressão (o disco do VPS fica no limite: ~150 GB em vez de ~35–40 GB com 30 dias de retenção); criação e remoção de partições feitas à mão por um job nosso. **Fica como plano de recurso** se a validação de RLS em chunks comprimidos falhar (§6) ou se a TSL se tornar um problema.

### Opção D — Object storage (S3) para o corpo dos eventos + índice no PostgreSQL
- **Prós:** disco barato e ilimitado para os payloads.
- **Contras:** duas escritas por evento, consistência eventual, latência na página do issue e mais uma dependência no go-live. Desnecessário para o MVP. **Rejeitada.**

## 3. Decisão

### 3.1 Motor
`issues` e `issue_events` vivem no **PostgreSQL existente**, com `issue_events` como **hypertable TimescaleDB**. Não se introduz ClickHouse na V1 enquanto os sinais de revisão do §6 não aparecerem.

### 3.2 `issues` (tabela normal, metadata)
- Colunas mínimas (README §8.2): `id`, `organization_id`, `project_id`, `fingerprint` (`bytea`, SHA-256 do fingerprint normalizado do ADR-017), `title`, `culprit`, `level`, `platform`, `status` (`unresolved | resolved | ignored`), `substatus` (`new | regressed | ongoing`), `first_seen`, `last_seen`, `occurrence_count`, `user_count_approx`, `first_release`, `last_release`, `assigned_to`, `resolved_at`, `created_at`, `updated_at`.
- `UNIQUE (project_id, fingerprint)` (README §8.2) e `UNIQUE (organization_id, id)` para FKs compostas; `FOREIGN KEY (organization_id, project_id) REFERENCES projects (organization_id, id)`.
- Índices a começar pelo tenant: `(organization_id, project_id, status, last_seen DESC, id DESC)` para a lista de issues com paginação por cursor.
- Contadores (`occurrence_count`, `last_seen`) actualizados pelo `worker` com `UPDATE ... SET occurrence_count = occurrence_count + $n` em lote por issue (nunca uma linha por evento sob contenção).

### 3.3 `issue_events` (hypertable)
- Coluna de partição: **`received_at`** (hora do servidor, de confiança). `occurred_at` (hora do cliente) é guardada mas nunca usada para partição nem retenção.
- Chunks de **1 dia** (`chunk_time_interval => INTERVAL '1 day'`).
- Colunas: `id uuid`, `organization_id`, `project_id`, `environment_id`, `issue_id`, `event_id` (o `event_id` do SDK, 32 hex), `received_at`, `occurred_at`, `level`, `release`, `environment` (nome), `platform`, `sdk_name`, `sdk_version`, `message` (truncada), `tags jsonb`, `payload jsonb` (o evento normalizado, já redigido e truncado pelos limites do ADR-017), `payload_size int`.
- Chave primária `(id, received_at)`: os índices únicos de uma hypertable têm de incluir a coluna de partição.
- Índices: `(organization_id, issue_id, received_at DESC)` (eventos de um issue) e `(organization_id, project_id, received_at DESC)`.
- **RLS fail-closed** igual às restantes tabelas de tenant (ADR-008): `ENABLE` + `FORCE` + política por `organization_id`. O teste-guarda do catálogo tem de a apanhar.
- ~~Compressão dos chunks com mais de 2 dias~~ **Retirado pela emenda de 2026-11-28 (§7):** o TimescaleDB 2.32.1 recusa columnstore em tabelas com RLS. `payload` e `tags` usam compressão TOAST **`lz4`** (`ALTER COLUMN ... SET COMPRESSION lz4`).
- **Schema interno fechado:** `REVOKE USAGE ON SCHEMA _timescaledb_internal FROM PUBLIC` na migration de `issue_events`. Sem isto, `vigia_app` lê os chunks directamente e **contorna o RLS** (verificado em 2026-11-28, §7).
- Sem FK de `issue_events` para `issues` (FKs de hypertables para tabelas normais funcionam, mas tornam a remoção de chunks e o `DELETE` de issues caros); a integridade é garantida pelo `worker` na mesma transacção, e a eliminação de um issue apaga os seus eventos explicitamente.

### 3.4 Deduplicação por `event_id`
Os SDKs repetem o envio quando não recebem resposta, por isso o mesmo `event_id` pode chegar várias vezes. Como a hypertable não permite `UNIQUE (project_id, event_id)` sem a coluna de partição:
- **1.ª linha (rápida):** na ingestão, `SET NX EX 86400` em Redis com a chave `dedup:<project_id>:<event_id>`; repetido → responde `200` com o mesmo `id` e não enfileira.
- **2.ª linha (garantia):** tabela normal `issue_event_ids (project_id, event_id, received_at, PRIMARY KEY (project_id, event_id))` com `organization_id` e RLS. O `worker` faz `INSERT ... ON CONFLICT DO NOTHING` **na mesma transacção** que insere em `issue_events`; 0 linhas → evento repetido, descarta sem contar. Linhas com mais de **7 dias** são removidas pelo `scheduler` (os SDKs não repetem envios tão antigos).

### 3.5 Retenção
- `issue_events`: **30 dias** no beta (ADR-009), aplicada por um job do `scheduler` que chama `drop_chunks('issue_events', older_than => now() - <retenção>)`. Com uma retenção única no beta, basta um job. Quando houver retenções diferentes por organização, a remoção por plano passa a ser `DELETE` por organização nos chunks acima do mínimo, ou hypertables por plano (decidir no ADR-009 revisto).
- `issues` sem eventos há mais de **90 dias** (`last_seen < now() - 90 days`) são apagados pelo mesmo job.
- A remoção não é instantânea; documentar no runbook e na política de privacidade (README §8.3, §17.2).

### 3.6 Revisão da Timescale License (README §5.3)
- As hypertables e o `drop_chunks` manual estão sob **Apache 2.0**. A compressão, os continuous aggregates e as políticas automáticas (`add_compression_policy`, `add_retention_policy`) estão sob a **Timescale License (TSL)**.
- A TSL permite usar estas funcionalidades num produto ou serviço que acrescenta valor próprio (*Value Added Product or Service*), desde que os clientes **não tenham acesso à base de dados como serviço** (não podem criar tabelas, correr SQL nem usar o TimescaleDB directamente). O Vigia é exactamente esse caso: os clientes só falam com a nossa API. **O uso no SaaS do Vigia é permitido.**
- **Self-hosted dedicado (futuro, pergunta 2 do CEO):** distribuir a imagem com TSL a um cliente também é permitido como parte do produto, mas o contrato com o cliente tem de proibir o uso do TimescaleDB fora do Vigia. 👔 Confirmar com o advogado **antes do primeiro contrato self-hosted**; não bloqueia o SaaS.
- Regra de código: **nada de correcção depende de funcionalidades TSL**. A retenção usa `drop_chunks` chamado pelo nosso `scheduler` (Apache); a compressão é só uma optimização de disco. Desligar a TSL (imagem `-oss`) tem de continuar a dar um sistema correcto, apenas com mais disco.

### 3.7 Abstracção para a evolução para ClickHouse (README §8.5)
O módulo `issues` acede aos eventos só através de uma interface própria (por exemplo `EventStore` com `Insert`, `ListByIssue`, `DeleteByIssue`, `DeleteByProject`). Nenhum outro módulo lê `issue_events` directamente. Migrar o detalhe dos eventos para ClickHouse no futuro troca a implementação dessa interface; `issues` fica no PostgreSQL.

## 4. Consequências

### Positivas
- Zero componentes novos de infraestrutura para o MVP; o backup e restore já testado na Fase 1 cobre os eventos.
- Isolamento entre clientes reforçado pela base de dados (RLS), também nos eventos de erro.
- Retenção barata (`drop_chunks`). Disco sem columnstore: estimativa a confirmar na tarefa 2.3 (§6.3), na ordem de 20–60 GB com 30 dias e 5 M eventos/mês com TOAST `lz4`, dentro do VPS de 160–250 GB.

### Negativas / Trade-offs aceites
- A ingestão partilha recursos com a API de produto; o `worker` tem de escrever em lote e com concorrência limitada.
- ~~Dependência parcial de funcionalidades TSL~~ Com a emenda, `issue_events` não usa nenhuma funcionalidade TSL.
- Mais disco do que com columnstore (sem compressão em colunas).
- Pesquisa de texto livre nos eventos limitada a filtros indexados e intervalos de tempo; pesquisa completa fica para depois do MVP.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| RLS contornado por queries directas aos chunks | **Certa se não se fizer nada** / Crítico | `REVOKE USAGE ON SCHEMA _timescaledb_internal FROM PUBLIC` na migration; teste-guarda do catálogo: `has_schema_privilege('vigia_app', '_timescaledb_internal', 'USAGE') = false`; repetir após `ALTER EXTENSION timescaledb UPDATE` |
| Rajada de ingestão degrada a API | Média / Alto | Ingestão assíncrona (ADR-004), escrita em lote, limites por organização (ADR-009), `statement_timeout`, monitorização do lag |
| Disco do VPS esgota antes da retenção | Média / Alto | Quotas (ADR-009), alerta a 70 % de disco, compressão a 2 dias, tamanho máximo por evento (ADR-017) |
| Mudança de termos da TSL | Baixa / Médio | Nenhuma correcção depende da TSL (§3.6); plano de recurso: opção C |
| Bloat por `UPDATE` frequente em `issues` | Média / Médio | Actualização em lote por issue no `worker`; `fillfactor` 80 e autovacuum mais agressivo em `issues` |

## 6. Validação / Protótipo / Benchmark

Obrigatório na tarefa 2.3, antes de fechar a migration:

1. **RLS** *(reescrito pela emenda, §7)***:** teste de integração como `vigia_app` que insere eventos de duas organizações em vários chunks diários e prova que `WithTenantTx(orgA)` nunca vê, altera nem apaga eventos de B; que sem tenant definido vê 0 linhas; que `INSERT` com `organization_id` de outra organização falha; e que `vigia_app` recebe `permission denied` ao ler um chunk directamente em `_timescaledb_internal`.
2. **Carga:** inserção em lote de 250 eventos/s durante 5 minutos (payload sintético de 8 KiB) no perfil de recursos do `compose.yaml`, com P95 da API de login abaixo de 300 ms durante a carga.
3. **Disco:** medir `pg_total_relation_size('issue_events')` por evento (TOAST `lz4`) com as fixtures dos SDKs e actualizar a estimativa de disco do go-live.
4. **Retenção:** `drop_chunks` remove só os chunks fora da janela e `issue_event_ids` é limpo pelo `scheduler`.

**Sinais para rever esta decisão (passar o detalhe dos eventos para ClickHouse):** mais de 50 M eventos/mês; P95 da lista de eventos de um issue acima de 1 s; disco da BD acima de 70 % com a retenção a funcionar; ou a ingestão a afectar o SLO da API de produto mesmo com o `worker` separado.

## 7. Emenda de 2026-11-28 — RLS e columnstore são incompatíveis

### 7.1 O que se verificou
Na porta do §6.1, o Gemini verificou e o CTO confirmou num contentor limpo `timescale/timescaledb:2.32.1-pg18`:

- RLS activado e depois `timescaledb.compress`: `ERROR: columnstore cannot be used on table with row security (SQLSTATE 0A000)`. Na ordem inversa: `operation not supported on hypertables that have columnstore enabled`. **Não há forma de ter as duas coisas na mesma hypertable.**
- Numa hypertable **sem** columnstore, o RLS funciona: com `ENABLE` + `FORCE`, um papel `NOSUPERUSER NOBYPASSRLS` vê só as linhas do seu tenant, vê 0 linhas sem tenant, e um `INSERT` de outro tenant falha.
- **Achado novo:** por omissão, `PUBLIC` tem `USAGE` em `_timescaledb_internal` e os chunks herdam os `GRANT` da hypertable. Um `SELECT` directo a `_timescaledb_internal._hyper_1_1_chunk` **sem tenant definido devolveu linhas**: o RLS da hypertable não se aplica aos chunks. Depois de `REVOKE USAGE ON SCHEMA _timescaledb_internal FROM PUBLIC`, o mesmo `SELECT` dá `permission denied`, e o `INSERT` pela hypertable (incluindo a criação de chunks novos), o `SELECT` e o `DELETE` continuam a funcionar.

### 7.2 Decisão
- `issue_events` continua **hypertable TimescaleDB** com chunks diários, `drop_chunks` (Apache 2.0) e **RLS `ENABLE` + `FORCE`**, **sem columnstore**.
- `payload` e `tags` com `SET COMPRESSION lz4` (TOAST nativo do PostgreSQL).
- `REVOKE USAGE ON SCHEMA _timescaledb_internal FROM PUBLIC` na mesma migration, com teste-guarda no catálogo.
- O isolamento entre clientes (ADR-008) não cede para poupar disco. O isolamento só no código, por funções `SECURITY DEFINER` sobre uma tabela sem RLS, foi **rejeitado**.
- O particionamento nativo (opção C) não traz vantagem enquanto não houver compressão em nenhum dos dois: obrigaria a escrever a criação de partições à mão. Continua a ser o plano de recurso se a TSL ou o TimescaleDB se tornarem um problema.

### 7.3 Consequências
- `issue_events` deixa de depender da TSL.
- Mais disco. O alerta a 70 % de disco e as quotas (ADR-009) passam a ser a protecção principal. Se a medição do §6.3 der mais de **80 GB** a 30 dias com 5 M eventos/mês, o CTO revê (retenção mais curta, `payload` mais pequeno ou o caminho ClickHouse do §3.7).
- **Fase 3 (métricas, TASKS §3):** a mesma limitação vale para a hypertable `metrics`, a compressão e os continuous aggregates. O ADR de métricas tem de partir deste facto, e não do desenho original.


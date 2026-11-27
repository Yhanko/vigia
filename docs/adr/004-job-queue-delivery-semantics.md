# ADR-004: Fila de jobs e semântica de entrega (Asynq vs River vs RabbitMQ/NATS)

- **Estado:** Aceite
- **Data:** 2026-11-27
- **Responsável:** CTO (Claude)
- **Revisão CTO:** Aprovado (2026-11-27)
- **Fase bloqueada:** Antes da Fase 2
- **Referências:** README §4.3, §4.4, §5.1, §5.2, §7.7, §13; TASKS 2.0, 2.2, 2.3, 2.5, 2.6; ADR-002, ADR-003, ADR-008, ADR-009, ADR-014

---

## 1. Contexto

A Fase 2 precisa de trabalho assíncrono em três sítios:

1. **Ingestão:** a API valida, redige e responde ao SDK em milissegundos; o agrupamento em issues e a escrita em `issue_events` acontecem depois, no `worker` (TASKS 2.2, README §4.3).
2. **Alertas e notificações:** criar ou reabrir um issue pode disparar uma regra; a notificação tem de sair **uma vez**, mesmo com falhas, retries e reinícios (TASKS 2.5, 2.6, README §7.7).
3. **Jobs periódicos:** detecção de picos, digests, retenção (`drop_chunks`, limpeza de `issue_event_ids`, sessões e tokens expirados), com garantia de que correm uma só vez mesmo com várias réplicas.

O README propunha Asynq (Redis) e deixava River (PostgreSQL) como alternativa a avaliar aqui (§5.2). Factos do nosso ambiente:

- Redis está configurado com `maxmemory 256mb`, `maxmemory-policy noeviction` e `appendfsync everysec` (`infrastructure/docker/redis/redis.conf`). Uma fila em Redis com eventos de 8–20 KiB enche 256 MB com ~15–30 mil eventos em espera; a partir daí **todas** as escritas em Redis falham, incluindo o rate limit, as sessões em cache e a deduplicação. Com `everysec`, um crash perde até 1 s de jobs aceites.
- O PostgreSQL é durável, tem backup e restore testados (Fase 1), e o processamento dos eventos escreve no próprio PostgreSQL (ADR-003).
- Volume do MVP: média ~2 eventos/s, rajadas até 250 eventos/s (pergunta 3 do CEO).

## 2. Alternativas consideradas

### Opção A — River (fila em PostgreSQL, `riverqueue/river` + `riverpgxv5`) (escolhida)
- **Prós:**
  - **Enfileirar na mesma transacção** da mudança de estado: o issue criado ou reaberto e o job de notificação entram ou falham juntos. É a outbox do README §4.3 sem tabela de outbox nem processo de publicação.
  - Durável e coberto pelo backup e restore que já existe; não há perda de jobs aceites num crash.
  - Usa o `pgx/v5` que já temos (ADR-014); jobs com tipos Go.
  - Retries com backoff, jobs descartados visíveis (o equivalente de DLQ), jobs únicos, agendados e **periódicos com eleição de líder** (resolve o "lock distribuído" do `scheduler` sem código nosso).
  - Licença MPL-2.0: podemos usar sem modificar e sem obrigações para o nosso código.
- **Contras:**
  - Põe a carga da fila na BD principal (inserção, `FOR UPDATE SKIP LOCKED`, limpeza). No volume do MVP é pequena, mas tem de ser medida (§6).
  - A tabela `river_job` recebe payloads com dados de clientes: precisa de regras próprias de acesso e de retenção curta (§3.4).
  - Sem justiça nativa entre clientes; uma organização com uma rajada ocupa a fila de ingestão (mitigado pelas quotas do ADR-009).

### Opção B — Asynq (Redis)
- **Prós:** muito rápido; maduro; tinha sido a proposta inicial do README.
- **Contras:** não enfileira na transacção do PostgreSQL (precisa de uma outbox à parte e de um publicador); Redis com 256 MB e `noeviction` torna-se o ponto único de falha da ingestão inteira sob backlog; até 1 s de perda num crash; backup e restore da fila separados da BD. **Rejeitada.**

### Opção C — RabbitMQ ou NATS JetStream
- **Prós:** semântica de mensagens rica; escala muito acima do necessário.
- **Contras:** mais um servidor para operar, proteger e fazer backup no VPS; outbox à parte; sobredimensionado para ≤ 250 ev/s. **Rejeitada** (reavaliar só pelos sinais do §6).

### Opção D — Redis Streams escritos à mão
- **Prós:** sem dependência nova.
- **Contras:** os mesmos problemas de memória e durabilidade da opção B, e retries, DLQ e agendamento escritos por nós. **Rejeitada.**

## 3. Decisão

### 3.1 Tecnologia
Adoptar **River** (`github.com/riverqueue/river` com o driver `riverpgxv5`), com a versão fixada no `go.mod` e actualizada pelo Dependabot com o `cooldown` habitual.

- As migrations do River entram no **goose**, não noutro migrador: gerar o SQL da versão fixada (`river migrate-get --version <n> --up/--down`) para ficheiros `migrations/000NN_river_*.sql`. Uma só ferramenta e um só histórico de migrations; o `up → down → up` do teste de integração cobre-as.
- As tabelas do River (`river_job`, `river_leader`, `river_queue`, …) ficam no schema `public`, com `GRANT` explícitos só a `vigia_app` (sem `PUBLIC`), e entram no teste-guarda do catálogo.

### 3.2 Filas e processos

| Fila | Jobs | Processo | Concorrência inicial | Tentativas |
|---|---|---|---|---|
| `ingest` | `ProcessErrorEvent` (normalizar, agrupar, gravar, contar) | `vigia worker` | 8 | 5 |
| `alerts` | avaliação de "novo issue", "regressão" e "pico" | `vigia worker` | 4 | 5 |
| `notifications` | um job por notificação e destino | `vigia dispatcher` | 8 (com limites por canal) | 8 |
| `maintenance` | retenção, limpezas, agregados de uso | `vigia worker` | 2 | 3 |

- **Jobs periódicos** (picos, digests, retenção, limpezas, agregados de uso) são `PeriodicJobs` do River com eleição de líder, a correr dentro do `vigia worker`. **O subcomando `vigia scheduler` deixa de ser necessário no MVP** (TASKS 2.0 actualizado). Volta a existir só se for preciso separar os periódicos para outro deploy.
- `vigia worker` e `vigia dispatcher` são o mesmo binário com conjuntos de filas diferentes (README §4.4). Ambos fazem *graceful shutdown*: param de buscar jobs, esperam os que estão a correr até um limite (`WORKER_SHUTDOWN_TIMEOUT`, 30 s por omissão) e saem.

### 3.3 Semântica de entrega: *at-least-once* + idempotência obrigatória
River garante que cada job corre **pelo menos uma vez**; pode correr mais do que uma (crash a meio, timeout). Por isso **todo o handler é idempotente**:

- **`ProcessErrorEvent`:** a deduplicação final é o `INSERT ... ON CONFLICT DO NOTHING` em `issue_event_ids` na mesma transacção que grava o evento e actualiza o issue (ADR-003 §3.4). Uma segunda execução do mesmo job não grava nada nem conta duas vezes.
- **Alertas e outbox:** o job de notificação é inserido com `InsertTx` **na mesma transacção** que cria/reabre o issue ou muda o estado do alerta. Não há tabela `notification_outbox`: a linha em `river_job` é a outbox (README §4.3 e §8.2 actualizados na prática por esta decisão).
- **Notificações:** cada envio tem uma **idempotency key** determinística (`notification_id`), gravada em `notifications` antes de chamar o fornecedor e enviada ao fornecedor quando este a suporta. Antes de enviar, o handler confirma que a notificação ainda está `pending`; depois de um envio aceite, marca `sent` com o `provider_message_id`. Um retry depois de um `sent` não reenvia.
- **Jobs únicos:** os periódicos e os jobs "um por chave" (por exemplo, o digest de um issue numa janela) usam as opções de unicidade do River.

### 3.4 Segurança e privacidade dos jobs
- Os `args` dos jobs levam **sempre** `organization_id`. O handler abre `WithTenantTx` com esse valor antes de tocar em dados de tenant; nunca confia noutro campo do payload para o tenant (ADR-008).
- O evento só entra na fila **depois** da redacção do servidor (TASKS 2.2): `river_job` nunca guarda passwords, tokens, cookies nem request bodies.
- Retenção curta dos jobs terminados: completos apagados após **1 hora**; cancelados após **24 horas**; descartados (tentativas esgotadas) após **7 dias**, para análise. Configurado nos parâmetros de limpeza do cliente River.
- Erros guardados pelo River nos jobs (`errors`) passam pelo mesmo cuidado dos logs: nada de segredos nem payloads nas mensagens de erro.

### 3.5 Backpressure
- Se a fila `ingest` tiver mais de **50 000** jobs disponíveis, ou o job mais antigo tiver mais de **5 minutos**, a ingestão responde `429` com `Retry-After` e `X-Sentry-Rate-Limits` (ADR-017) em vez de aceitar trabalho que não consegue processar (README §13, ponto 2). O valor é lido com cache de poucos segundos, não por pedido.
- As quotas e o rate limit por organização (ADR-009) são a primeira barreira; o backpressure da fila protege o sistema inteiro.

### 3.6 Observabilidade
Métricas por fila e tipo de job: inseridos, completos, falhados, descartados, duração, idade do job mais antigo e profundidade. Alerta da própria plataforma quando há jobs descartados em `notifications` ou o lag de `ingest` passa de 1 minuto (README §14.1).

## 4. Consequências

### Positivas
- Atomicidade entre mudança de estado e notificação sem outbox própria nem publicador.
- Um só sistema durável para fazer backup e restaurar; Redis volta a ser só cache, rate limit, deduplicação rápida e idempotência.
- O `scheduler` fica resolvido pela eleição de líder do River.

### Negativas / Trade-offs aceites
- Mais escrita no PostgreSQL; obriga a medir (§6) e a manter o autovacuum de `river_job` agressivo.
- Dependência de uma biblioteca de terceiros no caminho crítico, com versões a acompanhar.
- Sem justiça entre organizações dentro da fila `ingest` no MVP.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| A fila sobrecarrega a BD durante uma rajada | Média / Alto | Benchmark obrigatório (§6); backpressure (§3.5); concorrência limitada; autovacuum agressivo em `river_job` |
| Handler não idempotente gera duplicados | Média / Alto | Regra do §3.3 com teste obrigatório por handler: executar o mesmo job duas vezes não muda o resultado |
| Uma organização monopoliza a fila de ingestão | Média / Médio | Rate limit e quotas por organização (ADR-009); filas por organização ou pesos se o problema aparecer |
| Payloads de clientes esquecidos em `river_job` | Baixa / Alto | Redacção antes de enfileirar; limpeza de 1 h; `river_job` sem acesso fora de `vigia_app` |
| Actualização do River muda o schema | Baixa / Médio | Versão fixada; migrations geradas e revistas; `up → down → up` no CI |

## 6. Validação / Protótipo / Benchmark

Obrigatório na tarefa 2.0, antes de ligar a ingestão:

1. **Carga:** inserir e processar **250 jobs/s durante 5 minutos** (payload de 8 KiB) no perfil de recursos do `compose.yaml`, com o lag da fila abaixo de 30 s no fim, P95 do `InsertTx` abaixo de 20 ms e P95 do login abaixo de 300 ms durante o teste.
2. **Idempotência:** para cada tipo de job, teste que corre o mesmo job duas vezes (e uma terceira depois de um crash simulado a meio da transacção) e prova que não há duplicados.
3. **Atomicidade:** rollback da transacção que cria o issue não deixa job de notificação; commit deixa exactamente um.
4. **Shutdown:** `SIGTERM` com jobs a correr: terminam dentro do limite ou voltam à fila, sem perda.

**Sinais para rever esta decisão:** mais de 1 000 jobs/s sustentados; a fila a representar mais de 30 % da escrita da BD; lag de `ingest` acima de 1 minuto com a concorrência no máximo; ou necessidade de justiça forte entre clientes que o River não dê.

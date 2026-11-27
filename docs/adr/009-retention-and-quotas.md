# ADR-009: Retenção e quotas (eventos de erro, mensagens WhatsApp e limites da organização)

- **Estado:** Aceite
- **Data:** 2026-11-27
- **Responsável:** CTO (Claude)
- **Revisão CTO:** Aprovado (2026-11-27)
- **Fase bloqueada:** Antes da Fase 2
- **Referências:** README §7.5, §7.7, §17.1, §17.2, §17.3; TASKS 2.0, 2.2, 2.3, 2.7; ADR-003, ADR-004, ADR-017; `docs/decisions/perguntas-ceo.md` (perguntas 3 e 4); `docs/decisions/business-defaults.md` §4

---

## 1. Contexto

O CEO fixou um **plano único durante o beta** (pergunta 4): 30 dias de retenção de `issue_events`, 100 000 eventos/mês, 10 projectos, 15 membros e 200 mensagens WhatsApp/mês por organização; `audit_logs` com pelo menos 180 dias. O `business-defaults.md` §4 fixou ainda 1 000 eventos/minuto por organização na ingestão Sentry.

Falta decidir como se contam e aplicam estes limites, o que acontece quando se atingem, e a retenção de todos os outros dados que a Fase 2 cria. Duas razões tornam isto obrigatório antes de abrir a ingestão (README §17):

- **Custo e capacidade:** o VPS do MVP (ADR-003) só aguenta o volume previsto se cada organização tiver tecto. O WhatsApp custa dinheiro por mensagem.
- **Privacidade:** os eventos de erro podem conter dados pessoais; a retenção tem de ser curta, conhecida e aplicada automaticamente.

## 2. Alternativas consideradas

### Opção A — Limites em Redis com persistência periódica no PostgreSQL (escolhida)
- **Prós:** a verificação no caminho da ingestão é um `INCR` em Redis (rápida, sem tocar na BD por evento); o PostgreSQL guarda o consumo para relatórios, auditoria e recuperação se o Redis perder dados.
- **Contras:** dois sítios com contadores; numa falha do Redis os contadores ficam aproximados até à reconciliação.

### Opção B — Contadores só no PostgreSQL
- **Prós:** uma só fonte de verdade.
- **Contras:** uma escrita na BD por evento aceite, com contenção na mesma linha por organização. **Rejeitada.**

### Opção C — Sem quotas no beta, só rate limit
- **Prós:** mais simples.
- **Contras:** uma organização com um ciclo de erros consome o disco de todos e o orçamento de WhatsApp. **Rejeitada.**

## 3. Decisão

### 3.1 Limites do plano único do beta

| Recurso | Limite | Janela | Tipo |
|---|---|---|---|
| Eventos de erro aceites | **100 000** | mês civil (UTC) | rígido |
| Eventos de erro aceites | **20 000** | dia (UTC) | rígido (impede gastar o mês num só dia) |
| Ritmo de ingestão | **1 000 eventos/min** por organização e **600 eventos/min** por chave DSN | janela deslizante | rate limit |
| Mensagens WhatsApp enviadas | **200** | mês civil (UTC) | rígido, com fallback (§3.4) |
| Projectos activos | **10** | — | rígido na criação |
| Membros activos + convites pendentes | **15** | — | rígido no convite |
| Regras de alerta por projecto | **50** | — | rígido na criação |
| Destinos de notificação por organização | **50** | — | rígido na criação |
| Source maps e artefactos (2.4) | **1 GiB** | total por organização | rígido no upload |

Os valores vivem numa tabela `plans` (uma linha, `beta`) e numa coluna `organizations.plan`, não em constantes espalhadas. Mudar um limite é uma migration de dados revista pelo CTO e aprovada pelo CEO.

### 3.2 O que conta como "evento de erro aceite"
- Conta: cada item `event` (e cada corpo do `/store/`) que passou a autenticação, o rate limit, os filtros de entrada do projecto, a deduplicação por `event_id` (ADR-003 §3.4) e as validações de tamanho.
- **Não conta:** itens descartados por tipo (`transaction`, `session`, `replay_*`, …, ADR-017), eventos repetidos, eventos filtrados (extensões de browser, `localhost`, crawlers) e eventos rejeitados por limite.
- A contagem é incrementada **na ingestão**, antes de enfileirar (é aí que a quota se aplica). O `worker` não volta a contar.

### 3.3 Aplicação e resposta aos SDKs
- **Contadores:** Redis, `INCRBY` atómico em `quota:<org_id>:events:<YYYY-MM-DD>` (TTL 48 h) e `quota:<org_id>:events:<YYYY-MM>` (TTL 35 dias). A verificação e o incremento fazem-se num só script Lua, para que dois pedidos em simultâneo não passem os dois o limite.
- **Ao exceder:** resposta `429` com `Retry-After` (segundos até ao início do próximo dia ou mês UTC) e `X-Sentry-Rate-Limits: <segundos>:error;default:organization:quota_exceeded`. Os SDKs param de enviar até lá (ADR-017). O rate limit por minuto usa o mesmo formato com `scope` `key` ou `organization` e motivo `rate_limited`.
- **Redis indisponível:** a ingestão **não** aceita eventos sem conseguir verificar a quota (responde `503` com `Retry-After: 30`). É a mesma política *fail-closed* do `/auth/*`.
- **Persistência:** a cada minuto, um job periódico (ADR-004) copia os contadores para `usage_aggregates (organization_id, resource, period_start, period_kind, used)`. Se o Redis perder os contadores, o primeiro pedido do dia reconstrói-os a partir de `usage_aggregates` e de `count(*)` em `issue_event_ids` do período.
- **Avisos ao owner e admins:** por email a **80 %** e a **100 %** de cada limite mensal (uma vez por período e limite), e o uso fica visível em `GET /organizations/:id/usage` e `/quotas`.

### 3.4 WhatsApp
- Conta cada mensagem **aceite pelo fornecedor** (é o que é cobrado), não cada tentativa falhada.
- A **80 %**: aviso por email ao owner. A **100 %**: as notificações por WhatsApp passam a `suppressed` com motivo `quota_exceeded` e o dispatcher envia o mesmo alerta por **Telegram e email** aos mesmos destinatários (se tiverem esses destinos), sem duplicar se já os tinham.
- Os códigos de verificação de número (opt-in) contam para a quota, com limite adicional de **5 por número por dia**.

### 3.5 Retenção por tipo de dado

| Dado | Retenção | Como é aplicada |
|---|---|---|
| `issue_events` | **30 dias** | `drop_chunks` diário pelo job de retenção (ADR-003 §3.5) |
| `issue_event_ids` (deduplicação) | **7 dias** | `DELETE` em lote diário |
| `issues` | até **90 dias** depois de `last_seen` | apagados com os eventos que restarem |
| Artefactos de source maps | **90 dias** sem uso ou quando a release é apagada | job diário + limpeza do object storage |
| `notifications` (histórico de entregas) | **90 dias** | `DELETE` em lote diário |
| Jobs do River | 1 h (completos), 24 h (cancelados), 7 dias (descartados) | limpeza do River (ADR-004 §3.4) |
| `usage_aggregates` | **13 meses** | `DELETE` mensal |
| `audit_logs` | **400 dias** (acima do mínimo de 180 dias do CEO, para cobrir uma auditoria anual) | job mensal que chama a função `SECURITY DEFINER` `purge_audit_logs()`, dona `vigia_definer`, que só apaga linhas com mais de 400 dias (o limite está dentro da função, não é parâmetro); o `vigia_app` continua sem `DELETE` em `audit_logs` |
| Sessões expiradas ou revogadas | **30 dias** depois de expirar | `DELETE` diário |
| `user_tokens` usados ou expirados | **7 dias** | `DELETE` diário |
| Chaves de idempotência e deduplicação em Redis | 24 h | TTL |
| Dados de uma organização eliminada | apagados no fim dos **14 dias** de graça (critical-flows.md §3) | job de purga; `audit_logs` da organização mantêm-se pela sua retenção |
| Backups | conforme o runbook e a §16.6 do README | — |

- Todos os jobs de retenção correm na fila `maintenance` com eleição de líder (ADR-004), em lotes pequenos (≤ 5 000 linhas por transacção) para não bloquear a BD.
- A remoção não é instantânea (até 24 h de atraso); isto fica escrito na política de privacidade.
- **Pedidos de eliminação do titular (README §17.2):** apagar um issue apaga os seus eventos imediatamente (também em chunks comprimidos); apagar dados de um utilizador final dentro dos eventos faz-se por projecto, com filtro por `user.id`/`user.email` em `payload`, num job assíncrono com registo em `audit_logs`.

### 3.6 Depois do beta
Quando houver planos pagos, os limites passam a vir da linha do plano da organização. Retenções diferentes por plano em `issue_events` exigem rever o §3.5 do ADR-003 (o `drop_chunks` remove para todos). Esta revisão é pré-condição do primeiro plano pago, não do beta.

## 4. Consequências

### Positivas
- Custo e disco previsíveis: o pior caso do beta é 50 organizações × 100 000 eventos/mês = 5 M eventos/mês, dentro do dimensionamento do ADR-003.
- Os SDKs respeitam os limites sozinhos (`X-Sentry-Rate-Limits`), em vez de repetir pedidos.
- Retenção curta e automática dos dados mais sensíveis.

### Negativas / Trade-offs aceites
- Redis passa a ser obrigatório para aceitar eventos (fail-closed).
- Uma organização que bata no limite diário deixa de ver erros novos até ao dia seguinte; o aviso a 80 % e o painel de uso são a mitigação.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Contadores perdidos num restart do Redis | Baixa / Médio | AOF `everysec`; reconstrução a partir de `usage_aggregates` e `issue_event_ids` (§3.3) |
| Cliente legítimo bloqueado por um ciclo de erros | Média / Médio | Limite diário + aviso a 80 %; filtros de entrada; o owner vê o uso e pode corrigir a app |
| Fatura de WhatsApp acima do previsto | Baixa / Alto | Quota rígida por organização, contagem só de mensagens aceites, fallback para Telegram/email |
| Job de retenção falha em silêncio | Média / Alto | Métrica da idade do chunk mais antigo e alerta da plataforma se passar de 31 dias |

## 6. Validação / Protótipo / Benchmark

- Testes com `clock.Fake` para mudança de dia e de mês UTC, avisos a 80 % e 100 % emitidos uma só vez, e concorrência (N pedidos em simultâneo no limite: nenhum passa acima).
- Teste de integração: quota excedida devolve `429` com `Retry-After` e `X-Sentry-Rate-Limits` correctos; Redis em baixo devolve `503`.
- Teste de retenção: com relógio avançado, cada tabela da §3.5 fica só com o que está dentro da janela.

**Sinais para rever:** mais de 20 % das organizações a bater no limite mensal (limites baixos demais para o produto); disco a crescer acima da estimativa do ADR-003; ou o primeiro plano pago.

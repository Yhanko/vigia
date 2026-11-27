# ADR-017: Compatibilidade com o protocolo de ingestão dos SDKs Sentry

- **Estado:** Aceite
- **Data:** 2026-11-27
- **Responsável:** CTO (Claude)
- **Revisão CTO:** Aprovado (2026-11-27)
- **Fase bloqueada:** Antes da Fase 2
- **Referências:** README §7.8, §17.3, §19; TASKS 2.1, 2.2, 2.3, 2.4, 2.9; ADR-003, ADR-004, ADR-005, ADR-008, ADR-009; registo de decisões do CTO de 2026-11-26 (ingestão compatível Sentry, sem código do servidor Sentry)

---

## 1. Contexto

O MVP do Vigia recebe erros dos **SDKs oficiais Sentry** (licenças MIT/BSD), para que um cliente migre só trocando o DSN (decisão do CEO de 2026-11-26). Os SDKs falam um protocolo HTTP público, documentado para quem escreve SDKs (develop.sentry.dev). O Vigia implementa o lado do servidor desse protocolo **a partir dessa documentação e do comportamento observado dos SDKs**, sem usar código do servidor Sentry nem do Relay (licença FSL).

O protocolo é grande e evolui. Este ADR fixa o subconjunto que o MVP suporta, como se comporta com o resto, os limites, o agrupamento em issues e a matriz de SDKs. Sem ele, a TASKS 2.2 não tem especificação.

## 2. Alternativas consideradas

### Opção A — Implementar o subconjunto de erros do protocolo, aceitar e descartar o resto (escolhida)
- **Prós:** os SDKs funcionam sem alterações (nunca recebem erros por tipos que não suportamos); o âmbito do MVP fica pequeno; cada tipo novo pode ser activado depois.
- **Contras:** os clientes enviam dados que deitamos fora (largura de banda); mitigado com `X-Sentry-Rate-Limits` (§3.6).

### Opção B — Usar o Relay (proxy de ingestão do Sentry) à frente do Vigia
- **Contras:** licença FSL, que proíbe uso concorrente com o Sentry; contraria a decisão legal de 2026-11-26. **Rejeitada.**

### Opção C — Protocolo próprio com SDK próprio
- **Contras:** os clientes teriam de mudar código; foi cancelado no MVP pelo CEO. **Rejeitada.**

### Opção D — Implementar o protocolo completo (transactions, replays, profiling, …)
- **Contras:** meses de trabalho fora do âmbito do MVP (performance, replays e profiling estão fora da V1). **Rejeitada.**

## 3. Decisão

### 3.1 Endpoints
- `POST /api/{project_id}/envelope/` (actual) e `POST /api/{project_id}/store/` (legado), **com e sem barra final**, e `OPTIONS` nos dois para o preflight dos browsers.
- `{project_id}` é o `projects.public_id` numérico (TASKS 2.1), nunca o UUID interno. Valor não numérico → `400`.
- Estas rotas vivem **fora de `/api/v1`**, num grupo de rotas com limites de corpo, CORS e rate limit próprios (TASKS 2.2). Nunca passam pelo middleware de sessão, CSRF ou idempotência.
- Respostas de sucesso: `200` com `{"id":"<event_id>"}` (o `event_id` do evento aceite, ou o do header do envelope se não houver item `event`). Nunca `202` nestas rotas: os SDKs esperam `200`.
- Respostas de erro: JSON `{"detail":"<mensagem curta>"}` com `400` (pedido mal formado), `401` (sem chave ou chave inválida), `403` (chave de outro projecto, chave revogada, origem não permitida), `413` (demasiado grande), `415` (compressão não suportada), `429` (limites, §3.6) e `503` (sobrecarga ou dependência em baixo, com `Retry-After`).

### 3.2 Autenticação
A chave pública (`sentry_key`) é procurada por esta ordem, e usa-se a primeira encontrada:
1. Header `X-Sentry-Auth: Sentry sentry_key=<chave>, sentry_version=7, sentry_client=<sdk>/<versão>[, sentry_timestamp=…][, sentry_secret=…]`.
2. Header `Authorization: Sentry …` com o mesmo formato.
3. Query string `?sentry_key=<chave>&sentry_version=7[&sentry_client=…]` (é o que os SDKs de browser usam, para evitar o preflight de CORS).
4. Campo `dsn` do header do envelope (usado quando o cliente passa os envios por um *tunnel* próprio).

Regras:
- A chave tem 32 caracteres hexadecimais minúsculos e é uma credencial `kind = 'dsn'` (ADR-005). Formato inválido → `401`.
- A chave tem de pertencer ao projecto do `{project_id}` do path, estar activa, e o projecto e a organização têm de estar `active`. Uma função `SECURITY DEFINER` `lookup_dsn_key(public_key)` (dona `vigia_definer`, sem `EXECUTE` para `PUBLIC`, com os `JOIN` de estado da migration `00007`) devolve `organization_id`, `project_id`, `public_id`, `environment_id`, `allowed_origins` e o estado; cache Redis de 60 s com invalidação na revogação, igual às outras credenciais.
- O tenant, o projecto e o ambiente vêm **só** da chave validada (README §11.1). `organization`, `project` ou `dsn` dentro do payload nunca mudam o destino.
- `sentry_version`: aceita `7` ou ausente (assume 7). Outro valor → `400`.
- `sentry_secret` (chaves secretas antigas) é **ignorado**: o Vigia não usa segredos no DSN.
- `sentry_client` é guardado (truncado a 64 caracteres) só para estatísticas de SDK; nunca para decisões de segurança.

### 3.3 CORS (SDKs de browser)
- Pedidos com `Origin`: se a chave tiver `allowed_origins` não vazio e a origem não estiver na lista → `403` sem processar o corpo. Com a lista vazia, aceita qualquer origem.
- Respostas a pedidos com `Origin` levam `Access-Control-Allow-Origin` igual à origem pedida (se permitida) ou `*` (lista vazia), **sem** `Access-Control-Allow-Credentials`.
- Preflight `OPTIONS`: `Access-Control-Allow-Methods: POST, OPTIONS`; `Access-Control-Allow-Headers: Content-Type, Content-Encoding, X-Sentry-Auth, Authorization, sentry-trace, baggage`; `Access-Control-Max-Age: 3600`.
- `Access-Control-Expose-Headers: X-Sentry-Rate-Limits, Retry-After`. Sem isto, os SDKs de browser não conseguem ler os limites e continuam a enviar.
- `allowed_origins` serve para travar abuso de uma chave copiada, não é uma barreira de segurança: SDKs de servidor não enviam `Origin` e uma chave DSN é pública por natureza.

### 3.4 Formato do envelope
- Corpo: uma linha de header JSON do envelope, depois zero ou mais itens; cada item é uma linha de header JSON seguida do payload. Separador `\n`. `Content-Type` aceite: `application/x-sentry-envelope`, `text/plain` (browsers) ou ausente.
- Header do envelope: `event_id`, `dsn`, `sent_at`, `sdk` (`name`, `version`); campos desconhecidos são ignorados.
- Header do item: `type` (obrigatório), `length` (opcional), `content_type`, `filename`; campos desconhecidos são ignorados.
- Com `length`: lê exactamente esse número de bytes e depois espera `\n` ou fim do corpo; se não houver bytes suficientes ou o byte seguinte for outro → `400` (envelope com `length` mentiroso).
- Sem `length`: o payload vai até ao próximo `\n` ou ao fim do corpo.
- O parser lê em streaming com limites (§3.7) e é alvo de fuzzing (`go test -fuzz`, TASKS 2.2). Um item que não interessa (§3.5) é saltado sem ser guardado em memória.
- `/store/`: o corpo é o JSON do evento (equivalente a um envelope com um item `event`). O formato antigo com base64 + zlib dos SDKs muito antigos **não é suportado** (`400`).
- `event_id`: 32 hexadecimais (UUID sem hífenes), normalizado para minúsculas; também aceita UUID com hífenes. Ausente ou inválido → o servidor gera um.

### 3.5 Tipos de item

| Tipo de item | MVP | Contagem / métrica |
|---|---|---|
| `event` | **processado**: normalizado, redigido e enfileirado (ADR-004) | conta para a quota (ADR-009) |
| `transaction`, `span`, `profile`, `profile_chunk`, `replay_event`, `replay_recording`, `replay_video`, `session`, `sessions`, `client_report`, `attachment`, `check_in`, `log`, `otel_log`, `statsd`, `metric_buckets`, `feedback`, `user_report` e qualquer tipo desconhecido | **aceite e descartado** com `200` | não conta; `sentry_items_dropped_total{type}` |

- Um envelope só com itens descartados responde `200` como os outros.
- `client_report` (relatórios do próprio SDK sobre o que descartou) é descartado, mas os seus totais podem alimentar uma métrica interna mais tarde.
- `attachment` é descartado no MVP, incluindo minidumps; revisitar com os SDKs nativos.

### 3.6 Rate limits e quotas no formato dos SDKs
- `429` com `Retry-After: <segundos>` e `X-Sentry-Rate-Limits: <segundos>:<categorias>:<scope>:<motivo>`, por exemplo `86400:error;default:organization:quota_exceeded` (quota diária) ou `60:error;default:key:rate_limited` (ritmo por chave). Valores e regras no ADR-009.
- Quando a fila de ingestão estiver sobrecarregada (ADR-004 §3.5): `429` com `X-Sentry-Rate-Limits: 60::organization:backpressure` (categorias vazias = todas).
- **Categorias não suportadas:** todas as respostas `200` levam também `X-Sentry-Rate-Limits: 3600:transaction;span;session;replay;profile;profile_chunk;attachment;monitor;log_item;metric_bucket;feedback:project:unsupported`, para os SDKs deixarem de enviar o que vamos descartar. Controlado por `INGEST_ADVERTISE_UNSUPPORTED` (ligado por omissão) e validado na matriz de SDKs (§3.10); se algum SDK reagir mal, desliga-se.

### 3.7 Limites

| Limite | Valor | Ao exceder |
|---|---|---|
| Corpo do pedido (comprimido) | 1 MiB | `413` |
| Corpo descomprimido (todo o envelope) | 10 MiB, lido em streaming | `413` |
| Item `event` descomprimido | 1 MiB | item descartado, `413` se for o único item |
| Itens por envelope | 100 | `400` |
| Linha de header (envelope ou item) | 16 KiB | `400` |
| Profundidade de JSON | 64 níveis | `400` |
| Excepções encadeadas por evento | 10 (as mais recentes) | truncado |
| Frames por stack trace | 250 (mantém as 50 mais externas e as 200 mais internas) | truncado |
| Breadcrumbs | 100 (os mais recentes) | truncado |
| Tags | 50; chave ≤ 32 caracteres, valor ≤ 200 caracteres | as excedentes descartadas |
| `message` / `exception.value` | 8 KiB | truncado |
| `context_line`, `pre_context`, `post_context` | 1 KiB por linha; 5 linhas antes e 5 depois | truncado |
| `extra` e `contexts` serializados | 16 KiB cada | truncado |
| Evento normalizado final guardado (`payload` do ADR-003) | 256 KiB | campos maiores truncados por esta ordem: `extra`, `breadcrumbs`, contexto das frames |

Truncar marca o evento com `_meta` interno (`truncated: true` e os campos afectados), visível na UI.

### 3.8 Compressão
- `Content-Encoding` aceites: `gzip`, `deflate` (zlib e raw), `br` e `zstd`, além de ausente ou `identity`. Qualquer outro → `415`.
- Bibliotecas: `compress/gzip` e `compress/flate`/`zlib` da stdlib; `github.com/andybalholm/brotli` (MIT); `github.com/klauspost/compress/zstd` (BSD-3), com a janela de memória do zstd limitada.
- A descompressão é sempre por streaming com o limite do §3.7 contado **depois** de descomprimir (protecção contra zip-bomb), com teste negativo por algoritmo.

### 3.9 Normalização, privacidade e agrupamento

**Normalização** (TASKS 2.2): `timestamp` aceita número epoch (com fracção) ou ISO-8601; ausente → `received_at`. `level` normalizado para `fatal | error | warning | info | debug` (desconhecido → `error`). `environment` ausente → o ambiente da chave ou `production`. Os restantes campos seguem a lista da TASKS 2.2; campos desconhecidos são descartados (não guardamos estrutura arbitrária).

**Privacidade** (antes de enfileirar, independentemente do `send_default_pii` do SDK): as regras de `internal/platform/redaction` e da TASKS 2.3; `request.data` e cookies descartados salvo opt-in do projecto; `user.ip_address` guardado só se o projecto o permitir (por omissão, truncado a /24 ou /48).

**Agrupamento (fingerprint), versão `v1`:**
1. Se o evento tiver `fingerprint` (lista de strings, no máximo 10, cada uma até 256 caracteres): cada elemento `{{ default }}` é substituído pelos componentes do passo 2; os restantes elementos entram como texto literal. Outras variáveis (`{{ transaction }}`, `{{ type }}`, …) **não** são suportadas no MVP e entram como texto literal (documentado).
2. Componentes por omissão:
   - **Com excepções:** para cada excepção da cadeia (até 5, da mais externa para a mais interna): o `type` e, se houver stack trace, as frames `in_app` (ou todas, se nenhuma for `in_app`), no máximo as 50 mais internas. De cada frame usa-se o `module` ou, se não houver, o `filename` normalizado (sem caminho absoluto, sem query string, sem hashes de build como `.[0-9a-f]{8,}.` e sem segmentos de versão), e a `function` normalizada (sem endereços `0x…`, sem sufixos numéricos de lambdas e closures gerados). **Nunca** números de linha nem de coluna.
   - **Excepção sem frames:** `type` + `value` normalizado.
   - **Sem excepção mas com stack trace** (em `threads` ou `stacktrace`): as frames como acima.
   - **Só mensagem:** `logentry.message` (o template, sem `params`) ou `message`, normalizada: UUIDs, hexadecimais com 8 ou mais caracteres, números, emails, IPs e query strings de URLs substituídos por marcadores.
3. `fingerprint = SHA-256("v1\x00" + componentes separados por "\x00")`. A versão do algoritmo é guardada em `issues.grouping_version`, para uma mudança futura não partir issues antigos.

Título do issue: `<type>: <value>` truncado a 200 caracteres, ou a mensagem normalizada; `culprit`: a frame `in_app` mais interna (`module` ou `filename`, e `function`).

Os testes de agrupamento usam fixtures reais de cada SDK da matriz (TASKS 2.3): o mesmo erro em linhas diferentes dá 1 issue; erros diferentes dão issues diferentes; o mesmo erro em builds diferentes de JavaScript (hashes no nome do ficheiro) dá 1 issue.

### 3.10 Matriz de SDKs suportados
Versões mínimas que o MVP promete suportar. São confirmadas e gravadas como fixtures na matriz de compatibilidade automatizada (`tests/contract/sentry/`, TASKS 2.9); se uma versão mínima falhar, sobe-se a versão mínima e actualiza-se este ADR.

| Plataforma | SDK | Versão mínima |
|---|---|---|
| Node.js | `@sentry/node` | 8.0 |
| Browser / React / Vue | `@sentry/browser`, `@sentry/react`, `@sentry/vue` | 8.0 |
| Python (Django, Flask, FastAPI) | `sentry-sdk` | 2.0 |
| PHP / Laravel | `sentry/sentry` 4.0, `sentry/sentry-laravel` | 4.0 |
| Java / Spring Boot | `io.sentry:sentry`, `sentry-spring-boot` | 7.0 |
| .NET / ASP.NET Core | `Sentry`, `Sentry.AspNetCore` | 4.0 |
| Go | `github.com/getsentry/sentry-go` | 0.27 |
| React Native | `@sentry/react-native` | 5.0 |
| Flutter / Dart | `sentry_flutter` | 8.0 |

Versões mais antigas podem funcionar mas não são testadas nem suportadas.

### 3.11 Source maps e releases
O mecanismo de upload (subconjunto da API usada pelo `sentry-cli` e pelos plugins de bundler, ou upload próprio) fica para o spike da TASKS 2.4 e é decidido numa revisão deste ADR. Até lá, o campo `release` e os `debug_meta`/debug IDs são guardados no evento para a desminificação futura.

### 3.12 Notas legais e de marca
- Implementado a partir da documentação pública para autores de SDKs e do tráfego dos SDKs oficiais (licenças MIT/BSD). **Nenhum código do servidor Sentry nem do Relay** (FSL) é copiado, adaptado ou usado como referência linha a linha; quem trabalhar nesta área não consulta o código desses dois projectos.
- O produto chama-se Vigia; "Sentry" aparece só em frases de compatibilidade ("compatível com os SDKs Sentry"), sem logótipos nem cores da marca, e com a nota de que Sentry é marca do seu titular.
- Os SDKs oficiais são usados pelos clientes nas suas apps; o Vigia não os redistribui. As apps de teste da matriz (§3.10) usam-nos como dependências normais.

## 4. Consequências

### Positivas
- Migração do cliente só com a troca do DSN, em pelo menos 9 plataformas.
- Âmbito do MVP pequeno e claro: só eventos de erro; o resto é aceite, descartado e, idealmente, deixa de ser enviado.
- O agrupamento é determinístico, versionado e testado com dados reais.

### Negativas / Trade-offs aceites
- Funcionalidades que os clientes Sentry conhecem (performance, replays, profiling, anexos, cron monitors, feedback) não existem no MVP; isto fica na página "limitações conhecidas" (TASKS 2.9).
- O protocolo pode mudar nos SDKs novos; a matriz automática é obrigatória para o detectar cedo.
- Só `{{ default }}` nas variáveis de fingerprint.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| SDK novo muda o formato do envelope | Média / Alto | Parser tolerante a campos desconhecidos; matriz automática nightly; fixtures por versão |
| Abuso de uma chave DSN pública | Alta / Médio | Rate limit por chave e por organização, quotas, `allowed_origins`, revogação imediata (ADR-009, TASKS 2.1) |
| Payloads maliciosos (zip-bomb, JSON profundo, `length` falso) | Alta / Alto | Limites do §3.7 em streaming, fuzzing, testes negativos da TASKS 2.2 |
| Agrupamento mau (demasiados issues ou erros diferentes juntos) | Média / Alto | Algoritmo do §3.9 com fixtures reais; versão do algoritmo para corrigir sem partir dados antigos |
| Risco legal de marca ou de código | Baixa / Alto | Regras do §3.12; revisão do texto público pelo CEO antes do lançamento |
| `X-Sentry-Rate-Limits` para categorias não suportadas mal interpretado por um SDK | Baixa / Médio | Flag `INGEST_ADVERTISE_UNSUPPORTED`, validada na matriz |

## 6. Validação / Protótipo / Benchmark

- **Compatibilidade:** a matriz de §3.10 envia erros reais (excepção não apanhada, excepção apanhada, mensagem, erro com `fingerprint` próprio e com `{{ default }}`, e uma transacção que tem de ser descartada) e verifica issue criado, stack trace, ambiente, release e agrupamento. Corre no CI (nightly se for lenta).
- **Segurança:** fuzzing do parser de envelopes e do parser de `X-Sentry-Auth`; testes negativos da TASKS 2.2 (zip-bomb por algoritmo, `length` mentiroso, item gigante, JSON profundo, milhares de frames e breadcrumbs, `public_id` de outra organização, chave revogada, chave de outro projecto, origem não permitida).
- **Desempenho:** P95 da resposta da ingestão abaixo de 50 ms para um evento de 20 KiB, sem contar a rede, com 250 eventos/s.

**Sinais para rever:** um tipo de item descartado passa a ser pedido por muitos clientes (por exemplo, `attachment` ou `transaction`); um SDK da matriz deixa de funcionar; ou o spike de source maps da TASKS 2.4.

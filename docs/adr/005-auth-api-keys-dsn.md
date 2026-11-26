# ADR-005: Autenticação (sessões, cookies, CSRF) e formato/hash das API keys e DSN key

- **Estado:** Proposto (em segunda revisão do CTO)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Em revisão (correcções aplicadas em 2026-11-26)
- **Fase bloqueada:** Antes da 1.2 (e base para 1.3 e 2.1)
- **Referências:** README §10.1–10.5, §11.4, §19.0, §24.1; ADR-008, ADR-015; TASKS 1.2, 1.3, 2.1

---

## 1. Contexto

O Vigia tem quatro fronteiras distintas de autenticação, cada uma com um perfil de risco diferente:

1. **Utilizadores humanos na UI/API de produto:** gerem organizações, projectos, regras, credenciais e incidentes (alto privilégio).
2. **Sistemas/servidores a enviar telemetria (`ingest`):** escrita automatizada de métricas e eventos (Fase 3+).
3. **Clientes máquina-a-máquina de leitura (`client`):** consultas à API e subscrição de streams SSE (Fase 4+).
4. **SDKs Sentry em browsers, apps mobile e backends (`dsn`):** envio de erros para `/api/{public_id}/envelope/` e `/store/` (Fase 2), onde a chave do DSN é **pública por natureza** porque pode viver no JavaScript do cliente.

Misturar estas credenciais ou usar sessões não revogáveis (JWT stateless de longa duração em `localStorage`) criaria riscos graves de XSS, roubo de sessão, escalada de privilégios e impossibilidade de revogação imediata.

## 2. Alternativas consideradas

### 2.1 Sessões de utilizador
- **Opção A — Sessões stateful em PostgreSQL + cookie `HttpOnly` (escolhida):**
  - **Prós:** revogação imediata garantida (logout, mudança de password, compromisso, revogação de membro); imune a roubo via JavaScript (XSS não lê cookies `HttpOnly`); sem riscos de confusão de algoritmos JWT; rotação simples de ID de sessão.
  - **Contras:** requer lookup em BD/cache por pedido (mitigado por cache Redis de TTL curto com invalidação na revogação) e protecção CSRF explícita.
- **Opção B — JWT stateless em `localStorage`:**
  - **Prós:** sem lookup de sessão no servidor.
  - **Contras:** vulnerável a exfiltração por XSS (`localStorage`); revogação imediata impossível sem uma blocklist stateful (o que elimina a vantagem do stateless). Rejeitada.

### 2.2 Hash das API keys secretas (`vg_ing_` e `vg_cli_`)
- **Opção A — Prefixo não secreto + HMAC-SHA256 com pepper + comparação em tempo constante (escolhida):**
  - **Prós:** segredos têm 256 bits de entropia (CSPRNG), pelo que HMAC-SHA256 com pepper (`API_KEY_PEPPER_FILE`) é criptograficamente seguro contra brute-force mesmo se a BD vazar, e rápido o suficiente para o hot path de ingestão (microssegundos vs dezenas de milissegundos do Argon2id). Lookup indexado por `(kind, prefix)` (`UNIQUE`).
  - **Contras:** exige gestão segura e rotação planeada do pepper (Docker secret / secret manager).
- **Opção B — Argon2id para API keys:**
  - **Prós:** custo computacional elevado.
  - **Contras:** desnecessário para segredos de 256 bits de entropia e tornaria a ingestão de alto throughput vulnerável a CPU/memória-DoS. Rejeitada (Argon2id reserva-se exclusivamente a passwords humanas e códigos de recuperação).

### 2.3 Chave pública de DSN (`dsn`)
- **Opção A — Chave pública distinta (`kind = 'dsn'`) em `api_credentials`, ligada a `projects.public_id` (escolhida):**
  - **Prós:** compatível a 100% com o formato dos SDKs Sentry (`https://<public_key>@<host>/<public_id>`); reutiliza o ciclo de vida, auditoria, revogação e rotação de `api_credentials`; separação explícita garante que uma chave pública de browser nunca acede a `/api/v1/*`.
  - **Contras:** ao contrário de `vg_ing_`/`vg_cli_`, a `public_key` de um DSN é consultável/indexada para o cliente poder copiar o DSN na UI (aprovado pelo CTO em 2026-11-26); nunca é tratada como segredo administrativo, mas o seu valor completo continua a ser mascarado nos logs.

## 3. Decisão

### 3.1 Passwords, sessões, cookies e CSRF (utilizadores humanos)
1. **Passwords (Argon2id + protecção de memória/CPU):**
   - Hashing com **Argon2id** (`golang.org/x/crypto/argon2`), salt CSPRNG de 16 bytes, chave de 32 bytes, parâmetros mínimos OWASP de menor memória adequados ao container da API (`256 MiB` RAM): **`m = 19 MiB` (`19456 KiB`), `t = 2`, `p = 1`**. (Parâmetros superiores só podem ser adoptados após medição em container com o limite de memória real.)
   - Formato PHC (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`) para permitir upgrade transparente no próximo login. Comparação sempre com `subtle.ConstantTimeCompare`.
   - **Limitação de concorrência:** semáforo explícito no serviço de hashing (por defeito **4** hashes Argon2id concorrentes por instância → pico ≤ ~76 MiB RAM); se o semáforo saturar além de um timeout curto, responder `503 Service Unavailable` com `Retry-After`.
   - **Ordem obrigatória no login:** aplicar **rate limit por IP e por conta ANTES** de calcular qualquer hash Argon2id (incluindo o hash *dummy* anti-enumeração), evitando CPU/memória-DoS por flood de pedidos.
2. **Anti-enumeração:** login, registo e recuperação de password devolvem respostas genéricas. Depois de passar pelo rate limit, quando o email não existe no login, executa-se uma verificação Argon2id *dummy* (também sujeita ao semáforo) para manter o tempo de resposta consistente.
3. **Sessões:**
   - Token opaco gerado com `crypto/rand` (32 bytes / 256 bits, codificado em hex ou base64url).
   - Na tabela `sessions`, guarda-se apenas `token_hash = HMAC-SHA256(SESSION_SECRET, token)` (nunca o token em plaintext), `user_id`, `expires_at`, `revoked_at`, `last_auth_at` (para re-autenticação), `ip_prefix`/`user_agent` truncados.
   - **Rotação de sessão:** novo token emitido (e anterior revogado) no login, na verificação MFA, no reset de password e em elevação de privilégio (anti *session fixation*).
   - **Re-autenticação:** operações de alto risco (criar/revogar credenciais, mudar roles, transferir ownership, apagar organização/projecto) exigem `now - last_auth_at ≤ 10 min`.
4. **Cookies:**
   - Nome: `vigia_session` em `development` e `__Host-vigia_session` em `staging`/`production`.
   - Atributos obrigatórios: `HttpOnly`, `Path=/`, `SameSite=Lax`, `Secure=true` (obrigatório fora de `development`).
5. **Protecção CSRF (defesa em profundidade):**
   - Todos os pedidos mutáveis (`POST`, `PUT`, `PATCH`, `DELETE`) autenticados por cookie exigem:
     1. Validação estrita do header `Origin` (ou `Sec-Fetch-Site: same-origin` quando aplicável) contra `APP_URL`/`CORS_ORIGINS`;
     2. Token CSRF associado à sessão (`X-CSRF-Token`, gerado com CSPRNG e comparado em tempo constante).
6. **MFA (TOTP):** segredo TOTP (RFC 6238) encriptado em repouso via `internal/platform/crypto` (envelope encryption, **ADR-015**, antecipado para *antes da 1.2* por decisão do CTO); códigos de recuperação de uso único guardados como hash. Obrigatório para `owner` e `admin` antes de produção.
7. **Tokens de convite, verificação de email e reset de password:** CSPRNG ≥ 256 bits, guardados apenas como hash SHA-256/HMAC, expiração curta, uso único.

### 3.2 API Credentials (`api_credentials`)

**Formato exacto e parsing:** alfabeto **hexadecimal minúsculo (`[0-9a-f]`)**, sem o carácter `_`, com comprimentos fixos e **parsing estrito por posição** (nunca `strings.Split`), eliminando ambiguidade com o separador `_`:

- **Ingest key (`ingest`):** `vg_ing_` (7) + `<prefix>` (12 hex = 48 bits) + `_` (1) + `<secret>` (64 hex = 256 bits CSPRNG) = **84 caracteres**.
  - Exemplo: `vg_ing_a1b2c3d4e5f6_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
- **Client token (`client`):** `vg_cli_` (7) + `<prefix>` (12 hex = 48 bits) + `_` (1) + `<secret>` (64 hex = 256 bits CSPRNG) = **84 caracteres**.
  - Exemplo: `vg_cli_f6e5d4c3b2a1_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210`
- **DSN key (`dsn`):** `<public_key>` (32 hex = 128 bits CSPRNG) = **32 caracteres**, usada em `https://<public_key>@<host>/<public_id>`.
  - Exemplo: `3f2a9c4b1e8d7f6a0b5c4d3e2f1a9b8c`

| `kind` | Comprimento | Visibilidade | Armazenamento | Âmbito permitido |
|---|---|---|---|---|
| `ingest` | 84 chars | Mostrada **1 vez** na criação | `prefix` (12 hex, `UNIQUE (kind, prefix)`) + `secret_hash = HMAC-SHA256(API_KEY_PEPPER, full_key)` | Apenas `POST /api/v1/ingest/*` (escrita de telemetria). Proibida em leitura/admin. |
| `client` | 84 chars | Mostrada **1 vez** na criação | `prefix` (12 hex, `UNIQUE (kind, prefix)`) + `secret_hash = HMAC-SHA256(API_KEY_PEPPER, full_key)` | Apenas leitura (`GET /api/v1/*`) e stream SSE. Proibida em escrita/admin. |
| `dsn` | 32 hex | Pública (consultável/visível na UI para copiar o DSN; **mascarada nos logs**) | `prefix` (8 hex) + `public_key` (32 hex, `UNIQUE`, indexada) ligada a `project_id`/`projects.public_id` | Apenas `POST /api/{public_id}/envelope/` e `/store/`. **Rejeitada em todas as rotas `/api/v1/*`.** |

Regras transversais das credenciais:
1. O middleware valida comprimento e alfabeto hex por posição, deriva `(organization_id, project_id, environment_id, credential_kind, scopes)` da credencial validada e injecta-o no `context.Context`.
2. **Cache de credenciais e revogação imediata:** o lookup de credencial acontece **antes** de conhecer o tenant, pelo que a chave Redis usa o formato **`cred:<kind>:<prefix>`** (excepção documentada à regra de prefixo `org:<id>:` — registada também no ADR-008). O valor guardado contém `organization_id`, `project_id`, `environment_id`, `secret_hash`/`public_key` e `scopes`, com TTL curto. Ao revogar (`revoked_at = now()` em PostgreSQL), a chave `cred:<kind>:<prefix>` é removida de imediato do Redis.
3. **Rotação:** permite criar nova credencial com janela de sobreposição opcional e revogação automática da antiga.
4. **`last_used_at`:** actualizado de forma agrupada/assíncrona (nunca uma escrita síncrona em BD por pedido de ingestão).
5. **Protecção da `dsn` key:** `projects.public_id` é um inteiro aleatório de 53 bits (`UNIQUE`, nunca sequencial); cada chave `dsn` suporta `allowed_origins`, rate limit próprio e quotas de organização. **O valor completo da `public_key` nunca deve aparecer nos logs** — os logs registam apenas `credential_id` ou `prefix` mascarado.

## 4. Consequências

### Positivas
- Zero segredos de utilizador ou API keys confidenciais em plaintext na base de dados ou em `localStorage`.
- Parsing determinístico por posição sem colisão com o separador `_`.
- Protecção explícita contra exaustão de RAM/CPU em ataques de login concorrente dentro do limite de `256 MiB` do container.
- Revogação de sessões e credenciais efectiva de imediato (invalidação directa de `cred:<kind>:<prefix>`).
- Separação rígida entre chaves públicas de browser (`dsn`) e credenciais de backend (`vg_ing_`, `vg_cli_`).

### Negativas / Trade-offs aceites
- Antecipação de ADR-015 e `internal/platform/crypto` para a Fase 1.2 (necessário para encriptar segredos TOTP).
- Semáforo de Argon2id limita throughput de logins simultâneos por instância (comportamento desejado: degradação graciosa com `503` em vez de OOM kill).
- Rotação de `API_KEY_PEPPER` ou `SESSION_SECRET` requer suporte a `key_id`/pepper anterior durante a janela de transição (a planear na Fase 8).

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| **CPU/memória-DoS no login (exaustão de RAM por Argon2id concorrente)** | Alta / Alto | Parâmetros `m=19 MiB, t=2, p=1` + semáforo de concorrência (ex.: 4) + rate limit **antes** de qualquer hash (incluindo o *dummy*) + `503 Retry-After` em saturação |
| Brute-force em `/auth/login`, `/auth/mfa/*`, `/auth/password/*` | Alta / Alto | Rate limit por IP e por conta + lockout progressivo + auditoria |
| Abuso de chave `dsn` pública (flood de erros por terceiros) | Alta / Alto | Rate limit por chave/org, quotas diárias, `429` + `X-Sentry-Rate-Limits`, revogação imediata (`allowed_origins` complementa apenas para browsers) |
| Escalada horizontal/vertical usando `vg_ing_` ou `dsn` na API de produto | Média / Crítico | Middleware por tipo de credencial + testes negativos obrigatórios em todas as rotas `/api/v1/*` |
| CSRF em operações sensíveis via cookie | Média / Alto | `SameSite=Lax` + verificação de `Origin` + `X-CSRF-Token` + re-autenticação em acções críticas |
| Fuga de tokens ou `public_key` completa em logs ou respostas | Média / Crítico | Tipo `config.Secret`, mascaramento de `dsn` nos logs, `Cache-Control: no-store` em `/api/`, testes de regressão |

## 6. Validação / Protótipo / Benchmark

- **Testes obrigatórios na Fase 1.2/1.3/2.1:**
  - Benchmark do Argon2id (`m=19 MiB, t=2, p=1`) no container real de `256 MiB` com 4 logins concorrentes e sob carga (> 4 → `503 Retry-After` sem OOM).
  - Testes do parser de credenciais por posição (comprimento inválido, caracteres fora de `[0-9a-f]`, separador fora de posição).
  - Testes negativos: chave revogada rejeitada imediatamente; `vg_ing_` rejeitada em leitura/admin; `vg_cli_` rejeitada em escrita; `dsn` rejeitada em todas as rotas `/api/v1/*`; `dsn` completa nunca aparece em logs; CSRF sem token/origin rejeitado; enumeração de contas bloqueada.

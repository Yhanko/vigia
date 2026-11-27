# Pendentes da Revisão do CTO — Fase 1

> Itens técnicos identificados nas revisões do CTO durante a Fase 1 que **têm de ser fechados antes de abrir a porta da Fase 1**.

## Revisão da 1.1 (2026-11-26)

- [x] **1. `internal/platform/database/database_integration_test.go`:** remover a variável `termCtx` sem uso no `t.Cleanup` *(removida no commit `4b150ef`)*.
- [x] **2. `.github/workflows/ci.yml` (job `integration`):** correr `go test -race -count=1 -tags=integration -v ./...` (em todo o módulo, não apenas em `./internal/platform/database/...`).
- [x] **3. `.github/workflows/ci.yml` (lint da spec OpenAPI):** montar o repositório em modo *read-only* (`-v "$PWD:/spec:ro"`) e fixar a imagem `redocly/cli:1.34.5` por **digest SHA-256** (`@sha256:187c9838a3455d6e7820a19515982beafa26eb602949a27722976a85a73ea5ff`).
- [x] **4. Constante `DefaultDatabaseMaxConns` duplicada:** eliminar a duplicação entre `internal/platform/config` e `internal/platform/database` (uma só fonte de verdade em `config.DefaultDatabaseMaxConns`; `database.NewPool` exige `MaxConns > 0`).
- [x] **5. `api/openapi.yaml` (`429` em `/status`):** confirmar que `GET /api/v1/status` devolve efectivamente `429` quando o middleware de rate limit da 1.2 for aplicado.
- [ ] **6. Fronteira de handlers (`/api/v1/*`):** na 1.2, todos os handlers de domínio vivem em `internal/modules/<domínio>`, nunca em `internal/platform/httpserver` (apenas o `/status` de infra ficou lá no bootstrap).

## Revisão do crypto — 1.2 (2026-11-26)

- [ ] **7. `crypto.Encrypter` no produtor:** as convenções Go definem interfaces do lado do consumidor; quando `identity` (e outros módulos) usarem `EnvelopeEncrypter`, definir a interface mínima no pacote consumidor e remover a interface redundante do produtor se já não for necessária.
- [ ] **8. Injecção de `EnvelopeEncrypter` em `cmd/vigia/main.go`:** actualmente `main.go` cria e descarta o `EnvelopeEncrypter`; na 1.2 injectá-lo explicitamente no serviço de `identity` (sem global).

## Revisão da migration de identidade — 1.2 (2026-11-26)

> A fechar antes do serviço de `identity`.

- [x] **9. Retirar `DELETE` de `vigia_app` em `organizations`:** as organizações só passam a `status = 'deleted'` e a base de dados tem de o impor; adicionar teste de integração a provar que `DELETE` em `organizations` como `vigia_app` falha com SQLSTATE `42501`.
- [x] **10. Teste cross-tenant de `UPDATE` e `DELETE`:** dentro de `WithTenantTx(orgA)`, `UPDATE` e `DELETE` dirigidos a linhas da Org B afectam `0` linhas e as linhas da Org B ficam intactas.
- [x] **11. `isValidUUID` duplicado:** eliminar a duplicação entre `internal/platform/crypto` e `internal/platform/database` numa só implementação partilhada (`internal/platform/ids`).
- [x] **12. Verificação de role no arranque da API (`staging`/`production`):** consultar `current_user`, `rolsuper` e `rolbypassrls` no arranque e recusar arrancar se `rolsuper` ou `rolbypassrls` for `true` (com teste).
- [x] **13. `EnsureRoles` (`log_min_duration_statement` e `log_min_error_statement`):** na mesma transacção do `ALTER ROLE`, executar também `SET LOCAL log_min_duration_statement = -1` e `SET LOCAL log_min_error_statement = 'panic'`.

## Revisão das fatias D1–D4 do `identity` — 1.2 (2026-11-27)

> Veredicto: **D1–D4 aprovadas** e plano `docs/plans/1.2-identity.md` **aprovado**. **D5 e D6 ficam autorizadas**, com os itens abaixo como critérios de aceitação. D7–D8 (email, MFA) só depois de nova revisão. Itens 14–19 fecham dentro de D5/D6; o 20 bloqueia o início de D8.

- [x] **14. Sessões de utilizadores não activos (D6, bloqueante):** `GetActiveSessionByTokenHash` só olha para a sessão; um utilizador `disabled`/`deleted` continua autenticado. Fazer `JOIN users u ON u.id = s.user_id AND u.status = 'active'` na query (devolvendo também o que o middleware precisa do utilizador) **e** chamar `RevokeAllUserSessions` em qualquer transição para fora de `active`. Teste de integração: utilizador desactivado → sessão deixa de ser encontrada. No login, `status <> 'active'` devolve o mesmo `401 INVALID_CREDENTIALS` genérico (com `Verify` real, sem atalho de timing).
- [x] **15. Limites do `password.Hasher` (D5):** (a) `maxVerifyMemoryKiB = 256 MiB` com semáforo de 4 permite ~1 GiB num contentor de 256 MiB se um hash armazenado for adulterado: baixar para `2 × DefaultMemoryKiB` (38 912 KiB) — subir parâmetros no futuro é decisão consciente que muda este limite; validar também `SaltBytes ≤ maxSaltBytes` e `KeyBytes ≤ maxKeyBytes` em `NewHasher`. (b) `Hash`/`Verify` rejeitam passwords com mais de **512 bytes** (`ErrPasswordTooLong`, defesa em profundidade; a política de 12–128 caracteres continua no service). Testes para ambos.
- [x] **16. `format: email` no OpenAPI (D6):** o `oapi-codegen` gera `openapi_types.Email`, que valida no `UnmarshalJSON`; um email inválido sai como `INVALID_JSON` em vez de `VALIDATION_FAILED` e a validação fica dividida. Decisão: manter `format: email` na spec (documentação) com `x-go-type: string` nos campos de pedido, e validar/normalizar o email só na política de `identity` (`lower(btrim())`, ≤ 254). Teste: email malformado → `400 VALIDATION_FAILED`.
- [ ] **17. Verificação de `Origin` em `login` e `register` (D6):** sem sessão não há token CSRF, mas *login CSRF* (forçar a vítima a entrar na conta do atacante) continua possível. Os `POST /auth/*` públicos exigem `Origin` na allowlist (`CORS_ALLOWED_ORIGINS`/URL da app) e devolvem `403 CSRF_INVALID` caso contrário. Teste negativo para os dois endpoints.
- [ ] **18. Montagem do `/api/v1` (D6):** ao compor `api.ServerInterface` em `cmd/vigia` (handlers de `identity` + `/status`), usar `api.HandlerWithOptions` com `ErrorHandlerFunc` a devolver `400 VALIDATION_FAILED` pelo `WriteError` (como existia antes de `570d0c8`). O `/status` volta a ser servido pela interface gerada; nada de rotas `/auth/*` montadas à mão.
- [ ] **19. `session.Codec.BuildCookie` (D6, menor):** recebe `expiresAt` e `maxAge` em separado e os dois podem divergir. Passar a `BuildCookie(token string, expiresAt, now time.Time)` e derivar `MaxAge` de `expiresAt.Sub(now)` (com `clock.Clock` no chamador).
- [ ] **20. Fluxo de login com MFA (antes de D8):** o contrato actual responde `401 MFA_REQUIRED` sem dar ao cliente forma de continuar. O desenho do passo intermédio (sessão "pendente de MFA" de curta duração, sem acesso a nada além de `/auth/mfa/verify`) é do CTO e entra no plano antes de D8; o Gemini não o implementa por iniciativa própria.

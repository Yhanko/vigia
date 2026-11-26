# Pendentes da Revisão do CTO — Fase 1

> Itens técnicos identificados nas revisões do CTO durante a Fase 1 que **têm de ser fechados antes de abrir a porta da Fase 1**.

## Revisão da 1.1 (2026-11-26)

- [ ] **1. `internal/platform/database/database_integration_test.go`:** remover a variável `termCtx` sem uso no `t.Cleanup`.
- [ ] **2. `.github/workflows/ci.yml` (job `integration`):** correr `go test -race -count=1 -tags=integration -v ./...` (em todo o módulo, não apenas em `./internal/platform/database/...`).
- [ ] **3. `.github/workflows/ci.yml` (lint da spec OpenAPI):** montar o repositório em modo *read-only* (`-v "$PWD:/spec:ro"`) e fixar a imagem `redocly/cli:1.34.5` por **digest SHA-256** (`@sha256:187c9838a3455d6e7820a19515982beafa26eb602949a27722976a85a73ea5ff`).
- [ ] **4. Constante `DefaultDatabaseMaxConns` duplicada:** eliminar a duplicação entre `internal/platform/config` e `internal/platform/database` (uma só fonte de verdade).
- [ ] **5. `api/openapi.yaml` (`429` em `/status`):** confirmar que `GET /api/v1/status` devolve efectivamente `429` quando o middleware de rate limit da 1.2 for aplicado.
- [ ] **6. Fronteira de handlers (`/api/v1/*`):** na 1.2, todos os handlers de domínio vivem em `internal/modules/<domínio>`, nunca em `internal/platform/httpserver` (apenas o `/status` de infra ficou lá no bootstrap).

## Revisão do crypto — 1.2 (2026-11-26)

- [ ] **7. `crypto.Encrypter` no produtor:** as convenções Go definem interfaces do lado do consumidor; quando `identity` (e outros módulos) usarem `EnvelopeEncrypter`, definir a interface mínima no pacote consumidor e remover a interface redundante do produtor se já não for necessária.
- [ ] **8. Injecção de `EnvelopeEncrypter` em `cmd/vigia/main.go`:** actualmente `main.go` cria e descarta o `EnvelopeEncrypter`; na 1.2 injectá-lo explicitamente no serviço de `identity` (sem global).

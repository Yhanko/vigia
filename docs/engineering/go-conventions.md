# Convenções de Engenharia Go — Vigia (§23)

- **Versão:** 1.0 (Fase 0 — Discovery)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Referências:** README §2, §4.5, §5.1, §15.5, §23; `.golangci.yml`; `GEMINI.md`; TASKS 0.3

> Estas convenções são verificadas automaticamente por `golangci-lint` (`.golangci.yml`) e em code review pelo CTO. Consistência prevalece sobre preferência pessoal.

---

## 1. Estrutura de pacotes e fronteiras (§4.5, ADR-001)

- **Nomes de pacotes:** curtos, singulares quando natural, em minúsculas, sem `utils`, `helpers`, `common` ou `models` genéricos.
- **Fronteiras de módulos:**
  - `internal/platform/<x>`: infraestrutura transversal (config, database, httpserver, queue, crypto, redaction, ssrf, telemetry, clock). **Proibido importar `internal/modules/*`** (imposto por `depguard`).
  - `internal/modules/<domínio>/`: expõe apenas serviços, tipos de domínio e handlers públicos do módulo. Todo o código privado de implementação vive em `internal/modules/<domínio>/internal/`, impedindo imports cruzados pelo compilador Go.
- **Idioma:** código, identificadores, erros internos, API e commits em **inglês**; documentação em **português** (`GEMINI.md` §1).

---

## 2. SOLID aplicado ao Go deste projecto

- **Responsabilidade única (SRP):**
  - Handlers HTTP fazem apenas fronteira: decodificar (`httpserver.DecodeJSON`), validar input, chamar o serviço, mapear erro para o catálogo (`docs/api/error-catalog.md`) e escrever resposta. Zero SQL e zero regras de negócio nos handlers.
  - Serviços contêm regras de negócio, verificação de permissões e orquestração transaccional.
  - Repositórios/`sqlc` contêm apenas acesso a dados com `TenantID` obrigatório (ADR-008).
- **Segregação de interfaces (ISP):** interfaces pequenas (1–5 métodos) definidas **no pacote consumidor**, nunca no pacote produtor.
- **Inversão de dependências (DIP):** todas as dependências entram explicitamente por construtor (`NewService(repo, clk, logger)`). Proibido estado global mutável e `init()` com efeitos secundários.
- **Tempo determinístico:** nunca chamar `time.Now()` directamente em lógica de negócio; injectar `clock.Clock` (`internal/platform/clock`).

---

## 3. Tratamento de erros

1. **Nunca ignorar erros:** `errcheck` activo; qualquer `_ = fn()` (ex.: `defer rows.Close()`) tem de ser justificado e nunca esconder falha de escrita/commit.
2. **Embrulhar com contexto (`%w`):**
   ```go
   if err != nil {
       return fmt.Errorf("create project %q: %w", name, err)
   }
   ```
   Usar `errors.Is` / `errors.As` (nunca `==` em erros embrulhados; `errorlint` activo). Proibido `github.com/pkg/errors` (`depguard`).
3. **Erros sentinela de domínio:** definir erros tipados no módulo (ex.: `ErrNotFound`, `ErrConflict`, `ErrForbidden`) e traduzi-los na camada HTTP sem nunca expor mensagens SQL ou internas ao cliente.
4. **Sem `panic` para controlo de fluxo:** `panic` apenas em invariantes de arranque impossíveis; em runtime devolver sempre `error`.

---

## 4. `context.Context` e I/O

1. `ctx context.Context` é sempre o **primeiro parâmetro** de toda a função que faz I/O (BD, Redis, HTTP, ficheiros, locks) — imposto pelo linter `noctx`.
2. **Nunca guardar `context.Context` em structs.**
3. **Timeouts explícitos em toda a I/O:**
   - Proibido `http.Get`, `http.Post` e `http.DefaultClient` (imposto por `forbidigo`). Usar sempre `http.Client` configurado com `Timeout` e `Transport` próprio (ou `internal/platform/ssrf` para URLs de utilizador).
   - Sempre fechar `resp.Body.Close()` (`bodyclose`), `rows.Close()` (`sqlclosecheck`) e verificar `rows.Err()` (`rowserrcheck`).
4. **Transacções curtas:** nunca executar chamadas HTTP externas (SMTP, Telegram, WhatsApp, webhooks) dentro de `database.WithTenantTx`; escrever na `notification_outbox` dentro da transacção e despachar fora.

---

## 5. Concorrência e segurança

1. **Concorrência limitada:** nunca lançar `go fn()` sem limite por pedido. Usar worker pools limitados, `errgroup.SetLimit(n)` ou semáforos explícitos (ex.: semáforo de Argon2id no ADR-005).
2. **Ciclo de vida limpo:** toda goroutine lançada tem mecanismo claro de paragem via `ctx.Done()` e sincronização no graceful shutdown.
3. **Criptografia e aleatoriedade:** proibido `math/rand` (`depguard`); usar sempre `crypto/rand`. Comparação de hashes/tokens sempre com `subtle.ConstantTimeCompare`.
4. **Logging estruturado:** proibido `log` da stdlib e `fmt.Print*` fora de `cmd/vigia` (`depguard`/`forbidigo`). Usar sempre `log/slog` JSON com `request_id`; segredos sempre envolvidos em `config.Secret`.
5. **Regex seguras:** usar apenas `regexp` da stdlib (motor linear RE2, imune a ReDoS) com `regexp.MustCompile` apenas em variáveis de pacote inicializadas uma vez.

---

## 6. Estratégia de testes (§15.5)

- **Table-driven tests** como padrão para lógica de domínio, validadores, parsers, RBAC e máquinas de estado.
- **Testes negativos obrigatórios** ao lado dos casos felizes: input malformado, limites excedidos (`413`), acesso não autorizado (`401`/`403`), isolamento cross-tenant (`404`), segredos não vazados em logs.
- **Testes de integração** marcados com `//go:build integration` usando `testcontainers-go` (PostgreSQL/TimescaleDB e Redis reais).
- **Fuzzing (`go test -fuzz`)** obrigatório em parsers de input não confiável (envelopes Sentry, `X-Sentry-Auth`, envelopes criptográficos ADR-015, métricas).
- **Race detector:** todos os testes correm com `go test -race ./...` no CI Linux.

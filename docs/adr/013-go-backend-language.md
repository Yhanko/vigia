# ADR-013: Go como linguagem do backend

- **Estado:** Aceite
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Aprovado (2026-11-26)
- **Fase bloqueada:** Antes da Fase 1 (já decidido; formalizar)
- **Referências:** README §5.1, §5.2, §13, §16.4, §23, §24.1

---

## 1. Contexto

O backend do Vigia executa tanto API de produto (CRUD, RBAC, consultas) como cargas intensivas de I/O e CPU: ingestão contínua de envelopes/eventos (compatível Sentry e métricas), descompressão, scrubbing/redacção, fingerprinting, avaliação periódica de regras, dispatch de notificações em múltiplos canais e, mais tarde, pull collectors e uptime checks. O produto precisa de correr de forma económica em VPS modestos ("servidor leve, seguro e escalável") sem sacrificar segurança de memória, previsibilidade de latência ou facilidade de manutenção.

## 2. Alternativas consideradas

### Opção A — Go (versão estável mais recente, actualmente 1.27) (escolhida)
- **Prós:**
  - Binário único estático (`CGO_ENABLED=0`) empacotado numa imagem `distroless` (~17 MB), sem runtime, shell nem gestor de pacotes em produção (superfície de ataque mínima).
  - Baixo consumo de memória e arranque instantâneo, permitindo correr `api`, `worker`, `scheduler` e `dispatcher` num servidor modesto.
  - Concorrência nativa e previsível (goroutines + `context.Context` + channels) ideal para workers, SSE, rate limiting e dispatch de notificações.
  - Biblioteca padrão muito forte (`net/http`, `log/slog`, `crypto/*`, `regexp` RE2 imune a ReDoS, `embed`, `testing`/fuzzing/`pprof`).
  - Ecossistema excelente para observabilidade e infra (`pgx`, `sqlc`, `chi`, OpenTelemetry Go, Prometheus).
- **Contras:**
  - Duas linguagens no monorepo (Go no backend, TypeScript no frontend `web/`), exigindo contrato partilhado.
  - Tratamento explícito de erros é mais verboso (embora torne falhas impossíveis de ignorar silenciosamente).

### Opção B — Node.js + TypeScript
- **Prós:** Mesma linguagem que o frontend `web/` e partilha directa de tipos TS.
- **Contras:** Maior consumo de memória por processo, event loop single-threaded sensível a operações CPU-bound (descompressão de envelopes, scrubbing/regex, fingerprinting, hashing Argon2id), imagem Docker muito maior com runtime Node + `node_modules` (maior superfície de supply-chain).

### Opção C — Rust
- **Prós:** Performance máxima e segurança de memória sem GC.
- **Contras:** Tempos de compilação e curva de produtividade significativamente maiores para uma equipa pequena a construir um MVP; ganho de performance face a Go não é o gargalo do Vigia (que é maioritariamente I/O de BD/rede).

### Opção D — Python
- **Prós:** Desenvolvimento rápido e ecossistema rico.
- **Contras:** Consumo de memória e throughput por núcleo inferiores no hot path de ingestão; GIL e gestão de concorrência/deploy menos eficientes para um servidor leve unificado.

## 3. Decisão

Adoptar **Go** como linguagem única do backend do Vigia:

1. **Toolchain:** versão estável mais recente fixada em `go.mod` e no `Dockerfile` (imagem base fixada por digest).
2. **Stdlib primeiro:** preferir a biblioteca padrão; cada dependência externa nova exige justificação no PR (§11.6) e passa por `govulncheck`.
3. **Contrato com o frontend:** a fronteira entre Go e TypeScript é governada por `api/openapi.yaml` com geração automática de tipos nos dois lados (`oapi-codegen` em Go, `openapi-typescript` em TS) e verificação no CI.
4. **Qualidade e segurança obrigatórias:** `gofmt`, `go vet`, `golangci-lint` (com `gosec`, `errcheck`, `bodyclose`, `noctx`, `depguard`, `forbidigo`), `go test -race` e `govulncheck`.

## 4. Consequências

### Positivas
- Custo de infra reduzido e comportamento previsível sob rajadas de ingestão.
- Zero vulnerabilidades ReDoS em regex (`regexp` usa motor linear RE2).
- Fuzzing nativo (`go test -fuzz`) e profiling (`pprof`) prontos a usar sem dependências extra.

### Negativas / Trade-offs aceites
- Necessidade de manter disciplina no contrato OpenAPI para sincronizar backend (Go) e frontend (TS).
- Sem partilha directa de código entre backend e frontend.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Desalinhamento entre tipos Go e TypeScript | Média / Médio | `api/openapi.yaml` como fonte única de verdade + geração validada no CI |
| Curva de aprendizagem / inconsistência de estilo em Go | Baixa / Médio | Convenções Go escritas na Fase 0.3 + `golangci-lint` estrito + revisão do CTO |
| Goroutine leaks ou concorrência sem limite | Média / Alto | `context.Context` obrigatório em toda a I/O (`noctx`), pools limitados e `go test -race` no CI |

## 6. Validação / Protótipo / Benchmark

- Binário estático e imagem `distroless` (~17 MB) já compilados e testados no `Dockerfile` e `compose.yaml`.
- Pipeline de lint (`golangci-lint`), `go vet`, `go test -race` e `govulncheck` já configurado em `.github/workflows/ci.yml`.

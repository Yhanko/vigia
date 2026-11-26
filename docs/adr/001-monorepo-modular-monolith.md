# ADR-001: Monorepo e monólito modular

- **Estado:** Aceite
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Aprovado (2026-11-26)
- **Fase bloqueada:** Antes da Fase 1
- **Referências:** README §2, §4.4, §4.5, §6, §24.1

---

## 1. Contexto

O Vigia combina múltiplos domínios (identidade, organizações, projectos, credenciais, ingestão compatível Sentry, issues, métricas, alertas, incidentes, notificações, collectors, uptime, auditoria e quotas), um frontend web (`web/`) e futuros SDKs (`sdks/`). A equipa actual é pequena e precisa de entregar o MVP com alta fiabilidade, segurança multi-tenant desde o primeiro commit e baixo custo operacional, sem sacrificar a capacidade de escalar processos de forma independente quando a carga real o justificar.

## 2. Alternativas consideradas

### Opção A — Monorepo com monólito modular e binário único multi-papel (escolhida)
- Um único repositório Git com um módulo Go (`go.mod` na raiz), domínios isolados em `internal/modules/<domínio>/`, infraestrutura partilhada em `internal/platform/`, frontend em `web/` e contratos em `api/openapi.yaml`.
- Um único binário Go (`cmd/vigia`) com subcomandos por papel (`api`, `worker`, `scheduler`, `evaluator`, `dispatcher`, `migrate`, `healthcheck`).
- **Prós:**
  - Refactoring atómico entre backend, OpenAPI, migrations e frontend num único PR.
  - Deploy, CI, versionamento e debugging drasticamente mais simples (zero overhead de rede/serialização/orquestração distribuída prematura).
  - Separação de processos em runtime (ex.: escalar `worker` ou isolar `ingestion` da `api`) sem reescrever o código, apenas lançando containers com subcomandos diferentes.
  - Fronteiras entre domínios impostas pelo compilador Go (`internal/modules/<x>/internal/`) e por `depguard` no `golangci-lint`.
- **Contras:**
  - Exige disciplina para não acoplar domínios directamente (mitigado por estrutura de pacotes e lint).
  - O CI precisa de filtros/caching para não ficar lento quando o frontend crescer.

### Opção B — Microserviços em repositórios separados (polyrepo)
- **Prós:** Deploy e ciclo de vida independentes por equipa.
- **Contras:** Complexidade operacional desproporcional para a dimensão da equipa; contratos e versões desfasam-se facilmente; transacções entre domínios tornam-se sagas distribuídas; atrasa o MVP em semanas sem benefício real nesta fase.

### Opção C — Monólito sem fronteiras modulares
- **Prós:** Rapidez inicial aparente.
- **Contras:** Acoplamento cruzado rápido ("big ball of mud"), difícil de testar isoladamente, alto risco de contornar verificações de tenant/RBAC e impossibilidade prática de separar `ingestion`/`worker` mais tarde.

## 3. Decisão

Adoptar **monorepo com monólito modular** em Go:

1. **Estrutura:** domínios vivem em `internal/modules/<domínio>/`; código privado de cada módulo vive em `internal/modules/<domínio>/internal/`, garantindo pelo compilador Go que nenhum outro módulo o importa.
2. **Fronteiras:** `internal/platform/` nunca importa `internal/modules/` (já imposto por `depguard` em `.golangci.yml`). Comunicação entre módulos faz-se apenas pelas interfaces/serviços públicos definidos do lado do consumidor ou por eventos/outbox.
3. **Binário único multi-papel:** `cmd/vigia` expõe um subcomando por responsabilidade (`api`, `worker`, `scheduler`, `evaluator`, `dispatcher`, `migrate`, `healthcheck`).
4. **Ordem de separação quando medições justificarem (§4.4):** `ingestion → worker → evaluator → dispatcher`.
5. **Contrato único:** `api/openapi.yaml` é a fonte de verdade entre backend Go e frontend TypeScript no mesmo repositório.

## 4. Consequências

### Positivas
- Uma única imagem `distroless` (~17 MB) serve todos os papéis de backend, simplificando o deploy por SHA e rollback.
- Fronteiras arquitectónicas verificadas automaticamente em cada PR pelo compilador e por `golangci-lint`.
- Evolução incremental de processo único para múltiplos processos independentes sem migração de arquitectura.

### Negativas / Trade-offs aceites
- Todos os módulos partilham a mesma versão de Go e o mesmo `go.mod`.
- O acoplamento acidental via base de dados (queries de um módulo a ler tabelas internas de outro) não é bloqueado pelo compilador e tem de ser vigiado em code review.

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Acoplamento entre módulos via imports | Média / Médio | Código privado em `internal/modules/<x>/internal/` + `depguard` no CI |
| Acoplamento via partilha directa de tabelas SQL | Média / Médio | Cada módulo possui as suas queries em `queries/<módulo>/` e revisão obrigatória em PR |
| Ingestão sob rajada degradar a API de produto | Média / Alto | Separação de grupos de rotas/limites na Fase 2 e processo `ingestion` dedicado quando o P95 da API sofrer |

## 6. Validação / Protótipo / Benchmark

- Estrutura de pastas, `depguard` em `.golangci.yml` e build multi-stage `distroless` já validados na Fase 1.0/1.1.
- **Sinal para rever:** se a equipa crescer para múltiplas equipas autónomas com ciclos de release incompatíveis ou se um domínio exigir stack/escala radicalmente distinta.

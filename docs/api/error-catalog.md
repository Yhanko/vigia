# Catálogo de Códigos de Erro da API e Política de Versionamento

- **Versão:** 1.0 (Fase 0 — Discovery)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Referências:** README §9.1–9.2, §25.3; `api/openapi.yaml`; `internal/platform/httpserver/errors.go`; TASKS 0.3

---

## 1. Envelope padrão de erro (`/api/v1/*`)

Todas as respostas de erro sob `/api/v1/*` usam exclusivamente este envelope JSON (sem stack traces, sem SQL, sem detalhes internos):

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "One or more fields are invalid.",
    "requestId": "req_019a2f7d8b4c9e1023456789",
    "details": [
      { "field": "email", "message": "must be a valid email address" }
    ]
  }
}
```

*(Excepção contratual: os endpoints compatíveis Sentry `/api/{public_id}/envelope/` e `/store/` usam `{"detail": "..."}` conforme contrato dos SDKs Sentry — ADR-017.)*

---

## 2. Catálogo canónico de códigos de erro

### 2.1 Autenticação e Sessão (`401`)
| Código (`error.code`) | HTTP | Quando usar |
|---|---|---|
| `UNAUTHENTICATED` | `401` | Sem cookie de sessão nem credencial `Authorization` válida |
| `INVALID_CREDENTIALS` | `401` | Email ou password inválidos no login (mensagem sempre genérica — anti-enumeração) |
| `SESSION_EXPIRED` | `401` | Sessão expirada ou revogada |
| `MFA_REQUIRED` | `401` | Login válido mas falta verificação TOTP ou conta privilegiada sem MFA configurado |
| `INVALID_MFA_CODE` | `401` | Código TOTP ou código de recuperação inválido |
| `REAUTH_REQUIRED` | `401` | Operação de alto risco exige re-autenticação recente (≤ 10 min) |
| `INVALID_API_KEY` | `401` | Chave `vg_ing_` ou `vg_cli_` malformada, desconhecida, expirada ou revogada |

### 2.2 Autorização e CSRF (`403`)
| Código (`error.code`) | HTTP | Quando usar |
|---|---|---|
| `FORBIDDEN` | `403` | Utilizador autenticado na organização mas sem permissão RBAC para a acção |
| `INSUFFICIENT_SCOPE` | `403` | Credencial `vg_ing_`, `vg_cli_` ou `dsn` usada fora do seu âmbito permitido |
| `CSRF_INVALID` | `403` | `Origin` ou `X-CSRF-Token` em falta ou inválido em pedido mutável por cookie |
| `MFA_SETUP_REQUIRED` | `403` | Utilizador `owner`/`admin` sem MFA activado a tentar aceder a rota da organização quando `MFA_REQUIRED_FOR_PRIVILEGED=true` |
| `EMAIL_NOT_VERIFIED` | `403` | Conta sem email verificado a tentar aceitar convite, criar organização ou receber transferência de ownership |
| `PROTECTED_RESOURCE` | `403` | Tentativa de eliminar/alterar ambiente com `is_protected = true` ou último `owner` |

### 2.3 Validação, Parsing e Recursos (`400`, `404`, `405`, `409`, `413`, `415`)
| Código (`error.code`) | HTTP | Quando usar |
|---|---|---|
| `INVALID_JSON` | `400` | Corpo JSON malformado, vazio ou com vários objectos/dados à cauda (`httpserver.DecodeJSON`) |
| `VALIDATION_FAILED` | `400` | Validação de pedido: tipo de campo inválido, campo desconhecido (`DisallowUnknownFields`) ou falha de validação de domínio; `details[]` lista os campos quando aplicável (sem ecoar nomes de campos desconhecidos) |
| `INVALID_CURSOR` | `400` | Cursor de paginação inválido ou adulterado |
| `INVALID_TIME_RANGE` | `400` | Intervalo temporal inválido ou acima de `QUERY_MAX_RANGE_DAYS` |
| `RESOURCE_NOT_FOUND` | `404` | Recurso inexistente **ou pertencente a outro tenant** (nunca devolver `403` cross-tenant — ADR-008) |
| `METHOD_NOT_ALLOWED` | `405` | Método HTTP não suportado na rota |
| `CONFLICT` | `409` | Violação de unicidade (ex.: slug de organização/projecto já existente, membro já adicionado) |
| `IDEMPOTENCY_CONFLICT` | `409` | Mesma `Idempotency-Key` reutilizada com payload diferente |
| `PAYLOAD_TOO_LARGE` | `413` | Body acima de `API_MAX_BODY_BYTES` / `INGEST_MAX_PAYLOAD_BYTES` ou limite descomprimido |
| `UNSUPPORTED_MEDIA_TYPE` | `415` | `Content-Type` ausente ou diferente de `application/json` |

### 2.4 Limites, Quotas e Segurança Externa (`429`, `400`)
| Código (`error.code`) | HTTP | Quando usar |
|---|---|---|
| `RATE_LIMIT_EXCEEDED` | `429` | Rate limit atingido; inclui headers `RateLimit-*` e `Retry-After` |
| `QUOTA_EXCEEDED` | `429` | Quota do plano atingida (eventos/dia, projectos, membros, mensagens WhatsApp/mês) |
| `SSRF_BLOCKED` | `400` | URL de destino bloqueada pelas defesas SSRF (IP privado, loopback, metadata, esquema inválido) |
| `WEBHOOK_VERIFICATION_FAILED` | `422` | Destino falhou o desafio Challenge-Echo |

### 2.5 Erros de Servidor e Disponibilidade (`500`, `502`, `503`)
| Código (`error.code`) | HTTP | Quando usar |
|---|---|---|
| `INTERNAL_ERROR` | `500` | Erro interno inesperado ou panic recuperado (mensagem genérica fixa; detalhe só nos logs com `request_id`) |
| `UPSTREAM_UNAVAILABLE` | `502` | Fornecedor externo (Telegram, WhatsApp, SMTP) falhou durante operação síncrona de teste/verificação |
| `SERVICE_UNAVAILABLE` | `503` | Backpressure activo (semáforo Argon2id saturado, fila cheia ou dependência indisponível); inclui `Retry-After` |

---

## 3. Política de versionamento e depreciação

1. **Prefixo de versão major na URL:** `/api/v1/...`.
2. **Mudanças retrocompatíveis (sem nova versão):**
   - Adicionar novos endpoints, parâmetros opcionais ou campos novos em respostas JSON.
   - Clientes devem ignorar campos desconhecidos nas respostas.
3. **Mudanças incompatíveis (*breaking changes*):**
   - Remover ou renomear campos/endpoints, alterar tipos ou semântica obrigatória exige nova versão (`/api/v2/...`).
4. **Processo de depreciação:**
   - Endpoints ou campos depreciados recebem headers padrão RFC 8594 / `Deprecation: true` e `Sunset: <HTTP-date>`, mais `Link: <doc-url>; rel="deprecation"`.
   - Janela mínima de aviso antes de remoção: **90 dias** para clientes externos (documentada em changelog e notificada aos `owner`s).
5. **Contrato único:** qualquer alteração de endpoint, payload ou código de erro actualiza `api/openapi.yaml` no mesmo PR e é validada no CI.

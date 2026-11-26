# Classificação de Dados e Lista de Dados Proibidos

- **Versão:** 1.0 (Fase 0 — Discovery)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Referências:** README §7.8, §11.4, §14.2, §17.2–17.3, §20.1; ADR-005, ADR-008, ADR-015; TASKS 0.3

---

## 1. Classes de classificação de dados

| Classe | Definição | Exemplos no Vigia | Armazenamento e Trânsito | Logs da Plataforma | Retenção e Eliminação |
|---|---|---|---|---|---|
| **Público** | Informação destinada a divulgação externa ou não sensível | Documentação pública, `/api/v1/status` (versão/commit), guias de SDK, termos de serviço | HTTPS; sem encriptação adicional necessária | Permitido | Sem restrição |
| **Interno** | Informação operacional da plataforma sem dados de clientes nem segredos | Métricas Prometheus internas (`/metrics`), `request_id`, nomes de rotas parametrizadas, contagens agregadas de fila | Rede interna (`ADMIN_PORT`, rede `backend`); nunca exposto publicamente | Permitido | Conforme retenção de telemetria operacional |
| **Confidencial** | Dados de negócio dos tenants e PII necessária à operação | Emails de utilizadores, nomes de organizações/projectos, `issues`, `issue_events` (stack traces/breadcrumbs já redigidos), source maps, `audit_logs`, `chat_id` Telegram, telefones E.164 WhatsApp, regras de alerta, incidentes | TLS 1.2+ em trânsito; isolamento `TenantID` + PostgreSQL RLS (ADR-008); contactos (`chat_id`, telefone E.164) e subscriptions encriptados com AES-256-GCM (ADR-015); backups encriptados | **Apenas IDs opacos** (`organization_id`, `project_id`, `issue_id`, `credential_id`); nunca payloads, stack traces, telefones ou emails em logs de aplicação | Retenção configurável por plano (default conservador); `audit_logs` com retenção separada; suporte a export/delete (direito do titular, Lei n.º 22/11) |
| **Segredo** | Credenciais, chaves criptográficas e tokens cuja exposição compromete contas ou a plataforma | Passwords humanas, hashes Argon2id, tokens de sessão, `vg_ing_` / `vg_cli_` secrets, segredos TOTP, `SESSION_SECRET`, `API_KEY_PEPPER`, `ENCRYPTION_KEY` (KEKs), `postgres_password`, `postgres_app_password`, `redis_password`, `telegram_bot_token`, credenciais WhatsApp/SMTP, segredos HMAC de webhooks, credenciais de collectors | **Nunca** no repositório, **nunca** em env vars (apenas `*_FILE` / Docker secrets / secret manager); em BD apenas hash (Argon2id / HMAC-SHA256 com pepper) ou envelope encryption (ADR-015); em Go sempre `config.Secret` | **PROIBIDO** — redacção automática (`[REDACTED]`), `gitleaks` e testes de regressão | Rotação periódica; destruição imediata na revogação/eliminação |

*(Nota sobre `dsn` `public_key`: é pública por natureza para funcionar em browsers, mas nunca deve aparecer completa nos logs da plataforma — registar apenas `credential_id` ou `prefix` mascarado, conforme ADR-005.)*

---

## 2. Lista de dados proibidos de ingestão (§17.3)

O Vigia **não foi concebido** para armazenar dados financeiros, de saúde ou credenciais de clientes. Por defeito, o motor de scrubbing (`internal/platform/redaction`, aplicado **antes** de enfileirar ou persistir) remove ou substitui por `[Filtered]` as seguintes categorias:

### 2.1 Credenciais e autenticação (proibição absoluta)
- **Headers HTTP:** `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Csrf-Token`, `X-Sentry-Auth`.
- **Chaves de campos JSON / query params / tags / extra / breadcrumbs (case-insensitive, substring match):**
  `password`, `passwd`, `pwd`, `secret`, `api_key`, `apikey`, `token`, `access_token`, `refresh_token`, `id_token`, `auth`, `authorization`, `credentials`, `private_key`, `client_secret`, `cookie`, `set_cookie`, `session`, `session_id`, `mysql_pwd`, `pgpassword`, `dsn`, `connection_string`.
- **Padrões de valor (regex RE2 linear):**
  - Tokens Bearer / JWT (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`).
  - Chaves privadas PEM (`-----BEGIN [A-Z ]*PRIVATE KEY-----`).
  - Chaves de API comuns (`vg_ing_`, `vg_cli_`, `sk_live_`, `ghp_`, `AKIA[0-9A-Z]{16}`).

### 2.2 Dados financeiros e de pagamento (proibição absoluta)
- Números de cartão de crédito/débito (13–19 dígitos validados por algoritmo de **Luhn**).
- Códigos CVV/CVC/PIN em campos correspondentes (`cvv`, `cvc`, `card_number`, `pan`, `iban`, `pin`).

### 2.3 Documentos de identificação e PII sensível
- Números de Bilhete de Identidade (BI de Angola: padrão `^\d{9}[A-Z]{2}\d{3}$`), NIF, passaporte, número de carta de condução ou segurança social em campos correspondentes (`bi`, `nif`, `passport`, `ssn`, `tax_id`, `national_id`, `document_number`).
- **Request bodies (`request.data`) e cookies:** descartados **por defeito** na ingestão Sentry e de telemetria (§7.8, §17.3), salvo opt-in explícito e auditado ao nível do projecto.
- **Endereços IP de utilizadores finais:** descartados por defeito nos `issue_events`, salvo opt-in explícito do projecto.
- **Query strings em URLs:** valores de parâmetros sensíveis substituídos por `[Filtered]`.

---

## 3. Controlos de garantia

1. **Redacção antes da fila:** nenhum payload entra no Redis/fila ou na BD sem passar por `internal/platform/redaction`.
2. **Previsibilidade de regex:** apenas motor linear RE2 (`regexp` da stdlib Go) com limite de tamanho de entrada (zero risco de ReDoS).
3. **Previews de notificação:** email, Telegram e WhatsApp nunca incluem stack traces completos, `extra`, `request` ou `user` — apenas resumo curto + link autenticado.
4. **Testes de regressão obrigatórios:** cada pipeline de ingestão (Fase 2 e Fase 3) inclui fixtures com credenciais, JWTs, cartões Luhn e BI sintéticos e verifica que nenhum sobrevive em `issue_events`, `metrics` ou logs.

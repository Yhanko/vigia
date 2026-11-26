# Fluxos Críticos de Conta e Organização (§25.1)

- **Versão:** 1.0 (Fase 0 — Discovery)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Referências:** README §7.10, §9.2, §10.3, §10.5, §25.1; ADR-005, ADR-008; `docs/decisions/business-defaults.md`; TASKS 0.3, 1.2

> Todos os fluxos abaixo impõem RBAC no backend, registam eventos em `audit_logs` (sem segredos) e respeitam isolamento multi-tenant (ADR-008).

---

## 1. Fluxo de convite de membros (`invitations`)

1. **Criação (`POST /api/v1/organizations/:id/invitations`):**
   - Exige permissão `member:invite` (`owner` ou `admin`). Um `admin` **não pode** convidar alguém com role `owner`.
   - Valida quota de membros do plano e normaliza o email (`strings.ToLower(strings.TrimSpace(email))`).
   - Se já existir membership activa para esse email na organização, devolve `409 CONFLICT` (ou mensagem neutra se política anti-enumeração exigir).
   - Gera token CSPRNG (32 bytes / 256 bits), guarda apenas `token_hash = SHA-256(token)` e `expires_at = now + 7 dias`.
   - Envia email com link `APP_URL/invitations/<token>` (sem incluir dados sensíveis da org). Regista `member.invited` em `audit_logs`.
2. **Aceitação (`POST /api/v1/invitations/:token/accept`):**
   - Valida `token_hash`, `accepted_at IS NULL` e `expires_at > now` (caso contrário `404` / `400` genérico).
   - Se o utilizador já estiver autenticado, verifica que o email verificado da conta coincide com `invitations.email` (impede hijack de convite por outra conta). Se ainda não tiver conta, o fluxo de registo cria o utilizador com esse email e aceita atomicamente.
   - Na mesma transacção: marca `accepted_at = now()`, cria `memberships(organization_id, user_id, role, status='active')` e regista `member.joined` em `audit_logs`.
3. **Revogação (`DELETE /api/v1/invitations/:id`):**
   - Exige `member:invite`, invalida o convite e regista `invitation.revoked` em `audit_logs`.

---

## 2. Fluxo de recuperação de conta (`/auth/password/forgot` e `/reset`)

1. **Pedido (`POST /api/v1/auth/password/forgot`):**
   - Rate limit estrito por IP e por email **antes** de consultar a BD (3 req / 15 min por email).
   - Resposta **sempre** `202 Accepted` com mensagem genérica (*"If an account exists for this email, instructions have been sent."*) — **nunca revela se o email existe**.
   - Se a conta existir e estiver activa: gera token CSPRNG (32 bytes), guarda `token_hash` com expiração de **30 minutos** (invalidando tokens de reset anteriores do mesmo utilizador) e envia email com link de uso único.
2. **Redefinição (`POST /api/v1/auth/password/reset`):**
   - Valida `token_hash`, uso único e expiração; valida nova password contra política (≥ 12 chars, lista comum).
   - Na mesma transacção: actualiza `password_hash` (Argon2id), marca o token como usado, **revoga todas as sessões activas** do utilizador (e invalida cache Redis), regista `auth.password_reset` em `audit_logs` e envia email de confirmação de segurança.
   - *Nota MFA:* o reset de password **não** desactiva o MFA; a perda do dispositivo TOTP usa os códigos de recuperação de uso único ou procedimento de suporte verificado.

---

## 3. Fluxo de transferência de ownership

1. **Pré-condições:**
   - Apenas o `owner` actual pode iniciar; exige **re-autenticação recente** (≤ 10 min) e MFA verificado (quando activo).
   - O destinatário tem de ser um membro **activo** da organização com email verificado (e MFA activo em produção).
2. **Execução (dois passos ou confirmação explícita):**
   - `POST /api/v1/organizations/:id/transfer-ownership` cria um pedido de transferência pendente (token CSPRNG, expira em 24 h) e notifica ambos por email; o destinatário aceita (`POST .../transfer-ownership/accept`) **ou**, numa versão simplificada da Fase 1.2, o `owner` confirma directamente mediante re-autenticação + digitação do slug da organização.
   - Na mesma transacção PostgreSQL (`WithTenantTx`):
     - Promove o novo membro para `role = 'owner'`;
     - Despromove o anterior `owner` para `role = 'admin'` (garantindo que a organização tem sempre ≥ 1 `owner`);
     - Regista `organization.ownership_transferred` em `audit_logs` com actor, anterior owner e novo owner;
     - Envia email de alerta de segurança a ambos.
3. **Invariante obrigatória:** nunca é permitido remover ou despromover o **último `owner`** de uma organização (`403 PROTECTED_RESOURCE`).

---

## 4. Fluxo de eliminação de projecto e organização

### 4.1 Eliminação de projecto (`DELETE /api/v1/projects/:id`)
1. Exige permissão `project:delete` (`owner` ou `admin`) + **re-autenticação recente** (≤ 10 min) + confirmação explícita do slug do projecto.
2. Se o projecto tiver ambientes marcados `is_protected = true`, exige desprotecção explícita prévia (ou confirmação reforçada por `owner`).
3. **Execução imediata:**
   - Marca o projecto como `status = 'deleting'` (`deleted_at = now()`).
   - **Revoga imediatamente** todas as `api_credentials` (`vg_ing_`, `vg_cli_`, `dsn`) do projecto e remove as respectivas chaves Redis (`cred:<kind>:<prefix>` e `cred:dsn:<public_key>`), cessando toda a ingestão no instante seguinte.
   - Desactiva regras de alerta, collectors e monitors do projecto.
   - Regista `project.deleted` em `audit_logs`.
4. **Purge assíncrono:** job de retenção/limpeza elimina `issues`, `issue_events`, `metrics` e source maps após período de graça de **14 dias** (ou de imediato se pedido legal/admin).

### 4.2 Eliminação de organização (`DELETE /api/v1/organizations/:id`)
1. Exige role **`owner`** + **re-autenticação recente** (≤ 10 min) + confirmação do slug da organização.
2. **Soft delete com período de graça (14 dias):**
   - Marca `organizations.status = 'pending_deletion'` e `purge_after = now + 14 dias`.
   - **Revoga imediatamente** todas as `api_credentials` de todos os projectos (e limpa cache Redis), suspende alertas/notificações/collectors e revoga convites pendentes.
   - Regista `organization.deletion_scheduled` em `audit_logs` e envia email de confirmação a todos os `owner`/`admin`.
   - Durante os 14 dias, o `owner` pode cancelar a eliminação (com re-autenticação), mantendo o histórico intacto (as chaves revogadas continuam revogadas por segurança).
3. **Purge definitivo (após 14 dias ou pedido legal de eliminação imediata):**
   - Job assíncrono apaga dados dos projectos, telemetria, source maps e destinos encriptados, preservando apenas o registo mínimo de auditoria exigido por lei (anonimizado quando aplicável, conforme Lei n.º 22/11).

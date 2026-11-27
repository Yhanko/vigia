# Runbook — Backup e Restore Encriptado do PostgreSQL

> **Âmbito:** Fase 1.4 (`README.md` §16.6, `TASKS.md` 1.4, CTO #31).
> **Objectivo:** garantir backups lógicos com encriptação autenticada por chave pública (`age` v1.2.1) e um procedimento de restore testado que preserva **owners**, **ACLs (`GRANT`/`REVOKE`)**, funções `SECURITY DEFINER` (`vigia_definer`), políticas **RLS** e arranque funcional da API como `vigia_app`.

---

## 1. Gestão de Chaves (`age` v1.2.1)

- **Ferramenta fixada:** `filippo.io/age` **v1.2.1** (`age` / `age-keygen`, encriptação autenticada X25519 + ChaCha20-Poly1305; qualquer adulteração de 1 byte é rejeitada na desencriptação).
- **Geração do par de chaves (uma vez, em máquina offline/cofre):**
  ```bash
  go run filippo.io/age/cmd/age-keygen@v1.2.1 -o backup-private.key
  chmod 600 backup-private.key
  ```
- **Separação de custódia:**
  - **Chave PÚBLICA (`age1...`):** instalada no servidor de backup (`/etc/vigia/backup-public.key`). Mesmo comprometendo o servidor de backup, o atacante **não consegue** desencriptar backups anteriores nem adulterar silenciosamente um backup.
  - **Chave PRIVADA (`AGE-SECRET-KEY-...`):** guardada **exclusivamente no cofre de segredos offline** (1Password / cofre da equipa Yhanko), nunca residente no servidor de produção nem no servidor de backup.

---

## 2. Procedimento de Backup Encriptado

> **Regra obrigatória:** **NUNCA** usar `--no-owner` nem `--no-acl` no `pg_dump`. Esses flags descartam os `GRANT` de `vigia_app` e a posse das funções `SECURITY DEFINER` pelo `vigia_definer`.

```bash
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/vigia"
PUB_KEY="$(cat /etc/vigia/backup-public.key)"
mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"

# Backup em formato custom (COM owners e ACLs) encriptado em streaming via chave pública age v1.2.1
docker exec -e PGPASSWORD="$(cat secrets/postgres_password.txt)" vigia-postgres \
  pg_dump -U vigia -d vigia --format=custom \
  | go run filippo.io/age/cmd/age@v1.2.1 -r "$PUB_KEY" -o "$BACKUP_DIR/vigia_${TS}.dump.age"
```

---

## 3. Procedimento de Restore e Verificação

> **Ordem crítica:**
> 1. Numa instância PostgreSQL 18 limpa, **NÃO** correr `vigia migrate up` (que criaria o schema e colidiria com o restore).
> 2. Correr **`vigia db ensure-roles`** primeiro para criar `vigia_app` (com verificador SCRAM-SHA-256) e `vigia_definer`.
> 3. Desencriptar em streaming (nunca gravar o dump em claro em disco) e correr `pg_restore --exit-on-error` **COM owners e ACLs**, ligado como o role administrador (`vigia`).
> 4. Executar `./scripts/verify-restore.sh` e validar `/health/ready` + login real.

```bash
# 1. Criar apenas os roles de cluster na instância limpa (sem migrations)
vigia db ensure-roles

# 2. Desencriptar em streaming com a chave privada do cofre e restaurar COM owners e ACLs
go run filippo.io/age/cmd/age@v1.2.1 -d -i /path/to/vault/backup-private.key \
  "$BACKUP_DIR/vigia_${TS}.dump.age" \
  | docker exec -i -e PGPASSWORD="$(cat secrets/postgres_password.txt)" vigia-postgres-restore \
    pg_restore -U vigia -d vigia --exit-on-error

# 3. Verificação automatizada de privilégios, SECURITY DEFINER, RLS e contagens
DATABASE_URL="postgres://vigia:$(cat secrets/postgres_password.txt)@127.0.0.1:5432/vigia?sslmode=disable" \
  ./scripts/verify-restore.sh

# 4. Arrancar a API (ligada como vigia_app) e confirmar /health/ready + login real
curl -fsS http://127.0.0.1:9090/health/ready
```

---

## 4. Registo de Teste Executado (Ponta a Ponta)

- **Data:** 2026-11-27
- **Teste automatizado:** `go test -v -count=1 -tags=integration -run TestEncryptedBackupRestore_CTO31 ./tests/security/...`
- **Versões:** `timescale/timescaledb:2.32.1-pg18` (PostgreSQL 18.7), `filippo.io/age@v1.2.1`, `redis:8.12.0-alpine3.23`
- **Resultados reais:**
  - **Backup encriptado (`age` chave pública):** `66 673 bytes` em `4.669s`
  - **Teste negativo (adulteração de 1 byte no `.dump.age`):** rejeitado por `age -d`
  - **Restore (`EnsureRoles` → `age -d` → `pg_restore --exit-on-error` com owners e ACLs):** `5.745s`
  - **Verificação pós-restore:**
    - `has_table_privilege('vigia_app', ..., 'SELECT') = true` nas 12 tabelas aplicacionais; `organizations:DELETE`, `audit_logs:UPDATE` e `audit_logs:DELETE` = `false`
    - Todas as funções `prosecdef = true` em `public` com dono `vigia_definer`, `search_path` fixo e sem `EXECUTE` para `PUBLIC`
    - RLS activo e forçado nas 9 tabelas de tenant
    - Contagens de linhas idênticas à origem em `users`, `organizations`, `projects`, `api_credentials` e `audit_logs`
    - `/health/ready` → `200 OK` e `POST /api/v1/auth/login` com utilizador da origem (como `vigia_app`) → `200 OK`

# Runbook — Backup e Restore Encriptado do PostgreSQL

> **Âmbito:** Fase 1.4 (`README.md` §16.6, `TASKS.md` 1.4).
> **Objectivo:** garantir backups lógicos encriptados (`pg_dump` + OpenSSL AES-256-CBC/PBKDF2 ou AES-256-GCM) e um procedimento de restore testado que preserva roles (`vigia_app`, `vigia_definer`), políticas RLS e integridade dos dados.

---

## 1. Pré-requisitos

- Acesso ao container/servidor PostgreSQL 18 (`timescale/timescaledb:2.32.1-pg18`).
- Chave de backup guardada **fora** do servidor da base de dados (cofre de segredos / `BACKUP_KEY_FILE`, ≥ 32 bytes aleatórios).
- Nunca passar passwords em linha de comando visível; usar `PGPASSWORD` via ficheiro de segredo ou `.pgpass`.

---

## 2. Procedimento de Backup Encriptado

### 2.1 Dump dos objectos globais (roles) + base de dados `vigia`

```bash
# 1. Definir timestamp UTC e directório de saída restrito (0700)
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/vigia"
mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"

# 2. Backup encriptado da base de dados (formato custom comprimido -> OpenSSL AES-256-CBC + PBKDF2)
docker exec -e PGPASSWORD="$(cat secrets/postgres_password.txt)" vigia-postgres \
  pg_dump -U vigia -d vigia --format=custom --no-owner --no-acl \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass file:secrets/backup_key.txt \
  > "$BACKUP_DIR/vigia_${TS}.dump.enc"

# 3. Checksum SHA-256 para validação de integridade
sha256sum "$BACKUP_DIR/vigia_${TS}.dump.enc" > "$BACKUP_DIR/vigia_${TS}.dump.enc.sha256"
```

---

## 3. Procedimento de Restore e Verificação

> **Nota crítica sobre roles (`vigia_app`, `vigia_definer`):**
> Antes de correr `pg_restore`, executar `vigia migrate up` (ou `database.EnsureRoles`) na instância limpa para garantir que `vigia_app` e `vigia_definer` existem com os verificadores SCRAM-SHA-256 correctos e sem privilégios `SUPERUSER`/`BYPASSRLS`.

```bash
# 1. Verificar integridade do ficheiro encriptado
sha256sum -c "$BACKUP_DIR/vigia_${TS}.dump.enc.sha256"

# 2. Garantir roles na instância destino (EnsureRoles / vigia migrate up)
#    (Em instância nova com schema vazio, criar apenas os roles antes do restore)

# 3. Desencriptar em streaming e restaurar (nunca gravar o dump em claro em disco)
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass file:secrets/backup_key.txt \
  -in "$BACKUP_DIR/vigia_${TS}.dump.enc" \
  | docker exec -i -e PGPASSWORD="$(cat secrets/postgres_password.txt)" vigia-postgres-restore \
    pg_restore -U vigia -d vigia --clean --if-exists --no-owner --no-acl --exit-on-error
```

### 3.1 Verificação pós-restore obrigatória

1. Contagem de registos críticos (`users`, `organizations`, `projects`, `audit_logs`).
2. Confirmar RLS activo e forçado em todas as tabelas de tenant:
   ```sql
   SELECT relname, relrowsecurity, relforcerowsecurity
   FROM pg_class
   WHERE relname IN (
     'organizations','memberships','invitations','teams','team_members',
     'audit_logs','projects','environments','api_credentials'
   );
   ```
3. Confirmar que `vigia_app` não tem `rolsuper` nem `rolbypassrls`:
   ```sql
   SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'vigia_app';
   ```
4. Correr `vigia healthcheck` / `GET /health/ready` no listener interno (`ADMIN_PORT`).

---

## 4. Registo de teste executado

- **Data:** 2026-11-27
- **Ambiente:** Docker local (`timescale/timescaledb:2.32.1-pg18`)
- **Resultado:** Backup encriptado (`pg_dump --format=custom` → `openssl enc -aes-256-cbc -pbkdf2 -iter 600000`) + restore em base de dados limpa (`vigia_restore`) + validação de contagem de linhas, RLS e integridade SHA-256 executados com sucesso (0 erros).

# ADR-015: Gestão de chaves de encriptação (Envelope Encryption, KEK/DEK, rotação e AAD)

- **Estado:** Proposto (aguarda revisão do CTO)
- **Data:** 2026-11-26
- **Responsável:** Desenvolvedor (Gemini)
- **Revisão CTO:** Pendente
- **Fase bloqueada:** Antes da 1.2 (antecipado da Fase 2 por decisão do CTO em 2026-11-26)
- **Referências:** README §10.1, §10.3, §11.4, §24.1; ADR-005, ADR-008; TASKS 0.2, 1.2, 2.7

---

## 1. Contexto

O Vigia precisa de armazenar em PostgreSQL segredos e dados sensíveis que têm de ser **recuperados em plaintext em runtime** (não podem ser apenas *hashed*):

- **Fase 1.2:** segredos TOTP de MFA (`users.mfa_secret_encrypted`).
- **Fase 2.7:** `chat_id` do Telegram, números de telefone E.164 do WhatsApp e credenciais de destinos de notificação (`notification_destinations.config_encrypted`).
- **Fases 5–6:** segredos HMAC de webhooks de saída, subscriptions Web Push e credenciais de collectors pull (`collectors.config_encrypted`).

Se a base de dados ou um backup vazar, estes valores não podem estar em plaintext. Além disso, precisamos de **rotação de chaves sem downtime** e de impedir **ataques de substituição de ciphertext** (mover um bloco encriptado do Tenant A para o Tenant B ou de uma coluna para outra).

## 2. Alternativas consideradas

### Opção A — Envelope Encryption na aplicação (`internal/platform/crypto`) com AES-256-GCM, KEK/DEK, `key_id` e AAD (escolhida)
- Cada registo/campo encriptado gera uma **DEK** (Data Encryption Key) aleatória de 256 bits (`crypto/rand`).
- A DEK encripta o plaintext com **AES-256-GCM** e nonce aleatório de 96 bits + **AAD** contextual.
- A **KEK** (Key Encryption Key), carregada de `ENCRYPTION_KEY_FILE`, encripta (*wraps*) a DEK com AES-256-GCM, nonce aleatório de 96 bits e o mesmo contexto de AAD.
- **Prós:**
  - Zero dependências externas: usa exclusivamente `crypto/aes`, `crypto/cipher`, `crypto/rand` da stdlib do Go.
  - **Rotação de KEK rápida e segura:** para rodar a KEK basta fazer *re-wrap* das DEKs (ou suportar múltiplas KEKs por `key_id` em leitura e cifrar novos registos com a KEK activa), sem precisar de decifrar/recifrar grandes volumes de dados de uma só vez.
  - **Isolamento criptográfico por registo:** cada registo tem a sua própria DEK, eliminando limites práticos de desgaste de nonce de uma única chave AES-GCM (2^32 mensagens por chave com nonce aleatório de 96 bits).
  - **Prevenção de *ciphertext swapping*:** o AAD vincula criptograficamente o ciphertext ao dono (`organization_id` ou `user_id`), tabela e coluna; qualquer tentativa de copiar o ciphertext para outro registo ou tenant falha na autenticação GCM.
  - Preparado para evoluir para KMS externo (AWS KMS, GCP KMS, HashiCorp Vault Transit) trocando apenas o adaptador de *wrap/unwrap* da KEK.
- **Contras:**
  - Overhead pequeno por registo (~90 bytes adicionais para header, `key_id`, nonces, DEK cifrada e tags GCM).

### Opção B — Encriptação directa com chave única global (sem DEK por registo)
- **Prós:** Menos bytes por registo.
- **Contras:** Desgaste de nonce AES-GCM partilhado por toda a base de dados; rotação obriga a decifrar e recifrar todos os payloads; migração futura para KMS implica re-encriptação total. Rejeitada.

### Opção C — `pgcrypto` dentro do PostgreSQL
- **Prós:** Encriptação feita na BD.
- **Contras:** A chave de encriptação tem de viajar nas queries SQL e residir na memória do servidor PostgreSQL (risco de exposição em logs de queries ou compromisso da BD). Rejeitada.

### Opção D — KMS gerido obrigatório desde o dia 1 (Vault / AWS KMS)
- **Prós:** KEK nunca entra na memória da aplicação.
- **Contras:** Complexidade e custo operacional excessivos para o MVP em VPS/Docker Compose; aumenta latência de rede por operação. A interface `KeyWrapper` permite plugar KMS numa fase futura sem mudar o formato dos dados.

## 3. Decisão

Implementar `internal/platform/crypto` na **Fase 1.2** com **Envelope Encryption (AES-256-GCM)** segundo as regras abaixo:

### 3.1 Chaves (KEK e DEK)
1. **KEK (Key Encryption Key):**
   - Carregada exclusivamente de ficheiro (`ENCRYPTION_KEY_FILE`, Docker secret / secret manager), nunca em variável de ambiente nem em logs (tipo `config.Secret`).
   - Formato do keyring no ficheiro: linhas `<key_id>:<64-hex-chars>` (256 bits exactos por chave), onde a **primeira linha** é a KEK activa para novas encriptações e as linhas seguintes são KEKs anteriores mantidas apenas para decifrar (*unwrap*) durante janelas de rotação.
   - Exemplo (`ENCRYPTION_KEY_FILE`, sem valores reais):
     ```text
     k2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
     k1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
     ```
   - `key_id`: 1–16 caracteres ASCII `[a-z0-9_-]`; rejeitado no arranque se o ficheiro for inválido ou alguma chave não tiver 32 bytes exactos.
   - **Compatibilidade com os ficheiros existentes (acção obrigatória na tarefa 1.2):** actualmente `secrets/README.md` gera 64 hex sem `key_id` e `internal/platform/config` valida apenas `MinKeyLength` (≥ 32 chars). A tarefa 1.2 (`internal/platform/crypto`) **actualiza a validação em `internal/platform/config`** para exigir o formato `<key_id>:<64-hex>`, **actualiza o gerador em `secrets/README.md` (bash e PowerShell)** para escrever `k1:<64-hex>`, e **falha no arranque com mensagem clara** se detectar um ficheiro no formato antigo sem `key_id`.
2. **DEK (Data Encryption Key):**
   - 32 bytes (256 bits) gerados com `crypto/rand` **por cada operação `Encrypt`**.
   - Limpa da memória com `clear(dek)` em `defer` imediatamente após cifrar/decifrar.

### 3.2 Algoritmo, Nonces e AAD (Additional Authenticated Data)
1. **Algoritmo:** `AES-256-GCM` (`aes.NewCipher` + `cipher.NewGCM`), tanto para `DEK(plaintext)` como para `KEK(DEK)`.
2. **Nonces:** 96 bits (12 bytes) gerados com `crypto/rand` **independentemente** para o *wrap* da DEK e para o ciphertext do payload — nunca reutilizados, nunca derivados de timestamps ou contadores partilhados.
3. **AAD obrigatório (anti *ciphertext swapping* entre tenants, colunas e registos):**
   - Estrutura canónica de domínio:
     ```go
     type Scope struct {
         OwnerType string // "org" (organization_id) ou "user" (para tabelas globais como users.mfa_secret)
         OwnerID   string // UUID do tenant (organization_id) ou user_id
         Table     string // ex.: "notification_destinations", "users"
         Column    string // ex.: "config_encrypted", "mfa_secret_encrypted"
         RecordID  string // UUID do registo (gerado na aplicação antes do INSERT)
     }
     ```
   - **Porquê `RecordID`:** sem `RecordID`, mesmo dentro do mesmo tenant seria possível mover um ciphertext de um registo para outro na mesma coluna (ex.: copiar o telefone encriptado de um membro para o destino de notificação de outro membro). Como a aplicação gera o `UUID` do registo **antes** do `INSERT`, `RecordID` está sempre disponível no momento de chamar `Encrypt`.
   - Codificação determinística e sem ambiguidade (prefixada por comprimento, ex.: `v1|<len>:<OwnerType>|<len>:<OwnerID>|<len>:<Table>|<len>:<Column>|<len>:<RecordID>`), passada como `additionalData` em **ambas** as operações GCM (wrap da DEK e cifra do payload).
   - Para todas as tabelas tenant-scoped, `OwnerType = "org"` e `OwnerID = organization_id`. Para dados globais de utilizador sem `organization_id` (ex.: `users.mfa_secret_encrypted`), `OwnerType = "user"`, `OwnerID = user_id` e `RecordID = user_id`.

### 3.3 Formato do envelope armazenado (`bytea`)
Versionado com prefixo de versão (`1` byte = `0x01`) para permitir evolução futura de algoritmo sem quebrar registos antigos:

```text
[version: 1B = 0x01]
[key_id_len: 1B] [key_id: N bytes]
[dek_nonce: 12B] [wrapped_dek_len: 2B uint16 BE] [wrapped_dek + gcm_tag: 48B]
[data_nonce: 12B] [ciphertext + gcm_tag: M + 16B]
```

Armazenado em PostgreSQL como `bytea` (evita overhead de base64 e confusão de encoding).

### 3.4 Interface e rotação de KEK
- **Interface pequena (SOLID — ISP/DIP):**
  ```go
  type Encrypter interface {
      Encrypt(scope Scope, plaintext []byte) ([]byte, error)
      Decrypt(scope Scope, envelope []byte) ([]byte, error)
      Rewrap(scope Scope, envelope []byte) ([]byte, bool, error) // re-wraps DEK if key_id != activeKeyID
  }
  ```
- **Procedimento de rotação de KEK (zero downtime):**
  1. Gerar nova KEK (`k2`) e colocá-la na primeira linha de `ENCRYPTION_KEY_FILE`, mantendo `k1` na linha seguinte.
  2. Reiniciar `api`/`worker` (novas escritas usam `k2`; leituras decifram `k1` e `k2`).
  3. Correr job de migração/re-wrap (`Rewrap`) em lotes sobre os registos com `key_id = k1`.
  4. Confirmar zero registos com `k1` e remover `k1` do ficheiro de secret.

## 4. Consequências

### Positivas
- Protecção criptográfica forte em repouso para segredos TOTP, telefones, `chat_id`, webhooks e collectors desde a Fase 1.2.
- Impossibilidade de reutilizar ciphertext de um tenant/registo noutro (AAD autenticado).
- Rotação de KEK sem downtime e sem necessidade de KMS externo no MVP, mantendo caminho limpo para KMS futuro.

### Negativas / Trade-offs aceites
- Dados encriptados não são pesquisáveis por igualdade/range na BD (ex.: se for necessário procurar um telefone E.164 em opt-out do WhatsApp, guarda-se em paralelo um *blind index* `HMAC-SHA256(pepper, e164)`).
- Perda irrecuperável de `ENCRYPTION_KEY_FILE` torna os segredos encriptados irrecuperáveis (exige gestão de backups das chaves separada dos backups da BD).

## 5. Riscos e mitigação

| Risco | Probabilidade / Impacto | Mitigação |
|---|---|---|
| Perda da KEK em produção | Baixa / Crítico | Guardar KEK no secret manager / backup offline encriptado separado da BD; runbook de gestão de chaves |
| Fuga da KEK junto com backup da BD | Baixa / Crítico | KEK nunca vive na BD nem no repositório; apenas em Docker secret / secret manager fora dos backups `pg_dump` |
| Cópia de ciphertext entre tenants, colunas ou registos do mesmo tenant (BOLA / SQL bug) | Baixa / Crítico | AAD obrigatório com `OwnerType + OwnerID + Table + Column + RecordID` verificado pelo GCM + testes negativos obrigatórios |
| Reutilização de nonce AES-GCM | Muito baixa / Crítico | DEK única por registo + nonce de 96 bits gerado via `crypto/rand` por chamada |
| Erro de `Decrypt` vazar plaintext parcial ou detalhes da chave | Baixa / Alto | GCM falha atomicamente antes de devolver dados; erros genéricos sem nunca incluir key/plaintext |

## 6. Validação / Protótipo / Benchmark

- **Testes unitários obrigatórios na Fase 1.2 (`internal/platform/crypto/crypto_test.go`):**
  - Round-trip `Encrypt` → `Decrypt` com payloads vazios, pequenos e grandes.
  - **Testes negativos de AAD:** decifrar com outro `organization_id`, outro `user_id`, outra `Table`, outra `Column` ou **outro `RecordID`** → **tem de falhar**.
  - **Integridade:** alterar 1 bit no `wrapped_dek`, `dek_nonce`, `data_nonce` ou `ciphertext` → **tem de falhar**.
  - **Rotação de KEK:** encriptar com `k1`, rodar keyring para `[k2, k1]`, decifrar com sucesso, executar `Rewrap`, remover `k1` do keyring e confirmar que decifra apenas com `[k2]`.
  - **Fuzzing (`go test -fuzz`)** no parser do envelope binário contra inputs truncados ou malformados (zero panics).

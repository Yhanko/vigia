# secrets/

Ficheiros com passwords e chaves usados como Docker secrets pelo `compose.yaml`. Tudo nesta pasta, excepto este README, é ignorado pelo git e pelo `.dockerignore`.

| Ficheiro | Usado por | Variável na API |
|---|---|---|
| `postgres_password.txt` | Serviços `db`, `migrate` e `api` (utilizador `vigia`) | `DATABASE_PASSWORD_FILE` |
| `redis_password.txt` | Serviços `redis` e `api` (utilizador `default`) | `REDIS_PASSWORD_FILE` |
| `session_secret.txt` | `api`: assinatura de sessões | `SESSION_SECRET_FILE` |
| `api_key_pepper.txt` | `api`: pepper do HMAC das API keys (README §10.2) | `API_KEY_PEPPER_FILE` |
| `encryption_key.txt` | `api`: chave mestra da envelope encryption (README §11.4) | `ENCRYPTION_KEY_FILE` |

Em `staging` e `production` a API recusa arrancar sem `session_secret`, `api_key_pepper` e `encryption_key` (`session_secret` e `api_key_pepper` exigem ≥ 32 caracteres). `encryption_key.txt` usa o formato de keyring `<key_id>:<64-hex>` (ex.: `k1:<64-hex>`, uma KEK por linha; a primeira é a activa — ver ADR-015) e é validado no arranque em qualquer ambiente quando definido.

> ⚠ Trocar o `api_key_pepper` invalida todas as API keys emitidas, e remover uma KEK de `encryption_key.txt` antes de re-empacotar os registos torna ilegíveis os segredos cifrados com ela. Em ambientes reais, estas chaves só se rodam com o procedimento de rotação do ADR-015 / runbook.

Gerar valores aleatórios (sem quebra de linha no fim):

```bash
for n in postgres_password redis_password session_secret api_key_pepper; do
  [ -f "secrets/$n.txt" ] || openssl rand -hex 32 | tr -d '\n' > "secrets/$n.txt"
done
[ -f "secrets/encryption_key.txt" ] || printf 'k1:%s' "$(openssl rand -hex 32)" > "secrets/encryption_key.txt"
```

PowerShell:

```powershell
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
foreach ($n in 'postgres_password','redis_password','session_secret','api_key_pepper') {
  $p = Join-Path $PWD "secrets\$n.txt"
  if (Test-Path $p) { continue }
  $b = New-Object byte[] 32; $rng.GetBytes($b)
  [IO.File]::WriteAllText($p, (($b | ForEach-Object { $_.ToString('x2') }) -join ''))
}
$encPath = Join-Path $PWD "secrets\encryption_key.txt"
if (-not (Test-Path $encPath)) {
  $b = New-Object byte[] 32; $rng.GetBytes($b)
  [IO.File]::WriteAllText($encPath, 'k1:' + (($b | ForEach-Object { $_.ToString('x2') }) -join ''))
}
```

Os dois scripts só criam os ficheiros que faltam: nunca sobrescrevem passwords existentes (a BD já inicializada continuaria a usar a antiga).

O compose falha ao arrancar se algum destes ficheiros não existir: nunca há uma password por defeito.

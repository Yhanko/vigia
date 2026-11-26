# secrets/

Ficheiros com passwords usados como Docker secrets pelo `compose.yaml`. Tudo nesta pasta, excepto este README, é ignorado pelo git e pelo `.dockerignore`.

| Ficheiro | Usado por |
|---|---|
| `postgres_password.txt` | Serviço `db` (utilizador `vigia`) |
| `redis_password.txt` | Serviço `redis` (utilizador `default`) |

Gerar passwords aleatórias (sem quebra de linha no fim):

```bash
openssl rand -hex 32 | tr -d '\n' > secrets/postgres_password.txt
openssl rand -hex 32 | tr -d '\n' > secrets/redis_password.txt
```

PowerShell:

```powershell
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
foreach ($n in 'postgres_password','redis_password') {
  $b = New-Object byte[] 32; $rng.GetBytes($b)
  [IO.File]::WriteAllText((Join-Path $PWD "secrets\$n.txt"), (($b | ForEach-Object { $_.ToString('x2') }) -join ''))
}
```

O compose falha ao arrancar se algum destes ficheiros não existir: nunca há uma password por defeito.

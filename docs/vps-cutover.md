# VPS cutover: Warden to Guardian

One-time migration of the existing VPS install (service `WardenServer`, `C:\warden`, user `warden-deploy`, `WARDEN_*` variables) to the renamed one (service `GuardianServer`, `C:\guardian`, user `guardian-deploy`, `GUARDIAN_*` variables). A fresh install uses [vps-setup.md](vps-setup.md) instead. This file names the old service, paths, user and variables on purpose; it is the only document that does.

The server address, the certificate and its SPKI pin, the data (agents, tokens) and the admin password do not change. Downtime is expected (tens of minutes): stop, move, start, with a manual rollback in step 9. There is no side-by-side service.

Order of events (one sequence, no gaps):

1. Merge the server PR to `develop`; land the version bump PR (the release build then reports 0.2.0); merge the release PR `develop` to `main`. Nothing deploys yet (a deploy runs only for a pushed `v*` tag; a manual run on `main` only builds).
2. Steps 1 to 8 below (cutover, verified with the build from a manual run on `main`).
3. Right after step 8 passes, push the release tag `v0.2.0` and check the tag deploy (step 8, part 2).
4. Only after that deploy succeeded and the install has run for one stable day: step 10 (delete the backup and the old deploy user).

Ground rules, learned from the live install:

- The owner runs every command in an elevated PowerShell on the VPS (or in a terminal on the Mac where marked) and pastes the outputs; Claude has no VPS access.
- Never paste or store a password, private key or token (not in this file, not in chat, not in a file in the repository). Passwords come from your password manager, tokens from the agent Settings or the password manager; the commands below read them without echo or never touch them.
- Firewall rules are matched on `Name`, never on `DisplayName` (localized Windows).
- `Start-Service` takes about 15 seconds: wait before you probe.
- The scripts in `C:\guardian\scripts` never update themselves; you copy them by hand (step 7).
- Hard cut: the new server refuses to start (exit 2) while any `WARDEN_*` variable is set in its environment, and the old binary does not read `GUARDIAN_*`. The two cannot be mixed, which is why step 4 checks the service environment and step 9 restores the old service completely.
- Every command whose output you paste prints variable NAMES only, never values: environment values may hold the admin password. Do not run a raw `nssm get ... AppEnvironment...`; use the helper below, which reads the registry (the piped output of NSSM 2.24 can be UTF-16 and cannot be parsed reliably).
- Do not reboot the VPS between steps 4 and 8: the new service is registered for automatic start before it is ready.

In every PowerShell session below (also after a reconnect, and at the start of step 9), first run:

```powershell
Set-Alias nssm 'C:\Program Files\nssm\nssm.exe'
function Get-SvcEnv([string]$Svc, [string]$Value) {
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Svc\Parameters"
  @((Get-ItemProperty $key -Name $Value -ErrorAction SilentlyContinue).$Value) | Where-Object { $_ }
}
function Show-SvcEnvNames([string]$Svc) {   # names only, safe to paste
  foreach ($v in 'AppEnvironmentExtra', 'AppEnvironment') {
    "$Svc $v : " + ((Get-SvcEnv $Svc $v | ForEach-Object { ($_ -split '=', 2)[0] }) -join ', ')
  }
}
```

## Step 1. Preconditions

1. The server PR and the version bump PR are merged to `develop`, and `develop` is merged to `main` (release PR). Nothing is deployed by this: a deploy runs only for a pushed `v*` tag. Do not push the `v0.2.0` tag yet; it comes right after step 8.
2. Build the new binary: GitHub, Actions, `deploy`, Run workflow, branch `main`. Only the `build` job runs (the deploy job is skipped outside tag refs). Download the artifact `guardian-server-zip` to your Mac and upload it to the old install; the folder moves with the install in step 3:

```sh
scp guardian-server-<sha>.zip <owner-user>@<vps-ip>:C:/warden/incoming/
```

3. From the Mac, the pinned health check of the old install answers 200 (`<pin>` is the SPKI pin from the agent Settings; `cert pin` on the VPS prints the same value):

```sh
curl --pinnedpubkey 'sha256//<pin>' -k -sS -o /dev/null -w '%{http_code}\n' https://<vps-ip>:8443/healthz     # 200
```

4. On the VPS, record the old state and check there is room for a backup:

```powershell
Get-Service WardenServer                                  # Running
C:\warden\bin\warden-server.exe version                   # 0.1.1
nssm get WardenServer Application                         # C:\warden\bin\warden-server.exe
Show-SvcEnvNames WardenServer                             # names only; normally both lists are empty
[Environment]::GetEnvironmentVariables('Machine').Keys | Where-Object { $_ -like 'WARDEN_*' }   # machine-wide variables (names only)
Get-PSDrive C | Select-Object Free
```

5. Make an admin-only backup folder (the backup holds the private key and the config, so it is never copied anywhere):

```powershell
New-Item -ItemType Directory C:\cutover-backup | Out-Null
icacls.exe C:\cutover-backup /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
```

## Step 2. Stop the old service and back up

The backup is taken after the stop, so the stores are not written meanwhile. It restores the old binary, scripts, config and data for the rollback:

```powershell
Stop-Service WardenServer
(Get-Service WardenServer).Status                         # Stopped
Compress-Archive -Path (Get-ChildItem C:\warden -Exclude logs,staging,incoming,bin.prev,web.prev).FullName `
  -DestinationPath C:\cutover-backup\warden-pre-cutover.zip
reg.exe export HKLM\SYSTEM\CurrentControlSet\Services\WardenServer C:\cutover-backup\wardenserver.reg /y
foreach ($f in 'warden-pre-cutover.zip', 'wardenserver.reg') {
  $item = Get-Item "C:\cutover-backup\$f" -ErrorAction SilentlyContinue
  if (-not $item -or $item.Length -eq 0) { throw "No backup ($f): run Start-Service WardenServer and stop here" }
}
Get-Item C:\cutover-backup\* | Select-Object Name, Length
```

If the guard throws, nothing was changed except the stop: start the old service again and fix the backup before you retry. The rollback depends on both files.

The zip is the backup of `C:\warden\data` (agents, certificate, key) plus `bin`, `web`, `scripts` and the config; the `.reg` file keeps the exact NSSM settings of the old service, including its environment.

## Step 3. Move the install

```powershell
Move-Item C:\warden C:\guardian
Get-ChildItem C:\guardian\data\tls                        # the certificate and key are still there
Get-ChildItem C:\guardian\data                            # the token store (agents.json) is still there
if (Test-Path C:\warden-fw-disabled.txt) { Rename-Item C:\warden-fw-disabled.txt guardian-fw-disabled.txt }
```

`data\tls` and the token store move unchanged, so the pin and every issued token stay valid. The config file still holds `C:/warden/...` paths; rewrite only those four values (the admin password in it is neither read nor printed):

```powershell
$p = 'C:\guardian\config.local.json'
$c = Get-Content $p -Raw | ConvertFrom-Json
$c.tls.certPath = $c.tls.certPath -replace '^C:[\\/]warden', 'C:/guardian'
$c.tls.keyPath  = $c.tls.keyPath  -replace '^C:[\\/]warden', 'C:/guardian'
$c.dataDir      = $c.dataDir      -replace '^C:[\\/]warden', 'C:/guardian'
$c.webRoot      = $c.webRoot      -replace '^C:[\\/]warden', 'C:/guardian'
$c | ConvertTo-Json -Depth 5 | Set-Content -Path $p -Encoding ascii
$c.tls.certPath, $c.tls.keyPath, $c.dataDir, $c.webRoot   # all four start with C:/guardian
Remove-Variable c
```

## Step 4. Replace the service, set `GUARDIAN_*`, leave no `WARDEN_*`

Take the old environment from the registry (the lists stay in this session only; values are never printed or written to a file), then remove the old service and strip its accounts from the ACLs while they still resolve (`warden-deploy` stays as a user until step 10):

```powershell
$oldExtra = @(Get-SvcEnv WardenServer AppEnvironmentExtra)
$oldFull  = @(Get-SvcEnv WardenServer AppEnvironment)
icacls.exe C:\guardian /remove 'NT SERVICE\WardenServer' /T /C | Out-Null
icacls.exe C:\guardian /remove 'warden-deploy' /T /C | Out-Null
nssm remove WardenServer confirm
```

Register the new service with the new binary path (the binary arrives in step 7; `install-service.ps1` finishes the configuration there). Carry the old lists over under the new prefix, written straight to the registry as multi-strings:

```powershell
nssm install GuardianServer C:\guardian\bin\guardian-server.exe
nssm set GuardianServer AppParameters 'serve --config C:\guardian\config.local.json'
nssm set GuardianServer AppDirectory C:\guardian
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\GuardianServer\Parameters'
if ($oldExtra.Count -gt 0) {
  Set-ItemProperty -Path $key -Name AppEnvironmentExtra -Type MultiString -Value ([string[]]($oldExtra | ForEach-Object { $_ -replace '^WARDEN_', 'GUARDIAN_' }))
}
if ($oldFull.Count -gt 0) {
  Set-ItemProperty -Path $key -Name AppEnvironment -Type MultiString -Value ([string[]]($oldFull | ForEach-Object { $_ -replace '^WARDEN_', 'GUARDIAN_' }))
}
Remove-Variable oldExtra, oldFull, key
```

If the old service had no environment (the normal case, because `install-service.ps1` keeps all settings in the config file), nothing is set and the config file carries the configuration. Now the hard-cut check: the service inherits the machine-wide environment and both NSSM lists, so check all three:

```powershell
Show-SvcEnvNames GuardianServer                           # names only; every name must start with GUARDIAN_
$bad = @('AppEnvironmentExtra', 'AppEnvironment') | ForEach-Object { Get-SvcEnv GuardianServer $_ } | Where-Object { $_ -match '^\s*WARDEN_' }
$machine = @([Environment]::GetEnvironmentVariables('Machine').Keys | Where-Object { $_ -like 'WARDEN_*' })
if ($bad -or $machine) { 'STOP: a WARDEN_ variable is still set' } else { 'OK: no WARDEN_ variable anywhere' }
```

If it prints STOP, fix the cause and run the check again: for the NSSM lists, rewrite them with `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\GuardianServer\Parameters' -Name AppEnvironmentExtra -Type MultiString -Value @('GUARDIAN_<NAME>=<value>')`; for a machine-wide variable, note its name (and keep its value in your password manager if it is secret, the rollback needs it back), then `[Environment]::SetEnvironmentVariable('<NAME>', $null, 'Machine')`. Do not go on until it prints OK. Then `Remove-Variable bad, machine`.

## Step 5. Firewall: new rules first, then delete the old ones by `Name`

The old rules were created with a display name only, so their `Name` is generated. Find them by port, not by display name (the built-in OpenSSH rule is excluded):

```powershell
Get-NetFirewallRule -Direction Inbound -Action Allow | ForEach-Object {
  [pscustomobject]@{
    Name    = $_.Name
    Enabled = $_.Enabled
    Port    = "$(($_ | Get-NetFirewallPortFilter).LocalPort)"
    Remote  = "$(($_ | Get-NetFirewallAddressFilter).RemoteAddress)"
  }
} | Where-Object { $_.Port -in '22', '8443' -and $_.Name -notlike '*OpenSSH*' } | Format-Table -AutoSize
```

Paste the table and write down the `Remote` value of the old 8443 rule: the rollback needs it. Add the new rules (explicit `-Name`), reusing the `Remote` restriction of the old 8443 rule if it had one, and only then remove the old ones with the `Name` values from the table:

```powershell
New-NetFirewallRule -Name 'GuardianSSH' -DisplayName 'Guardian SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
New-NetFirewallRule -Name 'GuardianHTTPS' -DisplayName 'Guardian HTTPS' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
# only if the old 8443 rule was restricted:
Set-NetFirewallRule -Name 'GuardianHTTPS' -RemoteAddress '<allowed-address-1>','<allowed-address-2>'

Remove-NetFirewallRule -Name '<Name of the old SSH rule from the table>'
Remove-NetFirewallRule -Name '<Name of the old HTTPS rule from the table>'
Get-NetFirewallRule -Name 'GuardianSSH', 'GuardianHTTPS' | Select-Object Name, Enabled, Action
```

If the table showed no old SSH rule (only the built-in OpenSSH one), skip that removal. Keep your SSH session open until the new SSH rule is confirmed.

## Step 6. Deploy user `guardian-deploy`, key and GitHub secrets

Create the user exactly as in [vps-setup.md](vps-setup.md) step 1 (random password that is never shown):

```powershell
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
New-LocalUser -Name 'guardian-deploy' -Password $password -PasswordNeverExpires `
  -Description 'Guardian deploy (key-only, low privilege)'
Remove-Variable password, bytes
```

On the Mac, make a new key pair (do not reuse the old one):

```sh
ssh-keygen -t ed25519 -f ~/.ssh/guardian-deploy -C guardian-deploy
```

Put the public half on the VPS:

```powershell
$keys = 'C:\ProgramData\ssh\guardian-deploy_authorized_keys'
Set-Content -Path $keys -Value '<paste the guardian-deploy public key line here>' -Encoding ascii
icacls.exe $keys /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'
```

Edit `C:\ProgramData\ssh\sshd_config`: add `guardian-deploy` to the `AllowUsers` line (above the first `Match`), keep `warden-deploy` there until step 10 (rollback needs it), and add at the very end:

```text
Match User guardian-deploy
    AuthorizedKeysFile __PROGRAMDATA__/ssh/guardian-deploy_authorized_keys
```

```powershell
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t          # no output = valid
Restart-Service sshd
```

From a SECOND terminal on the Mac, prove the key login before you close the first session:

```sh
ssh -i ~/.ssh/guardian-deploy -o BatchMode=yes guardian-deploy@<vps-ip> "whoami"     # prints the deploy user
```

Move the GitHub environment secrets (environment `production`; `VPS_HOST` and `VPS_KNOWN_HOSTS` stay as they are, the host key is unchanged). The private key is read from the file and never printed:

```sh
gh secret set VPS_USER --env production --repo <owner>/guardian-server --body guardian-deploy
gh secret set VPS_SSH_KEY --env production --repo <owner>/guardian-server < ~/.ssh/guardian-deploy
gh secret list --env production --repo <owner>/guardian-server      # VPS_HOST, VPS_USER, VPS_SSH_KEY, VPS_KNOWN_HOSTS
```

Leave the old key `~/.ssh/warden-deploy` and the user `warden-deploy` in place until step 10: only they make a rollback possible.

## Step 7. Copy the new scripts, install the binary, finish the service

Scripts never update themselves. From a checkout of the merged `main` on the Mac:

```sh
scp scripts/install-service.ps1 scripts/apply-update.ps1 <owner-user>@<vps-ip>:C:/guardian/scripts/
```

Install the build uploaded in step 1 (this is the bootstrap mode: no service control, no health check), then let `install-service.ps1` configure the service, the service account `NT SERVICE\GuardianServer`, the deploy user's right to start and stop it, and every ACL. It does not start the service because of `-NoStart`, and it does not touch the environment set in step 4:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\guardian\scripts\apply-update.ps1 -Zip C:\guardian\incoming\guardian-server-<sha>.zip -Bootstrap
C:\guardian\bin\guardian-server.exe version                   # 0.2.0 (the release build after the version bump PR)
C:\guardian\bin\guardian-server.exe cert pin C:\guardian\data\tls\server.crt          # the same pin as before the cutover
powershell -NoProfile -ExecutionPolicy Bypass -File C:\guardian\scripts\install-service.ps1 -Nssm 'C:\Program Files\nssm\nssm.exe' -NoStart
Show-SvcEnvNames GuardianServer                           # run the step 4 check again
```

The version is the one the release was built with. If it prints 0.1.0 the bump PR was not part of the release: that is harmless for the cutover (the live install reports 0.1.1, but this is the renamed code line, not a downgrade), but then the tag in step 8 must wait for the bump. If the `cert pin` value differs from the pin you recorded, stop: the certificate was not moved intact.

## Step 8. Start, verify, then release

Part 1, the cutover build:

```powershell
Start-Service GuardianServer
Start-Sleep -Seconds 15                                   # the start takes about 15 s
Get-Service GuardianServer                                # Running
Get-Content C:\guardian\logs\guardian-server.err.log -Tail 20
```

From the Mac:

```sh
# 1. pinned health check answers 200
curl --pinnedpubkey 'sha256//<pin>' -k -sS -o /dev/null -w '%{http_code}\n' https://<vps-ip>:8443/healthz
# 2. a wrong pin is refused (curl exits with 90)
curl --pinnedpubkey 'sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' -k -sS -o /dev/null https://<vps-ip>:8443/healthz; echo "exit=$?"
# 3. an existing agent token still works: the token is read without echo, nothing is stored
read -rs TOKEN
curl --pinnedpubkey 'sha256//<pin>' -k -sS -o /dev/null -D - \
  -H "Authorization: Bearer $TOKEN" https://<vps-ip>:8443/api/v1/policy | grep -iE '^(HTTP|etag)'   # 200 and an ETag like "v3"
unset TOKEN
```

4. Admin panel: open `https://<vps-ip>:8443/` in a browser, sign in as `admin` with the admin password from your password manager, and check that the policy and the agents' events are the ones you had before.

If any check fails, read the log, and if it is not a trivial fix, go to step 9. Do not push the release tag while the checks fail.

Part 2, the first tag deploy. Only when part 1 passed completely: push the tag `v0.2.0` on the release commit on `main`, approve the `production` deployment, and wait for `[apply-update] Update applied.` in the workflow log. That deploy exercises the new `guardian-deploy` key, its right to start and stop the service and `apply-update.ps1` from `C:\guardian\scripts`. Then repeat checks 1 and 3 above (pinned `/healthz` 200, token `GET /api/v1/policy` 200 with its ETag). If the deploy fails, the script rolls back to the cutover build by itself (`bin.prev`); read the workflow log and the service log before you decide on step 9.

## Step 9. Manual rollback

Use it only when step 8 cannot be made to pass. Where you stop decides how much of it you need:

- Failure in step 2 or 3 (the service was never removed): if `C:\warden` was already moved, run `Move-Item C:\guardian C:\warden`; if you had renamed `C:\warden-fw-disabled.txt` to `guardian-fw-disabled.txt`, rename it back (`Rename-Item C:\guardian-fw-disabled.txt warden-fw-disabled.txt`). Then restore the old config unconditionally (the step 3 rewrite may have changed its paths to `C:/guardian`; skip this only if the step 2 guard stopped you, because then there is no backup and step 3 never ran):

  ```powershell
  $tmp = 'C:\cutover-backup\restore'
  Expand-Archive C:\cutover-backup\warden-pre-cutover.zip -DestinationPath $tmp -Force
  Copy-Item "$tmp\config.local.json" C:\warden\config.local.json -Force
  Remove-Item $tmp -Recurse -Force
  ```

  Finally `Start-Service WardenServer`, wait 15 seconds, check the pinned `/healthz`. Nothing else is needed.
- Failure in step 4 or later: do sub-steps 1 to 6 in order. Sub-steps for things you had not yet done (firewall before step 5, secrets before step 6) are harmless no-ops or can be skipped.

It restores the old service exactly: the v0.1.1 binary under `C:\warden` and the `WARDEN_*` environment (the old binary does not read `GUARDIAN_*`).

1. Stop and remove the new service, and strip its accounts from the ACLs:

```powershell
Set-Alias nssm 'C:\Program Files\nssm\nssm.exe'
Stop-Service GuardianServer
icacls.exe C:\guardian /remove 'NT SERVICE\GuardianServer' /T /C | Out-Null
icacls.exe C:\guardian /remove 'guardian-deploy' /T /C | Out-Null
nssm remove GuardianServer confirm
```

2. Firewall: add the old rules back (the 8443 rule with its address restriction, if it had one), then delete the new ones by `Name`:

```powershell
New-NetFirewallRule -DisplayName 'Warden SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
```

If the old 8443 rule was restricted (the `Remote` value from the step 5 table was not `Any`):

```powershell
New-NetFirewallRule -DisplayName 'Warden HTTPS' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow `
  -RemoteAddress '<Remote value of the old 8443 rule from the step 5 table>'
```

If it was `Any`, use instead:

```powershell
New-NetFirewallRule -DisplayName 'Warden HTTPS' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

Then:

```powershell
Remove-NetFirewallRule -Name 'GuardianSSH', 'GuardianHTTPS'
```

3. Move the install back and restore the old files from the backup (binary, web, scripts and config; the data stays as it is now, so tokens issued after the cutover survive):

```powershell
Move-Item C:\guardian C:\warden
if (Test-Path C:\guardian-fw-disabled.txt) { Rename-Item C:\guardian-fw-disabled.txt warden-fw-disabled.txt }
$tmp = 'C:\cutover-backup\restore'
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive C:\cutover-backup\warden-pre-cutover.zip -DestinationPath $tmp -Force
foreach ($d in 'bin', 'web', 'scripts') {
  Remove-Item "C:\warden\$d\*" -Recurse -Force
  Copy-Item "$tmp\$d\*" "C:\warden\$d" -Recurse
}
Copy-Item "$tmp\config.local.json" C:\warden\config.local.json -Force
C:\warden\bin\warden-server.exe version                   # 0.1.1
Remove-Item $tmp -Recurse -Force
```

4. Reinstall `WardenServer` with the restored v0.1.1 `install-service.ps1` (its defaults are the old service, root, account and deploy user), put back the exact NSSM settings of the old service, including its environment, and start it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\warden\scripts\install-service.ps1 -Nssm 'C:\Program Files\nssm\nssm.exe' -NoStart
reg.exe import C:\cutover-backup\wardenserver.reg
Show-SvcEnvNames WardenServer                             # names only; as before the cutover
# if you removed a machine-wide WARDEN_ variable in step 4: [Environment]::SetEnvironmentVariable('<NAME>', '<value from your password manager>', 'Machine')
Start-Service WardenServer
Start-Sleep -Seconds 15
Get-Service WardenServer                                  # Running
```

5. GitHub: set the environment secrets back (`VPS_USER` is `warden-deploy`, `VPS_SSH_KEY` is the file `~/.ssh/warden-deploy`, which you kept):

```sh
gh secret set VPS_USER --env production --repo <owner>/guardian-server --body warden-deploy
gh secret set VPS_SSH_KEY --env production --repo <owner>/guardian-server < ~/.ssh/warden-deploy
```

6. Check from the Mac: the pinned `/healthz` answers 200 (the command from step 1) and the agent's "test connection" succeeds. Do not push a release tag: the renamed workflow deploys to the new paths, which the restored install does not have. Keep `C:\cutover-backup` until the next attempt.

## Step 10. Cleanup after the tag deploy and one stable day

Only when the tag deploy of step 8 succeeded and the new install has run for a day without trouble (agents report events, `Get-Service GuardianServer` is Running, no errors in the log):

```powershell
Remove-Item C:\cutover-backup -Recurse -Force
Remove-LocalUser -Name 'warden-deploy'
Remove-Item C:\ProgramData\ssh\warden-deploy_authorized_keys
```

Then edit `C:\ProgramData\ssh\sshd_config`: remove `warden-deploy` from `AllowUsers` and delete the `Match User warden-deploy` block, and apply:

```powershell
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t          # no output = valid
Restart-Service sshd
```

On the Mac, delete the old key pair (`~/.ssh/warden-deploy` and `~/.ssh/warden-deploy.pub`). In GitHub, nothing named after the old user remains in the `production` environment (check with `gh secret list --env production`).

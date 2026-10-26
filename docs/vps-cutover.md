# VPS cutover: Warden to Guardian

One-time migration of the existing VPS install (service `WardenServer`, `C:\warden`, user `warden-deploy`, `WARDEN_*` variables) to the renamed one (service `GuardianServer`, `C:\guardian`, user `guardian-deploy`, `GUARDIAN_*` variables). A fresh install uses [vps-setup.md](vps-setup.md) instead. This file names the old service, paths, user and variables on purpose; it is the only document that does.

The server address, the certificate and its SPKI pin, the data (agents, tokens) and the admin password do not change. Downtime is expected (tens of minutes): stop, move, start, with a manual rollback in step 9. There is no side-by-side service.

Ground rules, learned from the live install:

- The owner runs every command in an elevated PowerShell on the VPS (or in a terminal on the Mac where marked) and pastes the outputs; Claude has no VPS access.
- Never paste or store a password, private key or token (not in this file, not in chat, not in a file in the repository). Passwords come from your password manager, tokens from the agent Settings or the password manager; the commands below read them without echo or never touch them.
- Firewall rules are matched on `Name`, never on `DisplayName` (localized Windows).
- `Start-Service` takes about 15 seconds: wait before you probe.
- The scripts in `C:\guardian\scripts` never update themselves; you copy them by hand (step 7).
- Hard cut: the new server refuses to start (exit 2) while any `WARDEN_*` variable is set in its environment, and the old binary does not read `GUARDIAN_*`. The two cannot be mixed, which is why step 4 checks the service environment and step 9 restores the old service completely.
- Do not reboot the VPS between steps 4 and 8: the new service is registered for automatic start before it is ready.

In every PowerShell session below, first run:

```powershell
Set-Alias nssm 'C:\Program Files\nssm\nssm.exe'
```

## Step 1. Preconditions

1. The server PR is merged to `develop`, and `develop` is merged to `main` (release PR). Nothing is deployed by this: a deploy runs only for a pushed `v*` tag. Do not push the `v0.2.0` tag yet.
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
nssm get WardenServer AppEnvironmentExtra                 # normally empty; do not paste it if it holds a password
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
Compress-Archive -Path (Get-ChildItem C:\warden -Exclude logs,staging,incoming,bin.prev,web.prev) `
  -DestinationPath C:\cutover-backup\warden-pre-cutover.zip
reg.exe export HKLM\SYSTEM\CurrentControlSet\Services\WardenServer C:\cutover-backup\wardenserver.reg /y
Get-Item C:\cutover-backup\* | Select-Object Name, Length
```

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

Take the old environment, then remove the old service and strip its accounts from the ACLs while they still resolve (`warden-deploy` stays as a user until step 10):

```powershell
$oldEnv = @(nssm get WardenServer AppEnvironmentExtra) | Where-Object { $_ -and $_.Trim() }
"Old variable names: " + (($oldEnv | ForEach-Object { ($_ -split '=', 2)[0] }) -join ', ')
icacls.exe C:\guardian /remove 'NT SERVICE\WardenServer' /T /C | Out-Null
icacls.exe C:\guardian /remove 'warden-deploy' /T /C | Out-Null
nssm remove WardenServer confirm
```

Register the new service with the new binary path (the binary arrives in step 7; `install-service.ps1` finishes the configuration there). Carry the old environment over under the new prefix, in memory only (a value, such as a password, is never printed or written to a file):

```powershell
nssm install GuardianServer C:\guardian\bin\guardian-server.exe
nssm set GuardianServer AppParameters 'serve --config C:\guardian\config.local.json'
nssm set GuardianServer AppDirectory C:\guardian
$newEnv = @($oldEnv | ForEach-Object { $_ -replace '^WARDEN_', 'GUARDIAN_' })
if ($newEnv.Count -gt 0) { nssm set GuardianServer AppEnvironmentExtra @newEnv }
Remove-Variable newEnv
```

If the old service had no environment (the normal case, because `install-service.ps1` keeps all settings in the config file), nothing is set and the config file carries the configuration. Now the hard-cut check. The exact command is `nssm get GuardianServer AppEnvironmentExtra`; run it through a filter so that values stay hidden, and it must report that nothing with the former prefix remains:

```powershell
$envNow = @(nssm get GuardianServer AppEnvironmentExtra) | Where-Object { $_ -and $_.Trim() }
if ($envNow | Where-Object { $_ -match '^\s*WARDEN_' }) { 'STOP: a WARDEN_ variable is still set' } else { 'OK: no WARDEN_ variable' }
$envNow | ForEach-Object { ($_ -split '=', 2)[0] }       # names only; each must start with GUARDIAN_
```

If it prints STOP, fix it with `nssm set GuardianServer AppEnvironmentExtra GUARDIAN_<NAME>=<value>` (all variables in one call, the call replaces the list) and run the check again. Do not go on until it prints OK.

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

Paste the table. Add the new rules (explicit `-Name`), reusing the `Remote` restriction of the old 8443 rule if it had one, and only then remove the old ones with the `Name` values from the table:

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
C:\guardian\bin\guardian-server.exe version
C:\guardian\bin\guardian-server.exe cert pin C:\guardian\data\tls\server.crt          # the same pin as before the cutover
powershell -NoProfile -ExecutionPolicy Bypass -File C:\guardian\scripts\install-service.ps1 -Nssm 'C:\Program Files\nssm\nssm.exe' -NoStart
nssm get GuardianServer AppEnvironmentExtra                 # run the step 4 check again; names only if it holds anything
```

If the `cert pin` value differs from the pin you recorded, stop: the certificate was not moved intact.

## Step 8. Start and verify

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
curl --pinnedpubkey 'sha256//<pin>' -k -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" https://<vps-ip>:8443/api/v1/policy      # 200
unset TOKEN
```

4. Admin panel: open `https://<vps-ip>:8443/` in a browser, sign in as `admin` with the admin password from your password manager, and check that the policy and the agents' events are the ones you had before.

If any check fails, read the log, and if it is not a trivial fix, go to step 9. Do not push the release tag while the checks fail.

## Step 9. Manual rollback

Use it only when step 8 cannot be made to pass. It restores the old service exactly: the v0.1.1 binary under `C:\warden` and the `WARDEN_*` environment (the old binary does not read `GUARDIAN_*`).

1. Stop and remove the new service, and strip its accounts from the ACLs:

```powershell
Set-Alias nssm 'C:\Program Files\nssm\nssm.exe'
Stop-Service GuardianServer
icacls.exe C:\guardian /remove 'NT SERVICE\GuardianServer' /T /C | Out-Null
icacls.exe C:\guardian /remove 'guardian-deploy' /T /C | Out-Null
nssm remove GuardianServer confirm
```

2. Firewall: add the old rules back, then delete the new ones by `Name` (re-apply the 8443 address restriction if you had one):

```powershell
New-NetFirewallRule -DisplayName 'Warden SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
New-NetFirewallRule -DisplayName 'Warden HTTPS' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
Remove-NetFirewallRule -Name 'GuardianSSH', 'GuardianHTTPS'
```

3. Move the install back and restore the old files from the backup (binary, web, scripts and config; the data stays as it is now, so tokens issued after the cutover survive):

```powershell
Move-Item C:\guardian C:\warden
if (Test-Path C:\guardian-fw-disabled.txt) { Rename-Item C:\guardian-fw-disabled.txt warden-fw-disabled.txt }
$tmp = 'C:\cutover-backup\restore'
Expand-Archive C:\cutover-backup\warden-pre-cutover.zip -DestinationPath $tmp
foreach ($d in 'bin', 'web', 'scripts') {
  Remove-Item "C:\warden\$d\*" -Recurse -Force
  Copy-Item "$tmp\$d\*" "C:\warden\$d" -Recurse
}
Copy-Item "$tmp\config.local.json" C:\warden\config.local.json -Force
C:\warden\bin\warden-server.exe version                   # 0.1.1
```

4. Reinstall `WardenServer` with the restored v0.1.1 `install-service.ps1` (its defaults are the old service, root, account and deploy user), put back the exact NSSM settings of the old service, including its environment, and start it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\warden\scripts\install-service.ps1 -Nssm 'C:\Program Files\nssm\nssm.exe' -NoStart
reg.exe import C:\cutover-backup\wardenserver.reg
nssm get WardenServer AppEnvironmentExtra                 # as before the cutover
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

## Step 10. Cleanup after one stable day

When the new install has run for a day without trouble (agents report events, `Get-Service GuardianServer` is Running, no errors in the log):

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

Only now push the release tag `v0.2.0` (after the separate version bump PR). The first deploy lands on the already migrated paths: `C:\guardian\incoming`, `C:\guardian\scripts\apply-update.ps1` and the service `GuardianServer`. A tag pushed earlier would fail its health check and roll back to whatever is in `bin.prev`.

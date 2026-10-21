# VPS setup runbook

Checklist for installing the Warden server on a Windows VPS. The owner runs every command on the VPS in an elevated PowerShell (Administrators); Claude cannot reach the VPS and only reviews outputs you paste back. Never paste a password, a private key or a token into chat or into the repository.

Placeholders: `<vps-ip>` is the public address of the VPS, `<owner-user>` your administrator account, `warden-deploy` the low-privilege deploy user created in step 1.

Design context: section 8 of `warden-macos/docs/superpowers/specs/2026-10-20-warden-design.md`; the service host is explained in [ADR 0002](adr/0002-windows-service-nssm.md); the HTTP API in [api.md](api.md).

Layout created by these steps:

```text
C:\warden\
  bin\ bin.prev\        warden-server.exe and the previous build
  web\ web.prev\        admin panel files and the previous copy
  data\ data\tls\       agents.json, policy, events; certificate and private key
  incoming\ staging\    uploaded update archives and their extraction area
  logs\                 service stdout/stderr (rotated by NSSM)
  scripts\              install-service.ps1, apply-update.ps1 (copied by the owner)
  <local config file>   copy of config.example.json with the admin password
```

## Step 1. OpenSSH Server, key-only login, deploy user

Install the server and make PowerShell the default shell:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
  -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force
```

Create the deploy user. It gets a random password that is never displayed or stored (login is by key only):

```powershell
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
New-LocalUser -Name 'warden-deploy' -Password $password -PasswordNeverExpires `
  -Description 'Warden deploy (key-only, low privilege)'
Remove-Variable password, bytes
```

The user is not in Administrators. Generate a dedicated key pair on your Mac (not on the VPS), with no reuse of any other key:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/warden-deploy -C warden-deploy
```

Put the public half (`warden-deploy.pub`) on the VPS. The key file lives outside the user profile, so the profile does not have to exist; sshd (running as SYSTEM) reads it and only Administrators and SYSTEM can change it:

```powershell
$keys = 'C:\ProgramData\ssh\warden-deploy_authorized_keys'
Set-Content -Path $keys -Value '<paste the public key line here>' -Encoding ascii
icacls.exe $keys /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'
```

Install your own public key too, otherwise you lose access once passwords are off and the `scp` commands in steps 4 and 5 fail. Members of Administrators use a shared file, not the profile:

```powershell
$admin = 'C:\ProgramData\ssh\administrators_authorized_keys'
Add-Content -Path $admin -Value '<paste the owner public key line here>' -Encoding ascii
icacls.exe $admin /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'
```

Now edit `C:\ProgramData\ssh\sshd_config` in an editor. The stock file ends with a `Match Group administrators` block, and anything placed after a `Match` line belongs to that block (`AllowUsers` is not even valid there, so sshd would not start). Put the global directives ABOVE the first `Match` line, uncommenting or replacing the existing `#PasswordAuthentication yes` and similar lines:

```text
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
AllowUsers warden-deploy <owner-user>
```

and add this block at the very end, after the existing `Match` blocks:

```text
Match User warden-deploy
    AuthorizedKeysFile __PROGRAMDATA__/ssh/warden-deploy_authorized_keys
```

The configuration must validate before the restart, and you prove key login in a SECOND terminal before closing this session:

```powershell
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t      # no output = valid; fix the file if it prints anything
Restart-Service sshd
```

Keep the first session open. From the Mac, in a SECOND terminal, log in with each key (see the verification below) before you close the first session; if either fails, put `PasswordAuthentication yes` back, run `sshd -t`, restart sshd and fix the key files first.

Verification (from the Mac):

```sh
ssh -i ~/.ssh/warden-deploy -o BatchMode=yes warden-deploy@<vps-ip> "whoami"           # prints the deploy user
ssh -o BatchMode=yes <owner-user>@<vps-ip> "whoami"                                      # owner key works
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password warden-deploy@<vps-ip>   # must be refused
```

```powershell
Select-String -Path C:\ProgramData\ssh\sshd_config -Pattern '^PasswordAuthentication'     # no
(Get-LocalGroupMember Administrators).Name -contains "$env:COMPUTERNAME\warden-deploy"      # False
```

## Step 2. Windows Firewall: TCP 22 and 8443 only

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
New-NetFirewallRule -DisplayName 'Warden SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
New-NetFirewallRule -DisplayName 'Warden HTTPS' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

Keep your remote-desktop rule if you administer the VPS through it (and restrict it too). Recommended: limit 8443 to the addresses that need it (your office or home address, the hosts the Macs connect from) instead of the whole internet:

```powershell
Set-NetFirewallRule -DisplayName 'Warden HTTPS' -RemoteAddress '<allowed-address-1>','<allowed-address-2>'
```

Windows ships many inbound allow rules (file sharing, remote management, ping and more) that would defeat "only 22 and 8443". Review every enabled inbound allow rule and disable what you do not need, keeping remote desktop only if you use it (restricted to your address):

```powershell
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
  Select-Object DisplayName, Profile | Sort-Object DisplayName
Disable-NetFirewallRule -DisplayName '<rule name to disable>'
```

Verification:

```powershell
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
  Get-NetFirewallPortFilter | Select-Object Protocol, LocalPort | Sort-Object LocalPort
```

From the Mac, `Test-NetConnection <vps-ip> -Port 22` (PowerShell) or `nc -vz <vps-ip> 22` succeeds; port 8443 succeeds after step 7.

## Step 3. VC++ redistributable and NSSM

```powershell
winget install --id Microsoft.VCRedist.2015+.x64 --accept-package-agreements --accept-source-agreements
winget install --id NSSM.NSSM --scope machine --accept-package-agreements --accept-source-agreements
```

NSSM is a portable package, so winget may still place it under your own profile (`%LOCALAPPDATA%\Microsoft\WinGet`), where the service account cannot read it and where it is not admin-protected. `install-service.ps1` refuses such a path. Copy it to an admin-only location:

```powershell
$src = (Get-Command nssm.exe).Source        # wherever winget put it
New-Item -ItemType Directory -Force 'C:\Program Files\nssm' | Out-Null
Copy-Item $src 'C:\Program Files\nssm\nssm.exe' -Force
```

`C:\Program Files` is writable only by Administrators and TrustedInstaller by default. Pass `-Nssm 'C:\Program Files\nssm\nssm.exe'` in step 7.

Open a new PowerShell so the PATH refreshes. Verification:

```powershell
winget list --id Microsoft.VCRedist.2015+.x64
& 'C:\Program Files\nssm\nssm.exe' version
```

If `nssm.exe` is not found, locate it (`Get-ChildItem "$env:ProgramFiles\WinGet","$env:LOCALAPPDATA\Microsoft\WinGet" -Recurse -Filter nssm.exe`) and copy it as shown above.

## Step 4. Directory layout and base ACLs

```powershell
$root = 'C:\warden'
foreach ($d in 'bin','bin.prev','web','web.prev','data','data\tls','incoming','staging','logs','scripts') {
  New-Item -ItemType Directory -Force (Join-Path $root $d) | Out-Null
}
$system = '*S-1-5-18:(OI)(CI)F'; $admins = '*S-1-5-32-544:(OI)(CI)F'
icacls.exe $root /inheritance:r /grant:r $system $admins 'warden-deploy:RX'
foreach ($d in 'bin','web','bin.prev','web.prev','staging','incoming') {
  icacls.exe (Join-Path $root $d) /inheritance:r /grant:r $system $admins 'warden-deploy:(OI)(CI)M'
}
icacls.exe (Join-Path $root 'scripts') /inheritance:r /grant:r $system $admins 'warden-deploy:(OI)(CI)RX'
icacls.exe (Join-Path $root 'data') /inheritance:r /grant:r $system $admins
icacls.exe (Join-Path $root 'logs') /inheritance:r /grant:r $system $admins
```

The model: SYSTEM and Administrators have full control everywhere. The deploy user can only write the update areas (`incoming`, `staging`, `bin`, `web` and their `.prev` copies) and read the scripts; it cannot read `data` (agents, certificate, private key) or the local config file. The service account is added in step 7 by `install-service.ps1`: read and execute on `bin` and `web`, modify on `data` and `logs`, read-only on the config file and the TLS files.

Copy the scripts from your checkout to the VPS. Scripts are updated by hand only: `apply-update.ps1` runs from `C:\warden\scripts` and never replaces itself or its sibling, and the deploy user cannot modify them. After you change anything under `scripts/` in the repository, re-copy both files as an Administrator and re-run `install-service.ps1` if it changed.

```sh
scp scripts/install-service.ps1 scripts/apply-update.ps1 <owner-user>@<vps-ip>:C:/warden/scripts/
```

Verification:

```powershell
icacls.exe C:\warden
icacls.exe C:\warden\data          # only SYSTEM and Administrators (service account appears after step 7)
Get-ChildItem C:\warden\scripts
```

## Step 5. Certificate on the VPS and the SPKI pin

The first build must exist on the VPS before `warden-server` can run. Bootstrap it: run the `deploy` workflow on the `main` branch after the PR is merged (Actions, `deploy`, Run workflow, branch `main`); only the `build` job runs, because the deploy job is skipped outside tag refs, download the artifact `warden-server-zip` on your Mac, and upload it:

```sh
scp warden-server-<sha>.zip <owner-user>@<vps-ip>:C:/warden/incoming/
```

```powershell
powershell -NoProfile -File C:\warden\scripts\apply-update.ps1 -Zip C:\warden\incoming\warden-server-<sha>.zip -Bootstrap
C:\warden\bin\warden-server.exe version
```

Generate the self-signed certificate on the VPS, so the private key never leaves it:

```powershell
C:\warden\bin\warden-server.exe cert generate --host <vps-ip> --out-dir C:\warden\data\tls
```

The command prints `SPKI pin: ...`. The pin is public: record it (it goes into the agent Settings on each Mac and into the README of the deployment). It refuses to overwrite an existing certificate. Verification:

```powershell
Get-ChildItem C:\warden\data\tls
C:\warden\bin\warden-server.exe cert pin C:\warden\data\tls\server.crt    # same pin again
```

## Step 6. Local config file

Create `C:\warden\config.local.json` by hand from `config.example.json` (the file is ignored by git; never commit or paste it). Edit it on the VPS in an editor:

```powershell
Copy-Item <path-to>\config.example.json C:\warden\config.local.json   # or paste the template, then edit
notepad.exe C:\warden\config.local.json
```

Set: `"allowInsecureHttp": false`, `"tls": { "certPath": "C:/warden/data/tls/server.crt", "keyPath": "C:/warden/data/tls/<private-key file>" }`, `"dataDir": "C:/warden/data"`, `"webRoot": "C:/warden/web"`, and `"adminPassword"` to a long random password (at least 12 characters) that you store in your password manager. `<private-key file>` is the private-key file written by `cert generate` next to the certificate in `data\tls` (list the directory; `install-service.ps1` expects it there).

Verification (without printing the password):

```powershell
(Get-Content C:\warden\config.local.json -Raw | ConvertFrom-Json).adminPassword.Length -ge 12   # True
Select-String -Path C:\warden\config.local.json -Pattern 'allowInsecureHttp'
```

## Step 7. Register the service with NSSM

```powershell
C:\warden\scripts\install-service.ps1 -DeployUser warden-deploy -Nssm 'C:\Program Files\nssm\nssm.exe'
```

The scripts are copied, not signed, so the deploy workflow calls `apply-update.ps1` with `-ExecutionPolicy Bypass`; start the install script the same way (`powershell -NoProfile -ExecutionPolicy Bypass -File ...`) if your execution policy blocks it.

The script registers `WardenServer` (NSSM; application `C:\warden\bin\warden-server.exe`, arguments `serve --config C:\warden\config.local.json`, working directory `C:\warden`), sends stdout/stderr to `C:\warden\logs` with rotation, starts it at boot, restarts it 5 seconds after a failure, stops it with a console Ctrl-C (`AppStopMethodConsole`) for a clean shutdown, and runs it as the virtual account `NT SERVICE\WardenServer`: no password, no interactive logon, and the only account besides Administrators that can read the TLS private key and the config file. It also lets the deploy user start and stop this one service, and applies the ACLs described in step 4. Re-run it any time; it edits the existing service. A re-run restarts the service (a short downtime) unless you pass `-NoStart`, which leaves it stopped for you to start.

Verification:

```powershell
Get-Service WardenServer                                   # Running
icacls.exe C:\warden\data\tls                              # SYSTEM, Administrators, NT SERVICE\WardenServer (R)
Invoke-WebRequest https://127.0.0.1:8443/healthz -SkipCertificateCheck   # PowerShell 7 only; 200
Get-Content C:\warden\logs\warden-server.err.log -Tail 20
```

From the Mac: `Test-NetConnection <vps-ip> -Port 8443` succeeds.

## Step 8. GitHub environment and secrets

In the repository settings:

1. Settings, Environments, New environment `production`, and configure it. These settings are MANDATORY, because the environment approval is the only gate in front of the secrets:
   - Required reviewers: the owner.
   - Deployment branches and tags: "Selected branches and tags" with exactly one rule, "Selected tags": `v*.*.*`. No branch may deploy.
   - Settings, Rules, Rulesets: add a tag ruleset for `v*` that restricts creation, update and deletion of matching tags to the owner (no bypass for others).
2. In that environment add four secrets (environment secrets, not repository secrets):

| Secret | Value |
| --- | --- |
| `VPS_HOST` | `<vps-ip>` |
| `VPS_USER` | `warden-deploy` |
| `VPS_SSH_KEY` | the full private key file `~/.ssh/warden-deploy` from step 1 |
| `VPS_KNOWN_HOSTS` | the host key line for `<vps-ip>` |

Obtain the host key line without trusting the network, then compare it out-of-band. On the VPS print the fingerprint of its own key, on the Mac scan and compare:

```powershell
ssh-keygen.exe -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub
```

```sh
ssh-keyscan -t ed25519 <vps-ip>            # the line goes into VPS_KNOWN_HOSTS
ssh-keyscan -t ed25519 <vps-ip> | ssh-keygen -lf -   # fingerprint must equal the VPS output above
```

Only when the two fingerprints match, store the `ssh-keyscan` line as `VPS_KNOWN_HOSTS`. The workflow uses `StrictHostKeyChecking=yes` with that file, so SSH never trusts on first use; a changed host key fails the deploy. Delete the local private key copy after storing it in the secret if you do not need it elsewhere.

The workflow adds its own guards: the `build` job fails unless the commit is reachable from `origin/main`, and the `deploy` job (the only one that sees the secrets, and it checks out no repository code) runs only for `refs/tags/v*`. A manual run (`workflow_dispatch`) on a branch therefore builds but never deploys; to redeploy, run the workflow on an existing tag ref (Run workflow, choose the tag).

Verification: after merging to main, push a tag `vX.Y.Z` on a main commit and approve the `production` deployment. The `deploy` job must end with `[apply-update] Update applied.`

## Step 9. First token

```powershell
C:\warden\bin\warden-server.exe token add mac-eugene --data-dir C:\warden\data
```

The token is printed once. Copy it straight into the agent Settings on the Mac (or into your password manager); do not paste it anywhere else. Enter the SPKI pin from step 5 in the same Settings screen. Verification:

```powershell
C:\warden\bin\warden-server.exe token list --data-dir C:\warden\data      # mac-eugene and a creation time
```

Then the agent's "test connection" in Settings must succeed. Tokens apply immediately (the server re-reads the agent store on every authentication, no restart). A 401 means a wrong token or a mismatching pin: check what was entered in the agent Settings.

## Deploying

Pushing a tag `vX.Y.Z` (or running the workflow by hand) builds Release, runs the tests, waits for your approval of the `production` environment, uploads the archive to `C:\warden\incoming` and runs `apply-update.ps1`. The script accepts only an archive inside `C:\warden\incoming` that contains `warden-server.exe` and `web/` and nothing else, stops the service, keeps the old files in `bin.prev` and `web.prev`, installs the new ones, and polls `https://127.0.0.1:8443/healthz` for 30 seconds. If the new build does not answer 200, it restores the previous files, restarts the service and exits with status 1 (the workflow fails).

## Rollback

Automatic: `apply-update.ps1` restores `bin.prev`/`web.prev` itself when the health check fails.

Manual, for a build that is healthy but wrong (as an Administrator):

```powershell
Stop-Service WardenServer
Remove-Item C:\warden\bin\* -Recurse -Force; Copy-Item C:\warden\bin.prev\* C:\warden\bin -Recurse
Remove-Item C:\warden\web\* -Recurse -Force; Copy-Item C:\warden\web.prev\* C:\warden\web -Recurse
Start-Service WardenServer
```

Only one previous generation is kept. To go further back, re-run the `deploy` workflow from the older tag.

## Operations

Logs (NSSM rotates them at 10 MiB or daily):

```powershell
Get-Content C:\warden\logs\warden-server.err.log -Tail 100 -Wait    # access log and errors (stderr)
Get-Content C:\warden\logs\warden-server.out.log -Tail 100
Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -like 'nssm*'
```

Rotate the admin password: edit `adminPassword` in the local config file (step 6), then `Restart-Service WardenServer`. Store the new password in your password manager; nothing else changes.

Revoke a token: `C:\warden\bin\warden-server.exe token remove <agentId> --data-dir C:\warden\data`; list with `token list`. Issue a replacement with `token add <agentId>`, then enter it in that Mac's agent Settings.

Renew the certificate (before it expires; default validity is 825 days): move the old pair out of `C:\warden\data\tls` (the command refuses to overwrite), run `cert generate --host <vps-ip> --out-dir C:\warden\data\tls` again, run `install-service.ps1 -NoStart` to re-apply the ACLs on the new files, then `Restart-Service WardenServer`. The new SPKI pin differs from the old one, so every agent must be given the new pin in its Settings, or it will (correctly) refuse to connect.

```powershell
$old = 'C:\warden\data\tls-old'; New-Item -ItemType Directory $old | Out-Null
Move-Item C:\warden\data\tls\* $old
C:\warden\bin\warden-server.exe cert generate --host <vps-ip> --out-dir C:\warden\data\tls
C:\warden\scripts\install-service.ps1 -NoStart
Restart-Service WardenServer
```

Delete `tls-old` once all agents work with the new pin.

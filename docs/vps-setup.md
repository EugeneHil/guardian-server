# VPS setup runbook

> Formerly Warden.

This is the fresh-install runbook. An existing install that still runs under the former name is migrated with [vps-cutover.md](vps-cutover.md).

Verified live on 2026-10-27: the reference VPS was migrated with [vps-cutover.md](vps-cutover.md) (pin, tokens, policy and events unchanged) and runs v0.2.0, deployed by the `v0.2.0` tag through the `guardian-deploy` user.

Checklist for installing the Guardian server on a Windows VPS. The owner runs every command on the VPS in an elevated PowerShell (Administrators); Claude cannot reach the VPS and only reviews outputs you paste back. Never paste a password, a private key or a token into chat or into the repository.

Placeholders: `<vps-ip>` is the public address of the VPS, `<owner-user>` your administrator account, `guardian-deploy` the low-privilege deploy user created in step 1.

Design context: section 8 of `guardian-macos/docs/superpowers/specs/2026-10-20-guardian-design.md`; the service host is explained in [ADR 0002](adr/0002-windows-service-nssm.md); the HTTP API in [api.md](api.md).

Layout created by these steps:

```text
C:\guardian\
  bin\ bin.prev\        guardian-server.exe and the previous build
  web\ web.prev\        admin panel files and the previous copy
  data\ data\tls\       agents.json, policy, events; certificate and private key
  incoming\ staging\    uploaded update archives and their extraction area
  logs\                 service stdout/stderr (rotated by NSSM)
  scripts\              install-service.ps1, apply-update.ps1 (copied by the owner)
  <local config file>   copy of config.example.json with the admin password
```

## Step 1. OpenSSH Server, key-only login, deploy user

Install the server, start it once and make PowerShell the default shell. `sshd_config` does not exist until the service has started for the first time, so do not skip `Start-Service`:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
  -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force
```

Create the deploy user. It gets a random password that is never displayed or stored (login is by key only):

```powershell
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
New-LocalUser -Name 'guardian-deploy' -Password $password -PasswordNeverExpires `
  -Description 'Guardian deploy (key-only, low privilege)'
Remove-Variable password, bytes
```

The user is not in Administrators. Generate a dedicated key pair on your Mac (not on the VPS), with no reuse of any other key:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/guardian-deploy -C guardian-deploy
```

Put the public half (`guardian-deploy.pub`) on the VPS. The key file lives outside the user profile, so the profile does not have to exist; sshd (running as SYSTEM) reads it and only Administrators and SYSTEM can change it:

```powershell
$keys = 'C:\ProgramData\ssh\guardian-deploy_authorized_keys'
Set-Content -Path $keys -Value '<paste the public key line here>' -Encoding ascii
icacls.exe $keys /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'
```

Install your own public key too, otherwise you lose access once passwords are off and the `scp` commands in steps 4 and 5 fail. Members of Administrators use a shared file, not the profile:

```powershell
$admin = 'C:\ProgramData\ssh\administrators_authorized_keys'
Add-Content -Path $admin -Value '<paste the owner public key line here>' -Encoding ascii
icacls.exe $admin /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'
```

Now edit `C:\ProgramData\ssh\sshd_config` in an editor. The stock file ends with a `Match Group administrators` block, and anything placed after a `Match` line belongs to that block (sshd would still start, but directives below `Match Group administrators` silently apply only to administrators, so password authentication would stay on for the deploy user). Put the global directives ABOVE the first `Match` line, uncommenting or replacing the existing `#PasswordAuthentication yes` and similar lines:

```text
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
AuthenticationMethods publickey
AllowUsers guardian-deploy <owner-user>
```

Write `<owner-user>` in lowercase: Windows OpenSSH matches `AllowUsers` names against the lowercased account name, so a mixed-case entry can lock you out.

`PasswordAuthentication no` alone is not enough: sshd still advertises `keyboard-interactive`, and the Windows build does not honour the `KbdInteractiveAuthentication` directive (`sshd -T` keeps reporting `yes`). `AuthenticationMethods publickey` is honoured and makes a key the only way in.

and add this block at the very end, after the existing `Match` blocks:

```text
Match User guardian-deploy
    AuthorizedKeysFile __PROGRAMDATA__/ssh/guardian-deploy_authorized_keys
```

The configuration must validate before the restart, and you prove key login in a SECOND terminal before closing this session:

```powershell
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t      # no output = valid; fix the file if it prints anything
Restart-Service sshd
```

Keep the first session open. From the Mac, in a SECOND terminal, log in with each key (see the verification below) before you close the first session; if either fails, remove the `AuthenticationMethods` line and put `PasswordAuthentication yes` back, run `sshd -t`, restart sshd and fix the key files first (the hosting provider's console stays available as a fallback).

Verification (from the Mac):

```sh
ssh -i ~/.ssh/guardian-deploy -o BatchMode=yes guardian-deploy@<vps-ip> "whoami"           # prints the deploy user
ssh -o BatchMode=yes <owner-user>@<vps-ip> "whoami"                                      # owner key works
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password guardian-deploy@<vps-ip>   # must be refused
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive guardian-deploy@<vps-ip>   # refused, and the list of methods in the error is only (publickey)
```

```powershell
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -T | Select-String -Pattern 'authenticationmethods|passwordauthentication|pubkeyauthentication|allowusers'   # publickey, no, yes, both users
Select-String -Path C:\ProgramData\ssh\sshd_config -Pattern '^PasswordAuthentication'     # no
(Get-LocalGroupMember Administrators).Name -contains "$env:COMPUTERNAME\guardian-deploy"      # False
```

## Step 2. Windows Firewall: TCP 22 and 8443 only

Add the two allow rules first and switch the default to "block" last, so you never block yourself:

```powershell
New-NetFirewallRule -Name 'GuardianSSH' -DisplayName 'Guardian SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
New-NetFirewallRule -Name 'GuardianHTTPS' -DisplayName 'Guardian HTTPS' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

Windows ships dozens of inbound allow rules (file sharing, remote management, discovery, streaming and more) that would defeat "only 22 and 8443". Their display names are localized and differ between machines, so do not disable them one by one by name. Disable everything except a keep list, matching on the language-independent rule `Name` (never on `DisplayName`; that is why the two rules above are created with an explicit `-Name`). Keep `CoreNet-*` (Core Networking: DHCP, IPv6 and ICMPv6; without DHCP the VPS can lose its address), the OpenSSH rule, the two `Guardian*` rules (matched by `Name`) and anything you deliberately use (for example your own VPN: add its rule to `$keepExtra`). Remote desktop is disabled here; keep it only if you administer the VPS through it, and then restrict it to your address.

First list what would stay (nothing is changed yet) and check that the list contains exactly what you expect:

```powershell
$keepExtra = @()   # e.g. @('*WireGuard*')
$all = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow
$toDisable = $all | Where-Object {
  $n = $_.Name
  -not ($n -like 'CoreNet-*' -or $n -like '*OpenSSH*' -or $n -like 'Guardian*' -or
        ($keepExtra | Where-Object { $n -like $_ }))
}
"Keep: $($all.Count - $toDisable.Count), disable: $($toDisable.Count)"
$all | Where-Object { $toDisable.Name -notcontains $_.Name } | Select-Object Name, DisplayName
```

Then disable the rest. The names are saved so you can undo it; set `$expected` to the `Keep` number printed above, so a wrong keep list stops the script instead of disabling too much:

```powershell
$expected = 0   # the "Keep" number from the listing above
if (($all.Count - $toDisable.Count) -eq $expected) {
  $toDisable.Name | Set-Content -Path C:\guardian-fw-disabled.txt
  $toDisable | Disable-NetFirewallRule
} else { 'Keep count differs from $expected: nothing was disabled' }
# undo: Get-Content C:\guardian-fw-disabled.txt | ForEach-Object { Enable-NetFirewallRule -Name $_ }
```

Now switch the default to "block" and confirm the allow rules still work (the hosting provider's console does not depend on the OS firewall, so it stays available if something goes wrong):

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
```

Recommended: limit 8443 to the addresses that need it (your office or home address, the hosts the Macs connect from) instead of the whole internet, when those addresses are stable:

```powershell
Set-NetFirewallRule -Name 'GuardianHTTPS' -RemoteAddress '<allowed-address-1>','<allowed-address-2>'
```

Verification:

```powershell
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
  Get-NetFirewallPortFilter | Select-Object Protocol, LocalPort | Sort-Object LocalPort
```

From the Mac, `Test-NetConnection <vps-ip> -Port 22` (PowerShell) or `nc -vz <vps-ip> 22` succeeds; port 8443 succeeds after step 7.

## Step 3. VC++ redistributable and NSSM

Windows Server has no `winget`, so both are downloaded directly. The binaries link the C++ runtime dynamically, so the Microsoft Visual C++ Redistributable (x64) is required. It is signed, so verify the signature before running it:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$vc = "$env:TEMP\vc_redist.x64.exe"
Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/vs/17/release/vc_redist.x64.exe' -OutFile $vc
Get-AuthenticodeSignature $vc | Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}}   # Valid, CN=Microsoft Corporation
Start-Process -FilePath $vc -ArgumentList '/install','/quiet','/norestart' -Wait
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' | Select-Object Installed, Version   # Installed 1
```

Do not run the installer unless the status is `Valid` and the signer is Microsoft Corporation. (In Windows PowerShell 5.1 `Start-Process -PassThru` may print an empty exit code; the registry check is the reliable one.)

NSSM is not signed, so verify the download against a pinned SHA-256. Use the build `2.24-101-g897c7ad`: the stock 2.24 release cannot start services reliably on Windows 10 1703 and newer, including Server 2022. The hash below is the one published in the `microsoft/winget-pkgs` manifest `NSSM.NSSM` 2.24-101-g897c7ad:

```powershell
$zip = "$env:TEMP\nssm.zip"
Invoke-WebRequest -UseBasicParsing -Uri 'https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip' -OutFile $zip
(Get-FileHash $zip -Algorithm SHA256).Hash    # must equal 99F5045FFFBFFB745D67FE3A065A953C4A3D9C253B868892D9B685B0EE7D07B8
```

Only if the hash is identical, install it into an admin-only location. `C:\Program Files` is writable only by Administrators and TrustedInstaller by default, and `install-service.ps1` refuses a path the service account or a normal user could modify:

```powershell
$x = "$env:TEMP\nssm-extract"
Expand-Archive -Path $zip -DestinationPath $x -Force
New-Item -ItemType Directory -Force 'C:\Program Files\nssm' | Out-Null
Copy-Item "$x\nssm-2.24-101-g897c7ad\win64\nssm.exe" 'C:\Program Files\nssm\nssm.exe' -Force
& 'C:\Program Files\nssm\nssm.exe' version    # NSSM 2.24-101-g897c7ad 64-bit
```

Pass `-Nssm 'C:\Program Files\nssm\nssm.exe'` in step 7. The site `nssm.cc` is sometimes unavailable (HTTP 503); retry later rather than taking the file from another place, because only this hash is trusted.

## Step 4. Directory layout and base ACLs

```powershell
$root = 'C:\guardian'
foreach ($d in 'bin','bin.prev','web','web.prev','data','data\tls','incoming','staging','logs','scripts') {
  New-Item -ItemType Directory -Force (Join-Path $root $d) | Out-Null
}
$system = '*S-1-5-18:(OI)(CI)F'; $admins = '*S-1-5-32-544:(OI)(CI)F'
icacls.exe $root /inheritance:r /grant:r $system $admins 'guardian-deploy:RX'
foreach ($d in 'bin','web','bin.prev','web.prev','staging','incoming') {
  icacls.exe (Join-Path $root $d) /inheritance:r /grant:r $system $admins 'guardian-deploy:(OI)(CI)M'
}
icacls.exe (Join-Path $root 'scripts') /inheritance:r /grant:r $system $admins 'guardian-deploy:(OI)(CI)RX'
icacls.exe (Join-Path $root 'data') /inheritance:r /grant:r $system $admins
icacls.exe (Join-Path $root 'logs') /inheritance:r /grant:r $system $admins
```

The model: SYSTEM and Administrators have full control everywhere. The deploy user can only write the update areas (`incoming`, `staging`, `bin`, `web` and their `.prev` copies) and read the scripts; it cannot read `data` (agents, certificate, private key) or the local config file. The service account is added in step 7 by `install-service.ps1`: read and execute on `bin` and `web`, modify on `data` and `logs`, read-only on the config file and the TLS files.

Copy the scripts from your checkout to the VPS. Scripts are updated by hand only: `apply-update.ps1` runs from `C:\guardian\scripts` and never replaces itself or its sibling, and the deploy user cannot modify them. After you change anything under `scripts/` in the repository, re-copy both files as an Administrator and re-run `install-service.ps1` if it changed.

```sh
scp scripts/install-service.ps1 scripts/apply-update.ps1 <owner-user>@<vps-ip>:C:/guardian/scripts/
```

Verification:

```powershell
icacls.exe C:\guardian
icacls.exe C:\guardian\data          # only SYSTEM and Administrators (service account appears after step 7)
Get-ChildItem C:\guardian\scripts
```

## Step 5. Certificate on the VPS and the SPKI pin

The first build must exist on the VPS before `guardian-server` can run. Bootstrap it: run the `deploy` workflow on the `main` branch after the PR is merged (Actions, `deploy`, Run workflow, branch `main`); only the `build` job runs, because the deploy job is skipped outside tag refs, download the artifact `guardian-server-zip` on your Mac, and upload it:

```sh
scp guardian-server-<sha>.zip <owner-user>@<vps-ip>:C:/guardian/incoming/
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\guardian\scripts\apply-update.ps1 -Zip C:\guardian\incoming\guardian-server-<sha>.zip -Bootstrap
C:\guardian\bin\guardian-server.exe version
```

Generate the self-signed certificate on the VPS, so the private key never leaves it:

```powershell
C:\guardian\bin\guardian-server.exe cert generate --host <vps-ip> --out-dir C:\guardian\data\tls
```

The command prints `SPKI pin: ...`. The pin is public: record it (it goes into the agent Settings on each Mac and into the README of the deployment). It refuses to overwrite an existing certificate. Verification:

```powershell
Get-ChildItem C:\guardian\data\tls
C:\guardian\bin\guardian-server.exe cert pin C:\guardian\data\tls\server.crt    # same pin again
```

## Step 6. Local config file

The release archive does not ship the template, so copy it from your checkout first (the local config file is ignored by git; never commit or paste it):

```sh
scp config.example.json <owner-user>@<vps-ip>:C:/guardian/config.example.json   # on the Mac, from the repository checkout
```

Create `C:\guardian\config.local.json` from it on the VPS. This script generates a random admin password (24 characters) and prints it once; store it in your password manager straight away, never paste it anywhere else, and clear the console afterwards (`Clear-Host`). The private-key file written by `cert generate` is the only file in `data\tls` that is not a `.crt`; `install-service.ps1` expects it there:

```powershell
$tls = 'C:\guardian\data\tls'
$key = Get-ChildItem $tls -File | Where-Object { $_.Extension -ne '.crt' } | Select-Object -First 1
if (-not $key) { throw 'private key file not found in data\tls' }
$bytes = New-Object byte[] 18
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pw = [Convert]::ToBase64String($bytes).Replace('+','A').Replace('/','b')
$cfg = Get-Content C:\guardian\config.example.json -Raw | ConvertFrom-Json
$cfg.PSObject.Properties.Remove('_comment')
$cfg.tls.certPath = 'C:/guardian/data/tls/server.crt'
$cfg.tls.keyPath  = "C:/guardian/data/tls/$($key.Name)"
$cfg.dataDir = 'C:/guardian/data'; $cfg.webRoot = 'C:/guardian/web'
$cfg.allowInsecureHttp = $false; $cfg.adminPassword = $pw
$cfg | ConvertTo-Json -Depth 5 | Set-Content -Path C:\guardian\config.local.json -Encoding ascii
"ADMIN PASSWORD (store it now, do not paste it anywhere): $pw"
```

The result sets `allowInsecureHttp` to `false`, the certificate and key paths, `dataDir` to `C:/guardian/data`, `webRoot` to `C:/guardian/web` and the generated `adminPassword`. To change a value later, edit the file in an editor (`notepad.exe C:\guardian\config.local.json`).

Verification (without printing the password):

```powershell
(Get-Content C:\guardian\config.local.json -Raw | ConvertFrom-Json).adminPassword.Length -ge 12   # True
Select-String -Path C:\guardian\config.local.json -Pattern 'allowInsecureHttp'
```

## Step 7. Register the service with NSSM

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\guardian\scripts\install-service.ps1 -DeployUser guardian-deploy -Nssm 'C:\Program Files\nssm\nssm.exe'
```

The scripts are copied, not signed, so the deploy workflow calls `apply-update.ps1` with `-ExecutionPolicy Bypass`; start the install script the same way.

The script registers `GuardianServer` (NSSM; application `C:\guardian\bin\guardian-server.exe`, arguments `serve --config C:\guardian\config.local.json`, working directory `C:\guardian`), sends stdout/stderr to `C:\guardian\logs` with rotation, starts it at boot, restarts it 5 seconds after a failure, stops it with a console Ctrl-C (`AppStopMethodConsole`) for a clean shutdown, and runs it as the virtual account `NT SERVICE\GuardianServer`: no password, no interactive logon, and the only account besides Administrators that can read the TLS private key and the config file. It also lets the deploy user start and stop this one service, and applies the ACLs described in step 4. Re-run it any time; it edits the existing service. A re-run restarts the service (a short downtime) unless you pass `-NoStart`, which leaves it stopped for you to start.

Verification:

```powershell
Get-Service GuardianServer                                   # Running
icacls.exe C:\guardian\data\tls                              # SYSTEM, Administrators, NT SERVICE\GuardianServer (R)
curl.exe -k -s -o NUL -w "healthz: %{http_code}`n" https://127.0.0.1:8443/healthz   # 200 (Windows PowerShell 5.1 has no -SkipCertificateCheck, so use curl.exe)
Get-Content C:\guardian\logs\guardian-server.err.log -Tail 20
```

From the Mac: `Test-NetConnection <vps-ip> -Port 8443` succeeds.

## Step 8. GitHub environment and secrets

In the repository settings:

1. Settings, Environments, New environment `production`, and configure it. These settings are MANDATORY, because the environment approval is the only gate in front of the secrets:
   - Required reviewers: the owner.
   - Deployment branches and tags: "Selected branches and tags" with exactly one rule, "Selected tags": `v*.*.*`. No branch may deploy.
   - Leave "Prevent self-review" off: the owner is the only reviewer and also the one who pushes the tag, so self-review prevention would make every deployment unapprovable.
   - Settings, Rules, Rulesets: add a tag ruleset for `v*` that restricts creation, update and deletion of matching tags to the owner. The only bypass actor is the repository Admin role (without a bypass actor nobody, including the owner, could create the release tag).
2. In that environment add four secrets (environment secrets, not repository secrets):

| Secret | Value |
| --- | --- |
| `VPS_HOST` | `<vps-ip>` |
| `VPS_USER` | `guardian-deploy` |
| `VPS_SSH_KEY` | the full private key file `~/.ssh/guardian-deploy` from step 1 |
| `VPS_KNOWN_HOSTS` | the host key line for `<vps-ip>` |

Obtain the host key line without trusting the network, then compare it out-of-band. On the VPS print the fingerprint of its own key, on the Mac scan and compare:

```powershell
ssh-keygen.exe -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub
```

```sh
ssh-keyscan -t ed25519 <vps-ip>            # the line goes into VPS_KNOWN_HOSTS
ssh-keyscan -t ed25519 <vps-ip> | ssh-keygen -lf -   # fingerprint must equal the VPS output above
```

Only when the two fingerprints match, store the `ssh-keyscan` line as `VPS_KNOWN_HOSTS`. The secrets can be set in the web interface or with the GitHub CLI; the private key is read from the file and is never printed (replace `<fingerprint>` with the `SHA256:...` value you verified, so the line is stored only if the key has not changed since the comparison):

```sh
gh secret set VPS_SSH_KEY --env production --repo <owner>/guardian-server < ~/.ssh/guardian-deploy
gh secret set VPS_HOST --env production --repo <owner>/guardian-server --body <vps-ip>
gh secret set VPS_USER --env production --repo <owner>/guardian-server --body guardian-deploy
kh=$(ssh-keyscan -t ed25519 <vps-ip> 2>/dev/null)
[ "$(printf '%s\n' "$kh" | ssh-keygen -lf - | awk '{print $2}')" = "<fingerprint>" ] \
  && printf '%s\n' "$kh" | gh secret set VPS_KNOWN_HOSTS --env production --repo <owner>/guardian-server
```
 The workflow uses `StrictHostKeyChecking=yes` with that file, so SSH never trusts on first use; a changed host key fails the deploy. Delete the local private key copy after storing it in the secret if you do not need it elsewhere.

The workflow adds its own guards: the `build` job fails unless the commit is reachable from `origin/main`, and the `deploy` job (the only one that sees the secrets, and it checks out no repository code) runs only for `refs/tags/v*`. A manual run (`workflow_dispatch`) on a branch therefore builds but never deploys; to redeploy, run the workflow on an existing tag ref (Run workflow, choose the tag).

Verification: after merging to main, push a tag `vX.Y.Z` on a main commit and approve the `production` deployment. The `deploy` job must end with `[apply-update] Update applied.`

## Step 9. First token

```powershell
C:\guardian\bin\guardian-server.exe token add mac-eugene --data-dir C:\guardian\data
```

The token is printed once. Copy it straight into the agent Settings on the Mac (or into your password manager); do not paste it anywhere else. Enter the SPKI pin from step 5 in the same Settings screen. Verification:

```powershell
C:\guardian\bin\guardian-server.exe token list --data-dir C:\guardian\data      # mac-eugene and a creation time
```

Then the agent's "test connection" in Settings must succeed. Tokens apply immediately (the server re-reads the agent store on every authentication, no restart). A 401 means a wrong token or a mismatching pin: check what was entered in the agent Settings.

## Deploying

Pushing a tag `vX.Y.Z` (or re-running it on an existing tag) builds Release, runs the tests, waits for your approval of the `production` environment, uploads the archive to `C:\guardian\incoming` and runs `apply-update.ps1`. The script accepts only an archive inside `C:\guardian\incoming` that contains `guardian-server.exe` and `web/` and nothing else, stops the service, keeps the old files in `bin.prev` and `web.prev`, installs the new ones, and polls `https://127.0.0.1:8443/healthz` for 60 seconds (a service start alone takes about 15 seconds on the reference VPS, and the window starts after the start has finished). The probe in Windows PowerShell 5.1 (the default shell of the SSH session) explicitly enables TLS 1.2 (`Tls12`) for its own process, because the server accepts nothing older; without it every deploy would time out and roll back. After a successful update the script deletes the consumed archive from `incoming`; after a failed one the archive stays for inspection, so clean `C:\guardian\incoming` by hand after you are done. If the new build does not answer 200, it restores the previous files, restarts the service and exits with status 1 (the workflow fails).

## Rollback

Automatic: `apply-update.ps1` restores `bin.prev`/`web.prev` itself when the health check fails.

Manual, for a build that is healthy but wrong (as an Administrator):

```powershell
Stop-Service GuardianServer
Remove-Item C:\guardian\bin\* -Recurse -Force; Copy-Item C:\guardian\bin.prev\* C:\guardian\bin -Recurse
Remove-Item C:\guardian\web\* -Recurse -Force; Copy-Item C:\guardian\web.prev\* C:\guardian\web -Recurse
Start-Service GuardianServer
```

Only one previous generation is kept. To go further back, re-run the `deploy` workflow from the older tag.

## Operations

Logs (NSSM rotates them at 10 MiB or daily):

```powershell
Get-Content C:\guardian\logs\guardian-server.err.log -Tail 100 -Wait    # access log and errors (stderr)
Get-Content C:\guardian\logs\guardian-server.out.log -Tail 100
Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -like 'nssm*'
```

Rotate the admin password: edit `adminPassword` in the local config file (step 6), then `Restart-Service GuardianServer`. Store the new password in your password manager; nothing else changes.

Revoke a token: `C:\guardian\bin\guardian-server.exe token remove <agentId> --data-dir C:\guardian\data`; list with `token list`. Issue a replacement with `token add <agentId>`, then enter it in that Mac's agent Settings.

Renew the certificate (before it expires; default validity is 825 days): move the old pair out of `C:\guardian\data\tls` (the command refuses to overwrite), run `cert generate --host <vps-ip> --out-dir C:\guardian\data\tls` again, run `install-service.ps1 -NoStart` to re-apply the ACLs on the new files, then `Restart-Service GuardianServer`. The new SPKI pin differs from the old one, so every agent must be given the new pin in its Settings, or it will (correctly) refuse to connect.

```powershell
$old = 'C:\guardian\data\tls-old'; New-Item -ItemType Directory $old | Out-Null
Move-Item C:\guardian\data\tls\* $old
C:\guardian\bin\guardian-server.exe cert generate --host <vps-ip> --out-dir C:\guardian\data\tls
C:\guardian\scripts\install-service.ps1 -NoStart
Restart-Service GuardianServer
```

Delete `tls-old` once all agents work with the new pin.

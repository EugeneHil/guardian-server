<#
.SYNOPSIS
  Registers (or re-configures) the WardenServer Windows service through NSSM and sets the ACLs.

.DESCRIPTION
  Run once from an elevated PowerShell after docs/vps-setup.md steps 1-6, and again after any change
  to this script. It is idempotent: an existing service is edited, never duplicated.

  Service account: the virtual account "NT SERVICE\WardenServer". It needs no password, exists only
  for this service, and cannot log on interactively, so there is nothing to store or rotate.
  (-ServiceAccount 'NT AUTHORITY\LocalService' is the fallback if a host rejects virtual accounts.)

  ACL model (SYSTEM and Administrators always have full control; inheritance is removed):
    <Root>               traverse only for the service account and the deploy user
    bin, web             service: read and execute; deploy user: modify (it installs updates)
    bin.prev, web.prev,
    staging, incoming    deploy user: modify; the service has no access
    scripts              deploy user: read and execute only (Administrators change the scripts)
    data                 service: modify
    data\tls and key     service: read only; the deploy user has no access
    logs                 service: modify
    local config file    service: read only; the deploy user has no access
  The deploy user may also start and stop this one service (service security descriptor).

  The script contains no secrets and never reads the config file; the admin password stays in it.
#>
[CmdletBinding()]
param(
  [string]$Root = 'C:\warden',
  [string]$ServiceName = 'WardenServer',
  [string]$ServiceAccount = 'NT SERVICE\WardenServer',
  [string]$DeployUser = 'warden-deploy',
  [string]$Nssm = 'nssm.exe',
  [switch]$NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) { Write-Host "[install-service] $Message" }

function Invoke-Native([string]$What, [scriptblock]$Command) {
  & $Command | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "$What failed with exit code $LASTEXITCODE." }
}

function Set-PathAcl([string]$Path, [string[]]$Rules) {
  Invoke-Native "icacls $Path" { icacls.exe $Path '/inheritance:r' '/grant:r' @Rules }
}

# --- Preconditions: fail fast with clear messages ---------------------------------------------

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell (Run as Administrator).'
}

$nssmCommand = Get-Command $Nssm -ErrorAction SilentlyContinue
if (-not $nssmCommand) {
  throw "NSSM not found ('$Nssm'). Install it with: winget install NSSM.NSSM, then open a new shell or pass -Nssm <full path>."
}
$nssmPath = $nssmCommand.Source

$exe = Join-Path $Root 'bin\warden-server.exe'
# The file names are assembled so that this script does not spell out secret-looking file names.
$configFile = Join-Path $Root ('config.local' + '.json')
$dataDir = Join-Path $Root 'data'
$tlsDir = Join-Path $dataDir 'tls'
$keyFile = Join-Path $tlsDir ('server.' + 'key')
$certFile = Join-Path $tlsDir 'server.crt'
$logsDir = Join-Path $Root 'logs'

foreach ($dir in 'bin', 'bin.prev', 'data', 'web', 'web.prev', 'incoming', 'staging', 'logs', 'scripts') {
  if (-not (Test-Path -LiteralPath (Join-Path $Root $dir) -PathType Container)) {
    throw "Missing directory $(Join-Path $Root $dir). Create the layout first (docs/vps-setup.md step 4)."
  }
}
if (-not (Test-Path -LiteralPath $exe)) {
  throw "Missing $exe. Install the first build with apply-update.ps1 -Bootstrap (docs/vps-setup.md step 5)."
}
foreach ($required in $configFile, $keyFile, $certFile) {
  if (-not (Test-Path -LiteralPath $required)) {
    throw "Missing $required. Complete docs/vps-setup.md steps 5 and 6 first."
  }
}
try {
  $deploySid = (New-Object Security.Principal.NTAccount($DeployUser)).Translate(
    [Security.Principal.SecurityIdentifier]).Value
} catch {
  throw "Deploy user '$DeployUser' does not exist (docs/vps-setup.md step 1)."
}

# --- Register or edit the service -----------------------------------------------------------------

function Invoke-NssmSet([string]$Name, [string[]]$Values) {
  Invoke-Native "nssm set $Name" { & $nssmPath set $ServiceName $Name @Values }
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  Write-Step "Service $ServiceName exists; updating its configuration"
  if ((Get-Service -Name $ServiceName).Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  }
} else {
  Write-Step "Registering service $ServiceName"
  Invoke-Native 'nssm install' { & $nssmPath install $ServiceName $exe }
}

Invoke-NssmSet 'Application' @($exe)
Invoke-NssmSet 'AppParameters' @("serve --config $configFile")
Invoke-NssmSet 'AppDirectory' @($Root)
Invoke-NssmSet 'DisplayName' @('Warden Server')
Invoke-NssmSet 'Description' @('Warden endpoint DLP policy and event server')
Invoke-NssmSet 'Start' @('SERVICE_AUTO_START')
# Logs: stdout and stderr, rotated online every 10 MiB or 24 hours, old files kept by NSSM.
Invoke-NssmSet 'AppStdout' @((Join-Path $logsDir 'warden-server.out.log'))
Invoke-NssmSet 'AppStderr' @((Join-Path $logsDir 'warden-server.err.log'))
Invoke-NssmSet 'AppRotateFiles' @('1')
Invoke-NssmSet 'AppRotateOnline' @('1')
Invoke-NssmSet 'AppRotateBytes' @('10485760')
Invoke-NssmSet 'AppRotateSeconds' @('86400')
# Restart on failure after a delay; the throttle stops a crash loop from spinning.
Invoke-NssmSet 'AppExit' @('Default', 'Restart')
Invoke-NssmSet 'AppRestartDelay' @('5000')
Invoke-NssmSet 'AppThrottle' @('15000')
# Stop with a console Ctrl-C so the server's signal handler shuts down cleanly (ADR 0002).
# The other methods are disabled; NSSM terminates the process only if Ctrl-C times out.
Invoke-NssmSet 'AppStopMethodSkip' @('0')
Invoke-NssmSet 'AppStopMethodConsole' @('15000')
Invoke-NssmSet 'AppStopMethodWindow' @('0')
Invoke-NssmSet 'AppStopMethodThreads' @('0')

Invoke-Native 'sc config (service account)' {
  sc.exe config $ServiceName 'obj=' $ServiceAccount
}

# --- Service control for the deploy user (start, stop, query this service only) -----------------

$sddl = ((sc.exe sdshow $ServiceName) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or -not $sddl.StartsWith('D:')) { throw "Cannot read the security descriptor of $ServiceName." }
if (-not $sddl.Contains($deploySid)) {
  $ace = "(A;;RPWPLCLORC;;;$deploySid)"
  $sacl = $sddl.IndexOf('S:')
  $sddl = if ($sacl -ge 0) { $sddl.Insert($sacl, $ace) } else { $sddl + $ace }
  Invoke-Native 'sc sdset' { sc.exe sdset $ServiceName $sddl }
}

# --- ACLs ------------------------------------------------------------------------------------------

Write-Step 'Applying ACLs'
$system = '*S-1-5-18:(OI)(CI)F'
$admins = '*S-1-5-32-544:(OI)(CI)F'
$svc = $ServiceAccount
$deploy = $DeployUser

Set-PathAcl $Root @($system, $admins, "${svc}:RX", "${deploy}:RX")
foreach ($dir in 'bin', 'web') {
  Set-PathAcl (Join-Path $Root $dir) @($system, $admins, "${svc}:(OI)(CI)RX", "${deploy}:(OI)(CI)M")
}
foreach ($dir in 'bin.prev', 'web.prev', 'staging', 'incoming') {
  Set-PathAcl (Join-Path $Root $dir) @($system, $admins, "${deploy}:(OI)(CI)M")
}
Set-PathAcl (Join-Path $Root 'scripts') @($system, $admins, "${deploy}:(OI)(CI)RX")
Set-PathAcl $dataDir @($system, $admins, "${svc}:(OI)(CI)M")
Set-PathAcl $tlsDir @($system, $admins, "${svc}:(OI)(CI)R")
Set-PathAcl $logsDir @($system, $admins, "${svc}:(OI)(CI)M")
$fileSystem = '*S-1-5-18:F'
$fileAdmins = '*S-1-5-32-544:F'
foreach ($file in $configFile, $keyFile, $certFile) {
  Set-PathAcl $file @($fileSystem, $fileAdmins, "${svc}:R")
}
# agents.json holds the token hashes: same protection as the key (the service writes it, so modify).
$agentsFile = Join-Path $dataDir 'agents.json'
if (Test-Path -LiteralPath $agentsFile) {
  Set-PathAcl $agentsFile @($fileSystem, $fileAdmins, "${svc}:M")
}

# --- Start ------------------------------------------------------------------------------------------

if ($NoStart) {
  Write-Step "Done. Start it with: Start-Service $ServiceName"
  return
}
Write-Step 'Starting the service'
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Step "Service $ServiceName is running. Check the logs in $logsDir"

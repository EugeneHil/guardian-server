<#
.SYNOPSIS
  Applies a Warden server release archive on the VPS and rolls back if the new build is unhealthy.

.DESCRIPTION
  Runs as the low-privilege deploy user from C:\warden\scripts. Steps:
    1. Validate the archive: it must live under <Root>\incoming and contain only
       warden-server.exe and web/ entries (zip-slip protection).
    2. Extract it into <Root>\staging (the service keeps running meanwhile).
    3. Stop the service, copy bin to bin.prev and web to web.prev, install the new files.
    4. Start the service and poll https://127.0.0.1:<Port>/healthz for 60 seconds.
    5. On any failure restore bin.prev and web.prev, restart the service and exit 1.

  The directories already exist with their ACLs (created by the runbook and install-service.ps1),
  so files are copied, never moved: copies inherit the ACL of the target directory.

  -Bootstrap installs the first build before the service exists: no service control, no health check.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Zip,
  [string]$Root = 'C:\warden',
  [string]$ServiceName = 'WardenServer',
  [int]$Port = 8443,
  [int]$HealthTimeoutSeconds = 60,
  [switch]$Bootstrap
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Write-Step([string]$Message) { Write-Host "[apply-update] $Message" }

function Test-UnderDirectory([string]$Path, [string]$Directory) {
  $dir = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\') + '\'
  $full = [System.IO.Path]::GetFullPath($Path)
  return $full.StartsWith($dir, [System.StringComparison]::OrdinalIgnoreCase)
}

# Zip-slip protection: every entry name must be exactly warden-server.exe or live under web/,
# with no absolute path, drive letter, ':' or '..' segment.
function Assert-SafeEntryName([string]$RawName) {
  $name = $RawName.Replace('\', '/')
  if ($name.StartsWith('/') -or $name.Contains(':')) {
    throw "Archive entry '$RawName' is an absolute path."
  }
  foreach ($segment in $name.Split('/')) {
    if ($segment -eq '..' -or $segment -eq '.') {
      throw "Archive entry '$RawName' contains a '..' or '.' segment (zip-slip)."
    }
  }
  if ($name -ne 'warden-server.exe' -and -not $name.StartsWith('web/')) {
    throw "Archive entry '$RawName' is not warden-server.exe or under web/."
  }
}

function Clear-Directory([string]$Path) {
  Get-ChildItem -LiteralPath $Path -Force | Remove-Item -Recurse -Force
}

function Copy-Contents([string]$From, [string]$To) {
  if (Get-ChildItem -LiteralPath $From -Force) {
    Copy-Item -Path (Join-Path $From '*') -Destination $To -Recurse -Force
  }
}

# The certificate of the local server is self-signed, so the probe skips validation. The skip is
# confined to the fixed loopback URL below: PowerShell 7 uses -SkipCertificateCheck on that URL
# only; Windows PowerShell 5.1 uses a per-request callback that accepts a certificate only when
# the request targets 127.0.0.1. No process-wide certificate validation setting is changed. The
# server requires TLS 1.2, which Windows PowerShell 5.1 may not offer by default, so that branch
# adds Tls12 to the (process-local) protocol list.
function Initialize-LoopbackProbe {
  if ($PSVersionTable.PSVersion.Major -ge 6) { return }
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  if ('WardenLoopbackProbe' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class WardenLoopbackProbe
{
    public static int GetStatus(string url, int timeoutMs)
    {
        Uri uri = new Uri(url);
        if (uri.Host != "127.0.0.1") { throw new ArgumentException("loopback only"); }
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
        request.Timeout = timeoutMs;
        request.ServerCertificateValidationCallback = delegate (object sender, X509Certificate cert,
            X509Chain chain, SslPolicyErrors errors)
        {
            HttpWebRequest origin = sender as HttpWebRequest;
            return origin != null && origin.RequestUri.Host == "127.0.0.1";
        };
        try
        {
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                return (int)response.StatusCode;
            }
        }
        catch (WebException e)
        {
            HttpWebResponse failed = e.Response as HttpWebResponse;
            return failed == null ? 0 : (int)failed.StatusCode;
        }
    }
}
'@
}

function Get-HealthStatus([string]$Url) {
  try {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
      $response = Invoke-WebRequest -Uri $Url -SkipCertificateCheck -UseBasicParsing `
        -TimeoutSec 3 -SkipHttpErrorCheck
      return [int]$response.StatusCode
    }
    return [WardenLoopbackProbe]::GetStatus($Url, 3000)
  } catch {
    return 0
  }
}

function Wait-Healthy {
  $url = "https://127.0.0.1:$Port/healthz"
  $deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
  do {
    if ((Get-HealthStatus $url) -eq 200) { return $true }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Stop-WardenService {
  $svc = Get-Service -Name $ServiceName
  if ($svc.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  }
}

function Start-WardenService {
  Start-Service -Name $ServiceName
  (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

# --- 1. Validate the archive before touching anything ---------------------------------------

$incoming = Join-Path $Root 'incoming'
$bin = Join-Path $Root 'bin'
$web = Join-Path $Root 'web'
$binPrev = Join-Path $Root 'bin.prev'
$webPrev = Join-Path $Root 'web.prev'
$staging = Join-Path $Root 'staging'

foreach ($dir in @($incoming, $bin, $web, $binPrev, $webPrev, $staging)) {
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
    throw "Missing directory $dir. Follow docs/vps-setup.md steps 4 and 7 first."
  }
}
if (-not (Test-Path -LiteralPath $Zip -PathType Leaf)) { throw "Archive not found: $Zip" }
$zipFull = [System.IO.Path]::GetFullPath($Zip)
if (-not (Test-UnderDirectory $zipFull $incoming)) {
  throw "Archive must be inside $incoming (got $zipFull)."
}
if ([System.IO.Path]::GetExtension($zipFull) -ne '.zip') { throw 'Archive must have the .zip extension.' }

$hasExe = $false
$archive = [System.IO.Compression.ZipFile]::OpenRead($zipFull)
try {
  foreach ($entry in $archive.Entries) {
    Assert-SafeEntryName $entry.FullName
    if ($entry.FullName -eq 'warden-server.exe') { $hasExe = $true }
  }
} finally {
  $archive.Dispose()
}
if (-not $hasExe) { throw 'Archive does not contain warden-server.exe.' }

if (-not $Bootstrap) {
  if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    throw "Service $ServiceName is not registered. Use -Bootstrap for the first install."
  }
  Initialize-LoopbackProbe
}

# --- 2. Extract into staging (service still running) ----------------------------------------

Write-Step "Extracting $zipFull"
Clear-Directory $staging
$stagingFull = [System.IO.Path]::GetFullPath($staging)
$archive = [System.IO.Compression.ZipFile]::OpenRead($zipFull)
try {
  foreach ($entry in $archive.Entries) {
    if ($entry.FullName.EndsWith('/')) { continue }
    $target = [System.IO.Path]::GetFullPath((Join-Path $stagingFull $entry.FullName.Replace('/', '\')))
    if (-not (Test-UnderDirectory $target $stagingFull)) {
      throw "Archive entry '$($entry.FullName)' escapes the staging directory (zip-slip)."
    }
    $parent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
  }
} finally {
  $archive.Dispose()
}

# --- 3-5. Swap, verify, roll back on failure ---------------------------------------------------

function Restore-Previous {
  Write-Step 'Restoring bin.prev and web.prev'
  Clear-Directory $bin
  Copy-Contents $binPrev $bin
  Clear-Directory $web
  Copy-Contents $webPrev $web
}

$swapped = $false
try {
  if (-not $Bootstrap) {
    Write-Step 'Stopping the service'
    Stop-WardenService
  }
  Clear-Directory $binPrev
  Copy-Contents $bin $binPrev
  Clear-Directory $webPrev
  Copy-Contents $web $webPrev
  $swapped = $true

  Clear-Directory $bin
  Copy-Item -LiteralPath (Join-Path $stagingFull 'warden-server.exe') -Destination $bin
  Clear-Directory $web
  $newWeb = Join-Path $stagingFull 'web'
  if (Test-Path -LiteralPath $newWeb) { Copy-Contents $newWeb $web }

  if ($Bootstrap) {
    Write-Step 'Bootstrap install finished; run install-service.ps1 next.'
    return
  }

  Write-Step 'Starting the service'
  Start-WardenService
  Write-Step "Waiting up to $HealthTimeoutSeconds s for https://127.0.0.1:$Port/healthz"
  if (-not (Wait-Healthy)) { throw 'The new build did not become healthy in time.' }
  Write-Step 'Update applied.'
  # The archive is consumed; keep incoming\ from filling up. A failure here must not roll back.
  Remove-Item -LiteralPath $zipFull -Force -ErrorAction SilentlyContinue
} catch {
  Write-Host "[apply-update] FAILED: $($_.Exception.Message)"
  if (-not $Bootstrap) {
    try {
      $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
      if ($svc -and $svc.Status -ne 'Stopped') { Stop-WardenService }
      if ($swapped) { Restore-Previous }
      Start-WardenService
      Write-Step 'Rolled back to the previous build.'
    } catch {
      Write-Host "[apply-update] ROLLBACK FAILED: $($_.Exception.Message)"
    }
  } elseif ($swapped) {
    Restore-Previous
  }
  exit 1
} finally {
  Clear-Directory $staging
}

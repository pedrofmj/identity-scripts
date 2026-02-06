<#
.SYNOPSIS
  Batch "rename" CyberArk Safe AD group members by adding the new group with identical permissions
  (and membership expiration) and optionally deleting the old group.

.DESCRIPTION
  CyberArk PVWA Safe Members APIs do not provide a direct "rename member principal".
  This script implements a safe, auditable replacement workflow:
    1) GET old safe member (group) to capture permissions + membershipExpirationDate
    2) POST new safe member with same permissions + expiration
       - If new already exists: update/skip/fail (OnConflict)
    3) DELETE old safe member (optional)

  Input: CSV (CSV-only).

  OPTION A (implemented):
    - Log the permissions/rights captured from the old group and applied to the new group
      for each operation (ADD/UPDATE), in a compact deterministic format.

.PARAMETER CLIPasswordSDK_Path
  Path to CyberArk ApplicationPasswordSdk CLIPasswordSDK.exe.
  If Token/Password are not provided, the script fetches the credential via AIM (CLIPasswordSDK).

.NOTES
  - This is a REST-only script (no psPAS / Connect-PASServer).
  - If AIM returns APPAP309E "untrusted shell", run from a trusted shell (typically powershell.exe),
    not ISE, not embedded terminals, or ask CyberArk admins to whitelist your shell/host.
  - Script runs sequentially by default (shared token). True parallelism usually requires per-worker tokens.
#>

[CmdletBinding()]
param(
  # ---------------------------
  # Input
  # ---------------------------
  [Parameter(Mandatory=$true)]
  [string]$InputPath,

  [string]$CsvDelimiter = ",",

  [ValidateSet("UTF8","UTF7","UTF32","Unicode","BigEndianUnicode","Default","OEM","ASCII")]
  [string]$CsvEncoding = "UTF8",

  # Optional filter to run only a specific environment subset (matches CSV value exactly)
  [string]$Environment,

  # ---------------------------
  # PVWA connection/auth
  # ---------------------------
  [Parameter(Mandatory=$true)]
  [string]$PVWA,

  [ValidateSet("Cyberark","LDAP","Windows","RADIUS")]
  [string]$AuthType = "Cyberark",

  # If Token is not provided, script will logon using Username+Password.
  # If Password is not provided, it will either be fetched from AIM (if configured) or prompted.
  [string]$Username = $env:CYBERARK_USERNAME,
  [SecureString]$Password,
  [string]$Token = $env:CYBERARK_TOKEN,

  # ---------------------------
  # AIM / CLIPasswordSDK (optional)
  # ---------------------------
  [string]$CLIPasswordSDK_Path = "D:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe",
  [string]$AIM_AppID           = "P-CarkAutomationApp",
  [string]$AIM_Safe            = "PSNSCarkAutomation",
  [string]$AIM_Username        = "App-Cark-Prod-Auto-L", # kept for reference/logging
  [string]$AIM_Object          = "Application-Prod-CyberArkVault-172.23.9.14-App-Cark-Prod-Auto-L",
  [string]$AIM_Folder          = "Root",

  # If enabled, requests concurrentSession during logon (if supported by PVWA version/auth method).
  [switch]$ConcurrentSession,

  # ---------------------------
  # Safe member settings
  # ---------------------------
  # Directory source in PVWA. Often "Vault" or your external directory source name.
  [string]$SearchIn = "Vault",

  # Member type for Safe Members API.
  [ValidateSet("Group","User")]
  [string]$MemberType = "Group",

  # Behavior when NEW member already exists:
  # - update: update perms/expiration
  # - skip: do nothing
  # - fail: abort with error
  [ValidateSet("update","skip","fail")]
  [string]$OnConflict = "update",

  # If set, delete the old member after add/update.
  [switch]$DeleteOld,

  # If set, missing old member becomes a non-fatal skip.
  # If not set, missing old member is still logged, and the row is skipped (current behavior preserved).
  [switch]$AllowMissingOld,

  # If set, performs no changes (only logs intended actions).
  [switch]$DryRun,

  # Optional: emits a bash curl script for audit/replay (uses captured permissions/expiration).
  [string]$EmitCurlScript,

  # ---------------------------
  # Logging
  # ---------------------------
  [ValidateSet("DEBUG","INFO","WARN","ERROR")]
  [string]$Loglevel = "INFO",

  [ValidateSet("stdout","file")]
  [string]$Logmode = "stdout",

  [string]$Logfile,

  # Reserved for future parallelism; retained for CLI compatibility.
  [int]$Workers = 8,

  # ---------------------------
  # HTTP behavior
  # ---------------------------
  [int]$TimeoutSec = 30,
  [int]$Retries = 3,
  [double]$RetryBackoffSec = 0.5,
  [string]$RetryStatus = "429,500,502,503,504",
  [double]$SleepSec = 0.0,

  # If set, skips TLS certificate verification (not recommended).
  [switch]$NoVerifyTls,

  # Output-only options
  [switch]$Info,
  [switch]$Version
)

$Script:ToolVersion = "0.1.0"

# ---------------------------
# Logging
# ---------------------------
function Initialize-Logger {
  param([string]$Level,[string]$Mode,[string]$File)

  $Script:LogLevelRank = @{
    "DEBUG" = 10
    "INFO"  = 20
    "WARN"  = 30
    "ERROR" = 40
  }

  if (-not $Script:LogLevelRank.ContainsKey($Level)) { throw "Invalid loglevel: $Level" }
  if ($Mode -eq "file" -and [string]::IsNullOrWhiteSpace($File)) { throw "-Logfile is required when -Logmode=file" }

  $Script:LogMode = $Mode
  $Script:LogFile = $File
  $Script:CurrentLevel = $Level
}

function Write-Log {
  param(
    [ValidateSet("DEBUG","INFO","WARN","ERROR")]
    [string]$Level,
    [string]$Message
  )

  # Skip messages below configured level
  if ($Script:LogLevelRank[$Level] -lt $Script:LogLevelRank[$Script:CurrentLevel]) { return }

  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = "$ts | $Level | $Message"

  if ($Script:LogMode -eq "file") {
    Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8
  } else {
    Write-Host $line
  }
}

Initialize-Logger -Level $Loglevel -Mode $Logmode -File $Logfile
$Script:StartTime = Get-Date

if ($Version) {
  Write-Output $Script:ToolVersion
  exit 0
}

# ---------------------------
# TLS handling
# ---------------------------
$Script:IRM_SkipCert = $false
try {
  $irmCmd = Get-Command Invoke-RestMethod -ErrorAction Stop
  if ($irmCmd.Parameters.ContainsKey("SkipCertificateCheck")) {
    $Script:IRM_SkipCert = $true
  }
} catch {}

if ($NoVerifyTls) {
  if (-not $Script:IRM_SkipCert) {
    # Older PowerShell: global callback (process-wide)
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  }
}

# ---------------------------
# Utilities
# ---------------------------
function Escape-Url([string]$s) { return [System.Uri]::EscapeDataString($s) }

function ConvertTo-PlainText([SecureString]$sec) {
  if ($null -eq $sec) { return $null }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Parse-RetryStatus([string]$csv) {
  $set = New-Object "System.Collections.Generic.HashSet[int]"
  $csv.Split(",") | ForEach-Object {
    $t = $_.Trim()
    if ($t) { [void]$set.Add([int]$t) }
  }
  return $set
}
$Script:RetryStatusSet = Parse-RetryStatus $RetryStatus

# ---------------------------
# OPTION A: Permission logging helpers
# ---------------------------

# Creates a stable, compact permissions summary string:
# Example: "useAccounts=true;retrieveAccounts=true;listAccounts=false;manageSafeMembers=true;..."
# - Only includes boolean keys, sorted alphabetically, to keep logs diff-friendly.
function Format-PermissionsSummary {
  param([Parameter(Mandatory=$true)]$Permissions)

  if ($null -eq $Permissions) { return "<null>" }

  # Permissions sometimes arrive as PSCustomObject / Hashtable
  $props =
    if ($Permissions -is [hashtable]) {
      $Permissions.Keys | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_; Value = $Permissions[$_] }
      }
    } else {
      $Permissions.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Value = $_.Value }
      }
    }

  $boolProps = $props | Where-Object { $_.Value -is [bool] }

  if (-not $boolProps) {
    return "<no-boolean-permissions>"
  }

  $pairs = $boolProps |
    Sort-Object Name |
    ForEach-Object { "{0}={1}" -f $_.Name, ($_.Value.ToString().ToLowerInvariant()) }

  return ($pairs -join ";")
}

# If you ever want the full JSON payload in logs (more verbose), use this:
function Format-PermissionsJson {
  param([Parameter(Mandatory=$true)]$Permissions)
  if ($null -eq $Permissions) { return "null" }
  try { return ($Permissions | ConvertTo-Json -Depth 30 -Compress) } catch { return "<json-serialize-failed>" }
}

# ---------------------------
# AIM credential fetch (CLIPasswordSDK.exe)
# ---------------------------
function Get-AimCredential {
  param(
    [Parameter(Mandatory=$true)][string]$CliPath,
    [Parameter(Mandatory=$true)][string]$AppId,
    [Parameter(Mandatory=$true)][string]$Safe,
    [Parameter(Mandatory=$true)][string]$Object,
    [Parameter(Mandatory=$false)][string]$Folder = "Root"
  )

  if (-not (Test-Path -LiteralPath $CliPath)) {
    throw "AIM CLI not found: $CliPath"
  }

  $query = "Safe=$Safe;Folder=$Folder;object=$Object"

  try {
    $out = & "$CliPath" password `
      /p "AppDescs.AppID=$AppId" `
      /p "query=$query" `
      /o PassProps.UserName,Password
  } catch {
    throw "AIM CLI execution failed: $($_.Exception.Message)"
  }

  if (-not $out) {
    throw "AIM returned empty output for query [$query] (AppId=$AppId)."
  }

  $text = ($out | Out-String)

  # Detect AIM provider rejection early (common failure)
  if ($text -match 'APPAP309E' -or $text -match 'untrusted shell') {
    throw ("AIM blocked the request (untrusted shell). Run from trusted powershell.exe (not ISE/embedded terminal) and/or whitelist the host/shell. Raw: " + ($text.Trim()))
  }

  # AIM CLI often prints a line like: username,password
  $line = ($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_.Contains(",") }) | Select-Object -First 1
  if (-not $line) {
    throw "Unexpected AIM output format (no 'user,password' line found). Raw: $($text.Trim())"
  }

  $parts = $line -split ',', 2
  if ($parts.Count -lt 2) { throw "Unexpected AIM output format (cannot split user/password). Line: $line" }

  $user  = $parts[0].Trim()
  $plain = $parts[1].Trim()
  if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($plain)) {
    throw "AIM returned blank username/password. Line: $line"
  }

  $sec = ConvertTo-SecureString $plain -AsPlainText -Force
  return [pscredential]::new($user, $sec)
}

# ---------------------------
# Read input (CSV)
# ---------------------------
function Normalize-Header([string]$h) {
  if ($null -eq $h) { return "" }
  $s = $h.Trim().ToLowerInvariant()
  $s = ($s -replace "\s+","")
  $s = $s.Replace("_","").Replace("-","")
  return $s
}

function Read-OpsFromCsv([string]$path,[string]$delimiter,[string]$encoding) {
  $text = Get-Content -Path $path -Encoding $encoding
  return $text | ConvertFrom-Csv -Delimiter $delimiter
}

function Resolve-Column([string[]]$headers, [string[]]$candidates) {
  $map = @{}
  for ($i=0; $i -lt $headers.Count; $i++) {
    $map[(Normalize-Header $headers[$i])] = $headers[$i]
  }
  foreach ($c in $candidates) {
    $k = Normalize-Header $c
    if ($map.ContainsKey($k)) { return $map[$k] }
  }
  return $null
}

function Read-RenameOps([string]$path, [string]$envFilter, [string]$delimiter, [string]$encoding) {
  $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()
  if ($ext -ne ".csv") { throw "Unsupported input extension: $ext (use .csv)" }

  $rows = Read-OpsFromCsv -path $path -delimiter $delimiter -encoding $encoding
  if (-not $rows) { return @() }

  $headers = @($rows[0].PSObject.Properties.Name)

  $colEnv  = Resolve-Column $headers @("Environment","Env")
  $colSafe = Resolve-Column $headers @("SafeName","Safe","SafeUrlId")
  $colOld  = Resolve-Column $headers @("ExistingSecurityGroupName","ExistingGroupName","OldGroup","Existing","CurrentGroup")
  $colNew  = Resolve-Column $headers @("NewSecurityGroupName","NewGroupName","NewGroup","New","TargetGroup")

  if (-not $colEnv -or -not $colSafe -or -not $colOld -or -not $colNew) {
    throw "Missing required columns. Need: Environment, SafeName, Existing group, New group (headers matched flexibly)."
  }

  $ops = New-Object System.Collections.Generic.List[object]
  $rowNum = 1
  foreach ($r in $rows) {
    $rowNum++

    $env  = [string]$r.$colEnv
    $safe = [string]$r.$colSafe
    $oldg = [string]$r.$colOld
    $newg = [string]$r.$colNew

    if ([string]::IsNullOrWhiteSpace($env) -or [string]::IsNullOrWhiteSpace($safe) -or
        [string]::IsNullOrWhiteSpace($oldg) -or [string]::IsNullOrWhiteSpace($newg)) { continue }

    if ($envFilter -and $env -ne $envFilter) { continue }

    $ops.Add([pscustomobject]@{
      Environment = $env.Trim()
      SafeName    = $safe.Trim()
      OldGroup    = $oldg.Trim()
      NewGroup    = $newg.Trim()
      RowNum      = $rowNum
    })
  }

  return $ops
}

function Print-Info($ops) {
  $total = $ops.Count
  $envs = $ops | Select-Object -ExpandProperty Environment -Unique | Sort-Object
  $safeCount = ($ops | ForEach-Object { "$($_.Environment)||$($_.SafeName)" } | Sort-Object -Unique).Count
  $pairCount = ($ops | ForEach-Object { "$($_.Environment)||$($_.SafeName)||$($_.OldGroup)||$($_.NewGroup)" } | Sort-Object -Unique).Count

  Write-Output "Ops: $total"
  Write-Output "Environments: $($envs -join ', ')"
  Write-Output "Unique (env,safe): $safeCount"
  Write-Output "Unique (env,safe,old,new): $pairCount"
}

$ops = Read-RenameOps -path $InputPath -envFilter $Environment -delimiter $CsvDelimiter -encoding $CsvEncoding
if ($Info) { Print-Info $ops; exit 0 }
if (-not $ops -or $ops.Count -eq 0) { Write-Log INFO "No operations found (after filtering)."; exit 0 }

# ---------------------------
# CyberArk REST
# ---------------------------
function Invoke-CyberArk {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","POST","PUT","DELETE")] [string]$Method,
    [Parameter(Mandatory=$true)][string]$Url,
    [hashtable]$Headers,
    [object]$Body
  )

  $attempt = 0
  $lastErr = $null

  while ($attempt -le $Retries) {
    try {
      $splat = @{
        Method      = $Method
        Uri         = $Url
        Headers     = $Headers
        TimeoutSec  = $TimeoutSec
        ErrorAction = "Stop"
      }

      if ($NoVerifyTls -and $Script:IRM_SkipCert) { $splat["SkipCertificateCheck"] = $true }

      if ($null -ne $Body) {
        $splat["ContentType"] = "application/json"
        $splat["Body"] = ($Body | ConvertTo-Json -Depth 30 -Compress)
      }

      return Invoke-RestMethod @splat
    } catch {
      $lastErr = $_

      $statusCode = $null
      try {
        $resp = $_.Exception.Response
        if ($resp -and $resp.StatusCode) { $statusCode = [int]$resp.StatusCode }
      } catch {}

      $retryable = $false
      if ($null -ne $statusCode -and $Script:RetryStatusSet.Contains($statusCode)) { $retryable = $true }

      # Avoid hard dependency on types across PS/.NET variants
      $ex = $_.Exception
      if ($ex -ne $null) {
        $t = $ex.GetType().FullName
        if ($t -eq 'System.Net.Http.HttpRequestException') { $retryable = $true }
        elseif ($ex.InnerException -ne $null -and $ex.InnerException.GetType().FullName -eq 'System.Net.Http.HttpRequestException') { $retryable = $true }
        elseif ($t -eq 'System.Net.WebException') { $retryable = $true }
        elseif ($ex.Message -match '(?i)timed out|timeout|temporarily unavailable|connection.*(closed|reset)') { $retryable = $true }
      }

      if ($attempt -lt $Retries -and $retryable) {
        $sleep = $RetryBackoffSec * [math]::Pow(2, $attempt)
        Write-Log WARN ("HTTP $Method $Url failed (status={0}). Retry in {1:N2}s. Error: {2}" -f $statusCode, $sleep, $_.Exception.Message)
        Start-Sleep -Seconds $sleep
        $attempt++
        continue
      }

      throw $lastErr
    }
  }

  throw $lastErr
}

function Get-Headers([string]$token) {
  $h = @{ "Content-Type" = "application/json" }
  if (-not [string]::IsNullOrWhiteSpace($token)) { $h["Authorization"] = $token }
  return $h
}

function CyberArk-Logon([string]$baseUrl, [string]$authType, [string]$user, [string]$pass, [bool]$concurrent) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/auth/$authType/Logon/"
  $body = @{ username = $user; password = $pass }
  if ($concurrent) { $body["concurrentSession"] = $true }
  $resp = Invoke-CyberArk -Method POST -Url $url -Headers (Get-Headers "") -Body $body
  if ($resp -is [string]) { return $resp.Trim('"') }
  return ([string]$resp).Trim('"')
}

function CyberArk-Logoff([string]$baseUrl, [string]$token) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Auth/Logoff/"
  try { Invoke-CyberArk -Method POST -Url $url -Headers (Get-Headers $token) -Body $null | Out-Null }
  catch { Write-Log WARN "Logoff failed: $($_.Exception.Message)" }
}

function CyberArk-GetMember([string]$baseUrl, [string]$token, [string]$safe, [string]$member) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$(Escape-Url $safe)/Members/$(Escape-Url $member)/"
  try { return Invoke-CyberArk -Method GET -Url $url -Headers (Get-Headers $token) -Body $null }
  catch {
    $statusCode = $null
    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
    if ($statusCode -eq 404) { return $null }
    throw
  }
}

function CyberArk-AddMember([string]$baseUrl, [string]$token, [string]$safe, [hashtable]$body) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$(Escape-Url $safe)/Members/"
  return Invoke-CyberArk -Method POST -Url $url -Headers (Get-Headers $token) -Body $body
}

function CyberArk-UpdateMember([string]$baseUrl, [string]$token, [string]$safe, [string]$member, [hashtable]$body) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$(Escape-Url $safe)/Members/$(Escape-Url $member)/"
  return Invoke-CyberArk -Method PUT -Url $url -Headers (Get-Headers $token) -Body $body
}

function CyberArk-DeleteMember([string]$baseUrl, [string]$token, [string]$safe, [string]$member) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$(Escape-Url $safe)/Members/$(Escape-Url $member)/"
  try { Invoke-CyberArk -Method DELETE -Url $url -Headers (Get-Headers $token) -Body $null | Out-Null }
  catch {
    $statusCode = $null
    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
    if ($statusCode -eq 404) { return }
    throw
  }
}

# ---------------------------
# Curl script emission (bash)
# ---------------------------
function New-CurlScript(
  [string]$baseUrl,
  [string]$authType,
  [string]$username,
  [string]$searchIn,
  [string]$memberType,
  [bool]$deleteOld,
  $captured
) {
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add('#!/usr/bin/env bash')
  $lines.Add('set -euo pipefail')
  $lines.Add('')
  $lines.Add(('PVWA_BASE="{0}"' -f $baseUrl.TrimEnd('/')))
  $lines.Add('TOKEN="${TOKEN:-}"')
  $lines.Add('')
  $lines.Add('if [[ -z "$TOKEN" ]]; then')
  $lines.Add('  echo "TOKEN is empty. Export TOKEN first, or login manually and export it." >&2')
  $lines.Add('  exit 2')
  $lines.Add('fi')
  $lines.Add('')

  foreach ($item in $captured) {
    $safe = [string]$item.SafeName
    $oldg = [string]$item.OldGroup
    $newg = [string]$item.NewGroup

    $safeQ = [System.Uri]::EscapeDataString($safe)
    $oldQ  = [System.Uri]::EscapeDataString($oldg)

    $addBody = @{
      memberName  = $newg
      searchIn    = $searchIn
      permissions = $item.Permissions
      MemberType  = $memberType
    }
    if ($null -ne $item.MembershipExpirationDate -and $item.MembershipExpirationDate -ne "" -and $item.MembershipExpirationDate -ne 0) {
      $addBody.membershipExpirationDate = $item.MembershipExpirationDate
    }

    $payloadJson = ($addBody | ConvertTo-Json -Depth 30 -Compress)

    $lines.Add(('echo "==> {0}: {1} -> {2}"' -f $safe, $oldg, $newg))
    $lines.Add('payload=$(cat <<''JSON''')
    $lines.Add($payloadJson)
    $lines.Add('JSON')
    $lines.Add(')')
    $lines.Add(('curl -sS -k -X POST "${{PVWA_BASE}}/PasswordVault/API/Safes/{0}/Members/" -H "Content-Type: application/json" -H "Authorization: $TOKEN" -d "$payload"' -f $safeQ))
    if ($deleteOld) {
      $lines.Add(('curl -sS -k -X DELETE "${{PVWA_BASE}}/PasswordVault/API/Safes/{0}/Members/{1}/" -H "Authorization: $TOKEN"' -f $safeQ, $oldQ))
    }
    $lines.Add('')
  }

  return ($lines -join "`n")
}

# ---------------------------
# Main execution
# ---------------------------
$PVWA = $PVWA.TrimEnd("/")
$didLogonHere = $false

# Acquire token if not provided:
# - If Password is missing, attempt AIM fetch using CLIPasswordSDK (if configured)
# - Otherwise prompt
if ([string]::IsNullOrWhiteSpace($Token)) {

  if ($null -eq $Password) {
    $aimProvided =
      (-not [string]::IsNullOrWhiteSpace($CLIPasswordSDK_Path)) -and
      (-not [string]::IsNullOrWhiteSpace($AIM_AppID)) -and
      (-not [string]::IsNullOrWhiteSpace($AIM_Safe)) -and
      (-not [string]::IsNullOrWhiteSpace($AIM_Object))

    if ($aimProvided) {
      Write-Log INFO "Fetching credential from AIM (CLIPasswordSDK) ..."
      $cred = Get-AimCredential -CliPath $CLIPasswordSDK_Path -AppId $AIM_AppID -Safe $AIM_Safe -Object $AIM_Object -Folder $AIM_Folder

      # If -Username not provided, use the AIM username automatically.
      if ([string]::IsNullOrWhiteSpace($Username)) {
        $Username = $cred.UserName
      } elseif ($Username -ne $cred.UserName) {
        Write-Log WARN ("AIM returned username '{0}' but -Username is '{1}'. Using -Username." -f $cred.UserName, $Username)
      }

      $Password = $cred.Password
      Write-Log INFO ("AIM credential retrieved for user '{0}'." -f $cred.UserName)
    }
  }

  if ([string]::IsNullOrWhiteSpace($Username)) {
    throw "Missing Username (or set CYBERARK_USERNAME), or provide -Token, or provide AIM parameters."
  }

  if ($null -eq $Password) {
    $Password = Read-Host -Prompt "Password for $Username" -AsSecureString
  }

  $plainPass = ConvertTo-PlainText $Password
  Write-Log INFO "Logging in to PVWA ($AuthType) ..."
  $Token = CyberArk-Logon -baseUrl $PVWA -authType $AuthType -user $Username -pass $plainPass -concurrent ([bool]$ConcurrentSession)
  $didLogonHere = $true
  $plainPass = $null

  if ([string]::IsNullOrWhiteSpace($Token)) { throw "Logon returned empty token." }

} else {
  Write-Log INFO "Using existing token (logon skipped)."
}

$capturedForCurl = New-Object System.Collections.Generic.List[object]
Write-Log INFO ("Starting {0} operation(s). dry_run={1} workers={2}" -f $ops.Count, [bool]$DryRun, $Workers)

# ---------------------------
# Summary counters
# ---------------------------
$summary = [ordered]@{
  TotalOps          = $ops.Count
  SkippedSameName   = 0
  MissingOld        = 0
  AddedNew          = 0
  UpdatedNew        = 0
  DeletedOld        = 0
  ConflictsSkipped  = 0
  DryRunActions     = 0
  Errors            = 0
}

# ---------------------------
# Main loop (sequential)
# ---------------------------
foreach ($op in $ops) {

  if ($SleepSec -gt 0) { Start-Sleep -Seconds $SleepSec }

  try {
    # 0) trivial skip: names are identical
    if ($op.OldGroup -eq $op.NewGroup) {
      $summary.SkippedSameName++
      Write-Log INFO ("SKIP_SAME_NAME: safe={0} old={1} new={2}" -f $op.SafeName, $op.OldGroup, $op.NewGroup)
      continue
    }

    # 1) Load OLD member to capture permissions + expiration.
    $oldMember = CyberArk-GetMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
    if ($null -eq $oldMember) {
      $summary.MissingOld++
      if ($AllowMissingOld) {
        Write-Log WARN ("MISSING_OLD (skipped): safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
        continue
      }

      # Preserving your current behavior: log and continue instead of throwing.
      Write-Log WARN ("MISSING_OLD (skipped): safe={0} member={1} (AllowMissingOld not set)" -f $op.SafeName, $op.OldGroup)
      continue
    }

    $permissions = $oldMember.permissions
    $expiration  = $oldMember.membershipExpirationDate

    # OPTION A: Always log what was captured (DEBUG only).
    if ($Loglevel -eq "DEBUG") {
      $permSummary = Format-PermissionsSummary -Permissions $permissions
      Write-Log DEBUG ("CAPTURED_PERMS: safe={0} old={1} perms=[{2}] exp=[{3}]" -f $op.SafeName, $op.OldGroup, $permSummary, $expiration)
      # If you prefer full JSON:
      # Write-Log DEBUG ("CAPTURED_PERMS_JSON: " + (Format-PermissionsJson -Permissions $permissions))
    }

    # 2) Check if NEW member already exists
    $newMember = CyberArk-GetMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.NewGroup

    # Keep curl capture (if enabled)
    if ($EmitCurlScript) {
      $capturedForCurl.Add([pscustomobject]@{
        SafeName = $op.SafeName
        OldGroup = $op.OldGroup
        NewGroup = $op.NewGroup
        Permissions = $permissions
        MembershipExpirationDate = $expiration
      }) | Out-Null
    }

    if ($null -ne $newMember) {

      # NEW exists: apply OnConflict policy
      switch ($OnConflict) {

        "skip" {
          $summary.ConflictsSkipped++
          Write-Log INFO ("NEW_ALREADY_EXISTS_SKIP: safe={0} member={1}" -f $op.SafeName, $op.NewGroup)
          continue
        }

        "fail" {
          throw "[row $($op.RowNum)] New member already exists: safe=$($op.SafeName) member=$($op.NewGroup)"
        }

        default {
          # update
          $permSummary = Format-PermissionsSummary -Permissions $permissions

          if ($DryRun) {
            $summary.DryRunActions++
            Write-Log INFO ("[DRY] Would UPDATE new member perms: safe={0} member={1} perms=[{2}] exp=[{3}]" -f $op.SafeName, $op.NewGroup, $permSummary, $expiration)
          } else {
            $body = @{ permissions = $permissions }
            if ($null -ne $expiration -and $expiration -ne "" -and $expiration -ne 0) {
              $body.membershipExpirationDate = $expiration
            }

            CyberArk-UpdateMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.NewGroup -body $body | Out-Null
            $summary.UpdatedNew++

            # OPTION A: Log applied perms (INFO) so it appears even without DEBUG.
            Write-Log INFO ("UPDATED_NEW: safe={0} member={1} perms=[{2}] exp=[{3}]" -f $op.SafeName, $op.NewGroup, $permSummary, $expiration)
          }

          # Optionally delete old
          if ($DeleteOld) {
            if ($DryRun) {
              $summary.DryRunActions++
              Write-Log INFO ("[DRY] Would DELETE old member: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
            } else {
              CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
              $summary.DeletedOld++
              Write-Log INFO ("DELETED_OLD: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
            }
          }

          continue
        }
      }
    }

    # 3) NEW does NOT exist: create it using exact same permissions + expiration
    $permSummary = Format-PermissionsSummary -Permissions $permissions

    if ($DryRun) {
      $summary.DryRunActions++
      Write-Log INFO ("[DRY] Would ADD new member: safe={0} member={1} perms=[{2}] exp=[{3}]" -f $op.SafeName, $op.NewGroup, $permSummary, $expiration)
    } else {
      $addBody = @{
        memberName  = $op.NewGroup
        searchIn    = $SearchIn
        permissions = $permissions
        MemberType  = $MemberType
      }

      if ($null -ne $expiration -and $expiration -ne "" -and $expiration -ne 0) {
        $addBody.membershipExpirationDate = $expiration
      }

      CyberArk-AddMember -baseUrl $PVWA -token $Token -safe $op.SafeName -body $addBody | Out-Null
      $summary.AddedNew++

      # OPTION A: Log applied perms for creation (INFO).
      Write-Log INFO ("ADDED_NEW: safe={0} member={1} perms=[{2}] exp=[{3}]" -f $op.SafeName, $op.NewGroup, $permSummary, $expiration)
    }

    # 4) Optional delete OLD after successful add
    if ($DeleteOld) {
      if ($DryRun) {
        $summary.DryRunActions++
        Write-Log INFO ("[DRY] Would DELETE old member: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
      } else {
        CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
        $summary.DeletedOld++
        Write-Log INFO ("DELETED_OLD: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
      }
    }

  } catch {
    $summary.Errors++
    Write-Log ERROR ("ROW_FAILED: env={0} safe={1} old={2} new={3} err={4}" -f $op.Environment, $op.SafeName, $op.OldGroup, $op.NewGroup, $_.Exception.Message)
    continue
  }
}

# Emit curl script (optional)
if ($EmitCurlScript) {
  $scriptText = New-CurlScript -baseUrl $PVWA -authType $AuthType -username ($(if ([string]::IsNullOrWhiteSpace($Username)) { "<username>" } else { $Username })) `
    -searchIn $SearchIn -memberType $MemberType -deleteOld ([bool]$DeleteOld) -captured $capturedForCurl

  Set-Content -Path $EmitCurlScript -Value $scriptText -Encoding UTF8
  Write-Log INFO "Wrote curl script: $EmitCurlScript"
}

# Runtime duration
$endTime  = Get-Date
$duration = New-TimeSpan -Start $Script:StartTime -End $endTime
$runtimeFormatted = "{0:hh\:mm\:ss\.fff}" -f $duration
Write-Log INFO ("Runtime duration: {0}" -f $runtimeFormatted)

# Logoff only if we performed logon in this run
if ($didLogonHere) {
  CyberArk-Logoff -baseUrl $PVWA -token $Token
}

# Final summary
Write-Log INFO "================ SUMMARY ================"
Write-Log INFO ("Total operations        : {0}" -f $summary.TotalOps)
Write-Log INFO ("Skipped (same name)     : {0}" -f $summary.SkippedSameName)
Write-Log INFO ("Missing old group       : {0}" -f $summary.MissingOld)
Write-Log INFO ("New members added       : {0}" -f $summary.AddedNew)
Write-Log INFO ("Existing members updated: {0}" -f $summary.UpdatedNew)
Write-Log INFO ("Old members deleted     : {0}" -f $summary.DeletedOld)
Write-Log INFO ("Conflicts skipped       : {0}" -f $summary.ConflictsSkipped)
Write-Log INFO ("Dry-run actions         : {0}" -f $summary.DryRunActions)
Write-Log INFO ("Errors                  : {0}" -f $summary.Errors)
Write-Log INFO "========================================="

exit 0

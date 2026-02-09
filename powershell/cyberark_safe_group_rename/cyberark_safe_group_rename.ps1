<#
.SYNOPSIS
  Batch "rename" CyberArk Safe AD group members by adding the new group with identical permissions
  (and membership expiration) and optionally deleting the old group.

.DESCRIPTION
  CyberArk PVWA Safe Members APIs do not provide a direct "rename member principal".
  This script implements a safe and auditable replacement workflow:

    WHY A "RENAME" IS NOT POSSIBLE DIRECTLY
    --------------------------------------
    Safe Members are principals (users/groups) assigned to a Safe with a permissions object.
    The PVWA Safe Members API does not offer an API call like "rename principal".
    Therefore, to "rename" a group member, you must:
      1) Read (GET) the old member to capture its permissions and expiration
      2) Create (POST) the new member with the same permissions/expiration (KEY FIX)
      3) Optionally delete (DELETE) the old member

    CONFLICT HANDLING (NEW ALREADY EXISTS)
    --------------------------------------
    If the "new group" already exists as a safe member, you can:
      - update : PUT the new member so its permissions match the old (default)
      - skip   : do nothing
      - fail   : stop with error

    ROLLBACK ARTIFACTS
    ------------------
    If -EmitRollback is enabled, the script will emit:
      - a CSV rollback plan listing rollback steps
      - a PowerShell rollback script that can undo the performed changes

    Rollback logic:
      - If we ADDED a new member -> rollback step is DELETE that new member
      - If we UPDATED an existing new member -> rollback step is RESTORE that new member to its prior state
      - If we DELETED the old member -> rollback step is ADD the old member back with captured perms/expiration

    DRY-RUN + ROLLBACK
    ------------------
    If -DryRun and -EmitRollback are both enabled, this script will still generate rollback artifacts,
    but they will be a "PLAN" (based on intended actions). No changes are made to PVWA.

  Input: CSV only.
    - Required columns (flexibly matched):
        Environment, SafeName, ExistingSecurityGroupName (old), NewSecurityGroupName (new)

.PARAMETER EmitRollback
  If set, writes rollback artifacts (CSV plan + PS1 script) for performed changes (or a plan if DryRun).

.PARAMETER RollbackCsvPath
  Path to write rollback plan CSV. If not provided, defaults next to InputPath.

.PARAMETER RollbackPs1Path
  Path to write rollback PowerShell script. If not provided, defaults next to InputPath.

.PARAMETER RollbackInsecureTls
  If set, rollback script defaults to insecure TLS behavior (not recommended).

.NOTES
  - This is a REST-only script (no psPAS / Connect-PASServer).
  - For safety/compatibility, this runs sequentially (token shared across operations).
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$InputPath,

  [string]$CsvDelimiter = ",",
  [ValidateSet("UTF8","UTF7","UTF32","Unicode","BigEndianUnicode","Default","OEM","ASCII")]
  [string]$CsvEncoding = "UTF8",
  [string]$Environment,

  [Parameter(Mandatory=$true)]
  [string]$PVWA,

  [ValidateSet("Cyberark","LDAP","Windows","RADIUS")]
  [string]$AuthType = "Cyberark",

  [string]$Username = $env:CYBERARK_USERNAME,
  [SecureString]$Password,
  [string]$Token = $env:CYBERARK_TOKEN,

  # AIM / CLIPasswordSDK (optional)
  [string]$CLIPasswordSDK_Path = "D:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe",
  [string]$AIM_AppID           = "P-CarkAutomationApp",
  [string]$AIM_Safe            = "PSNSCarkAutomation",
  [string]$AIM_Username        = "App-Cark-Prod-Auto-L",
  [string]$AIM_Object          = "Application-Prod-CyberArkVault-172.23.9.14-App-Cark-Prod-Auto-L",
  [string]$AIM_Folder          = "Root",

  [switch]$ConcurrentSession,

  [string]$SearchIn = "COSTCO",

  # IMPORTANT: PVWA commonly expects "Group"/"User" (case sensitive)
  [ValidateSet("Group","User")]
  [string]$MemberType = "Group",

  [ValidateSet("update","skip","fail")]
  [string]$OnConflict = "update",

  [switch]$DeleteOld,
  [switch]$AllowMissingOld,
  [switch]$DryRun,

  [string]$EmitCurlScript,

  # ---------------------------
  # Rollback artifacts (optional)
  # ---------------------------
  [switch]$EmitRollback,
  [string]$RollbackCsvPath,
  [string]$RollbackPs1Path,
  [switch]$RollbackInsecureTls,

  [ValidateSet("DEBUG","INFO","WARN","ERROR")]
  [string]$Loglevel = "INFO",
  [ValidateSet("stdout","file")]
  [string]$Logmode = "stdout",
  [string]$Logfile,

  [int]$Workers = 8,     # kept for compatibility; script runs sequentially (single shared token)
  [int]$TimeoutSec = 30,
  [int]$Retries = 3,
  [double]$RetryBackoffSec = 0.5,
  [string]$RetryStatus = "429,500,502,503,504",
  [double]$SleepSec = 0.0,

  [switch]$NoVerifyTls,

  [switch]$Info,
  [switch]$Version
)

$Script:ToolVersion = "0.2.1"

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
    # Fallback for older PowerShell: global callback (process-wide)
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

function Resolve-DefaultOutPath([string]$suffix) {
  $dir  = Split-Path -Parent $InputPath
  $base = [IO.Path]::GetFileNameWithoutExtension($InputPath)
  return (Join-Path $dir "$base.$suffix")
}

# Log-friendly summary (keeps audit readable; does not affect API payloads).
function Format-PermissionsSummary($permissions) {
  if ($null -eq $permissions) { return "<null>" }
  try {
    $pairs = @()
    foreach ($p in $permissions.PSObject.Properties) {
      $pairs += ("{0}={1}" -f $p.Name, $p.Value)
    }
    return ($pairs -join ", ")
  } catch {
    try { return ($permissions | ConvertTo-Json -Depth 10 -Compress) } catch { return "<unprintable>" }
  }
}

function Is-ValidExpiration($exp) {
  if ($null -eq $exp) { return $false }
  if ($exp -is [int] -or $exp -is [long]) { return ($exp -gt 0) }
  if ($exp -is [double]) { return ($exp -gt 0) }
  $s = [string]$exp
  if ([string]::IsNullOrWhiteSpace($s)) { return $false }
  if ($s -eq "0") { return $false }
  return $true
}

function Get-HttpErrorBody($_err) {
  try {
    $resp = $_err.Exception.Response
    if ($null -eq $resp) { return $null }
    $stream = $resp.GetResponseStream()
    if ($null -eq $stream) { return $null }
    $reader = New-Object System.IO.StreamReader($stream)
    return $reader.ReadToEnd()
  } catch {
    return $null
  }
}

# ---------------------------
# AIM / CLIPasswordSDK
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

  if ($text -match 'APPAP309E' -or $text -match 'untrusted shell') {
    throw ("AIM blocked the request (untrusted shell). Run from a trusted host (powershell.exe console) or whitelist. Raw: " + ($text.Trim()))
  }

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

      $errBody = Get-HttpErrorBody $_
      if ($errBody) {
        Write-Log DEBUG ("PVWA error body (status={0}): {1}" -f $statusCode, $errBody)
      }

      $retryable = $false
      if ($null -ne $statusCode -and $Script:RetryStatusSet.Contains($statusCode)) { $retryable = $true }

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
        Write-Log WARN ("HTTP {0} {1} failed (status={2}). Retry in {3:N2}s. Error: {4}" -f $Method, $Url, $statusCode, $sleep, $_.Exception.Message)
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
      memberType  = $memberType
    }
    if (Is-ValidExpiration $item.MembershipExpirationDate) {
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
# Rollback artifacts
# ---------------------------
$rollbackSteps = New-Object System.Collections.Generic.List[object]

function Add-RollbackStep {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("DELETE_NEW","ADD_OLD_BACK","RESTORE_NEW_PREVIOUS")]
    [string]$Action,
    [Parameter(Mandatory=$true)][string]$SafeName,
    [Parameter(Mandatory=$true)][string]$MemberName,
    $Permissions,
    $MembershipExpirationDate,
    [string]$Why
  )

  $rollbackSteps.Add([pscustomobject]@{
    Action = $Action
    SafeName = $SafeName
    MemberName = $MemberName
    Permissions = $Permissions
    MembershipExpirationDate = $MembershipExpirationDate
    Why = $Why
    CreatedAt = (Get-Date).ToString("o")
  }) | Out-Null
}

function Write-RollbackCsv {
  param([string]$Path, $Steps)
  $Steps | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function New-RollbackPs1 {
  param(
    [string]$SearchIn,
    [string]$MemberType,
    [bool]$IncludeInsecureTls,
    $Steps,

    # These come from the main script so the rollback script matches your environment.
    [string]$DefaultAuthType = "Cyberark",
    [bool]$DefaultConcurrentSession = $false,
    [string]$DefaultCLIPasswordSDK_Path = "D:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe",
    [string]$DefaultAIM_AppID = "P-CarkAutomationApp",
    [string]$DefaultAIM_Safe = "PSNSCarkAutomation",
    [string]$DefaultAIM_Object = "Application-Prod-CyberArkVault-172.23.9.14-App-Cark-Prod-Auto-L",
    [string]$DefaultAIM_Folder = "Root",
    [string]$DefaultAIM_Username = ""
  )

  # Materialize steps into a plain array (robust for List[object], arrays, pipelines, etc.)
  $stepsArr = @()
  foreach ($x in $Steps) { $stepsArr += $x }

  $lines = New-Object System.Collections.Generic.List[string]

  $lines.Add('<#')
  $lines.Add('Rollback script generated by cyberark_safe_group_rename (REST-only).')
  $lines.Add('Runs steps in reverse order of the original changes/plan.')
  $lines.Add('')
  $lines.Add('AUTH OPTIONS')
  $lines.Add('------------')
  $lines.Add('You can run with either:')
  $lines.Add('  A) -Token (preferred if you already have a PVWA token), OR')
  $lines.Add('  B) AIM + Logon (no Token provided) using CLIPasswordSDK to fetch password, then PVWA Logon.')
  $lines.Add('#>')
  $lines.Add('')

  $lines.Add('param(')
  $lines.Add('  [Parameter(Mandatory=$true)][string]$PVWA,')
  $lines.Add('  [string]$Token,')
  $lines.Add('  [ValidateSet("Cyberark","LDAP","Windows","RADIUS")][string]$AuthType = "' + $DefaultAuthType + '",')
  $lines.Add('  [string]$Username = "' + ($DefaultAIM_Username.Replace('"','`"')) + '",')
  $lines.Add('  [SecureString]$Password,')
  $lines.Add('  [switch]$ConcurrentSession,')
  $lines.Add('')
  $lines.Add('  # AIM / CLIPasswordSDK (optional)')
  $lines.Add('  [string]$CLIPasswordSDK_Path = "' + ($DefaultCLIPasswordSDK_Path.Replace('"','`"')) + '",')
  $lines.Add('  [string]$AIM_AppID  = "' + ($DefaultAIM_AppID.Replace('"','`"')) + '",')
  $lines.Add('  [string]$AIM_Safe   = "' + ($DefaultAIM_Safe.Replace('"','`"')) + '",')
  $lines.Add('  [string]$AIM_Object = "' + ($DefaultAIM_Object.Replace('"','`"')) + '",')
  $lines.Add('  [string]$AIM_Folder = "' + ($DefaultAIM_Folder.Replace('"','`"')) + '",')
  $lines.Add('')
  $lines.Add('  [switch]$NoVerifyTls')
  $lines.Add(')')
  $lines.Add('')

  $lines.Add('$PVWA = $PVWA.TrimEnd("/")')
  $lines.Add('')

  # TLS handling
  $lines.Add('$Script:IRM_SkipCert = $false')
  $lines.Add('try {')
  $lines.Add('  $irmCmd = Get-Command Invoke-RestMethod -ErrorAction Stop')
  $lines.Add('  if ($irmCmd.Parameters.ContainsKey("SkipCertificateCheck")) { $Script:IRM_SkipCert = $true }')
  $lines.Add('} catch {}')
  $lines.Add('if ($NoVerifyTls) {')
  $lines.Add('  if (-not $Script:IRM_SkipCert) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }')
  $lines.Add('}')
  $lines.Add('')

  # Utilities
  $lines.Add('function Escape-Url([string]$s){ [System.Uri]::EscapeDataString($s) }')
  $lines.Add('function Get-Headers([string]$t){ @{ "Content-Type"="application/json"; "Authorization"=$t } }')
  $lines.Add('function ConvertTo-PlainText([SecureString]$sec) {')
  $lines.Add('  if ($null -eq $sec) { return $null }')
  $lines.Add('  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)')
  $lines.Add('  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }')
  $lines.Add('  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }')
  $lines.Add('}')
  $lines.Add('')

  # IRM wrapper
  $lines.Add('function IRM([string]$m,[string]$u,$b){')
  $lines.Add('  $s=@{ Method=$m; Uri=$u; Headers=(Get-Headers $Token); ErrorAction="Stop" }')
  $lines.Add('  if($NoVerifyTls -and $Script:IRM_SkipCert){ $s["SkipCertificateCheck"]=$true }')
  $lines.Add('  if($null -ne $b){ $s["ContentType"]="application/json"; $s["Body"]=($b|ConvertTo-Json -Depth 30 -Compress) }')
  $lines.Add('  Invoke-RestMethod @s')
  $lines.Add('}')
  $lines.Add('')

  # AIM
  $lines.Add('function Get-AimCredential {')
  $lines.Add('  param([string]$CliPath,[string]$AppId,[string]$Safe,[string]$Object,[string]$Folder="Root")')
  $lines.Add('  if (-not (Test-Path -LiteralPath $CliPath)) { throw "AIM CLI not found: $CliPath" }')
  $lines.Add('  $query = "Safe=$Safe;Folder=$Folder;object=$Object"')
  $lines.Add('  $out = & "$CliPath" password /p "AppDescs.AppID=$AppId" /p "query=$query" /o PassProps.UserName,Password')
  $lines.Add('  if (-not $out) { throw "AIM returned empty output for query [$query] (AppId=$AppId)." }')
  $lines.Add('  $text = ($out | Out-String)')
  $lines.Add('  if ($text -match "APPAP309E" -or $text -match "untrusted shell") {')
  $lines.Add('    throw ("AIM blocked the request (untrusted shell). Run from a trusted powershell.exe console or whitelist. Raw: " + ($text.Trim()))')
  $lines.Add('  }')
  $lines.Add('  $line = ($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_.Contains(",") }) | Select-Object -First 1')
  $lines.Add('  if (-not $line) { throw "Unexpected AIM output format (no user,password line). Raw: $($text.Trim())" }')
  $lines.Add('  $parts = $line -split ",", 2')
  $lines.Add('  if ($parts.Count -lt 2) { throw "Unexpected AIM output format (cannot split user/password). Line: $line" }')
  $lines.Add('  $user = $parts[0].Trim()')
  $lines.Add('  $plain = $parts[1].Trim()')
  $lines.Add('  if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($plain)) { throw "AIM returned blank username/password. Line: $line" }')
  $lines.Add('  $sec = ConvertTo-SecureString $plain -AsPlainText -Force')
  $lines.Add('  return [pscredential]::new($user, $sec)')
  $lines.Add('}')
  $lines.Add('')

  # Logon/Logoff
  $lines.Add('function PVWA-Logon {')
  $lines.Add('  param([string]$BaseUrl,[string]$AuthType,[string]$User,[string]$Pass,[bool]$Concurrent)')
  $lines.Add('  $u = $BaseUrl.TrimEnd("/") + "/PasswordVault/API/auth/$AuthType/Logon/"')
  $lines.Add('  $body = @{ username=$User; password=$Pass }')
  $lines.Add('  if($Concurrent){ $body["concurrentSession"]=$true }')
  $lines.Add('  $s=@{ Method="POST"; Uri=$u; Headers=@{ "Content-Type"="application/json" }; ErrorAction="Stop" }')
  $lines.Add('  if($NoVerifyTls -and $Script:IRM_SkipCert){ $s["SkipCertificateCheck"]=$true }')
  $lines.Add('  $s["Body"]=($body|ConvertTo-Json -Depth 10 -Compress)')
  $lines.Add('  $s["ContentType"]="application/json"')
  $lines.Add('  $resp = Invoke-RestMethod @s')
  $lines.Add('  if ($resp -is [string]) { return $resp.Trim(''""'') }')
  $lines.Add('  return ([string]$resp).Trim(''""'')')
  $lines.Add('}')
  $lines.Add('function PVWA-Logoff {')
  $lines.Add('  param([string]$BaseUrl,[string]$Tok)')
  $lines.Add('  if([string]::IsNullOrWhiteSpace($Tok)){ return }')
  $lines.Add('  $u = $BaseUrl.TrimEnd("/") + "/PasswordVault/API/Auth/Logoff/"')
  $lines.Add('  try {')
  $lines.Add('    $s=@{ Method="POST"; Uri=$u; Headers=(Get-Headers $Tok); ErrorAction="Stop" }')
  $lines.Add('    if($NoVerifyTls -and $Script:IRM_SkipCert){ $s["SkipCertificateCheck"]=$true }')
  $lines.Add('    Invoke-RestMethod @s | Out-Null')
  $lines.Add('  } catch { }')
  $lines.Add('}')
  $lines.Add('')

  # Ensure Token
  $lines.Add('$didLogonHere = $false')
  $lines.Add('if ([string]::IsNullOrWhiteSpace($Token)) {')
  $lines.Add('  if ($null -eq $Password) {')
  $lines.Add('    $aimProvided = (-not [string]::IsNullOrWhiteSpace($CLIPasswordSDK_Path)) -and (-not [string]::IsNullOrWhiteSpace($AIM_AppID)) -and (-not [string]::IsNullOrWhiteSpace($AIM_Safe)) -and (-not [string]::IsNullOrWhiteSpace($AIM_Object))')
  $lines.Add('    if ($aimProvided) {')
  $lines.Add('      Write-Host "Fetching credential from AIM (CLIPasswordSDK) ..."')
  $lines.Add('      $cred = Get-AimCredential -CliPath $CLIPasswordSDK_Path -AppId $AIM_AppID -Safe $AIM_Safe -Object $AIM_Object -Folder $AIM_Folder')
  $lines.Add('      if ([string]::IsNullOrWhiteSpace($Username)) { $Username = $cred.UserName }')
  $lines.Add('      $Password = $cred.Password')
  $lines.Add('    }')
  $lines.Add('  }')
  $lines.Add('  if ([string]::IsNullOrWhiteSpace($Username)) { throw "Missing -Username and no -Token provided." }')
  $lines.Add('  if ($null -eq $Password) { $Password = Read-Host -Prompt "Password for $Username" -AsSecureString }')
  $lines.Add('  $plainPass = ConvertTo-PlainText $Password')
  $lines.Add('  Write-Host "Logging in to PVWA ($AuthType) ..."')
  $lines.Add('  $Token = PVWA-Logon -BaseUrl $PVWA -AuthType $AuthType -User $Username -Pass $plainPass -Concurrent ([bool]$ConcurrentSession)')
  $lines.Add('  $plainPass = $null')
  $lines.Add('  if ([string]::IsNullOrWhiteSpace($Token)) { throw "Logon returned empty token." }')
  $lines.Add('  $didLogonHere = $true')
  $lines.Add('}')
  $lines.Add('')

  $lines.Add('try {')
  $lines.Add('')

  # Rollback operations
  $lines.Add('function AddMember($safe,$body){')
  $lines.Add('  $u="$PVWA/PasswordVault/API/Safes/$(Escape-Url $safe)/Members/"')
  $lines.Add('  IRM "POST" $u $body | Out-Null')
  $lines.Add('}')
  $lines.Add('function UpdateMember($safe,$member,$body){')
  $lines.Add('  $u="$PVWA/PasswordVault/API/Safes/$(Escape-Url $safe)/Members/$(Escape-Url $member)/"')
  $lines.Add('  IRM "PUT" $u $body | Out-Null')
  $lines.Add('}')
  $lines.Add('function DeleteMember($safe,$member){')
  $lines.Add('  $u="$PVWA/PasswordVault/API/Safes/$(Escape-Url $safe)/Members/$(Escape-Url $member)/"')
  $lines.Add('  try{ IRM "DELETE" $u $null | Out-Null } catch { }')
  $lines.Add('}')
  $lines.Add('')

  if ($IncludeInsecureTls) {
    $lines.Add('if(-not $PSBoundParameters.ContainsKey("NoVerifyTls")){ $NoVerifyTls = $true }')
    $lines.Add('')
  }

  # Emit steps in reverse order (no Sort-Object)
  for ($i = $stepsArr.Count - 1; $i -ge 0; $i--) {
    $s = $stepsArr[$i]

    $safe   = [string]$s.SafeName
    $mem    = [string]$s.MemberName
    $action = [string]$s.Action

    if ($action -eq "DELETE_NEW") {
      $lines.Add("Write-Host ""ROLLBACK: DELETE member '$mem' from safe '$safe'""")
      $lines.Add("DeleteMember '" + $safe.Replace("'","''") + "' '" + $mem.Replace("'","''") + "'")
      $lines.Add("")
      continue
    }

    if ($action -eq "ADD_OLD_BACK") {
      $body = @{
        memberName  = $mem
        searchIn    = $SearchIn
        permissions = $s.Permissions
        memberType  = $MemberType
      }
      if ($null -ne $s.MembershipExpirationDate -and $s.MembershipExpirationDate -ne "" -and $s.MembershipExpirationDate -ne 0) {
        $body.membershipExpirationDate = $s.MembershipExpirationDate
      }

      $json = ($body | ConvertTo-Json -Depth 30 -Compress).Replace("'","''")

      $lines.Add("Write-Host ""ROLLBACK: ADD member '$mem' back to safe '$safe'""")
      $lines.Add('$bodyJson = ''' + $json + '''')
      $lines.Add('$body = $bodyJson | ConvertFrom-Json')
      $lines.Add("AddMember '" + $safe.Replace("'","''") + "' $body")
      $lines.Add("")
      continue
    }

    if ($action -eq "RESTORE_NEW_PREVIOUS") {
      $body = @{ permissions = $s.Permissions }
      if ($null -ne $s.MembershipExpirationDate -and $s.MembershipExpirationDate -ne "" -and $s.MembershipExpirationDate -ne 0) {
        $body.membershipExpirationDate = $s.MembershipExpirationDate
      }

      $json = ($body | ConvertTo-Json -Depth 30 -Compress).Replace("'","''")

      $lines.Add("Write-Host ""ROLLBACK: RESTORE member '$mem' (permissions/expiration) in safe '$safe'""")
      $lines.Add('$bodyJson = ''' + $json + '''')
      $lines.Add('$body = $bodyJson | ConvertFrom-Json')
      $lines.Add("UpdateMember '" + $safe.Replace("'","''") + "' '" + $mem.Replace("'","''") + "' $body")
      $lines.Add("")
      continue
    }

    $lines.Add("Write-Host ""ROLLBACK: SKIP unknown action '$action' for member '$mem' safe '$safe'""")
    $lines.Add("")
  }

  $lines.Add('} finally {')
  $lines.Add('  if($didLogonHere){ PVWA-Logoff -BaseUrl $PVWA -Tok $Token }')
  $lines.Add('}')
  $lines.Add('')

  return ($lines -join "`n")
}

# ---------------------------
# Main execution
# ---------------------------
$PVWA = $PVWA.TrimEnd("/")
$didLogonHere = $false

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

      if ([string]::IsNullOrWhiteSpace($Username)) {
        $Username = $cred.UserName
      } elseif ($Username -ne $cred.UserName) {
        Write-Log WARN ("AIM returned username '{0}' but -Username is '{1}'. Using -Username." -f $cred.UserName, $Username)
      }

      $Password = $cred.Password
      Write-Log INFO ("AIM credential retrieved for user '{0}'." -f $cred.UserName)
    }
  }

  if ([string]::IsNullOrWhiteSpace($Username)) { throw "Missing Username (or set CYBERARK_USERNAME), or provide -Token, or provide AIM parameters." }
  if ($null -eq $Password) { $Password = Read-Host -Prompt "Password for $Username" -AsSecureString }

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
Write-Log INFO ("Starting {0} operation(s). dry_run={1} workers={2} (sequential token)" -f $ops.Count, [bool]$DryRun, $Workers)

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

foreach ($op in $ops) {

  try {
    if ($SleepSec -gt 0) { Start-Sleep -Seconds $SleepSec }

    if ($op.OldGroup -eq $op.NewGroup) {
      $summary.SkippedSameName++
      Write-Log INFO ("SKIP_SAME_NAME: env={0} safe={1} old={2} new={3}" -f $op.Environment, $op.SafeName, $op.OldGroup, $op.NewGroup)
      continue
    }

    # 1) GET old member
    $oldMember = CyberArk-GetMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
    if ($null -eq $oldMember) {
      $summary.MissingOld++
      if ($AllowMissingOld) {
        Write-Log WARN ("MISSING_OLD: env={0} safe={1} member={2} (skipped)" -f $op.Environment, $op.SafeName, $op.OldGroup)
        continue
      }
      Write-Log WARN ("MISSING_OLD: env={0} safe={1} member={2} (skipped; non-fatal behavior)" -f $op.Environment, $op.SafeName, $op.OldGroup)
      continue
    }

    # IMPORTANT: Keep PVWA permission object as-is (do NOT rebuild a hashtable)
    $permissions = $oldMember.permissions
    $expiration  = $oldMember.membershipExpirationDate

    if ($Loglevel -eq "DEBUG") {
      Write-Log DEBUG ("Captured OLD permissions: env={0} safe={1} old={2} -> {3}" -f $op.Environment, $op.SafeName, $op.OldGroup, (Format-PermissionsSummary $permissions))
      Write-Log DEBUG ("Captured OLD expiration : env={0} safe={1} old={2} -> {3}" -f $op.Environment, $op.SafeName, $op.OldGroup, $expiration)
    }

    # 2) GET new member (if exists)
    $newMember = CyberArk-GetMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.NewGroup

    # capture "new before" for rollback if we update it (or for dry-run plan)
    $newBeforePermissions = $null
    $newBeforeExpiration  = $null
    if ($null -ne $newMember) {
      $newBeforePermissions = $newMember.permissions
      $newBeforeExpiration  = $newMember.membershipExpirationDate
    }

    # capture for curl emission
    $capture = [pscustomobject]@{
      SafeName = $op.SafeName
      OldGroup = $op.OldGroup
      NewGroup = $op.NewGroup
      Permissions = $permissions
      MembershipExpirationDate = $expiration
    }
    if ($EmitCurlScript) { $capturedForCurl.Add($capture) | Out-Null }

    # new exists -> OnConflict
    if ($null -ne $newMember) {
      switch ($OnConflict) {
        "skip" {
          $summary.ConflictsSkipped++
          Write-Log INFO ("NEW_ALREADY_EXISTS_SKIP: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.NewGroup)

          # DryRun rollback plan: none (because skip does nothing)
          continue
        }
        "fail" {
          throw "[row $($op.RowNum)] New member already exists: safe=$($op.SafeName) member=$($op.NewGroup)"
        }
        default {
          # update (default)
          if ($DryRun) {
            $summary.DryRunActions++
            Write-Log INFO ("[DRY] Would UPDATE new member perms: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.NewGroup)

            if ($EmitRollback) {
              Add-RollbackStep -Action "RESTORE_NEW_PREVIOUS" -SafeName $op.SafeName -MemberName $op.NewGroup `
                -Permissions $newBeforePermissions -MembershipExpirationDate $newBeforeExpiration -Why "PLAN rollback for UPDATED_NEW"
            }
          } else {
            $body = @{ permissions = $permissions }
            if (Is-ValidExpiration $expiration) { $body.membershipExpirationDate = $expiration }

            Write-Log DEBUG ("UPDATE payload: " + ($body | ConvertTo-Json -Depth 30 -Compress))
            CyberArk-UpdateMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.NewGroup -body $body | Out-Null

            $summary.UpdatedNew++
            Write-Log INFO ("UPDATED_NEW: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.NewGroup)

            if ($EmitRollback) {
              Add-RollbackStep -Action "RESTORE_NEW_PREVIOUS" -SafeName $op.SafeName -MemberName $op.NewGroup `
                -Permissions $newBeforePermissions -MembershipExpirationDate $newBeforeExpiration -Why "Rollback for UPDATED_NEW"
            }
          }

          if ($DeleteOld) {
            if ($DryRun) {
              $summary.DryRunActions++
              Write-Log INFO ("[DRY] Would DELETE old member: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.OldGroup)

              if ($EmitRollback) {
                Add-RollbackStep -Action "ADD_OLD_BACK" -SafeName $op.SafeName -MemberName $op.OldGroup `
                  -Permissions $permissions -MembershipExpirationDate $expiration -Why "PLAN rollback for DELETED_OLD"
              }
            } else {
              CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
              $summary.DeletedOld++
              Write-Log INFO ("DELETED_OLD: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.OldGroup)

              if ($EmitRollback) {
                Add-RollbackStep -Action "ADD_OLD_BACK" -SafeName $op.SafeName -MemberName $op.OldGroup `
                  -Permissions $permissions -MembershipExpirationDate $expiration -Why "Rollback for DELETED_OLD"
              }
            }
          }

          continue
        }
      }
    }

    # 3) ADD new member with identical perms/expiration (KEY FIX)
    $addBody = @{
      memberName  = $op.NewGroup
      searchIn    = $SearchIn
      permissions = $permissions
      memberType  = $MemberType
    }
    if (Is-ValidExpiration $expiration) {
      $addBody.membershipExpirationDate = $expiration
    }

    if ($DryRun) {
      $summary.DryRunActions++
      Write-Log DEBUG ("ADD payload (DRY): " + ($addBody | ConvertTo-Json -Depth 30 -Compress))
      Write-Log INFO ("[DRY] Would ADD new member: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.NewGroup)

      if ($EmitRollback) {
        Add-RollbackStep -Action "DELETE_NEW" -SafeName $op.SafeName -MemberName $op.NewGroup `
          -Permissions $null -MembershipExpirationDate $null -Why "PLAN rollback for ADDED_NEW"
      }
    } else {
      Write-Log DEBUG ("ADD payload: " + ($addBody | ConvertTo-Json -Depth 30 -Compress))
      CyberArk-AddMember -baseUrl $PVWA -token $Token -safe $op.SafeName -body $addBody | Out-Null

      $summary.AddedNew++
      Write-Log INFO ("ADDED_NEW: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.NewGroup)

      if ($EmitRollback) {
        Add-RollbackStep -Action "DELETE_NEW" -SafeName $op.SafeName -MemberName $op.NewGroup `
          -Permissions $null -MembershipExpirationDate $null -Why "Rollback for ADDED_NEW"
      }
    }

    # 4) DELETE old (optional)
    if ($DeleteOld) {
      if ($DryRun) {
        $summary.DryRunActions++
        Write-Log INFO ("[DRY] Would DELETE old member: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.OldGroup)

        if ($EmitRollback) {
          Add-RollbackStep -Action "ADD_OLD_BACK" -SafeName $op.SafeName -MemberName $op.OldGroup `
            -Permissions $permissions -MembershipExpirationDate $expiration -Why "PLAN rollback for DELETED_OLD"
        }
      } else {
        CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
        $summary.DeletedOld++
        Write-Log INFO ("DELETED_OLD: env={0} safe={1} member={2}" -f $op.Environment, $op.SafeName, $op.OldGroup)

        if ($EmitRollback) {
          Add-RollbackStep -Action "ADD_OLD_BACK" -SafeName $op.SafeName -MemberName $op.OldGroup `
            -Permissions $permissions -MembershipExpirationDate $expiration -Why "Rollback for DELETED_OLD"
        }
      }
    }

  } catch {
    $summary.Errors++

    $errBody = Get-HttpErrorBody $_
    if ($errBody) {
      Write-Log ERROR ("ERROR: env={0} safe={1} old={2} new={3} row={4} :: {5} :: PVWA_BODY={6}" -f `
        $op.Environment, $op.SafeName, $op.OldGroup, $op.NewGroup, $op.RowNum, $_.Exception.Message, ($errBody -replace "\r?\n"," "))
    } else {
      Write-Log ERROR ("ERROR: env={0} safe={1} old={2} new={3} row={4} :: {5}" -f `
        $op.Environment, $op.SafeName, $op.OldGroup, $op.NewGroup, $op.RowNum, $_.Exception.Message)
    }
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

# Emit rollback artifacts (optional)
if ($EmitRollback) {
  if ($rollbackSteps.Count -eq 0) {
    if ($DryRun) {
      Write-Log INFO "EmitRollback requested + DryRun enabled, but no actionable steps were produced (nothing planned)."
    } else {
      Write-Log INFO "EmitRollback requested, but no changes were performed. No rollback artifacts written."
    }
  } else {
    if ([string]::IsNullOrWhiteSpace($RollbackCsvPath)) { $RollbackCsvPath = Resolve-DefaultOutPath "rollback.csv" }
    if ([string]::IsNullOrWhiteSpace($RollbackPs1Path)) { $RollbackPs1Path = Resolve-DefaultOutPath "rollback.ps1" }

    Write-RollbackCsv -Path $RollbackCsvPath -Steps $rollbackSteps
    if ($DryRun) {
      Write-Log INFO "Wrote rollback plan (CSV) [DRY PLAN]: $RollbackCsvPath"
    } else {
      Write-Log INFO "Wrote rollback plan (CSV): $RollbackCsvPath"
    }

    $rb = New-RollbackPs1 -SearchIn $SearchIn -MemberType $MemberType -IncludeInsecureTls ([bool]$RollbackInsecureTls) -Steps $rollbackSteps
    Set-Content -Path $RollbackPs1Path -Value $rb -Encoding UTF8
    if ($DryRun) {
      Write-Log INFO "Wrote rollback script (PS1) [DRY PLAN]: $RollbackPs1Path"
    } else {
      Write-Log INFO "Wrote rollback script (PS1): $RollbackPs1Path"
    }
  }
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

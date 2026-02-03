<#
.SYNOPSIS
  Batch "rename" CyberArk Safe AD group members by adding the new group with identical permissions
  (and membership expiration) and optionally deleting the old group.

.DESCRIPTION
  CyberArk PVWA Safe Members APIs do not provide a direct "rename member principal".
  This script implements a safe and auditable replacement workflow:
    1) GET old safe member (group) to capture permissions + membershipExpirationDate
    2) POST new safe member with same permissions + expiration
       - If new already exists: update/skip/fail (OnConflict)
    3) DELETE old safe member (optional)

  Input: XLSX (preferred) or CSV.
    - XLSX: uses ImportExcel module if available; otherwise (Windows only) uses Excel COM automation if Excel is installed.
    - CSV: must contain the required headers.

.PARAMETER InputPath
  Path to XLSX or CSV containing operations.

.PARAMETER SheetList
  Worksheet name for XLSX. Default: "List"

.PARAMETER Environment
  Optional filter for Environment column.

.PARAMETER PVWA
  PVWA base URL (e.g., https://pvwa.company.com)

.PARAMETER AuthType
  One of: Cyberark, LDAP, Windows, RADIUS. Default: Cyberark

.PARAMETER Username
  Username for logon (if not using Token).

.PARAMETER Password
  Password for logon (if not using Token). If not provided, you will be prompted.

.PARAMETER Token
  Existing PVWA token. If provided, logon is skipped.

.PARAMETER ConcurrentSession
  Requests concurrentSession during logon (if supported).

.PARAMETER SearchIn
  Value for "searchIn" when adding member (commonly "Vault" or your directory source). Default: Vault

.PARAMETER MemberType
  Member type for add member. Usually "Group". Default: Group

.PARAMETER OnConflict
  What to do if NEW member already exists: update | skip | fail. Default: update

.PARAMETER DeleteOld
  If set, deletes the old member after add/update.

.PARAMETER AllowMissingOld
  If set, missing old member becomes a non-fatal skip.

.PARAMETER DryRun
  If set, performs no changes (logs intended actions).

.PARAMETER EmitCurlScript
  If set, writes a bash script with curl commands using fetched permissions/expiration (audit-friendly).

.PARAMETER Loglevel
  DEBUG, INFO, WARN, ERROR. Default: INFO

.PARAMETER Logmode
  stdout (default) or file

.PARAMETER Logfile
  Log file path (required when Logmode=file)

.PARAMETER Workers
  Concurrency level (PowerShell 7+). Default: 8

.PARAMETER TimeoutSec
  HTTP timeout seconds. Default: 30

.PARAMETER Retries
  HTTP retry count on retryable codes/timeouts. Default: 3

.PARAMETER RetryBackoffSec
  Base backoff seconds for retries (exponential). Default: 0.5

.PARAMETER RetryStatus
  Comma-separated HTTP status codes to retry. Default: 429,500,502,503,504

.PARAMETER SleepSec
  Optional delay before each operation (rate-limit friendly). Default: 0

.PARAMETER NoVerifyTls
  If set, skips TLS certificate verification (not recommended).

.PARAMETER Info
  Prints a summary of the spreadsheet operations and exits.

.PARAMETER Version
  Prints version and exits.

.EXAMPLE
  ./cyberark_safe_group_rename.ps1 -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" -PVWA https://pvwa.company.com -Info

.EXAMPLE
  ./cyberark_safe_group_rename.ps1 -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" -Environment PROD -PVWA https://pvwa.company.com `
    -AuthType LDAP -Username svc_pvwa_api -DryRun -Loglevel DEBUG

.EXAMPLE
  ./cyberark_safe_group_rename.ps1 -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" -Environment PROD -PVWA https://pvwa.company.com `
    -AuthType LDAP -Username svc_pvwa_api -DeleteOld -Workers 16
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$InputPath,

  [string]$SheetList = "List",
  [string]$Environment,

  [Parameter(Mandatory=$true)]
  [string]$PVWA,

  [ValidateSet("Cyberark","LDAP","Windows","RADIUS")]
  [string]$AuthType = "Cyberark",

  [string]$Username = $env:CYBERARK_USERNAME,
  [SecureString]$Password,
  [string]$Token = $env:CYBERARK_TOKEN,
  [switch]$ConcurrentSession,

  [string]$SearchIn = "Vault",
  [ValidateSet("Group","User")]
  [string]$MemberType = "Group",

  [ValidateSet("update","skip","fail")]
  [string]$OnConflict = "update",

  [switch]$DeleteOld,
  [switch]$AllowMissingOld,
  [switch]$DryRun,

  [string]$EmitCurlScript,

  [ValidateSet("DEBUG","INFO","WARN","ERROR")]
  [string]$Loglevel = "INFO",
  [ValidateSet("stdout","file")]
  [string]$Logmode = "stdout",
  [string]$Logfile,

  [int]$Workers = 8,
  [int]$TimeoutSec = 30,
  [int]$Retries = 3,
  [double]$RetryBackoffSec = 0.5,
  [string]$RetryStatus = "429,500,502,503,504",
  [double]$SleepSec = 0.0,

  [switch]$NoVerifyTls,

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
  if ($Mode -eq "file" -and [string]::IsNullOrWhiteSpace($File)) { throw "--Logfile is required when --Logmode=file" }

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
function Escape-Url([string]$s) {
  return [System.Uri]::EscapeDataString($s)
}

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
# Read input (XLSX / CSV)
# ---------------------------
function Normalize-Header([string]$h) {
  if ($null -eq $h) { return "" }
  $s = $h.Trim().ToLowerInvariant()
  $s = ($s -replace "\s+","")
  $s = $s.Replace("_","").Replace("-","")
  return $s
}

function Read-OpsFromCsv([string]$path) {
  $rows = Import-Csv -Path $path
  return $rows
}

function Read-OpsFromXlsx([string]$path, [string]$sheet) {
  # Try ImportExcel first
  $importExcel = Get-Module -ListAvailable -Name ImportExcel | Select-Object -First 1
  if ($importExcel) {
    Import-Module ImportExcel -ErrorAction Stop | Out-Null
    return Import-Excel -Path $path -WorksheetName $sheet
  }

  # Fallback: Excel COM automation (Windows + Excel installed)
  if ($IsWindows) {
    try {
      $excel = New-Object -ComObject Excel.Application
      $excel.Visible = $false
      $wb = $excel.Workbooks.Open($path)
      $ws = $wb.Worksheets.Item($sheet)
      $used = $ws.UsedRange
      $data = $used.Value2
      # data is 2D array [row,col], 1-based
      $rowCount = $data.GetLength(0)
      $colCount = $data.GetLength(1)

      # headers in row 1
      $headers = @()
      for ($c=1; $c -le $colCount; $c++) {
        $headers += [string]$data[1,$c]
      }

      $objs = New-Object System.Collections.Generic.List[object]
      for ($r=2; $r -le $rowCount; $r++) {
        $o = [ordered]@{}
        for ($c=1; $c -le $colCount; $c++) {
          $o[$headers[$c-1]] = $data[$r,$c]
        }
        $objs.Add([pscustomobject]$o)
      }
      $wb.Close($false)
      $excel.Quit()
      [Runtime.InteropServices.Marshal]::ReleaseComObject($ws) | Out-Null
      [Runtime.InteropServices.Marshal]::ReleaseComObject($wb) | Out-Null
      [Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
      return $objs
    } catch {
      throw "XLSX read failed. Install ImportExcel module (recommended): Install-Module ImportExcel -Scope CurrentUser"
    }
  }

  throw "XLSX read requires ImportExcel (recommended) or Windows+Excel COM. On Linux/macOS, install ImportExcel or export to CSV."
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

function Read-RenameOps([string]$path, [string]$sheet, [string]$envFilter) {
  $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()

  $rows =
    if ($ext -eq ".csv") { Read-OpsFromCsv $path }
    elseif ($ext -eq ".xlsx" -or $ext -eq ".xlsm" -or $ext -eq ".xls") { Read-OpsFromXlsx $path $sheet }
    else { throw "Unsupported input extension: $ext (use .xlsx or .csv)" }

  if (-not $rows) { return @() }

  # Determine headers from first object
  $headers = @($rows[0].PSObject.Properties.Name)

  $colEnv  = Resolve-Column $headers @("Environment","Env")
  $colSafe = Resolve-Column $headers @("SafeName","Safe","SafeUrlId")
  $colOld  = Resolve-Column $headers @("ExistingSecurityGroupName","ExistingGroupName","OldGroup","Existing","CurrentGroup")
  $colNew  = Resolve-Column $headers @("NewSecurityGroupName","NewGroupName","NewGroup","New","TargetGroup")

  if (-not $colEnv -or -not $colSafe -or -not $colOld -or -not $colNew) {
    throw "Missing required columns. Need: Environment, SafeName, Existing group, New group (headers are matched flexibly)."
  }

  $ops = New-Object System.Collections.Generic.List[object]
  $rowNum = 1
  foreach ($r in $rows) {
    $rowNum++

    $env = [string]$r.$colEnv
    $safe = [string]$r.$colSafe
    $oldg = [string]$r.$colOld
    $newg = [string]$r.$colNew

    if ([string]::IsNullOrWhiteSpace($env) -or [string]::IsNullOrWhiteSpace($safe) -or
        [string]::IsNullOrWhiteSpace($oldg) -or [string]::IsNullOrWhiteSpace($newg)) {
      continue
    }
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

  $collisions = $ops |
    Group-Object -Property @{Expression={ "$($_.Environment)||$($_.SafeName)||$($_.NewGroup)" }} |
    Where-Object { $_.Count -gt 1 }

  if ($collisions) {
    Write-Output ""
    Write-Output "WARNING: multiple old groups map to same new group inside same (env,safe):"
    foreach ($g in $collisions | Select-Object -First 50) {
      $parts = $g.Name.Split("||")
      $env = $parts[0]; $safe = $parts[1]; $newg = $parts[2]
      $olds = ($g.Group | Select-Object -ExpandProperty OldGroup -Unique | Sort-Object) -join ", "
      Write-Output "  - env=$env safe=$safe new=$newg <- olds: $olds"
    }
  }
}

$ops = Read-RenameOps -path $InputPath -sheet $SheetList -envFilter $Environment
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

      if ($NoVerifyTls -and $Script:IRM_SkipCert) {
        $splat["SkipCertificateCheck"] = $true
      }

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
        if ($resp -and $resp.StatusCode) {
          $statusCode = [int]$resp.StatusCode
        }
      } catch {}

      $retryable = $false
      if ($null -ne $statusCode -and $Script:RetryStatusSet.Contains($statusCode)) { $retryable = $true }
      if ($_.Exception -is [System.Net.Http.HttpRequestException]) { $retryable = $true }

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
  if (-not [string]::IsNullOrWhiteSpace($token)) {
    $h["Authorization"] = $token
  }
  return $h
}

function CyberArk-Logon([string]$baseUrl, [string]$authType, [string]$user, [string]$pass, [bool]$concurrent) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/auth/$authType/Logon/"
  $body = @{
    username = $user
    password = $pass
  }
  if ($concurrent) { $body["concurrentSession"] = $true }
  $resp = Invoke-CyberArk -Method POST -Url $url -Headers (Get-Headers "") -Body $body
  # Token is typically returned as a JSON string; Invoke-RestMethod may already parse it, but handle both.
  if ($resp -is [string]) { return $resp.Trim('"') }
  return ([string]$resp).Trim('"')
}

function CyberArk-Logoff([string]$baseUrl, [string]$token) {
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Auth/Logoff/"
  try {
    Invoke-CyberArk -Method POST -Url $url -Headers (Get-Headers $token) -Body $null | Out-Null
  } catch {
    Write-Log WARN "Logoff failed: $($_.Exception.Message)"
  }
}

function CyberArk-GetMember([string]$baseUrl, [string]$token, [string]$safe, [string]$member) {
  $safeQ = Escape-Url $safe
  $memQ  = Escape-Url $member
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$safeQ/Members/$memQ/"
  try {
    return Invoke-CyberArk -Method GET -Url $url -Headers (Get-Headers $token) -Body $null
  } catch {
    # Treat 404 as missing
    $statusCode = $null
    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
    if ($statusCode -eq 404) { return $null }
    throw
  }
}

function CyberArk-AddMember([string]$baseUrl, [string]$token, [string]$safe, [hashtable]$body) {
  $safeQ = Escape-Url $safe
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$safeQ/Members/"
  return Invoke-CyberArk -Method POST -Url $url -Headers (Get-Headers $token) -Body $body
}

function CyberArk-UpdateMember([string]$baseUrl, [string]$token, [string]$safe, [string]$member, [hashtable]$body) {
  $safeQ = Escape-Url $safe
  $memQ  = Escape-Url $member
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$safeQ/Members/$memQ/"
  return Invoke-CyberArk -Method PUT -Url $url -Headers (Get-Headers $token) -Body $body
}

function CyberArk-DeleteMember([string]$baseUrl, [string]$token, [string]$safe, [string]$member) {
  $safeQ = Escape-Url $safe
  $memQ  = Escape-Url $member
  $url = ($baseUrl.TrimEnd("/")) + "/PasswordVault/API/Safes/$safeQ/Members/$memQ/"
  try {
    Invoke-CyberArk -Method DELETE -Url $url -Headers (Get-Headers $token) -Body $null | Out-Null
  } catch {
    $statusCode = $null
    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
    if ($statusCode -eq 404) { return }
    throw
  }
}

# ---------------------------
# Curl script emission (bash)
# ---------------------------
function New-CurlScript([string]$baseUrl,[string]$authType,[string]$username,[string]$searchIn,[string]$memberType,[bool]$deleteOld,$captured) {
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("#!/usr/bin/env bash")
  $lines.Add("set -euo pipefail")
  $lines.Add("")
  $lines.Add("PVWA_BASE=""$($baseUrl.TrimEnd('/'))""")
  $lines.Add('TOKEN="${TOKEN:-}"')
  $lines.Add("")
  $lines.Add('if [[ -z "$TOKEN" ]]; then')
  $lines.Add('  echo "TOKEN is empty. Export TOKEN first, or login manually and export it." >&2')
  $lines.Add('  echo "Example:" >&2')
  $lines.Add("  echo ""  curl -sk -X POST \\`"$PVWA_BASE/PasswordVault/API/auth/$authType/Logon/\\`" \\\\"" >&2")
  $lines.Add('  echo "    -H \"Content-Type: application/json\" \\" >&2')
  $lines.Add("  echo ""    -d '{\""username\"":\""$username\""\",\""password\"":\""***\"" }'"" >&2")
  $lines.Add("  exit 2")
  $lines.Add("fi")
  $lines.Add("")

  foreach ($item in $captured) {
    $safe = $item.SafeName
    $oldg = $item.OldGroup
    $newg = $item.NewGroup
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
    $payloadJson = $payloadJson -replace "'", "'""'""'"

    $lines.Add("echo ""==> $safe: $oldg -> $newg""")
    $lines.Add("curl -sS -k -X POST ""`"$PVWA_BASE/PasswordVault/API/Safes/$safeQ/Members/`""" -H ""Content-Type: application/json"" -H ""Authorization: `${TOKEN}"" -d '$payloadJson'")
    if ($deleteOld) {
      $lines.Add("curl -sS -k -X DELETE ""`"$PVWA_BASE/PasswordVault/API/Safes/$safeQ/Members/$oldQ/`""" -H ""Authorization: `${TOKEN}""")
    }
    $lines.Add("")
  }

  return ($lines -join "`n")
}

# ---------------------------
# Main execution
# ---------------------------
$PVWA = $PVWA.TrimEnd("/")

if ([string]::IsNullOrWhiteSpace($Token)) {
  if ([string]::IsNullOrWhiteSpace($Username)) { throw "Missing Username (or set CYBERARK_USERNAME), or provide -Token." }
  if ($null -eq $Password) {
    $Password = Read-Host -Prompt "Password for $Username" -AsSecureString
  }
  $plainPass = ConvertTo-PlainText $Password
  Write-Log INFO "Logging in to PVWA ($AuthType) ..."
  $Token = CyberArk-Logon -baseUrl $PVWA -authType $AuthType -user $Username -pass $plainPass -concurrent ([bool]$ConcurrentSession)
  if ([string]::IsNullOrWhiteSpace($Token)) { throw "Logon returned empty token." }
} else {
  Write-Log INFO "Using existing token (logon skipped)."
}

$capturedForCurl = New-Object System.Collections.Generic.List[object]

function Invoke-OneOp {
  param($op)

  if ($SleepSec -gt 0) { Start-Sleep -Seconds $SleepSec }

  if ($op.OldGroup -eq $op.NewGroup) {
    return [pscustomobject]@{ Op=$op; Status="SKIP_SAME_NAME"; Capture=$null }
  }

  $oldMember = CyberArk-GetMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
  if ($null -eq $oldMember) {
    if ($AllowMissingOld) {
      return [pscustomobject]@{ Op=$op; Status="MISSING_OLD"; Capture=$null }
    }
    throw "[row $($op.RowNum)] Old member not found: safe=$($op.SafeName) member=$($op.OldGroup)"
  }

  $permissions = $oldMember.permissions
  $expiration  = $oldMember.membershipExpirationDate

  $newMember = CyberArk-GetMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.NewGroup

  $capture = [pscustomobject]@{
    SafeName = $op.SafeName
    OldGroup = $op.OldGroup
    NewGroup = $op.NewGroup
    Permissions = $permissions
    MembershipExpirationDate = $expiration
  }

  if ($EmitCurlScript) { $capturedForCurl.Add($capture) | Out-Null }

  if ($null -ne $newMember) {
    switch ($OnConflict) {
      "skip" { return [pscustomobject]@{ Op=$op; Status="NEW_ALREADY_EXISTS_SKIP"; Capture=$capture } }
      "fail" { throw "[row $($op.RowNum)] New member already exists: safe=$($op.SafeName) member=$($op.NewGroup)" }
      default {
        if ($DryRun) {
          Write-Log INFO "[DRY] Would UPDATE new member perms: safe=$($op.SafeName) member=$($op.NewGroup)"
        } else {
          $body = @{ permissions = $permissions }
          if ($null -ne $expiration -and $expiration -ne "" -and $expiration -ne 0) { $body.membershipExpirationDate = $expiration }
          CyberArk-UpdateMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.NewGroup -body $body | Out-Null
        }

        if ($DeleteOld) {
          if ($DryRun) {
            Write-Log INFO "[DRY] Would DELETE old member: safe=$($op.SafeName) member=$($op.OldGroup)"
          } else {
            CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
          }
          return [pscustomobject]@{ Op=$op; Status="UPDATED_NEW_AND_DELETED_OLD"; Capture=$capture }
        }

        return [pscustomobject]@{ Op=$op; Status="UPDATED_NEW"; Capture=$capture }
      }
    }
  }

  # Add new
  if ($DryRun) {
    Write-Log INFO "[DRY] Would ADD new member: safe=$($op.SafeName) member=$($op.NewGroup)"
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
  }

  if ($DeleteOld) {
    if ($DryRun) {
      Write-Log INFO "[DRY] Would DELETE old member: safe=$($op.SafeName) member=$($op.OldGroup)"
    } else {
      CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
    }
    return [pscustomobject]@{ Op=$op; Status="ADDED_NEW_AND_DELETED_OLD"; Capture=$capture }
  }

  return [pscustomobject]@{ Op=$op; Status="ADDED_NEW"; Capture=$capture }
}

Write-Log INFO ("Starting {0} operation(s). dry_run={1} workers={2}" -f $ops.Count, [bool]$DryRun, $Workers)

$results = New-Object System.Collections.Generic.List[object]

$canParallel = $false
if ($PSVersionTable.PSVersion.Major -ge 7) { $canParallel = $true }

if ($canParallel -and $Workers -gt 1) {
  # NOTE: We keep all needed values in $using: scope.
  $parallelResults = $ops | ForEach-Object -Parallel {
    param($op)

    # local logging inside parallel is intentionally minimal to avoid interleaving
    if ($using:SleepSec -gt 0) { Start-Sleep -Seconds $using:SleepSec }

    # Call back into script functions via $using: is not supported for function references reliably in all PS versions.
    # So we do a simplified "call" by invoking the outer script block through & and $using:InvokeOne
    & $using:InvokeOne $op
  } -ThrottleLimit $Workers

  foreach ($r in $parallelResults) { $results.Add($r) | Out-Null }
} else {
  foreach ($op in $ops) {
    $r = Invoke-OneOp $op
    $results.Add($r) | Out-Null
    Write-Log INFO ("Result: env={0} safe={1} {2} -> {3} : {4}" -f $op.Environment, $op.SafeName, $op.OldGroup, $op.NewGroup, $r.Status)
  }
}

# Summary
$summary = $results | Group-Object -Property Status | Sort-Object Name | ForEach-Object {
  [pscustomobject]@{ Status=$_.Name; Count=$_.Count }
}
Write-Log INFO ("Summary:`n" + ($summary | Format-Table -AutoSize | Out-String))

# Emit curl script (optional)
if ($EmitCurlScript) {
  $scriptText = New-CurlScript -baseUrl $PVWA -authType $AuthType -username ($Username ? $Username : "<username>") `
    -searchIn $SearchIn -memberType $MemberType -deleteOld ([bool]$DeleteOld) -captured $capturedForCurl

  Set-Content -Path $EmitCurlScript -Value $scriptText -Encoding UTF8
  Write-Log INFO "Wrote curl script: $EmitCurlScript"
  if ($IsWindows) {
    Write-Log INFO "Tip: run curl script in WSL or Git Bash; it expects TOKEN exported."
  }
}

# Logoff only if we performed logon in this run (i.e., Token not originally supplied)
if (-not $env:CYBERARK_TOKEN -and -not $PSBoundParameters.ContainsKey("Token")) {
  CyberArk-Logoff -baseUrl $PVWA -token $Token
}

exit 0

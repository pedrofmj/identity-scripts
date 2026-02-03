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

  Input: CSV (CSV-only).

.PARAMETER AimCliPath
  Path to CyberArk ApplicationPasswordSdk CLIPasswordSDK.exe. If provided with AimAppId/AimSafe/AimObject,
  the script will fetch the PVWA credential from AIM instead of prompting.

.NOTES
  - This is a REST-only script (no psPAS / Connect-PASServer).
  - If AIM returns APPAP309E "untrusted shell", run from a trusted shell (typically powershell.exe),
    not ISE, not certain embedded terminals, or ask CyberArk admins to whitelist your shell/host.
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
  [string]$AimCliPath,
  [string]$AimAppId,
  [string]$AimSafe,
  [string]$AimObject,
  [string]$AimFolder = "Root",

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
    throw ("AIM blocked the request (untrusted shell). Run from a trusted host (normal powershell.exe console, not ISE/embedded terminal) and/or ask AIM admins to whitelist this shell. Raw: " + ($text.Trim()))
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

if ([string]::IsNullOrWhiteSpace($Token)) {

  # If no password was provided, optionally fetch it from AIM/CLIPasswordSDK
  if ($null -eq $Password) {
    $aimProvided =
      (-not [string]::IsNullOrWhiteSpace($AimCliPath)) -and
      (-not [string]::IsNullOrWhiteSpace($AimAppId)) -and
      (-not [string]::IsNullOrWhiteSpace($AimSafe)) -and
      (-not [string]::IsNullOrWhiteSpace($AimObject))

    if ($aimProvided) {
      Write-Log INFO "Fetching credential from AIM (CLIPasswordSDK) ..."
      $cred = Get-AimCredential -CliPath $AimCliPath -AppId $AimAppId -Safe $AimSafe -Object $AimObject -Folder $AimFolder

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
Write-Log INFO ("Starting {0} operation(s). dry_run={1} workers={2}" -f $ops.Count, [bool]$DryRun, $Workers)

# NOTE: For safety/compatibility, this runs sequentially (token shared across operations).
# If you want true parallel, you typically need per-worker tokens.
foreach ($op in $ops) {

  if ($SleepSec -gt 0) { Start-Sleep -Seconds $SleepSec }

  if ($op.OldGroup -eq $op.NewGroup) {
    Write-Log INFO ("SKIP_SAME_NAME: safe={0} old={1} new={2}" -f $op.SafeName, $op.OldGroup, $op.NewGroup)
    continue
  }

  $oldMember = CyberArk-GetMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
  if ($null -eq $oldMember) {
    if ($AllowMissingOld) {
      Write-Log WARN ("MISSING_OLD: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
      continue
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
      "skip" {
        Write-Log INFO ("NEW_ALREADY_EXISTS_SKIP: safe={0} member={1}" -f $op.SafeName, $op.NewGroup)
        continue
      }
      "fail" {
        throw "[row $($op.RowNum)] New member already exists: safe=$($op.SafeName) member=$($op.NewGroup)"
      }
      default {
        if ($DryRun) {
          Write-Log INFO ("[DRY] Would UPDATE new member perms: safe={0} member={1}" -f $op.SafeName, $op.NewGroup)
        } else {
          $body = @{ permissions = $permissions }
          if ($null -ne $expiration -and $expiration -ne "" -and $expiration -ne 0) { $body.membershipExpirationDate = $expiration }
          CyberArk-UpdateMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.NewGroup -body $body | Out-Null
          Write-Log INFO ("UPDATED_NEW: safe={0} member={1}" -f $op.SafeName, $op.NewGroup)
        }

        if ($DeleteOld) {
          if ($DryRun) {
            Write-Log INFO ("[DRY] Would DELETE old member: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
          } else {
            CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
            Write-Log INFO ("DELETED_OLD: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
          }
        }
        continue
      }
    }
  }

  # Add new
  if ($DryRun) {
    Write-Log INFO ("[DRY] Would ADD new member: safe={0} member={1}" -f $op.SafeName, $op.NewGroup)
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
    Write-Log INFO ("ADDED_NEW: safe={0} member={1}" -f $op.SafeName, $op.NewGroup)
  }

  if ($DeleteOld) {
    if ($DryRun) {
      Write-Log INFO ("[DRY] Would DELETE old member: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
    } else {
      CyberArk-DeleteMember -baseUrl $PVWA -token $Token -safe $op.SafeName -member $op.OldGroup
      Write-Log INFO ("DELETED_OLD: safe={0} member={1}" -f $op.SafeName, $op.OldGroup)
    }
  }
}

# Emit curl script (optional)
if ($EmitCurlScript) {
  $scriptText = New-CurlScript -baseUrl $PVWA -authType $AuthType -username ($(if ([string]::IsNullOrWhiteSpace($Username)) { "<username>" } else { $Username })) `
    -searchIn $SearchIn -memberType $MemberType -deleteOld ([bool]$DeleteOld) -captured $capturedForCurl

  Set-Content -Path $EmitCurlScript -Value $scriptText -Encoding UTF8
  Write-Log INFO "Wrote curl script: $EmitCurlScript"
}

# Logoff only if we performed logon in this run
if ($didLogonHere) {
  CyberArk-Logoff -baseUrl $PVWA -token $Token
}

exit 0

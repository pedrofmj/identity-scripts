<#
.SYNOPSIS
  Remove CyberArk accounts by (SafeName, ObjectName) from a CSV.
  Optimized for speed (prefetch per Safe), resilient (auto-reconnect on 401),
  and compatible with multiple psPAS parameter sets.

.DESCRIPTION
  - Reads a CSV with SafeName,ObjectName (aliases tolerated).
  - Exact match on BOTH safename and name.
  - Default is Simulation; set -Delete to actually delete.
  - Prefetches accounts once per Safe (if psPAS supports -safeName or -search),
    builds an in-memory index for O(1) lookups.
  - Optional parallel deletes via PowerShell 7 (-ParallelDeletes -ThrottleLimit N).
  - Auto-reconnects on 401 with configurable retries/delay.
  - psPAS compatibility: tries -safeName → -Safe/-Keywords → -search.

.PARAMETER CsvPath
  Path to CSV containing SafeName,ObjectName (or accepted aliases).

.PARAMETER Delete
  Perform real deletions (non-interactive). If omitted (and -Simulate not provided), defaults to simulation.

.PARAMETER Simulate
  Dry-run (no deletions). Default when neither -Delete nor -Simulate is provided.

.PARAMETER AllowMultiple
  If more than one account matches the (SafeName, ObjectName) pair, delete all of them.
  Otherwise, the row is skipped.

.PARAMETER LogLevel
  Verbosity: Info (default), Debug, Trace.

.PARAMETER LogPath
  If provided, logs are appended to this file (UTF-8). Otherwise logs go to stdout.

.PARAMETER BaseURI
  If provided with -Credential, the script will Connect-PASServer automatically (and on 401 reauth).

.PARAMETER Credential
  PSCredential to authenticate when using -BaseURI.

.PARAMETER ReauthMaxRetries
  How many times to attempt re-authentication after a 401 (default 2).

.PARAMETER ReauthDelaySeconds
  Delay between re-auth attempts (default 5).

.PARAMETER ParallelDeletes
  If set, attempt parallel deletion using PowerShell 7's ForEach-Object -Parallel (requires -ThrottleLimit > 1).

.PARAMETER ThrottleLimit
  Degree of parallelism when -ParallelDeletes is used (default 1 = sequential).

.PARAMETER MaxFetchLimit
  Upper bound on list fetch size for prefetching (default 2000).

.PARAMETER Help
  Show inline usage (including CSV format) and exit.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$CsvPath,

  [switch]$Delete,
  [switch]$Simulate,
  [switch]$AllowMultiple,

  [ValidateSet('Info','Debug','Trace')]
  [string]$LogLevel = 'Info',

  [string]$LogPath,

  # Optional auto-connect inputs
  [string]$BaseURI,
  [System.Management.Automation.PSCredential]$Credential,

  [int]$ReauthMaxRetries = 2,
  [int]$ReauthDelaySeconds = 5,

  [switch]$ParallelDeletes,
  [int]$ThrottleLimit = 1,

  [int]$MaxFetchLimit = 2000,

  [switch]$Help
)



# ──────────────────────────────────────────────────────────────
# Inline help (-Help and /?) with CSV format
# ──────────────────────────────────────────────────────────────
if ($PSBoundParameters.ContainsKey('Help') -or $args -contains '/?') {
  Write-Host ""
  Write-Host "=========================================" -ForegroundColor Cyan
  Write-Host " Remove-AccountsByPair.ps1 - Help Summary" -ForegroundColor Cyan
  Write-Host "=========================================" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "  .\Remove-AccountsByPair.ps1 -CsvPath <path> [-Delete] [-Simulate] [-AllowMultiple]"
  Write-Host "                              [-LogLevel <Info|Debug|Trace>] [-LogPath <file>]"
  Write-Host "                              [-BaseURI <url>] [-Credential <PSCredential>]"
  Write-Host "                              [-ReauthMaxRetries <n>] [-ReauthDelaySeconds <s>]"
  Write-Host "                              [-ParallelDeletes] [-ThrottleLimit <n>] [-MaxFetchLimit <n>]"
  Write-Host "                              [-Help] [/?]"
  Write-Host ""
  Write-Host "Parameters:" -ForegroundColor Yellow
  Write-Host "  -CsvPath <string>     Path to the CSV with SafeName,ObjectName pairs."
  Write-Host "  -Delete               Perform real deletions (non-interactive)."
  Write-Host "  -Simulate             Dry-run (no deletions). Default if -Delete not specified."
  Write-Host "  -AllowMultiple        Delete all matches if multiple found (otherwise skipped)."
  Write-Host "  -LogLevel <level>     Info (default), Debug, or Trace."
  Write-Host "  -LogPath <path>       Append logs to UTF-8 file. Defaults to stdout."
  Write-Host "  -BaseURI <url>        If provided with -Credential, auto-connect to PVWA."
  Write-Host "  -Credential <creds>   PSCredential used with -BaseURI."
  Write-Host "  -ReauthMaxRetries     Retries after 401 (default 2)."
  Write-Host "  -ReauthDelaySeconds   Delay between reauth attempts (default 5)."
  Write-Host "  -ParallelDeletes      Use PS7 parallelism for deletes."
  Write-Host "  -ThrottleLimit <n>    Degree of parallelism (default 1 = sequential)."
  Write-Host "  -MaxFetchLimit <n>    Prefetch page size (default 2000)."
  Write-Host "  -Help, /?             Show this help summary and exit."
  Write-Host ""
  Write-Host "CSV Format:" -ForegroundColor Yellow
  Write-Host "  Required columns (case-insensitive):"
  Write-Host "    SafeName,ObjectName"
  Write-Host ""
  Write-Host "  Example:"
  Write-Host "    SafeName,ObjectName"
  Write-Host "    FinanceSafe,Server01_Admin"
  Write-Host "    HRVault,OracleDB_Prod"
  Write-Host "    NetworkSafe,Firewall_Admin"
  Write-Host ""
  Write-Host "  Accepted column name aliases:"
  Write-Host "    SafeName → 'Safe', 'safe', 'Vault', 'VaultName'"
  Write-Host "    ObjectName → 'Object', 'Name', 'AccountName', 'Object Name'"
  Write-Host ""
  Write-Host "Notes:" -ForegroundColor Yellow
  Write-Host "  • Prefetch per Safe is used when psPAS supports -safeName or -search."
  Write-Host "  • Parallel deletes require PowerShell 7."
  Write-Host ""
  Write-Host "=========================================" -ForegroundColor Cyan
  Write-Host ""
  exit 0
}

# ──────────────────────────────────────────────────────────────
# Defaults and validations
# ──────────────────────────────────────────────────────────────
if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV not found: $CsvPath" }
if (-not $Delete -and -not $Simulate) { $Simulate = $true } # safe default
if (($BaseURI -and -not $Credential) -or ($Credential -and -not $BaseURI)) {
  throw "When using auto-connect, both -BaseURI and -Credential must be provided together."
}
if ($ParallelDeletes -and $ThrottleLimit -lt 1) { $ThrottleLimit = 1 }

# ──────────────────────────────────────────────────────────────
# Logging (buffered)
# ──────────────────────────────────────────────────────────────
$__LEVELS = @{ 'Error' = 0; 'Warn' = 0; 'Info' = 1; 'Debug' = 2; 'Trace' = 3 }
$__CURRENT = $__LEVELS[$LogLevel]
$__LOG_BUF = New-Object System.Collections.Generic.List[string]
$__BUF_FLUSH = 250

function Flush-Logs {
  if ($LogPath -and $__LOG_BUF.Count -gt 0) {
    Add-Content -LiteralPath $LogPath -Value $__LOG_BUF -Encoding UTF8
    $__LOG_BUF.Clear() | Out-Null
  }
}

if ($LogPath) {
  $dir = Split-Path -Parent $LogPath
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  "[{0}] === Run start ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $LogPath -Encoding UTF8
}

function Write-Log {
  param([ValidateSet('Trace','Debug','Info','Warn','Error')]$Level,[string]$Message)
  $p = $__LEVELS[$Level]; if ($p -gt $__CURRENT -and $Level -in @('Trace','Debug','Info')) { return }
  $stamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')
  $line  = "[{0}] [{1}] {2}" -f $stamp, $Level.ToUpper(), $Message
  if ($LogPath) {
    $__LOG_BUF.Add($line) | Out-Null
    if ($__LOG_BUF.Count -ge $__BUF_FLUSH) { Flush-Logs }
  } else {
    switch ($Level) {
      'Info'  { Write-Host    $line }
      'Debug' { Write-Host    $line }
      'Trace' { Write-Host    $line }
      'Warn'  { Write-Warning $line }
      'Error' { Write-Error   $line }
    }
  }
}

# ──────────────────────────────────────────────────────────────
# psPAS import and optional auto-connection
# ──────────────────────────────────────────────────────────────
Import-Module psPAS -ErrorAction Stop

# Process to Authenticate with PVWA via AIM

$AIM_AppID = "P-CarkAutomationApp"
$AIM_Safe = "PSNSCarkAutomation"
$AIM_Username = "App-Cark-Prod-Auto-L"
$AIM_Object = "Application-Prod-CyberArkVault-172.23.9.14-App-Cark-Prod-Auto-L"
$CLIPasswordSDK_Path = "D:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe"


$RETRIEVED_CRED = & "$CLIPasswordSDK_Path" password /p "AppDescs.AppID=$AIM_AppID" /p "query=Safe=$AIM_Safe;Folder=Root;object=$AIM_Object" /o PassProps.UserName,Password
 
 # Write-Host $RETRIEVED_CRED

if (-not $RETRIEVED_CRED) {
    Write-Host "Failed to retrieve password."
    return
}
 
# normalize to first non-empty line
# $line = ($RETRIEVED_CRED -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })[0]
$line = $RETRIEVED_CRED
# Write-Host $line

# remove surrounding quotes if present
# $line = $line.Trim('"')
 
# split on first comma (safer if password might include commas — see note below)
$parts = $line -split ',', 2
$username = $parts[0].Trim()
$plainPassword = $parts[1].Trim()
 
# create PSCredential
$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
 
Write-Host "Using username: $username"
# don't print password!
 
# pass PSCredential to session creation
# Next 2 lines are commented and being replaced
# New-PASSession -Credential $credential -BaseURI "https://pvwa.costco.com"
# Get-PASSession

$script:BaseURI   = "https://pvwa.costco.com"
$script:Credential = $credential

function New-Login {
    Write-Log -Level Info -Message "Creating new PAS session"
    Disconnect-PASSession -ErrorAction SilentlyContinue | Out-Null
    New-PASSession -BaseURI $script:BaseURI -Credential $script:Credential -ErrorAction Stop | Out-Null
}

New-Login


$connectedHere = $false
function Connect-IfNeeded {
  if ($BaseURI -and $Credential) {
    Write-Log -Level Info -Message "Connecting to PVWA: $BaseURI"
    Connect-PASServer -BaseURI $BaseURI -Credential $Credential -ErrorAction Stop | Out-Null
    $script:connectedHere = $true
    Write-Log -Level Info -Message "Connected to PVWA."
  } else {
    Write-Log -Level Info -Message "Assuming an existing psPAS session."
  }
}

# Initial connect (if parameters provided)
if ($BaseURI -and $Credential) {
  try { Connect-IfNeeded } catch { Write-Log -Level Error -Message ("Initial connect failed: {0}" -f $_.Exception.Message); throw }
}

# Retry wrapper with reauth on 401
function Invoke-WithReauth {
  param(
    [Parameter(Mandatory)] [ScriptBlock]$Operation,
    [Parameter(Mandatory)] [string]$OpLabel
  )
  $attempt = 0
  while ($true) {
    try {
      return & $Operation
    }
    catch {
      $attempt++
      $msg = $_.Exception.Message
# The next line is commented out for a replacement line to define is401
#      $is401 = ($msg -match '\b401\b') -or ($msg -match 'Unauthorized') -or ($msg -match 'token.*(expired|missing|invalid)')
$isAuthFailure =
    ($msg -match '\b401\b') -or
    ($msg -match 'Unauthorized') -or
    ($msg -match 'automatically logged off') -or
    ($msg -match 'token.*(expired|invalid|missing)') -or
    ($msg -match 'PASWS') -or
    ($msg -match 'No active session')

if ($isAuthFailure -and $attempt -le $ReauthMaxRetries) {
                Write-Log -Level Warn -Message (
                    "{0}: Vault session expired → re-login attempt {1}/{2}" -f
                    $OpLabel, $attempt, $ReauthMaxRetries
                )

                Start-Sleep -Seconds $ReauthDelaySeconds

                try {
                    New-Login
                    continue
                }
                catch {
                    Write-Log -Level Error -Message "Re-login failed: $($_.Exception.Message)"
                    throw
                }
            }

            throw
        }
    }
}

# ──────────────────────────────────────────────────────────────
# Read CSV
# ──────────────────────────────────────────────────────────────
$rows = Import-Csv -Path $CsvPath
if (-not $rows -or $rows.Count -eq 0) { throw "CSV appears empty: $CsvPath" }

# Counters
$processed       = 0
$deleted         = 0
$notFound        = 0
$skippedMultiple = 0
$errors          = 0

# Helper: tolerant field resolver
Write-Host "Retrieving source data from $CsvPath"
function Get-Field {
  param($row, [string]$primary, [string[]]$fallbacks)
  $candidates = @($primary) + $fallbacks
  foreach ($name in $candidates) {
    if ($row.PSObject.Properties.Name -contains $name) {
      $v = $row.$name; if ($null -ne $v -and "$v".Trim().Length -gt 0) { return "$v".Trim() }
    }
  }
  return $null
}

# Detect available Get-PASAccount parameters (case-insensitive)
try {
  $cmd = Get-Command Get-PASAccount -ErrorAction Stop
  $paramKeys = @($cmd.Parameters.Keys)
  $hasSafeName = $paramKeys -contains 'safeName'
  $hasSafe     = $paramKeys -contains 'Safe'
  $hasKeywords = $paramKeys -contains 'Keywords'
  $hasLimit    = $paramKeys -contains 'limit'
  $hasSearch   = $paramKeys -contains 'search'
  Write-Log -Level Debug -Message ("Get-PASAccount params → -safeName:{0} -Safe:{1} -Keywords:{2} -limit:{3} -search:{4}" -f $hasSafeName, $hasSafe, $hasKeywords, $hasLimit, $hasSearch)
} catch { Write-Log -Level Error -Message "Get-PASAccount not found. Is psPAS installed?"; throw }

# ──────────────────────────────────────────────────────────────
# PREFETCH (per Safe) when possible → build {Safe,Object}->matches index
# ──────────────────────────────────────────────────────────────
$index = @{}     # key = "<safe>`n<object>", value = array of account objects
$bySafe = @{}    # optional: Safe -> all accounts (for debugging/inspection)

# Collect unique safe names from CSV, respecting aliases
$uniqueSafes = New-Object System.Collections.Generic.HashSet[string]
foreach ($r in $rows) {
  $s = Get-Field -row $r -primary 'SafeName' -fallbacks @('safe','Safe','Vault','VaultName')
  if ($s) { $null = $uniqueSafes.Add($s) }
}

$prefetchEnabled = $false
if ($hasSafeName -or $hasSearch) {
  $prefetchEnabled = $true
  foreach ($safe in $uniqueSafes) {
    try {
      $list = $null
      if ($hasSafeName) {
        $list = Invoke-WithReauth -OpLabel ("Prefetch: Get-PASAccount -safeName '{0}'" -f $safe) -Operation {
          $args = @{ safeName = $safe; ErrorAction = 'Stop' }
          if ($hasLimit) { $args['limit'] = $MaxFetchLimit }
          Get-PASAccount @args
        }
      } elseif ($hasSearch) {
        # Fallback prefetch using -search; broader but still reduces per-row queries
        $list = Invoke-WithReauth -OpLabel ("Prefetch: Get-PASAccount -search '{0}'" -f $safe) -Operation {
          $args = @{ search = $safe; ErrorAction = 'Stop' }
          if ($hasLimit) { $args['limit'] = $MaxFetchLimit }
          Get-PASAccount @args
        }
      }

      $arr = @($list)
      $bySafe[$safe] = $arr
      foreach ($acc in $arr) {
        $k = "$($acc.safename)`n$($acc.name)"
        if (-not $index.ContainsKey($k)) { $index[$k] = @() }
        $index[$k] += ,$acc
      }
      Write-Log -Level Debug -Message ("Prefetch: Safe='{0}', accounts loaded={1}" -f $safe, $arr.Count)
    }
    catch {
      Write-Log -Level Warn -Message ("Prefetch: failed for Safe='{0}' → {1}" -f $safe, $_.Exception.Message)
    }
    Flush-Logs
  }
} else {
  Write-Log -Level Info -Message "Prefetch disabled (psPAS lacks -safeName/-search). Using row-by-row lookup."
}

# Helper: resolve row matches either via index or remote lookup
function Resolve-Matches {
  param([string]$SafeName,[string]$ObjectName,[int]$RowIndex)

  if ($prefetchEnabled) {
    $key = "$SafeName`n$ObjectName"
    if ($index.ContainsKey($key)) { return ,$index[$key] } # array
    return ,@()
  }

  # Row-by-row remote lookup (Gen2 → Gen1 → search)
  if ($hasSafeName) {
    $list = Invoke-WithReauth -OpLabel ("Row {0}: Get-PASAccount -safeName" -f $RowIndex) -Operation {
      $args = @{ safeName = $SafeName; ErrorAction = 'Stop' }
      if ($hasLimit) { $args['limit'] = $MaxFetchLimit }
      Get-PASAccount @args
    }
    return ,(@($list) | Where-Object { $_.name -eq $ObjectName })
  }
  elseif ($hasSafe -and $hasKeywords) {
    $list = Invoke-WithReauth -OpLabel ("Row {0}: Get-PASAccount -Safe/-Keywords" -f $RowIndex) -Operation {
      Get-PASAccount -Safe $SafeName -Keywords $ObjectName -ErrorAction Stop
    }
    return ,(@($list) | Where-Object { $_.name -eq $ObjectName })
  }
  elseif ($hasSearch) {
    $list = Invoke-WithReauth -OpLabel ("Row {0}: Get-PASAccount -search" -f $RowIndex) -Operation {
      $args = @{ search = $ObjectName; ErrorAction = 'Stop' }
      if ($hasLimit) { $args['limit'] = $MaxFetchLimit }
      Get-PASAccount @args
    }
    return ,(@($list) | Where-Object { $_.name -eq $ObjectName -and $_.safename -eq $SafeName })
  }
  else {
    Write-Log -Level Error -Message "Get-PASAccount exposes neither -safeName/-Safe nor -search. Update psPAS."
    return ,@()
  }
}

# Preamble
$mode = if ($Delete) { 'DELETE' } else { 'SIMULATION' }
Write-Log -Level Info  -Message "Mode            : $mode"
Write-Log -Level Info  -Message "CSV             : $CsvPath"
Write-Log -Level Info  -Message "Rows            : $($rows.Count)"
Write-Log -Level Debug -Message "LogLevel        : $LogLevel"
Write-Log -Level Debug -Message ("LogPath         : {0}" -f ($(if ($LogPath) { $LogPath } else { '<stdout>' })))
Write-Log -Level Debug -Message ("Prefetch        : {0}" -f $prefetchEnabled)
Write-Log -Level Debug -Message ("ParallelDeletes : {0} (ThrottleLimit={1})" -f $ParallelDeletes, $ThrottleLimit)
if ($BaseURI) { Write-Log -Level Debug -Message "BaseURI         : $BaseURI" }
Flush-Logs

# ──────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────
$idx = 0
foreach ($row in $rows) {
  $idx++; $processed++
 
 # ── Keepalive every 25 rows ──
  if ($idx % 25 -eq 0) {
      Invoke-WithReauth -OpLabel "Keepalive" -Operation {
          Get-PASSession | Out-Null
      }
      Write-Log -Level Trace -Message "Keepalive ping sent"
  }
# ── End Keepalive every 25 rows portion ──

  $safeName   = Get-Field -row $row -primary 'SafeName'   -fallbacks @('safe','Safe','Vault','VaultName')
  $objectName = Get-Field -row $row -primary 'ObjectName' -fallbacks @('Object','Name','AccountName','Object Name')

  if (-not $safeName -or -not $objectName) {
    Write-Log -Level Warn -Message "Row $idx missing SafeName/ObjectName. Skipping."
    $errors++; continue
  }

  try {
    $matches = Resolve-Matches -SafeName $safeName -ObjectName $objectName -RowIndex $idx
    $matches = @($matches) # normalize

    $count = ($matches | Measure-Object).Count
    if ($count -eq 0) {
      Write-Log -Level Info -Message ("Row {0}: NOT FOUND → Safe='{1}' Object='{2}'" -f $idx, $safeName, $objectName)
      $notFound++; continue
    }

    Write-Log -Level Debug -Message ("Row {0}: found {1} exact match(es) for Safe='{2}' Object='{3}'" -f $idx, $count, $safeName, $objectName)
    if ($count -gt 1 -and -not $AllowMultiple) {
      Write-Log -Level Warn -Message ("Row {0}: multiple matches (count={1}) → skipped (use -AllowMultiple)" -f $idx, $count)
      $skippedMultiple++; continue
    }

    if ($Simulate) {
      foreach ($acc in $matches) {
        Write-Log -Level Info -Message ("[SIMULATE] Would remove: Safe='{0}' Object='{1}' (id={2})" -f $safeName, $objectName, $acc.id)
      }
      continue
    }
    # Real deletions

if ($ParallelDeletes -and $ThrottleLimit -gt 1 -and ($PSVersionTable.PSVersion.Major -ge 7)) {
  $results = $matches | ForEach-Object -Parallel {
    param($buri, $clipath, $appid, $safe, $obj, $reauthMax, $reauthDelay)
     Import-Module psPAS -ErrorAction Stop | Out-Null
     function Get-FreshCredential {
      $retrieved = & "$clipath" password `
        /p "AppDescs.AppID=$appid" `
        /p "query=Safe=$safe;Folder=Root;object=$obj" `
        /o PassProps.UserName,Password
       if (-not $retrieved) { throw "Failed to retrieve credential from CLIPasswordSDK." }
      # If the SDK prints "user,password"
      $parts = $retrieved -split ',', 2
      if ($parts.Count -lt 2) { throw "Unexpected credential format from CLIPasswordSDK." }
       $user = $parts[0].Trim()
      $plain = $parts[1].Trim()
       $secure = ConvertTo-SecureString $plain -AsPlainText -Force
      return [pscredential]::new($user, $secure)
    }
 
    function Connect-Fresh {
      $cred = Get-FreshCredential
      try {
        # psPAS v6+: Connect-PASServer establishes the session
        Connect-PASServer -BaseURI $buri -Credential $cred -ErrorAction Stop | Out-Null
      } catch {
        # Some environments only expose New-PASSession
        New-PASSession -BaseURI $buri -Credential $cred -ErrorAction Stop | Out-Null
      }
    }
 
    # Initial connect for this worker
    Connect-Fresh

     # Local retry wrapper that re-auths on 401/token errors
    $attempt = 0
    while ($true) {
      try {
                  Remove-PASAccount -Id $using:($_.id) -Confirm:$false -ErrorAction Stop
          [PSCustomObject]@{ Id = $using:($_.id); Ok = $true; Error = $null 
        } catch {
          [PSCustomObject]@{ Id = $using:($_.id); Ok = $false; Error = $_.Exception.Message }
        }
      } -ThrottleLimit $ThrottleLimit -ArgumentList $BaseURI, $Credential

      } catch {
        $attempt++
        $msg = $_.Exception.Message
        $is401 = ($msg -match '\b401\b') -or ($msg -match 'Unauthorized') -or ($msg -match 'token.*(expired|missing|invalid)')
        if ($is401 -and $attempt -le $reauthMax) {
          try {
            Start-Sleep -Seconds $reauthDelay

            # Tear down (best effort) and reconnect with a brand-new token
            try { Disconnect-PASSession -ErrorAction SilentlyContinue | Out-Null } catch {}
            Connect-Fresh
            continue

          } catch
          {
            if ($attempt -ge $reauthMax) {
              [PSCustomObject]@{ Id = $using $_.id; Ok = $false; Error = "Re-auth failed: $($PSItem.Exception.Message)" }
              break
            }
          }
        } else {
          [PSCustomObject]@{ Id = $using:($_.id); Ok = $false; Error = $msg }
          break
        }
      }
    }
   } -ThrottleLimit $ThrottleLimit -ArgumentList `
      $BaseURI, $CLIPasswordSDK_Path, $AIM_AppID, $AIM_Safe, $AIM_Object, `
      ($ReauthMaxRetries ?? 2), ($ReauthDelaySeconds ?? 2)
}
 
      foreach ($r in $results) {
        if ($r.Ok) {
          Write-Log -Level Info -Message ("[OK] Deleted: {0}" -f $r.Id)
          $deleted++
        } else {
          Write-Log -Level Error -Message ("[FAIL] Delete id={0} → {1}" -f $r.Id, $r.Error)
          $errors++
        }
      }
    }
    else {
      
      # Sequential (with reauth)
      foreach ($acc in $matches) {
        $id = $acc.id
        if (-not $id) { Write-Log -Level Warn -Message ("Row {0}: match missing id → skipped" -f $idx); $errors++; continue }
        Invoke-WithReauth -OpLabel ("Row {0}: Remove-PASAccount id={1}" -f $idx, $id) -Operation {
          Write-Log -Level Info -Message ("[DELETE] Removing: Safe='{0}' Object='{1}' (id={2})" -f $safeName, $objectName, $id)
          Remove-PASAccount -Id $id -Confirm:$false -ErrorAction Stop
          Write-Log -Level Info -Message ("[OK] Deleted: {0}" -f $id)
        }
        $deleted++
      }
    }
  
  catch {
    Write-Log -Level Error -Message ("Row {0}: error for Safe='{1}' Object='{2}' → {3}" -f $idx, $safeName, $objectName, $_.Exception.Message)
    $errors++; continue
  }

  Flush-Logs


# ──────────────────────────────────────────────────────────────
# Summary & optional disconnect
# ──────────────────────────────────────────────────────────────
# Write-Log -Level Info -Message ""
Write-Log -Level Info -Message "================ SUMMARY ================"
Write-Log -Level Info -Message ("Processed       : {0}" -f $processed)
Write-Log -Level Info -Message ("Deleted         : {0}" -f $deleted)
Write-Log -Level Info -Message ("Not Found       : {0}" -f $notFound)
Write-Log -Level Info -Message ("Skipped Multiple: {0}" -f $skippedMultiple)
Write-Log -Level Info -Message ("Errors          : {0}" -f $errors)
Write-Log -Level Info -Message ("Mode            : {0}" -f $mode)
Write-Log -Level Info -Message "========================================="

if ($connectedHere) {
  try {
    Write-Log -Level Info -Message "Disconnecting from PVWA…"
    Disconnect-PASServer -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Level Info -Message "Disconnected."
  } catch {
    Write-Log -Level Warn -Message "Disconnect failed (continuing): $($_.Exception.Message)"
  }
}

Flush-Logs
if ($LogPath) { Write-Log -Level Info -Message "Logs written to: $LogPath"; Flush-Logs }

Write-Host "Closing PAS Session"
Close-PASSession

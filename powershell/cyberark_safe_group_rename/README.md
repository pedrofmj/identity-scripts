# CyberArk Safe AD Group Rename — PowerShell Edition

Batch tool to “rename” Active Directory security groups used as **Safe members** in CyberArk PVWA by applying the Safe-member workflow supported by the REST APIs:

> **Add the new group as a Safe member with the same permissions (and membership expiration), then optionally delete the old group.**

This repository includes:
- `cyberark_safe_group_rename.ps1` — main script
- `bootstrap.ps1` — installs required PowerShell modules (dependency management)
- (optional) your input file: `Copy of CyberArk AD Group Rename List.xlsx`

---

## What this tool does

For each row in the input list, it performs:

1. **GET** the old group as a Safe member to capture:
   - `permissions`
   - `membershipExpirationDate` (if present)
2. **POST** the new group as a Safe member using the same permissions/expiration
3. If the new group already exists, behavior is controlled via `-OnConflict`:
   - `update` (default): update permissions/expiration
   - `skip`: do nothing
   - `fail`: stop with an error
4. Optionally **DELETE** the old member (`-DeleteOld`)

---

## What this tool does not do

- It does **not** rename groups in Active Directory.
- It does **not** “rename” a Safe member principal in-place (that is not how the Safe member APIs work).
- It does **not** apply custom spreadsheet columns (e.g., `costco-object-approver`, `costco-object-author-sme`) as CyberArk attributes.

---

## Input file format

Preferred format is **XLSX**, sheet `List` (default). CSV is also supported.

Required columns (header matching is flexible):
- `Environment`
- `SafeName`
- Existing group column (examples: `ExistingSecurityGroupName`, `OldGroup`, `ExistingGroupName`)
- New group column (examples: `NewSecurityGroupName`, `NewGroup`, `NewGroupName`)

Optional columns are allowed and ignored by execution.

---

## Requirements

### PowerShell
- **PowerShell 7+ recommended** (best cross-platform experience)
- Windows PowerShell 5.1 works for single-thread (parallel execution is PS7+)

### Modules
- **ImportExcel** (recommended) — enables XLSX reading without Microsoft Excel  
  Installed automatically by `bootstrap.ps1`.

> If ImportExcel is not available and you’re on Windows with Microsoft Excel installed, the script can fall back to Excel COM automation (slower and requires Excel).

---

## Quick start

### 1) Install dependencies (modules)
Run:

```powershell
.\bootstrap.ps1
```

This installs required modules (currently: `ImportExcel`) under the current user scope.

### 2) Run the tool

```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -PVWA "https://pvwa.company.com" `
  -Info
```

---

## Authentication options

You can authenticate by:
- providing `-Username` and `-Password` (prompt if password omitted), or
- providing an existing `-Token`

You can also use environment variables:
- `CYBERARK_USERNAME`
- `CYBERARK_PASSWORD` *(only used if you wire it in; by default the script prompts for SecureString)*
- `CYBERARK_TOKEN`

### Example: prompt for password
```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -PVWA "https://pvwa.company.com" `
  -AuthType LDAP `
  -Username "svc_pvwa_api" `
  -DryRun
```

### Example: use existing token
```powershell
$env:CYBERARK_TOKEN = "PASTE_TOKEN_HERE"

.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -PVWA "https://pvwa.company.com" `
  -Token $env:CYBERARK_TOKEN `
  -DeleteOld
```

---

## Typical workflows

### Inspect input (counts, collisions)
```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -PVWA "https://pvwa.company.com" `
  -Info
```

### Dry-run (recommended first)
```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -Environment "PROD" `
  -PVWA "https://pvwa.company.com" `
  -AuthType LDAP `
  -Username "svc_pvwa_api" `
  -DryRun `
  -Loglevel DEBUG
```

### Execute for real: add new + delete old
```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -Environment "PROD" `
  -PVWA "https://pvwa.company.com" `
  -AuthType LDAP `
  -Username "svc_pvwa_api" `
  -DeleteOld `
  -Workers 8
```

### If new member already exists
Control behavior with `-OnConflict`:
- `update` (default): update permissions/expiration for new group
- `skip`: leave new group untouched
- `fail`: stop execution

Example:
```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -Environment "PROD" `
  -PVWA "https://pvwa.company.com" `
  -AuthType LDAP `
  -Username "svc_pvwa_api" `
  -OnConflict skip `
  -DeleteOld
```

---

## Generate a curl script (optional)

You can generate a bash script containing `curl` commands using the permissions/expiration fetched from PVWA.

```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -Environment "PROD" `
  -PVWA "https://pvwa.company.com" `
  -AuthType LDAP `
  -Username "svc_pvwa_api" `
  -EmitCurlScript ".\apply_rename_prod.sh" `
  -DryRun
```

To run the script:
- On Windows: use **WSL** or **Git Bash**
- On Linux/macOS: run normally

```bash
export TOKEN="PASTE_TOKEN_HERE"
./apply_rename_prod.sh
```

---

## Cross-platform notes

### Windows
- Works best with PowerShell 7+
- XLSX reading works after `bootstrap.ps1` installs ImportExcel
- If running generated curl scripts, use WSL or Git Bash

### Linux / macOS
- Requires PowerShell 7 (`pwsh`)
- ImportExcel module works fine (no Excel needed)

---

## Performance & safety tuning

Useful options:
- `-DryRun` — log actions only, no changes
- `-Workers <n>` — concurrency (PowerShell 7+)
- `-TimeoutSec`, `-Retries`, `-RetryBackoffSec`, `-RetryStatus` — resiliency
- `-SleepSec` — rate-limit friendly delay per operation
- `-AllowMissingOld` — skip rows where old member is missing
- `-NoVerifyTls` — disable TLS verification (avoid unless you truly need it)

Recommended approach:
1. Run `-Info`
2. Run `-DryRun`
3. Run real execution with a conservative `-Workers` value
4. Increase workers only if PVWA tolerates the rate

---

## Logging

Default: logs to stdout.

### Log to file
```powershell
.\cyberark_safe_group_rename.ps1 `
  -InputPath ".\Copy of CyberArk AD Group Rename List.xlsx" `
  -PVWA "https://pvwa.company.com" `
  -AuthType LDAP `
  -Username "svc_pvwa_api" `
  -DryRun `
  -Logmode file `
  -Logfile ".\run.log"
```

---

## Troubleshooting

### “Missing required columns”
- Confirm sheet name (default `List`) or pass `-SheetList`
- Confirm required headers exist (matching is flexible, but the column intent must be present)

### XLSX reading errors
- Run `.\bootstrap.ps1` to install ImportExcel
- On Linux/macOS ensure you are using `pwsh` (PowerShell 7)
- If using Windows PowerShell 5.1, ImportExcel still works, but parallel execution won’t

### TLS / certificate issues
- Prefer installing your internal CA into the trust store
- As a last resort, use `-NoVerifyTls`

### Rate limiting / throttling
- Reduce `-Workers`
- Add `-SleepSec 0.1` or higher
- Increase retries/backoff

---

## Files in this repo

- `cyberark_safe_group_rename.ps1` — main PowerShell script
- `bootstrap.ps1` — module installer
- `README.md` — this document

---

## License
Internal / project-specific. Add a license section if you plan to publish externally.
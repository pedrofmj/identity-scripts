# CyberArk Safe AD Group Rename — Python Edition

Batch tool to “rename” Active Directory security groups used as **Safe members** in CyberArk PVWA by applying the Safe-member workflow supported by the REST APIs:

> **Add the new group as a Safe member with the same permissions (and membership expiration), then optionally delete the old group.**

This repository includes:
- `cyberark_safe_group_rename.py` — main script
- `requirements.txt` — Python dependencies
- (optional) your input file: `Copy of CyberArk AD Group Rename List.xlsx`

---

## What this tool does

For each row in the input list, it performs:

1. **GET** the old group as a Safe member to capture:
   - `permissions`
   - `membershipExpirationDate` (if present)
2. **POST** the new group as a Safe member using the same permissions/expiration
3. If the new group already exists, behavior is controlled via `--on-conflict`:
   - `update` (default): update permissions/expiration
   - `skip`: do nothing
   - `fail`: stop with an error
4. Optionally **DELETE** the old member (`--delete-old`)

---

## What this tool does not do

- It does **not** rename groups in Active Directory.
- It does **not** “rename” a Safe member principal in-place (that is not how the Safe member APIs work).
- It does **not** apply custom spreadsheet columns (e.g., `costco-object-approver`, `costco-object-author-sme`) as CyberArk attributes.

---

## Input file format

Preferred format is **XLSX**, sheet `List` (default).

Required columns (header matching is flexible):
- `Environment`
- `SafeName`
- Existing group column (examples: `ExistingSecurityGroupName`, `OldGroup`, `ExistingGroupName`)
- New group column (examples: `NewSecurityGroupName`, `NewGroup`, `NewGroupName`)

Optional columns are allowed and ignored by execution.

---

## Requirements

- Python **3.10+** recommended
- Network access to PVWA
- Dependencies listed in `requirements.txt`:
  - `requests`
  - `openpyxl`

---

## Installation

### 1) Create a virtual environment

#### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows (PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

#### Windows (cmd.exe)
```bat
py -m venv .venv
.\.venv\Scripts\activate.bat
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

---

## Optional: pyenv setup (Linux / macOS)

If you want consistent Python versions across machines, `pyenv` is a good option.

### 1) Install pyenv
Install `pyenv` using your OS instructions and ensure your shell loads it.

### 2) Install and select a Python version
Example:
```bash
pyenv install 3.11.9
pyenv local 3.11.9
python --version
```

### 3) Create the venv using pyenv’s Python
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Note: On Windows, `pyenv` is less common. Use the standard Python installer or the `py` launcher.

---

## Configuration

You can provide credentials via command-line flags or environment variables.

### Environment variables
- `CYBERARK_USERNAME`
- `CYBERARK_PASSWORD`
- `CYBERARK_TOKEN` (if you already have a token)

Linux/macOS example:
```bash
export CYBERARK_USERNAME="svc_pvwa_api"
export CYBERARK_PASSWORD="..."
```

Windows PowerShell example:
```powershell
$env:CYBERARK_USERNAME="svc_pvwa_api"
$env:CYBERARK_PASSWORD="..."
```

---

## Usage

### Show help
```bash
python cyberark_safe_group_rename.py --help
```

### Print version
```bash
python cyberark_safe_group_rename.py --version
```

### Inspect the spreadsheet (counts, collisions, etc.)
```bash
python cyberark_safe_group_rename.py \
  --input "Copy of CyberArk AD Group Rename List.xlsx" \
  --pvwa https://pvwa.company.com \
  --info
```

### Dry-run (recommended first)
```bash
python cyberark_safe_group_rename.py \
  --input "Copy of CyberArk AD Group Rename List.xlsx" \
  --environment PROD \
  --pvwa https://pvwa.company.com \
  --auth-type LDAP \
  --username "svc_pvwa_api" \
  --password "$PVWA_PASS" \
  --dry-run \
  --loglevel DEBUG
```

### Execute for real: add new + delete old
```bash
python cyberark_safe_group_rename.py \
  --input "Copy of CyberArk AD Group Rename List.xlsx" \
  --environment PROD \
  --pvwa https://pvwa.company.com \
  --auth-type LDAP \
  --username "svc_pvwa_api" \
  --password "$PVWA_PASS" \
  --delete-old \
  --workers 16
```

### Use an existing token (skip logon)
```bash
python cyberark_safe_group_rename.py \
  --input "Copy of CyberArk AD Group Rename List.xlsx" \
  --environment PROD \
  --pvwa https://pvwa.company.com \
  --token "$CYBERARK_TOKEN" \
  --delete-old
```

---

## Generate a curl script (optional)

You can generate a bash script containing `curl` commands using the permissions/expiration fetched from PVWA.

```bash
python cyberark_safe_group_rename.py \
  --input "Copy of CyberArk AD Group Rename List.xlsx" \
  --environment PROD \
  --pvwa https://pvwa.company.com \
  --auth-type LDAP \
  --username "svc_pvwa_api" \
  --password "$PVWA_PASS" \
  --delete-old \
  --emit-curl ./apply_rename_prod.sh \
  --dry-run
```

To run the generated script:
```bash
export TOKEN="PASTE_TOKEN_HERE"
./apply_rename_prod.sh
```

> On Windows, run the generated bash script via **WSL** or **Git Bash**.

---

## Performance & safety tuning

Useful options:
- `--dry-run` — log actions only, no changes
- `--workers <n>` — concurrency
- `--timeout`, `--retries`, `--retry-backoff`, `--retry-status` — resiliency
- `--sleep` — rate-limit friendly delay per operation
- `--allow-missing-old` — skip rows where old member is missing
- `--no-verify-tls` — disable TLS verification (avoid unless you truly need it)

Recommended approach:
1. Run `--info`
2. Run `--dry-run`
3. Run real execution with a conservative `--workers` value
4. Increase workers only if PVWA tolerates the rate

---

## Logging

Default: logs to stdout.

### Log to file
```bash
python cyberark_safe_group_rename.py \
  --input "Copy of CyberArk AD Group Rename List.xlsx" \
  --pvwa https://pvwa.company.com \
  --auth-type LDAP \
  --username "svc_pvwa_api" \
  --password "$PVWA_PASS" \
  --dry-run \
  --logmode file \
  --logfile ./run.log
```

---

## Troubleshooting

### “No operations found”
- Verify the sheet name (`--sheet-list`)
- Verify headers match expected columns
- Verify your `--environment` filter matches exactly

### Authentication issues
- Confirm `--auth-type` matches your environment (LDAP vs Cyberark etc.)
- Ensure the account has Safe membership management permissions

### TLS / certificate errors
- Prefer installing your internal CA into the trust store
- As a last resort, use `--no-verify-tls`

### Rate limiting / throttling
- Reduce `--workers`
- Add `--sleep 0.1` or higher
- Increase retries/backoff

---

## Files in this repo

- `cyberark_safe_group_rename.py` — main script
- `requirements.txt` — Python dependencies
- `README.md` — this document

---

## License
Internal / project-specific. Add a license section if you plan to publish externally.

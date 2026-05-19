# Manage-DefenderOffline — Technical Reference

## Project Overview

**Manage-DefenderOffline** is a PowerShell toolkit for managing Microsoft Defender antivirus definition updates across Windows 10/11 and Windows Server 2016+ endpoints in air-gapped, disconnected, or network-segmented environments — without MECM, Intune, or any commercial AV management platform.

The project covers the full operational lifecycle:
- **Deploying** definition updates over WinRM from a versioned network share
- **Monitoring** fleet-wide Defender health interactively (Forms GUI) or as a persistent service (HTTP dashboard)
- **Reporting** via HTML, CSV, and Windows Event Log

### Target Environments
- Government / military air-gapped networks
- SCADA / ICS industrial control systems
- Healthcare environments with strict network isolation
- Financial institutions with segmented security zones
- Any Windows estate without cloud-connected AV management

---

## Project Structure

```
Manage-DefenderOffline/
├── Update-DefenderOffline.ps1      # Deploys definition updates to endpoints
├── Show-DefenderStatus.ps1         # Interactive Windows Forms fleet monitor
├── Start-DefenderDashboard.ps1     # Headless HTTP dashboard (runs as scheduled task)
├── Install-DefenderDashboard.ps1   # One-time installer for the dashboard service
├── conf/
│   ├── config.conf                 # Central configuration (tracked in git)
│   └── dashboard.status            # Runtime port/status file (gitignored)
├── README.md                       # User-facing quick reference
├── claude.md                       # This file — technical reference
├── LICENSE.txt
└── hosts.conf                      # Target computer list (gitignored; auto-generated)
```

### Runtime Directories (gitignored, created automatically)
| Path | Created by | Contents |
|---|---|---|
| `Config/` | `Update-DefenderOffline.ps1 -SaveSmtpCredential` | Encrypted SMTP credential XML |
| `C:\Logs\` | `Update-DefenderOffline.ps1` | Timestamped execution logs |
| `C:\Logs\PerHost\` | `Update-DefenderOffline.ps1` (parallel mode) | Per-computer update logs |
| `C:\Logs\DefenderDashboard\` | `Start-DefenderDashboard.ps1` | Dashboard service logs |
| `.\Reports\` | `Update-DefenderOffline.ps1` | HTML + CSV update reports |

---

## Scripts

### Update-DefenderOffline.ps1

Discovers the latest available definition version on the network share, connects to each target endpoint over WinRM, compares versions, and installs only where needed.

**Source share structure (required):**
```
<SourceSharePath>\<YYYYMMDD>\v#.###.###.#\mpam-fe.exe
```
Example: `\\NAS01\DataShare\...\Microsoft_Defender\20260519\v1.449.681.0\mpam-fe.exe`

Version is parsed from the `v#.###.###.#` folder name — not from the filename. The file is always named `mpam-fe.exe`.

**Key parameters:**

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-SourceSharePath` | Yes* | — | *Can be set in `conf/config.conf` |
| `-ComputerName` | No | (auto) | Bypasses hosts.conf and AD |
| `-TempFolderOnTarget` | No | `C:\Temp\Update-DefenderOffline` | Deleted after update |
| `-LogSharePath` | No | — | UNC path for centralised log collection |
| `-WhatIfMode` | No | `$false` | No changes; full connectivity/version test |
| `-ParallelThreads` | No | 16 | PS 7+ only; range 1-32 |
| `-SendEmail` | No | `$false` | Requires `-SmtpServer` and `-To` |
| `-SaveSmtpCredential` | No | — | Interactive helper; exits after saving |
| `-ConfigPath` | No | `.\conf\config.conf` | Override config file location |

**Execution flow:**
1. Load `conf/config.conf`, apply values for any omitted parameters
2. Validate admin privileges
3. Resolve target computers (CLI → hosts.conf → AD auto-discovery)
4. Discover latest mpam-fe.exe via version-folder parsing; validate accessibility
5. For each endpoint (parallel PS7+ / serial PS5.1):
   - Test WinRM (TCP 5985)
   - Check Defender service is Running
   - Read current signature version
   - **Skip if endpoint version ≥ available version** (no file transfer)
   - Copy mpam-fe.exe to remote temp folder
   - Silent install (`mpam-fe.exe /q`)
   - Verify new version; collect logs if `-LogSharePath` set; clean up temp
   - Classify failures as hard (no retry) vs soft (retry up to 3×)
6. Compute version analytics (oldest/newest/average delta)
7. Write HTML report and CSV
8. Send email (if configured)

**Update result states:** `Success` | `No Update Needed` | `Failed` | `WhatIf`

---

### Show-DefenderStatus.ps1

Interactive Windows Forms dashboard for manual fleet monitoring. Queries all endpoints in parallel and displays results in a colour-coded data grid. Designed for admin desktop use only — requires an interactive Windows session.

**Colour coding:** Green = healthy/current · Amber = outdated or RT protection off · Red = offline

**Key parameters:**

| Parameter | Default | Notes |
|---|---|---|
| `-SourceSharePath` | — | Enables version currency comparison |
| `-ParallelThreads` | 16 | PS 7+ parallel query threads |
| `-TimeoutSeconds` | 30 | Per-host WinRM timeout |
| `-ConfigPath` | `.\conf\config.conf` | — |

**Features:** Live refresh · Auto-refresh timer (5 min) · Name filter · Export CSV · Export HTML

---

### Start-DefenderDashboard.ps1

Headless HTTP listener that serves a self-refreshing browser dashboard. Designed to run continuously as a Windows Scheduled Task under a service account or gMSA. All output goes to a log file; no interactive console required.

**Endpoints served:**

| Path | Response |
|---|---|
| `/defender` | HTML dashboard (auto-refreshes every `RefreshInterval` seconds) |
| `/status` | JSON snapshot of current fleet data |
| `/health` | Plain-text `OK` liveness probe |
| `/refresh` | Forces immediate background data refresh; redirects to `/defender` |

**Port resolution logic:**
1. Tests if `-Port` (default 8080) is free using `TcpListener.Start()`
2. If in use, walks from `-FallbackPort` (default 8443) upward, up to 10 candidates
3. Binds to the first available port
4. Writes `conf/dashboard.status` with the actual port and fallback flag
5. Writes Windows Event Log: EventId **100** (normal) or **101** (fallback, `Warning`)

**Key parameters:**

| Parameter | Default | Notes |
|---|---|---|
| `-Port` | 8080 | Primary port |
| `-FallbackPort` | 8443 | First fallback candidate |
| `-RefreshInterval` | 300 | Data refresh and browser auto-refresh in seconds |
| `-LogPath` | `C:\Logs\DefenderDashboard` | Service log directory |
| `-ParallelThreads` | 16 | Concurrent WinRM queries per refresh cycle |
| `-TimeoutSeconds` | 30 | Per-host WinRM timeout |
| `-ConfigPath` | `.\conf\config.conf` | — |

**Dashboard status file** (`conf/dashboard.status`):
Written at every startup, deleted on clean shutdown. Contains `Port`, `PrimaryPort`, `IsFallback`, `StartTime`, `ProcessId`, `Hostname`. Parseable by `Read-ConfigFile`. Installer reads this to confirm the actual port.

**Windows Event Log** (source: `Manage-DefenderOffline`, log: Application):
- EventId 100 — started on primary port (Information)
- EventId 101 — started on fallback port (Warning)
- EventId 102 — stopped (Information)

---

### Install-DefenderDashboard.ps1

One-time installer that registers `Start-DefenderDashboard.ps1` as a Windows Scheduled Task. Run as Administrator.

**What it does:**
1. Validates prerequisites (pwsh.exe, Task Scheduler service)
2. Validates the service account or gMSA exists in AD; checks gMSA password retrieval authorisation
3. Registers the `Manage-DefenderOffline` Windows Event Log source
4. Creates runtime directories; grants filesystem permissions to the service identity
5. Checks port availability; selects fallback if primary is in use
6. Registers the scheduled task (AtStartup, no time limit, restart-on-failure × 3)
7. Optionally creates an inbound Windows Firewall rule
8. Optionally starts the task immediately and reads `conf/dashboard.status` to confirm the actual port

**Service identity support:**

| Type | Parameter | Password needed |
|---|---|---|
| gMSA | `-GmsaName "DOMAIN\name$"` | No — system manages key |
| Traditional account | `-ServiceAccount "DOMAIN\user"` `-Credential $cred` | Yes |

**Task configuration:**
- Trigger: At system startup
- Action: `pwsh.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "..."`
- Execution time limit: None (runs indefinitely)
- Multiple instances: Ignore new (one copy only)
- Restart on failure: Yes, up to 3 times, 1-minute delay

**Key parameters:**

| Parameter | Default | Notes |
|---|---|---|
| `-Port` | 8080 | Primary port (from config or CLI) |
| `-FallbackPort` | 8443 | Fallback if primary is in use |
| `-TaskName` | `DefenderDashboard` | Scheduled task name |
| `-TaskFolder` | `\` | Task Scheduler folder |
| `-AddFirewallRule` | — | Creates TCP inbound rule |
| `-StartImmediately` | — | Starts task and verifies endpoint |
| `-Force` | — | Overwrites existing task |
| `-ConfigPath` | `.\conf\config.conf` | — |

---

## Configuration System

All scripts read `conf/config.conf` at startup. **Priority:** CLI parameter > config.conf value > script default.

`$PSBoundParameters.ContainsKey()` is used to detect whether a parameter was explicitly passed, so config values only fill in what was omitted.

**Parser behaviour:**
- Lines beginning with `#` or `[` are ignored (comments and section headers)
- Keys and values are trimmed of leading/trailing whitespace
- Empty values (`Key =`) are ignored (script default applies)
- Numeric values are cast with `try/catch`; a malformed value falls back to the script default

**Config sections:** `[Common]` · `[Update]` · `[Dashboard]` · `[Install]` · `[Email]`

See `conf/config.conf` for full documentation of every key.

---

## hosts.conf

**What it is:** A plain-text list of target computer names (one per line), gitignored because it is environment-specific.

**How it is created:** Automatically on first run of `Update-DefenderOffline.ps1` or `Show-DefenderStatus.ps1` if no `-ComputerName` parameter is provided and no `hosts.conf` exists. The script queries Active Directory (via the `ActiveDirectory` module or ADSI fallback) and writes the file with a generated header.

**Format:**
```
# Auto-generated header ...
WORKSTATION01
WORKSTATION02
SERVER01
# TESTLAB-PC01   ← commented out; will be skipped
```

**Priority:** `-ComputerName` CLI parameter > `hosts.conf` > AD auto-discovery

**Location:** Project root (same directory as the scripts).

Edit the file after first generation to exclude lab/test machines or add workgroup systems that are not in AD.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 minimum; 7+ strongly recommended (parallel processing) |
| Admin rights (local) | Required on the machine running the scripts |
| Admin rights (remote) | Required on all target endpoints for WinRM and `Get-MpComputerStatus` |
| WinRM | Must be enabled on all target endpoints (TCP 5985) |
| Source share | UNC path accessible to the running account; `mpam-fe.exe` in versioned subfolder |
| ActiveDirectory module | Optional; ADSI fallback used if absent |
| PowerShell 7 (pwsh.exe) | Required on the host running the dashboard service |

**Enable WinRM on targets (via GPO or locally):**
```powershell
Enable-PSRemoting -Force
```

**Enable WinRM via GPO:**
`Computer Configuration → Policies → Administrative Templates → Windows Components → Windows Remote Management (WinRM) → WinRM Service → Allow remote server management through WinRM`

---

## Operational Notes

### Scheduled Task (Update-DefenderOffline.ps1)
The update script is fully non-interactive in its main execution path. Run via Task Scheduler:
```
pwsh.exe -NonInteractive -ExecutionPolicy Bypass -File "D:\...\Update-DefenderOffline.ps1"
```
SMTP credentials must be saved interactively by the service account first (`-SaveSmtpCredential`), or the gMSA workaround must be used (see SMTP section in README).

### Dashboard Service Port
If the dashboard starts on a fallback port, the admin is notified via:
1. `conf/dashboard.status` — check with `Get-Content conf\dashboard.status`
2. Windows Event Log — EventId 101 Warning in Application log
3. Installation summary (if installed with `-StartImmediately`)

### Version History Logging
`Update-DefenderOffline.ps1` logs per-host version transitions in the format:
```
VersionHistory: HOSTNAME | Old=1.405.233.0 | New=1.449.681.0 | Delta=1012
```
The Delta value is `NewVersion.Build - OldVersion.Build`.

---

## Author & Credits

**Author:** Kismet Agbasi · [GitHub](https://github.com/kismetgerald) · KismetG17@gmail.com

**AI Contributors:** Claude AI, Grok

**License:** MIT — see LICENSE.txt

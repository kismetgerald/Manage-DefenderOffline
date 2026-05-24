# Manage-DefenderOffline

> Deploy, verify, and monitor Microsoft Defender antivirus definitions across air-gapped and offline Windows environments

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.txt)
[![Version](https://img.shields.io/badge/Version-0.0.6-orange.svg)](https://github.com/kismetgerald/Manage-DefenderOffline)

## Overview

**Manage-DefenderOffline** is a PowerShell toolkit for managing Microsoft Defender antivirus definitions on Windows 10/11 and Windows Server 2016+ endpoints that cannot reach the internet directly. It covers the full lifecycle: deploying updates, monitoring fleet health, and reporting — without requiring MECM, Intune, or any commercial AV management platform.

**Key Features:**
- 🚀 **10x faster** with PowerShell 7+ parallel processing (up to 32 threads)
- 📊 **Real-time update dashboard** with live progress tracking during deployments
- 🖥️ **Fleet monitor GUI** — interactive Windows Forms status dashboard
- 🌐 **Persistent web dashboard** — headless HTTP service for continuous fleet visibility
- 🔄 **Auto-discovery** of computers from Active Directory
- 🔧 **Email notifications** with HTML reports and CSV attachments
- 🛡️ **Safe & tested** with dry-run mode and automatic retry logic
- ⚙️ **Enterprise-ready** for scheduled tasks, service accounts, and gMSA
- 📈 **Version analytics** with fleet-wide statistics and CSV exports

## Scripts

| Script | Purpose | Run by |
|---|---|---|
| `Update-DefenderOffline.ps1` | Deploys definition updates to all endpoints | Admin (manual or scheduled task) |
| `Show-DefenderStatus.ps1` | Interactive Windows Forms fleet health monitor | Admin, interactively |
| `Start-DefenderDashboard.ps1` | Headless HTTP dashboard service | Scheduled task (service account / gMSA) |
| `Install-DefenderDashboard.ps1` | One-time installer for the dashboard service | Admin, once |

## Prerequisites Checklist

**Before running, ensure you have:**

- ☐ **PowerShell 5.1 or higher** (7+ strongly recommended for parallel performance)
- ☐ **Administrator privileges** on the machine running the scripts
- ☐ **Administrative rights** on all target computers
- ☐ **WinRM enabled** on target computers (TCP port 5985)
- ☐ **Network share** with definitions in the required folder structure (see below)
- ☐ **Firewall rules** allow TCP 5985 between the admin machine and all targets
- ☐ **Domain membership** OR ActiveDirectory PowerShell module (for auto-discovery)

### Quick Environment Test

```powershell
# Test WinRM on a target computer (run on the target)
Enable-PSRemoting -Force

# Verify WinRM is reachable from admin machine
Test-NetConnection -ComputerName TARGETPC -Port 5985

# Verify Defender service is running on a target
Invoke-Command -ComputerName TARGETPC -ScriptBlock {
    Get-Service WinDefend | Select-Object Status, StartType
}
```

---

## Quick Start: Update-DefenderOffline.ps1

### Step 1: Download Latest Definitions

On an **internet-connected** machine, download from Microsoft:

| Architecture | URL |
|---|---|
| x64 (most common) | https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64 |
| x86 | https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86 |
| ARM64 | https://go.microsoft.com/fwlink/?LinkID=121721&arch=arm64 |

The downloaded file is always named `mpam-fe.exe`.

### Step 2: Place the File on the Network Share

The share **must** follow this folder structure:

```
<SourceSharePath>\<YYYYMMDD>\v#.###.###.#\mpam-fe.exe
```

**Example:**
```
\\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender\
    20260520\
        v1.449.681.0\
            mpam-fe.exe
```

The script discovers the available version by parsing the `v#.###.###.#` folder name — not by file modification date. Creating a new date/version subfolder for each download keeps the history clean and makes rollback straightforward.

### Step 3: Configure

Edit `conf\config.conf` and set `SourceSharePath` to your base share path:

```
SourceSharePath = \\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender
```

All other settings are optional with sensible defaults. See [Configuration](#configuration) below.

### Step 4: First Run

Open **PowerShell 7 as Administrator** in the script directory:

```powershell
# WhatIf mode first — tests everything without making changes
.\Update-DefenderOffline.ps1 -WhatIfMode

# Live run once WhatIf looks good
.\Update-DefenderOffline.ps1
```

**What happens:**
1. Loads settings from `conf\config.conf`
2. Validates admin privileges
3. Resolves target computers (see [Target Discovery](#target-computer-discovery))
4. Discovers the latest available version from the share
5. For each endpoint: tests WinRM, checks Defender service, compares versions — skips if already current
6. Transfers and silently installs only on endpoints that need updating
7. Generates HTML report and CSV in `.\Reports\`

---

## Target Computer Discovery

Scripts resolve targets in this priority order:

1. **`-ComputerName` parameter** — explicit list, bypasses everything else
2. **`hosts.conf`** — plain-text file in the script directory (auto-generated on first run, then manually maintained)
3. **Active Directory** — queries AD for all enabled Windows computers, auto-creates `hosts.conf`

### hosts.conf Format

```
# One computer name per line. Lines starting with # are ignored.

WORKSTATION01
WORKSTATION02
SERVER01
# TESTLAB-PC01   ← commented out; will be skipped
```

After the first run generates `hosts.conf` from AD, edit it to exclude test/lab machines.

**Install RSAT if AD query fails:**
```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

---

## Configuration

All scripts read `conf\config.conf` at startup. **Command-line parameters always override config values.** The file is a template — fill in your environment values, leave anything you don't need blank.

```
# conf\config.conf — example values

[Common]
SourceSharePath  = \\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender
ExcludeComputers =                      ← comma-separated; skip these endpoints entirely
ParallelThreads  = 16
TimeoutSeconds   = 30
LogPath          = C:\Logs
DisableIPv6      = true                 ← drops unreachable-host detection from ~21s to ~3s

[Update]
TempFolderOnTarget = C:\Temp\Update-DefenderOffline
LogSharePath       =                    ← leave blank to disable centralised log collection
ReportPath         = .\Reports

[Dashboard]
Port            = 8080
FallbackPort    = 8090                  ← 8443 is commonly taken (Tomcat, Splunk); 8090 is safer
RefreshInterval = 300                   ← seconds
DashboardTheme  = Dark                  ← Dark | Light (per-browser toggle overrides this default)

[Install]
TaskName   = DefenderDashboard
TaskFolder = \                          ← e.g. \Security to keep tasks organised

[Credentials]
ClassificationMethod    =               ← AD | Pattern | Single (auto-detected if blank)
WorkstationPattern      = ^(DESKTOP|LAPTOP|WS|WIN10|WIN11)
DomainControllerPattern = ^DC

[Email]
SendEmail  = false
SmtpServer =
SmtpPort   = 25
SmtpUseSsl = false
EmailFrom  = DefenderUpdate@contoso.com
EmailTo    =
```

See `conf\config.conf` for full documentation of every setting.

---

## Update-DefenderOffline.ps1 — Reference

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-SourceSharePath` | *(config or required)* | Base UNC path containing versioned definition subfolders |
| `-ComputerName` | *(auto-discover)* | Manual list of target computers |
| `-TempFolderOnTarget` | `C:\Temp\Update-DefenderOffline` | Temp directory created on each remote system during update |
| `-LogSharePath` | *(disabled)* | UNC path for centralised remote log collection |
| `-LogPath` | `C:\Logs` | Local log directory |
| `-ReportPath` | `.\Reports` | HTML and CSV report output directory |
| `-ParallelThreads` | `16` | Max concurrent threads (PS 7+ only, range 1–32) |
| `-DisableIPv6` | `$true` | Skip IPv6 in reachability tests (drops unreachable-host detection from ~21s to ~3s on LANs that advertise AAAA but don't route IPv6) |
| `-WhatIfMode` | `$false` | Dry-run — no changes made |
| `-Credential` | *(caller context)* | Single WinRM credential for all endpoints when classification isn't needed |
| `-WorkstationCredential` | — | Tier-specific WinRM credential for workstations (used with classification) |
| `-ServerCredential` | — | Tier-specific WinRM credential for member servers |
| `-DomainControllerCredential` | — | Tier-specific WinRM credential for domain controllers |
| `-SaveCredential` | — | Interactive helper; saves WinRM credentials to `conf\*.xml` (DPAPI per-user + per-machine) |
| `-ADCredential` | *(caller context)* | Credential for AD auto-discovery — required in STIG-hardened environments where the running account lacks AD read rights |
| `-SaveADCredential` | — | Interactive helper; saves AD credential to `conf\ADCredential.xml` |
| `-ClassificationMethod` | `AD` *(or `Single` off-domain)* | How to classify endpoints into credential tiers: `AD`, `Pattern`, or `Single` |
| `-WorkstationPattern` | *(see config)* | Regex for workstation hostnames (used with `-ClassificationMethod Pattern`) |
| `-DomainControllerPattern` | `^DC` | Regex for DC hostnames (used with `-ClassificationMethod Pattern`) |
| `-SendEmail` | `$false` | Enable email notification after each run |
| `-SmtpServer` | *(required if -SendEmail)* | SMTP server address |
| `-SmtpPort` | `25` | SMTP port |
| `-SmtpUseSsl` | `$false` | Use SSL/TLS for SMTP |
| `-From` | `DefenderUpdate@contoso.com` | Sender address |
| `-To` | *(required if -SendEmail)* | Recipient address(es) |
| `-SmtpCredential` | *(optional)* | PSCredential for SMTP authentication |
| `-SaveSmtpCredential` | — | Interactive helper; saves encrypted SMTP credentials to `.\conf\SmtpCredential.xml` |
| `-ConfigPath` | `.\conf\config.conf` | Override config file location |

### Email Setup

**Save credentials once (interactive):**
```powershell
.\Update-DefenderOffline.ps1 -SaveSmtpCredential
```
This creates `.\conf\SmtpCredential.xml` encrypted per-user + per-machine via DPAPI. Safe for scheduled tasks running as the same account.

**Production run with email:**
```powershell
$cred = Import-Clixml ".\conf\SmtpCredential.xml"

.\Update-DefenderOffline.ps1 `
    -SendEmail `
    -SmtpServer "smtp.company.com" `
    -SmtpPort 587 `
    -SmtpUseSsl `
    -From "defender@company.com" `
    -To "it-team@company.com","security@company.com" `
    -SmtpCredential $cred
```

### Common Usage Examples

```powershell
# Dry-run (no changes)
.\Update-DefenderOffline.ps1 -WhatIfMode

# Specific computers
.\Update-DefenderOffline.ps1 -ComputerName "PC01","PC02","SRV01"

# Centralised log collection
.\Update-DefenderOffline.ps1 -LogSharePath "\\NAS01\DefenderLogs"

# Maximum parallel threads
.\Update-DefenderOffline.ps1 -ParallelThreads 32
```

### Execution Flow

| Phase | What happens |
|---|---|
| Initialization | Load config, validate admin rights, create output folders |
| Target discovery | CLI → hosts.conf → AD auto-discovery |
| Source discovery | Recurse share, parse `v#.###.###.#` folder names, select highest version |
| Per-endpoint loop | WinRM check → Defender service check → **version compare (skip if current)** → file transfer → silent install → verify → log collection → cleanup |
| Reporting | HTML report, CSV export, email (if configured) |

### Output

**Logs:** `C:\Logs\Update-DefenderOffline_YYYYMMDD_HHmmss.log`

```
2026-05-20 09:15:00 [HEADER] === Microsoft Defender Offline Update v0.0.6 ===
2026-05-20 09:15:00 [INFO]   Parallel Mode : ENABLED (16 threads)
2026-05-20 09:15:01 [SUCCESS] Latest definition version: v1.449.681.0
2026-05-20 09:15:01 [INFO]   Source file   : \\NAS01\...\20260520\v1.449.681.0\mpam-fe.exe
2026-05-20 09:15:30 [INFO]   VersionHistory: WS01 | Old=1.405.233.0 | New=1.449.681.0 | Delta=1012
2026-05-20 09:20:00 [HEADER] UPDATE COMPLETE in 00:05:00
2026-05-20 09:20:00 [HEADER] Success: 48 | Failed: 1 | Skipped: 1 | Total: 50
```

**Per-host logs:** `C:\Logs\PerHost\COMPUTERNAME.log`

**Reports:** `.\Reports\DefenderUpdateReport_YYYYMMDD_HHmmss.html` and `.csv`

---

## Show-DefenderStatus.ps1 — Reference

Opens a live Windows Forms dashboard showing the Defender health status of all endpoints. Requires an interactive desktop session.

```powershell
.\Show-DefenderStatus.ps1
```

**Features:** Fluent-style dark theme matching the HTML report · Colour-coded badges (Healthy / Outdated / Degraded / Offline) · **Clickable stat cards** filter the grid (Online / Offline / Outdated / RT Prot Off) · Name filter · Live query-progress counter (`12/33`) · Manual refresh + auto-refresh with countdown timer · Export CSV · Export HTML

| Parameter | Default | Description |
|---|---|---|
| `-SourceSharePath` | *(config)* | Enables version currency comparison (green/amber colouring) |
| `-ComputerName` | *(auto-discover)* | Query specific computers only |
| `-ParallelThreads` | `16` | Concurrent WinRM queries (PS 7+) |
| `-TimeoutSeconds` | `30` | Per-host query timeout |
| `-DisableIPv6` | `$true` | Skip IPv6 in reachability tests (see Update reference) |
| `-Credential` / `-WorkstationCredential` / `-ServerCredential` / `-DomainControllerCredential` | — | Same tiered WinRM credential model as `Update-DefenderOffline.ps1` |
| `-SaveCredential` | — | Interactive helper; saves WinRM credentials to `conf\*.xml` |
| `-ADCredential` | *(caller context)* | AD-bind credential for hosts.conf auto-discovery in STIG environments |
| `-SaveADCredential` | — | Interactive helper; saves AD credential to `conf\ADCredential.xml` |
| `-ClassificationMethod` / `-WorkstationPattern` / `-DomainControllerPattern` | — | Same classification model as `Update-DefenderOffline.ps1` |
| `-ConfigPath` | `.\conf\config.conf` | Override config file location |

---

## Start-DefenderDashboard.ps1 — Reference

Headless HTTP server that serves a self-refreshing browser dashboard. Designed to run continuously as a Windows Scheduled Task under a service account or gMSA. Use `Install-DefenderDashboard.ps1` to register it as a service.

**Endpoints:**

| Path | Response |
|---|---|
| `/defender` | HTML dashboard with **clickable stat cards** (Online / Offline / Outdated / RT Prot Off filter the table), **light/dark theme toggle** (☀/☾) persisted per-browser via `localStorage`, and meta-refresh aligned with the data-refresh countdown |
| `/status` | JSON snapshot of current fleet data |
| `/health` | Plain-text `OK` liveness probe |
| `/refresh` | Forces immediate background data refresh; redirects to `/defender` |

**Port fallback:** If the configured port is in use at startup, the script automatically tries `FallbackPort` and up to 9 sequential candidates. The actual bound port is written to `conf\dashboard.status` so admins and monitoring tools can always discover it. A Windows Event Log Warning (EventId 101) is also written when a fallback fires.

**Theme priority:** Browser `localStorage` (per-user, persists across visits) > `DashboardTheme` in config.conf (server-supplied default) > script default `Dark`.

```powershell
# Run interactively for testing
.\Start-DefenderDashboard.ps1 -Port 8080

# Then open: http://localhost:8080/defender
```

| Parameter | Default | Description |
|---|---|---|
| `-Port` | `8080` | Primary HTTP port |
| `-FallbackPort` | `8443` | First fallback candidate if primary is in use (config.conf ships `8090` because 8443 collides with Tomcat/Splunk/etc.) |
| `-RefreshInterval` | `300` | Data refresh interval in seconds |
| `-LogPath` | `C:\Logs\DefenderDashboard` | Service log directory |
| `-SourceSharePath` | *(config)* | Enables version currency comparison |
| `-ComputerName` | *(auto-discover)* | Query specific computers only |
| `-ParallelThreads` | `16` | Concurrent WinRM queries per refresh cycle |
| `-TimeoutSeconds` | `30` | Per-host query timeout |
| `-DisableIPv6` | `$true` | Skip IPv6 in reachability tests |
| `-DashboardTheme` | `Dark` | Default theme served to first-time visitors: `Dark` or `Light` |
| `-Credential` | *(caller context)* | WinRM credential for endpoint queries |
| `-SaveCredential` | — | Interactive helper; saves WinRM credential to `conf\WinRmCredential.xml` (run once under the service identity) |
| `-ADCredential` | *(caller context)* | AD-bind credential for hosts.conf auto-discovery in STIG environments |
| `-SaveADCredential` | — | Interactive helper; saves AD credential to `conf\ADCredential.xml` |
| `-ConfigPath` | `.\conf\config.conf` | Override config file location |

---

## Install-DefenderDashboard.ps1 — Reference

One-time installer. Run as Administrator.

**What it does:**
1. Validates prerequisites (pwsh.exe, Task Scheduler)
2. Validates the service account or gMSA in Active Directory
3. Registers the `Manage-DefenderOffline` Windows Event Log source
4. Creates directories and grants filesystem permissions to the service identity
5. Checks port availability; selects fallback automatically if needed
6. Registers a Windows Scheduled Task (AtStartup, no time limit, restart-on-failure)
7. Optionally creates an inbound Windows Firewall rule
8. Optionally starts the task immediately and reads `conf\dashboard.status` to confirm the actual port

**gMSA installation (recommended):**
```powershell
.\Install-DefenderDashboard.ps1 `
    -GmsaName "CONTOSO\svc-defender$" `
    -SourceSharePath "\\NAS01\DataShare\...\Microsoft_Defender" `
    -AddFirewallRule `
    -StartImmediately
```

**Traditional service account:**
```powershell
$cred = Get-Credential -UserName "CONTOSO\svc-defender" -Message "Service account password"
.\Install-DefenderDashboard.ps1 `
    -ServiceAccount "CONTOSO\svc-defender" `
    -Credential $cred `
    -AddFirewallRule `
    -StartImmediately
```

| Parameter | Default | Description |
|---|---|---|
| `-GmsaName` | — | gMSA in `DOMAIN\name$` format. No password required. |
| `-ServiceAccount` | — | Traditional account in `DOMAIN\user` format. Requires `-Credential`. |
| `-Credential` | — | PSCredential for the service account. Not used with gMSA. |
| `-Port` | `8080` | Primary port (checked for availability at install time) |
| `-FallbackPort` | `8443` | Fallback if primary is in use |
| `-RefreshInterval` | `300` | Passed to Start-DefenderDashboard.ps1 |
| `-TaskName` | `DefenderDashboard` | Scheduled task name |
| `-TaskFolder` | `\` | Task Scheduler folder |
| `-AddFirewallRule` | — | Create inbound TCP rule for the dashboard port |
| `-StartImmediately` | — | Start task after registration and verify via status file |
| `-Force` | — | Overwrite existing task without prompting; replaces existing firewall rule if `-AddFirewallRule` is supplied |
| `-SaveCredential` | — | Pass-through to `Start-DefenderDashboard.ps1`; saves WinRM credential under the running identity |
| `-ConfigPath` | `.\conf\config.conf` | Override config file location |

The installer prints a tailored "Useful commands" block at the end of every run. If `TaskFolder` is non-root, those commands include `-TaskPath` because `Get-ScheduledTask -TaskPath` requires the **trailing backslash** (`'\WGSDAC\'`, not `'\WGSDAC'`).

**Manage the installed service** (substitute the `-TaskPath` value the installer printed):
```powershell
# Root folder (TaskFolder = '\') — no -TaskPath required
Start-ScheduledTask  -TaskName 'DefenderDashboard'
Stop-ScheduledTask   -TaskName 'DefenderDashboard'
Get-ScheduledTask    -TaskName 'DefenderDashboard' | Select-Object State, LastRunTime, LastTaskResult
Unregister-ScheduledTask -TaskName 'DefenderDashboard' -Confirm:$false

# Non-root folder (e.g. TaskFolder = '\Security') — trailing backslash required
Get-ScheduledTask -TaskName 'DefenderDashboard' -TaskPath '\Security\' |
    Select-Object State, LastRunTime, LastTaskResult
```

**Initial collection delay:** The dashboard runs its first fleet collection synchronously after `HttpListener.Start()` and before entering the request loop, so `/health` won't respond until that pass finishes (~0.5s per host). The installer's `-StartImmediately` probe retries up to 6× / 10s each to accommodate large fleets.

---

## Troubleshooting

### ❌ "This script requires administrative privileges"

Run PowerShell as Administrator (right-click → Run as Administrator).

```powershell
# Verify elevation
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
# Must return: True
```

---

### ❌ "WinRM (5985) not reachable"

Enable PowerShell Remoting on the target:

```powershell
# On the target computer
Enable-PSRemoting -Force

# Verify from admin machine
Test-NetConnection -ComputerName TARGETPC -Port 5985
```

**Via Group Policy:**
`Computer Configuration → Policies → Administrative Templates → Windows Components → Windows Remote Management (WinRM) → WinRM Service → Allow remote server management through WinRM`

---

### ❌ "Cannot proceed without target list"

AD query failed and no `hosts.conf` exists. Create `hosts.conf` manually:

```powershell
@"
WORKSTATION01
WORKSTATION02
SERVER01
"@ | Out-File -FilePath ".\hosts.conf" -Encoding UTF8
```

Or use `-ComputerName` to bypass discovery entirely.

---

### ❌ Source file not found / no versioned folder detected

Verify the share structure matches the required pattern:
```
<SourceSharePath>\<YYYYMMDD>\v#.###.###.#\mpam-fe.exe
```

```powershell
# Check what the script will find
Get-ChildItem "\\NAS01\YourShare" -Recurse -Filter mpam-fe.exe |
    Select-Object FullName, @{n='VersionFolder'; e={ $_.Directory.Name }}
# VersionFolder must match: v#.###.###.#
```

---

### ❌ "Access is denied" on target

```powershell
# Verify admin rights reach the target
Invoke-Command -ComputerName TARGETPC -ScriptBlock {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}
# Must return: True

# Workgroup environments — add to TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "TARGETPC" -Concatenate -Force
```

---

### ❌ "Windows Defender service not running"

```powershell
# On the target computer
Start-Service WinDefend
Set-Service WinDefend -StartupType Automatic
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled
```

---

### ❌ Dashboard not responding / wrong port

Check the runtime status file for the actual bound port:

```powershell
Get-Content ".\conf\dashboard.status"
# Port=8443  ← if fallback was used
```

Check the Windows Event Log:
```powershell
Get-EventLog -LogName Application -Source 'Manage-DefenderOffline' -Newest 5 |
    Select-Object EventID, EntryType, Message
# EventId 101 = started on fallback port (Warning)
# EventId 100 = started on primary port
# EventId 102 = stopped
```

Check the dashboard service log:
```powershell
Get-Content "C:\Logs\DefenderDashboard\DefenderDashboard_$(Get-Date -f yyyyMMdd).log" -Tail 20
```

---

### ⚠️ Email not sending

```powershell
# Test SMTP connectivity
Test-NetConnection -ComputerName smtp.company.com -Port 587

# Re-save credentials if authentication is failing
.\Update-DefenderOffline.ps1 -SaveSmtpCredential
```

**Common SMTP ports:** 25 (relay, no SSL) · 587 (STARTTLS, use `-SmtpUseSsl`) · 465 (SSL, use `-SmtpUseSsl`)

---

### ⚠️ Slow performance

```powershell
# Reduce threads if network is saturated
.\Update-DefenderOffline.ps1 -ParallelThreads 8

# Or set in conf\config.conf:
# ParallelThreads = 8
```

---

## Performance Benchmarks

Approximate times for `Update-DefenderOffline.ps1` with a ~200 MB definition file:

| Computers | PS 5.1 (Serial) | PS 7+ (8 threads) | PS 7+ (16 threads) | PS 7+ (32 threads) |
|---|---|---|---|---|
| 10 | ~3 min | ~2 min | ~1 min | ~1 min |
| 50 | ~15 min | ~8 min | ~4 min | ~3 min |
| 100 | ~30 min | ~15 min | ~8 min | ~5 min |
| 250 | ~75 min | ~40 min | ~20 min | ~12 min |
| 500 | ~150 min | ~80 min | ~40 min | ~25 min |
| 1000 | ~300 min | ~160 min | ~80 min | ~50 min |

*Assumes 15–20 seconds per computer on a 1 Gbps network with no connectivity failures.*

**Recommendations:**
- **< 50 computers:** PS 5.1 or PS 7+ with 8 threads
- **50–250 computers:** PS 7+ with 16 threads (default)
- **250–500 computers:** PS 7+ with 24 threads
- **500+ computers:** PS 7+ with 32 threads; consider splitting by site

---

## Version History

### v0.0.6 (2026-05-24) — Current

**New scripts:**
- ✨ `Show-DefenderStatus.ps1` — interactive Windows Forms fleet monitor with Fluent-style theme, clickable stat cards that filter the grid, live query-progress counter, and auto-refresh countdown
- ✨ `Start-DefenderDashboard.ps1` — headless HTTP dashboard with auto-refresh, JSON endpoint, port fallback, light/dark theme toggle (config-supplied default + per-browser localStorage override), and clickable stat-card filtering
- ✨ `Install-DefenderDashboard.ps1` — scheduled task installer supporting gMSA and traditional service accounts; registers Windows Event Log source, sets ACLs, optional firewall rule, optional immediate start with `/health` retry probe

**Configuration system (`conf/config.conf`):**
- ✨ Central configuration with `[Common]`, `[Update]`, `[Dashboard]`, `[Install]`, `[Credentials]`, `[Email]` sections
- ✨ `DisableIPv6` — drops unreachable-host detection from ~21s to ~3s on LANs that advertise AAAA records but don't route IPv6
- ✨ `DashboardTheme` — server-supplied default theme for first-time visitors
- ✨ `ExcludeComputers` — comma-separated list to bypass entirely (e.g. third-party AV endpoints)

**Update script (`Update-DefenderOffline.ps1`):**
- ✨ Version discovery now parses `v#.###.###.#` folder name (removed `-MpamFileName` parameter)
- ✨ Pre-transfer version check — endpoints already current are skipped without file transfer
- ✨ Unified execution path for parallel and serial modes
- ✨ Tiered WinRM credentials (`-Credential` / `-WorkstationCredential` / `-ServerCredential` / `-DomainControllerCredential`) with AD-, Pattern-, or Single-based classification
- ✨ `-ADCredential` / `-SaveADCredential` — DPAPI-encrypted AD-bind credential for STIG-hardened environments where the running account lacks AD read rights
- ✨ Email backend rewritten on top of `System.Net.Mail.SmtpClient` (Send-MailMessage deprecated in PS7); UTF-8 pinned for Subject/Body/Headers; attachment paths resolved to absolute before passing to `MailMessage`
- ✨ HTML report uses semantic table-based Fleet Version Summary that renders correctly in Gmail (CSS Grid was stripped)
- 🐛 Fixed version delta calculation (was always `Unknown`)
- 🐛 Fixed version sorting (was string-based, not version-based)
- 🐛 Fixed log collection copying wrong files
- 🐛 Fixed HTML report referencing unpopulated columns
- 🐛 Fixed `$ScriptVersion` hardcoded as `0.0.1`
- 🐛 Fixed HTML report badge-filter hiding the column header row

**Dashboard service (`Start-DefenderDashboard.ps1`):**
- ✨ Async `BeginGetContext` request loop (HttpListener has no `Pending()` method)
- ✨ Port availability check with automatic fallback; `conf/dashboard.status` runtime file
- ✨ Windows Event Log integration (EventId 100 = started normally, 101 = fallback port, 102 = stopped)
- ✨ Meta-refresh aligned with countdown so the page reload always fires shortly after "Next refresh in: 0s"

**Installer (`Install-DefenderDashboard.ps1`):**
- ✨ `Manage-DefenderOffline` event log source registration
- ✨ ACL grants to the service identity (script folder + conf + log path)
- ✨ Optional `-AddFirewallRule` (Inbound TCP, Domain+Private profiles); `-Force` replaces an existing rule
- ✨ `-StartImmediately` waits up to 45s for `dashboard.status`, then probes `/health` with retries
- ✨ Normalizes `TaskFolder` with trailing backslash so `Get-ScheduledTask -TaskPath` matches

### v0.0.1 (2025-12-18) — Initial Release

- Initial alpha release
- Administrative privilege validation
- Parallel mode with PS 7+ thread jobs
- HTML reports and optional email notification

### Planned Features

- Integration with Windows Update Service API
- Support for multiple definition file formats (FEP, NIS)
- Rollback capability for failed updates
- Integration with monitoring systems (SCOM, Splunk)

---

## Best Practices

### Production Deployments

1. **Test with `-WhatIfMode` first** — validates connectivity and version detection without touching endpoints
2. **Use a dedicated service account or gMSA** — never run scheduled tasks as a personal admin account
3. **Set `SourceSharePath` in `conf\config.conf`** — eliminates the need to repeat it on every command line
4. **Schedule for off-peak hours** (e.g., 2 AM) to avoid impacting users
5. **Monitor the HTML reports** for failure trends; investigate hard failures promptly

### Network Share Management

- Keep the 2–3 most recent definition versions; archive or delete older ones
- Use the `<YYYYMMDD>\v#.###.###.#\` folder structure consistently for every download
- Monitor share disk space (~200 MB per version)

### Security

- Use Group Managed Service Accounts (gMSA) where possible — no password rotation required
- SMTP credentials stored via `Export-Clixml` use DPAPI (per-user + per-machine) — never commit `conf\SmtpCredential.xml` to version control (`.gitignore` excludes `*.xml`)
- Restrict `-LogSharePath` write access to the service account only

---

## Contributing

Contributions welcome. Please open an issue before submitting a large pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes
4. Push and open a Pull Request

---

## License

MIT — see [LICENSE.txt](LICENSE.txt)

## Author

**Kismet Agbasi** · [GitHub](https://github.com/kismetgerald) · KismetG17@gmail.com

*AI Contributors: Claude AI, Grok*

## Documentation

- [Quick Reference](README.md) — this file
- [Architecture](ARCHITECTURE.md) — system overview, lifecycles, runtime state, design decisions

**Getting Help:**
- [GitHub Issues](https://github.com/kismetgerald/Manage-DefenderOffline/issues) — bug reports and feature requests
- [Discussions](https://github.com/kismetgerald/Manage-DefenderOffline/discussions) — questions and community support

---

**⭐ If this project helps you, please consider giving it a star!**

# Quick Start — Dashboard in under 10 minutes

Get the Defender fleet dashboard running and reachable from a remote workstation.
For full reference, see [README.md](README.md).

---

## What you'll have at the end

A browser-accessible HTTPS dashboard at `https://<host>:8444/defender` showing
per-host Defender health for every Windows endpoint discovered via AD (or a
`hosts.conf` subset you supply). Auto-refreshes every 5 minutes. Survives reboots.

---

## Prerequisites

**On the host that will run the dashboard:**
- Windows 10/11 or Windows Server 2016+
- **PowerShell 7+** ([download](https://github.com/PowerShell/PowerShell/releases))
- **Local Administrator** rights for the install
- A **service account** (or gMSA) that is a local administrator on every endpoint
  you want to monitor. The same account needs network access to those endpoints
  over **WinRM (TCP 5985)**.

**On each target endpoint** (one-time, do this first if not already done):
```powershell
Enable-PSRemoting -Force
```
…or do it at scale via GPO:
`Computer Configuration → Policies → Administrative Templates →
Windows Components → Windows Remote Management (WinRM) → WinRM Service →
Allow remote server management through WinRM`

---

## Step 1 — Download and extract (1 min)

In an **elevated PowerShell 7** window on the dashboard host:

```powershell
$Zip = "$env:TEMP\manage-defenderoffline-0.0.12.zip"

Invoke-WebRequest `
    -Uri 'https://github.com/kismetgerald/Manage-DefenderOffline/releases/download/v0.0.12/manage-defenderoffline-0.0.12.zip' `
    -OutFile $Zip

Expand-Archive -Path $Zip -DestinationPath 'C:\Tools' -Force
Set-Location 'C:\Tools\manage-defenderoffline'
```

---

## Step 2 — Configure (2 min)

Open `conf\config.conf` in Notepad and set, at minimum:

```ini
# [Common] section
SourceSharePath = \\NAS01\Share\_AVDefinitions\Microsoft_Defender

# [Dashboard] section
Port     = 8444
UseHttps = true
```

`SourceSharePath` enables the *Outdated* badge by comparing each endpoint's
signature version against the latest in the share. Skip it if you don't have
one yet — the dashboard still shows health pills, just without the currency
comparison.

Everything else in `config.conf` has sensible defaults. Tune later from the
[README](README.md#configuration).

---

## Step 3 — Install (2 min)

### Option A — Traditional service account

```powershell
$cred = Get-Credential `
    -UserName 'CONTOSO\svc-defender' `
    -Message 'Password for the dashboard service account'

.\Install-DefenderDashboard.ps1 `
    -ServiceAccount 'CONTOSO\svc-defender' `
    -Credential     $cred `
    -UseHttps `
    -Port           8444 `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

### Option B — gMSA (no password needed)

```powershell
.\Install-DefenderDashboard.ps1 `
    -GmsaName       'CONTOSO\svc-defender$' `
    -UseHttps `
    -Port           8444 `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

What the installer does (~30 seconds end-to-end):
- Generates a self-signed TLS cert (or reuses an existing one via `-CertificateThumbprint <thumb>`)
- Binds the cert to port 8444 via `netsh http add sslcert`
- Registers a scheduled task that runs the dashboard at system startup as the service identity
- Creates inbound Windows Firewall rules for TCP 8444 (Domain + Private profiles)
- Starts the task and probes `https://localhost:8444/health` for `200 OK`

---

## Step 4 — Verify (30 sec)

Browser test from the dashboard host:

```powershell
Start-Process 'https://localhost:8444/defender'
```

You should see the fleet grid with per-host pills:

| Pill | Meaning |
|---|---|
| **Healthy** (green) | All Defender protections on, no recent threats |
| **ThreatsDetected** (red) | One or more quarantined detections in the last 24h |
| **Degraded** (amber) | At least one protection toggle is off (e.g. RT disabled) |
| **Offline** (grey) | WinRM unreachable |
| **ProbeFailed** (grey) | WinRM reached but health probe threw |

If the page doesn't load, check the dashboard log:

```powershell
Get-Content "C:\Logs\DefenderDashboard\DefenderDashboard_$(Get-Date -Format yyyyMMdd).log" -Tail 30
```

Expected lines:
- `[SUCCESS] HTTPS pre-flight: Cert <thumb> is bound to 0.0.0.0:8444.`
- `[SUCCESS] HTTPS listener started on https://+:8444/`
- `[SUCCESS] Initial collection complete: N computers`

Common errors are self-diagnosing — if you see `[ERROR] HTTPS pre-flight FAILED`
or `[WARN] URL-ACL collision`, the log includes the exact `netsh` command to fix it.

---

## Step 5 — Access from a remote workstation (30 sec)

From any workstation on the same network, browse to:

```
https://<dashboard-hostname>:8444/defender
```

**The browser will warn about an untrusted certificate** because the installer
generates a self-signed cert by default. Click **Advanced → Proceed** for testing.

For production, replace with a PKI-issued cert:

```powershell
# On the dashboard host, after importing your PKI cert into Cert:\LocalMachine\My:
.\Install-DefenderDashboard.ps1 `
    -ServiceAccount         'CONTOSO\svc-defender' `
    -Credential             $cred `
    -UseHttps `
    -CertificateThumbprint  '<new-thumbprint>' `
    -Port                   8444 `
    -Force
```

If the page doesn't load from a remote workstation at all:

```powershell
# Run this from the workstation
Test-NetConnection -ComputerName <dashboard-host> -Port 8444
# Expected: TcpTestSucceeded : True
```

If `False`, the dashboard host's firewall is blocking TCP 8444 on the network
profile the remote workstation is connecting from. The installer enables
**Domain + Private** profiles; if your network is on the **Public** profile,
add it manually:

```powershell
# On the dashboard host
Set-NetFirewallRule -DisplayName 'DefenderDashboard-HTTPS-8444' -Profile Domain,Private,Public
```

---

## What's next

- **Lock down access** — the default `AuthMethod = None` allows anonymous
  access. Set `AuthMethod = ADIntegrated` in `conf\config.conf` plus
  `AuthAllowedGroups = Domain Admins,Helpdesk` to restrict to specific AD groups.
  See the [README authentication section](README.md#start-defenderdashboardps1-reference).
- **Deploy definition updates** — `Update-DefenderOffline.ps1` is the
  complementary script for pushing signature updates to the same fleet.
  Quick test: `.\Update-DefenderOffline.ps1 -WhatIfMode`. Full reference in the README.
- **Interactive monitor** — `Show-DefenderStatus.ps1` is a Windows Forms GUI
  variant of the same dashboard for desktop use (admin workstation).
- **Workgroup environments** — if your endpoints are not domain-joined, use
  a `hosts.conf` file instead of AD discovery. See
  [README → Workgroup deployments](README.md#workgroup-deployments).

---

## Common installer parameters reference

| Parameter | What it does | When to set |
|---|---|---|
| `-Port` | TCP port for HTTPS listener (default 8080) | Always specify; 8443 is often taken, 8444 is a safe pick |
| `-UseHttps` | Enable TLS | Recommended for any non-local use |
| `-CertificateThumbprint` | Reuse an existing cert from `Cert:\LocalMachine\My` | When you have a PKI-issued cert, or upgrading and want to keep the same cert |
| `-AddFirewallRule` | Open inbound TCP `Port` on Domain + Private profiles | Almost always |
| `-StartImmediately` | Start the task right after registration + probe `/health` | Recommended — proves the install works |
| `-Force` | Overwrite an existing task with the same name | When re-installing or upgrading |
| `-SourceSharePath` | UNC path for the definitions share (also config-driven) | When you want the *Outdated* pill |
| `-ServiceAccount` + `-Credential` | Traditional account | One or the other — they're mutually exclusive |
| `-GmsaName` | Group Managed Service Account (ends with `$`) | Preferred — no password to rotate |

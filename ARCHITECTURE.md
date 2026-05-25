# Manage-DefenderOffline — Architecture

This document describes how the four scripts, shared configuration, runtime state, and external systems fit together. It complements [README.md](README.md), which is the user-facing quick reference for installing and operating the toolkit.

Read this when you need to understand **why** something is the way it is, or how a change to one component will ripple through the rest of the system.

---

## 1. System Overview

```mermaid
flowchart LR
    classDef script fill:#dff6dd,stroke:#107c10,color:#000
    classDef infra  fill:#eee5f7,stroke:#5c2d91,color:#000
    classDef state  fill:#fff4ce,stroke:#ca5010,color:#000
    classDef ext    fill:#edebe9,stroke:#605e5c,color:#000

    subgraph admin["Admin / Operator workstation"]
        update["Update-DefenderOffline.ps1<br/>(scheduled or manual)"]:::script
        show["Show-DefenderStatus.ps1<br/>(interactive Forms GUI)"]:::script
        installer["Install-DefenderDashboard.ps1<br/>(one-time, elevated)"]:::script
    end

    subgraph dashHost["Dashboard host (continuous service)"]
        dashboard["Start-DefenderDashboard.ps1<br/>(Scheduled Task / gMSA or svc acct)"]:::script
        task[("Task Scheduler<br/>AtStartup, restart-on-failure")]:::infra
        evtlog[("Windows Event Log<br/>source: Manage-DefenderOffline")]:::infra
        fw[("Windows Firewall<br/>Inbound TCP rule")]:::infra
    end

    subgraph shared["Shared on-disk state (script folder)"]
        cfg[/"conf/config.conf"/]:::state
        hosts[/"hosts.conf"/]:::state
        creds[/"conf/*.xml<br/>(DPAPI credentials)"/]:::state
        status[/"conf/dashboard.status<br/>(runtime port)"/]:::state
        reports[/".\Reports\<br/>HTML + CSV"/]:::state
    end

    subgraph external["External systems"]
        share[("\\\\NAS\\...\\YYYYMMDD\\v#.#.#.#\\<br/>mpam-fe.exe")]:::ext
        ad[("Active Directory")]:::ext
        targets[("Target endpoints<br/>WinRM TCP 5985")]:::ext
        smtp[("SMTP server")]:::ext
        browser(["Browser clients"]):::ext
    end

    cfg -.->|read by| update
    cfg -.->|read by| show
    cfg -.->|read by| dashboard
    cfg -.->|read by| installer

    creds -.->|DPAPI decrypt| update
    creds -.->|DPAPI decrypt| show
    creds -.->|DPAPI decrypt| dashboard

    update --> ad
    show --> ad
    dashboard --> ad
    ad --> hosts

    update --> share
    dashboard --> share

    update -->|WinRM| targets
    show -->|WinRM| targets
    dashboard -->|WinRM| targets

    update -->|HTML + CSV| reports
    update -->|optional| smtp

    installer -->|register| task
    installer -->|register source| evtlog
    installer -->|optional| fw
    task -->|launches| dashboard
    dashboard -->|writes| status
    dashboard -->|writes 100/101/102| evtlog
    installer -.->|reads on -StartImmediately| status

    dashboard -->|HTTP :8080/defender| browser
```

**Legend:** 🟢 green = toolkit scripts · 🟣 purple = Windows infrastructure · 🟡 amber = shared on-disk state · ⚪ gray = external systems

**Component responsibilities:**

| Component | Owns | Reads but doesn't own |
|---|---|---|
| `Update-DefenderOffline.ps1` | Per-host install logs, HTML/CSV reports, email | config, hosts.conf, credentials, share, AD |
| `Show-DefenderStatus.ps1` | Forms GUI, ad-hoc CSV/HTML export | config, hosts.conf, credentials, AD |
| `Start-DefenderDashboard.ps1` | `conf/dashboard.status`, dashboard log, event log writes | config, hosts.conf, credentials, AD |
| `Install-DefenderDashboard.ps1` | Scheduled task, event log source registration, ACLs, firewall rule | config, dashboard.status (read after start) |

---

## 2. Update Lifecycle (`Update-DefenderOffline.ps1`)

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant Script as Update-DefenderOffline.ps1
    participant Config as conf/config.conf
    participant AD
    participant Share as \\NAS\...\mpam-fe.exe
    participant Target as Target endpoint (WinRM)
    participant LogShare as LogSharePath (optional)
    participant SMTP

    Admin->>Script: .\Update-DefenderOffline.ps1 [-WhatIfMode]
    Script->>Config: Read-ConfigFile
    Script->>Script: Validate admin rights
    alt -ComputerName supplied
        Script->>Script: Use CLI list
    else hosts.conf exists
        Script->>Script: Read hosts.conf
    else
        Script->>AD: Auto-discover (-ADCredential if set)
        AD-->>Script: Computer list
        Script->>Script: Write hosts.conf
    end
    Script->>Share: Enumerate \YYYYMMDD\v#.#.#.#\ folders
    Share-->>Script: Latest version + file path

    loop For each target (parallel PS7+ / serial PS5.1)
        Script->>Target: TCP 5985 reachability (IPv4-only if DisableIPv6)
        Target-->>Script: reachable / timeout
        opt Reachable
            Script->>Target: Get-Service WinDefend
            Script->>Target: Read SignatureVersion
            alt Version >= Available
                Script->>Script: Mark "No Update Needed" (no transfer)
            else
                Script->>Target: Copy mpam-fe.exe to TempFolderOnTarget
                Script->>Target: mpam-fe.exe /q (silent install)
                Script->>Target: Re-read SignatureVersion
                opt LogSharePath set
                    Target->>LogShare: Copy install logs
                end
                Script->>Target: Remove temp folder
            end
        end
        Note right of Script: Soft failures retried up to 3 times. Hard failures such as offline or access denied skip retry
    end

    Script->>Script: Compute fleet analytics (oldest/newest/avg delta)
    Script->>Script: Write HTML + CSV to .\Reports\
    opt SendEmail = true
        Script->>SMTP: SmtpClient SendMail (UTF-8 pinned)
    end
    Script-->>Admin: Summary (Success / Failed / Skipped / Total)
```

**Skip-without-transfer is the central optimisation.** A host whose installed `SignatureVersion` already matches or exceeds the latest available version is marked `No Update Needed` *before* the ~200 MB file copy. This is what makes the script tolerable on large fleets where the majority of hosts are already current.

---

## 3. Dashboard Service Lifecycle

### 3a. Install → first start

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant Installer as Install-DefenderDashboard.ps1
    participant TS as Task Scheduler
    participant FS as Filesystem (script + conf + logs)
    participant FW as Windows Firewall
    participant EL as Event Log
    participant Dashboard as Start-DefenderDashboard.ps1
    participant Status as conf/dashboard.status

    Admin->>Installer: .\Install-DefenderDashboard.ps1<br/>-ServiceAccount X -Credential c<br/>-AddFirewallRule -StartImmediately
    Installer->>Installer: Prereq checks (admin, pwsh.exe, dashboard script)
    Installer->>EL: Register source 'Manage-DefenderOffline'
    Installer->>Installer: Validate AD account exists
    Installer->>FS: Create dirs, grant ACLs (RX on script, Modify on conf + log)
    Installer->>Installer: Test-PortFree then select primary or fallback
    Installer->>TS: Register-ScheduledTask (AtStartup, LogonType=Password, RunLevel=Highest)
    opt -AddFirewallRule
        Installer->>FW: New-NetFirewallRule (Inbound TCP, Domain+Private)
    end
    opt -StartImmediately
        Installer->>TS: Start-ScheduledTask
        TS->>Dashboard: pwsh.exe -File ... (under service identity)
        Dashboard->>Dashboard: Read config, resolve targets, find available version
        Dashboard->>Dashboard: HttpListener.Start (primary or auto-fallback)
        Dashboard->>Status: Write Port, IsFallback, ProcessId, Hostname
        Dashboard->>EL: EventId 100 (or 101 if fallback)
        Dashboard->>Dashboard: Initial fleet collection (synchronous, ~0.5s/host)
        Dashboard->>Dashboard: Enter main request loop
        loop Up to 6 retries of 10s each
            Installer->>Dashboard: GET /health
            alt 200 OK
                Dashboard-->>Installer: OK
            else timeout
                Installer->>Installer: Sleep 5s, retry
            end
        end
        Installer-->>Admin: Print "Useful commands" + final URLs
    end
```

### 3b. Steady-state request loop

```mermaid
sequenceDiagram
    autonumber
    participant Listener as HttpListener
    participant MainLoop as Main request loop
    participant Job as Background refresh job
    participant Browser
    participant Status as conf/dashboard.status

    MainLoop->>MainLoop: Determine if refresh due (NextRefresh < now AND no job running)
    opt Refresh due
        MainLoop->>Job: Start ForEach-Object -Parallel (N threads)
        Note right of Job: Asynchronous. Does NOT block request handling
    end

    MainLoop->>Listener: BeginGetContext (async)
    MainLoop->>MainLoop: AsyncWaitHandle.WaitOne(500ms)
    alt Request arrived
        Browser->>Listener: GET /defender or /status or /health or /refresh
        Listener->>MainLoop: EndGetContext yields context
        MainLoop->>Browser: Render HTML / JSON / "OK" / redirect
    else No request in 500ms
        MainLoop->>MainLoop: Tick to check refresh status again
    end

    opt Refresh complete (job state = Completed)
        Job-->>MainLoop: New fleet data
        MainLoop->>MainLoop: Atomic swap into $script:CurrentData
    end

    Note over MainLoop: Ctrl+C / Stop-ScheduledTask triggers cleanup
    MainLoop->>Status: Delete conf/dashboard.status
    MainLoop->>MainLoop: EventId 102 (Stopped)
```

**Why `BeginGetContext` + `WaitOne(500)`:** the previous attempt used `HttpListener.Pending()` (which doesn't exist) and the obvious `GetContext()` (which blocks forever). The async pattern with a 500 ms wait keeps the loop responsive enough to check the background refresh job's state and to handle `Ctrl+C` cleanly, without busy-looping.

**Why the initial collection is synchronous before the request loop:** the first `/defender` GET would otherwise return an empty grid. Cost: the listener accepts TCP connections during init but won't respond to HTTP until the loop starts, which is why the installer's `/health` probe retries.

---

## 4. Credential & Classification Model

The Update and Show scripts can use **per-tier credentials** so that a workstation-admin account isn't sent to a domain controller (and vice versa). The dashboard service uses a single WinRM credential for simplicity.

```mermaid
flowchart TD
    classDef startEnd fill:#cce4f7,stroke:#0078d4,color:#000,stroke-width:2px
    classDef decision fill:#fff4ce,stroke:#ca5010,color:#000
    classDef method   fill:#dff6dd,stroke:#107c10,color:#000
    classDef tierWs   fill:#cfe5cc,stroke:#107c10,color:#000
    classDef tierSrv  fill:#fde7c4,stroke:#ca5010,color:#000
    classDef tierDc   fill:#f7c8c5,stroke:#a4262c,color:#000
    classDef cred     fill:#eee5f7,stroke:#5c2d91,color:#000

    start([Need to query host X]):::startEnd --> hasCfg{ClassificationMethod set?}:::decision
    hasCfg -- "blank (auto)" --> autoDetect{Machine domain-joined?}:::decision
    autoDetect -- yes --> useAD[Use AD method]:::method
    autoDetect -- no --> useSingle[Use Single method]:::method
    hasCfg -- AD --> useAD
    hasCfg -- Pattern --> usePattern[Use Pattern method]:::method
    hasCfg -- Single --> useSingle

    useAD --> adQuery[Query AD: OperatingSystem + userAccountControl bit 0x2000]:::method
    adQuery --> adTier{OS / DC flag}:::decision
    adTier -- "Workstation OS" --> ws
    adTier -- "Server OS, not DC" --> srv
    adTier -- "Server OS, DC bit set" --> dc

    usePattern --> patternMatch{Hostname matches…}:::decision
    patternMatch -- WorkstationPattern --> ws
    patternMatch -- DomainControllerPattern --> dc
    patternMatch -- "no match" --> srv

    useSingle --> single[Use -Credential or conf/WinRmCredential.xml]:::cred
    single --> done([Connect via WinRM]):::startEnd

    ws[Tier: Workstation]:::tierWs --> wsCred[Use -WorkstationCredential or conf/WorkstationCredential.xml]:::cred
    srv[Tier: Member Server]:::tierSrv --> srvCred[Use -ServerCredential or conf/ServerCredential.xml]:::cred
    dc[Tier: Domain Controller]:::tierDc --> dcCred[Use -DomainControllerCredential or conf/DomainControllerCredential.xml]:::cred

    wsCred --> done
    srvCred --> done
    dcCred --> done
```

**Legend:** 🟦 blue = start/end · 🟡 yellow = decision · 🟢 green = method/workstation · 🟠 orange = member server · 🔴 red = domain controller · 🟣 purple = credential file

**`-ADCredential` is separate.** It controls *how the script binds to AD for hosts.conf discovery*, not which credential is sent to the target endpoint. It exists for STIG-hardened environments where the running account has WinRM rights on endpoints but no AD read rights. Saved to `conf/ADCredential.xml` via DPAPI.

---

## 5. Runtime State & Event Log Contract

### On-disk runtime state

| File | Owner | Lifecycle | Purpose |
|---|---|---|---|
| `conf/config.conf` | Operator (committed to git) | Persistent | All script defaults |
| `hosts.conf` | First script run (gitignored) | Persistent, editable | Target computer list |
| `conf/WinRmCredential.xml` | `-SaveCredential` (DPAPI) | Persistent | Single WinRM credential |
| `conf/WorkstationCredential.xml` | `-SaveCredential` (DPAPI) | Persistent | Workstation-tier credential |
| `conf/ServerCredential.xml` | `-SaveCredential` (DPAPI) | Persistent | Member-server-tier credential |
| `conf/DomainControllerCredential.xml` | `-SaveCredential` (DPAPI) | Persistent | DC-tier credential |
| `conf/ADCredential.xml` | `-SaveADCredential` (DPAPI) | Persistent | AD-bind credential |
| `conf/SmtpCredential.xml` | `-SaveSmtpCredential` (DPAPI) | Persistent | SMTP credential |
| `conf/dashboard.status` | Dashboard process | **Created on start, deleted on clean stop** | Runtime port + PID; installer reads on `-StartImmediately`, ops scripts read to discover actual port |
| `C:\Logs\Update-DefenderOffline_*.log` | Update script | One per run | Update execution log |
| `C:\Logs\PerHost\<HOST>.log` | Update script (parallel mode) | One per host per run | Per-host install log |
| `C:\Logs\DefenderDashboard\DefenderDashboard_YYYYMMDD.log` | Dashboard service | Rolling daily | Dashboard service log |
| `.\Reports\DefenderUpdateReport_*.html` / `.csv` | Update script | One per run | Operator-facing reports |

**DPAPI credentials are scoped to the *user who saved them, on the machine where they were saved*.** A scheduled task running under `DOMAIN\svc-defender` cannot read a credential file saved by `DOMAIN\kismet`. That's why the installer has `-SaveCredential` (delegated to `Start-DefenderDashboard.ps1`) — it has to run as the service identity.

### Windows Event Log contract

Source: `Manage-DefenderOffline` · Log: `Application`

| EventId | Severity | When | Used by |
|---|---|---|---|
| **100** | Information | Dashboard started on the primary port | Ops monitoring (success heartbeat) |
| **101** | **Warning** | Dashboard started on a fallback port (primary was in use) | Ops monitoring (alert: investigate primary port collision) |
| **102** | Information | Dashboard stopped cleanly | Ops monitoring (uptime tracking) |

The source is registered once by `Install-DefenderDashboard.ps1`. Dashboard runs gracefully degrade if the source is missing — they log to the file log and continue. This is intentional so the dashboard can be run interactively from a non-elevated session for testing without forcing event log registration.

### Dashboard ↔ installer handshake

The `conf/dashboard.status` file is the **only** machine-readable contract between the installer's `-StartImmediately` probe and the running dashboard service. It uses the same key-value format as `config.conf` so `Read-ConfigFile` can parse both. Fields:

```ini
Port        = 8080      ; actually-bound port (may differ from configured Port)
PrimaryPort = 8080      ; the configured primary
IsFallback  = False     ; True if primary was in use and FallbackPort/sequential was selected
StartTime   = 2026-05-24T12:29:53
ProcessId   = 12345
Hostname    = HOME-DH01
```

The installer waits up to 45 s for this file, then performs an HTTP `/health` probe (retried up to 6 × 10 s). The status file is deleted on `Stop-ScheduledTask` or `Ctrl+C` so its mere presence implies a live service.

---

## 6. Design Decisions Worth Knowing

| Decision | Why | Where it bites |
|---|---|---|
| Theme priority is `localStorage` > config > script default | A user's per-browser preference shouldn't be silently overridden every time an admin flips the server-side default | Operators expecting `DashboardTheme = Light` in config to force-override a browser that already has Dark cached |
| Initial fleet collection runs synchronously before the request loop | First `/defender` GET would otherwise show an empty grid | `/health` does not respond until init finishes — `-StartImmediately` must retry |
| `FallbackPort` ships as `8090` in config but CLI default is `8443` | 8443 collides with Tomcat / Splunk / many self-signed test setups; 8090 is much less crowded | Documentation has to call out both values |
| `Send-MailMessage` replaced by `SmtpClient` | Marked `[Obsolete]` in PS7; emits a warning on every run | UTF-8 encoding and attachment paths must be set explicitly (defaults are ASCII + .NET CurrentDirectory) |
| `DisableIPv6 = true` by default | On LANs that advertise AAAA records but don't actually route IPv6, every unreachable host eats the full ~21 s TCP timeout before IPv4 fallback | Set `false` on networks where IPv6 is fully routed |
| `TaskFolder` normalized with trailing `\` | `Get-ScheduledTask -TaskPath` uses CIM WQL exact matching and won't find `'\HOME'` without the trailing slash | Useful-commands output and `Get-ScheduledTask` calls all need the normalized form |
| Async `BeginGetContext` request loop | `HttpListener.Pending()` doesn't exist (TcpListener-only idiom); `GetContext()` blocks forever | Loop responsiveness controlled by `WaitOne(500)` |

---

## See also

- [README.md](README.md) — quick reference
- [docs/tests/test-plan-v0.0.6.md](docs/tests/test-plan-v0.0.6.md) — release test plan with all attempt history

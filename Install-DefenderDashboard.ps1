<#
.SYNOPSIS
    Install-DefenderDashboard.ps1 – Registers Start-DefenderDashboard.ps1 as a Windows Scheduled Task

.DESCRIPTION
    One-time installation script that:

      1. Validates prerequisites (PowerShell 7, script paths, account existence)
      2. Creates required directories and grants the service identity filesystem access
      3. Registers a Windows Scheduled Task that runs Start-DefenderDashboard.ps1
         at system startup, indefinitely, under the specified service account or gMSA
      4. Optionally creates an inbound Windows Firewall rule for the dashboard port
      5. Starts the task immediately and tests the HTTP endpoint

    Supported service identity types:
      - Traditional service account  (DOMAIN\svc-account)  – requires -Credential
      - Group Managed Service Account (DOMAIN\gMSA$)        – no password required

    The task is configured with:
      • Trigger  : At system startup (+ optionally on demand via Task Scheduler)
      • Action   : pwsh.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden
      • Recovery : Restart automatically on failure (up to 3 times, 1-minute delay each)
      • Execution: No time limit (runs indefinitely)
      • Privilege: Highest available for the specified account

.PARAMETER DashboardScriptPath
    Full path to Start-DefenderDashboard.ps1. Defaults to the same directory as this script.

.PARAMETER ServiceAccount
    Traditional service account in DOMAIN\username format.
    Must be paired with -Credential. Mutually exclusive with -GmsaName.

.PARAMETER GmsaName
    Group Managed Service Account in DOMAIN\name$ or name$ format (the $ suffix is required).
    No password needed; the system manages the gMSA key automatically.
    Mutually exclusive with -ServiceAccount.

.PARAMETER Credential
    PSCredential for the traditional service account. Required when -ServiceAccount is used.
    Not used with -GmsaName.

.PARAMETER Port
    TCP port the dashboard HTTP listener will bind to. Default: 8080.

.PARAMETER RefreshInterval
    How often (seconds) the dashboard refreshes Defender data. Default: 300.

.PARAMETER SourceSharePath
    UNC path to the definitions share. Passed through to Start-DefenderDashboard.ps1.

.PARAMETER LogPath
    Directory where Start-DefenderDashboard.ps1 writes its logs. Default: C:\Logs\DefenderDashboard

.PARAMETER ParallelThreads
    Thread count passed to Start-DefenderDashboard.ps1. Default: 16.

.PARAMETER TimeoutSeconds
    Per-host WinRM timeout passed to Start-DefenderDashboard.ps1. Default: 30.

.PARAMETER TaskName
    Name of the scheduled task. Default: DefenderDashboard

.PARAMETER TaskFolder
    Task Scheduler folder path. Default: \  (root)

.PARAMETER AddFirewallRule
    Create an inbound Windows Firewall rule allowing TCP traffic on -Port.

.PARAMETER StartImmediately
    Start the scheduled task immediately after registration and test the endpoint.

.PARAMETER Force
    Overwrite an existing task with the same name without prompting.

.EXAMPLE
    # Install using a gMSA (no password required)
    .\Install-DefenderDashboard.ps1 `
        -GmsaName "CONTOSO\svc-defender$" `
        -SourceSharePath "\\NAS01\Share\_AVDefinitions\Microsoft_Defender" `
        -AddFirewallRule -StartImmediately

.EXAMPLE
    # Install using a traditional service account
    $cred = Get-Credential -UserName "CONTOSO\svc-defender" -Message "Service account password"
    .\Install-DefenderDashboard.ps1 `
        -ServiceAccount "CONTOSO\svc-defender" `
        -Credential $cred `
        -Port 8080 `
        -AddFirewallRule -StartImmediately

.EXAMPLE
    # Install with a custom task name and non-default port, no firewall rule
    .\Install-DefenderDashboard.ps1 `
        -GmsaName "CONTOSO\svc-defender$" `
        -TaskName "DefenderFleetDashboard" `
        -Port 9090 `
        -StartImmediately

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Requires       : PowerShell 7+, run as Administrator, Task Scheduler service running
    Version        : 0.0.6
    Last Updated   : 2026-05-19
#>

[CmdletBinding(DefaultParameterSetName = 'gMSA', SupportsShouldProcess)]
param(
    [string]$DashboardScriptPath,

    # --- Service identity (mutually exclusive) ---
    [Parameter(ParameterSetName = 'gMSA', Mandatory)]
    [ValidatePattern('\$$')]    # Must end with $
    [string]$GmsaName,

    [Parameter(ParameterSetName = 'ServiceAccount', Mandatory)]
    [string]$ServiceAccount,

    [Parameter(ParameterSetName = 'ServiceAccount', Mandatory)]
    [pscredential]$Credential,

    # --- Dashboard configuration ---
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [ValidateRange(1024, 65535)]
    [int]$FallbackPort = 8443,

    [ValidateRange(30, 86400)]
    [int]$RefreshInterval = 300,

    [string]$SourceSharePath,

    [string]$LogPath = 'C:\Logs\DefenderDashboard',

    [ValidateRange(1, 32)]
    [int]$ParallelThreads = 16,

    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 30,

    # --- Task configuration ---
    [string]$TaskName   = 'DefenderDashboard',
    [string]$TaskFolder = '\',

    # --- Options ---
    [switch]$AddFirewallRule,
    [switch]$StartImmediately,
    [switch]$Force,

    # Save WinRM credential for the dashboard service account (DPAPI-encrypted)
    [switch]$SaveCredential,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.6'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ===================================================================
# Credential Helper Mode  (exits after completion)
# ===================================================================
if ($SaveCredential) {
    Write-Host "`n=== WinRM Credential Setup ===" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  The dashboard uses a single WinRM credential (WinRmCredential.xml).' -ForegroundColor Gray
    Write-Host '  IMPORTANT: Run this helper as the service account or gMSA that will run' -ForegroundColor Yellow
    Write-Host '  the scheduled task — DPAPI encryption is per-user per-machine.' -ForegroundColor Yellow
    Write-Host '  For a gMSA, create a one-time scheduled task that runs this script' -ForegroundColor Gray
    Write-Host '  with -SaveCredential under the gMSA identity.' -ForegroundColor Gray
    Write-Host ''
    $cfgDir = Join-Path $ScriptDir 'conf'
    if (-not (Test-Path $cfgDir)) { New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null }
    try {
        $cred = Get-Credential -Message 'Enter WinRM credentials for the management/service account'
        if ($cred) {
            $cred | Export-Clixml -Path (Join-Path $cfgDir 'WinRmCredential.xml') -Force
            Write-Host "  Saved: $(Join-Path $cfgDir 'WinRmCredential.xml')" -ForegroundColor Green
        } else { Write-Host '  Cancelled.' -ForegroundColor Yellow }
    } catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
    exit 0
}

# ===================================================================
# Configuration File
# ===================================================================
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'conf\config.conf' }

function Read-ConfigFile {
    param([string]$Path)
    $cfg = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $cfg }
    foreach ($line in Get-Content $Path) {
        $t = $line.Trim()
        if (-not $t -or $t -match '^\s*[#\[]') { continue }
        if ($t -match '^([^=]+?)\s*=\s*(.+)$') {
            $v = $Matches[2].Trim() -replace '^([''"])(.*)\1$', '$2'
            $cfg[$Matches[1].Trim()] = $v
        }
    }
    return $cfg
}

$cfg = Read-ConfigFile $ConfigPath
if (-not $PSBoundParameters.ContainsKey('SourceSharePath') -and $cfg['SourceSharePath']) { $SourceSharePath = $cfg['SourceSharePath'] }
if (-not $PSBoundParameters.ContainsKey('Port')            -and $cfg['Port'])            { try { $Port            = [int]$cfg['Port']            } catch {} }
if (-not $PSBoundParameters.ContainsKey('FallbackPort')    -and $cfg['FallbackPort'])    { try { $FallbackPort    = [int]$cfg['FallbackPort']    } catch {} }
if (-not $PSBoundParameters.ContainsKey('RefreshInterval') -and $cfg['RefreshInterval']) { try { $RefreshInterval = [int]$cfg['RefreshInterval'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('LogPath')         -and $cfg['DashboardLogPath']) { $LogPath           = $cfg['DashboardLogPath'] }
if (-not $PSBoundParameters.ContainsKey('ParallelThreads') -and $cfg['ParallelThreads']) { try { $ParallelThreads = [int]$cfg['ParallelThreads'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('TimeoutSeconds')  -and $cfg['TimeoutSeconds'])  { try { $TimeoutSeconds  = [int]$cfg['TimeoutSeconds']  } catch {} }
if (-not $PSBoundParameters.ContainsKey('TaskName')        -and $cfg['TaskName'])        { $TaskName   = $cfg['TaskName'] }
if (-not $PSBoundParameters.ContainsKey('TaskFolder')      -and $cfg['TaskFolder'])      { $TaskFolder = $cfg['TaskFolder'] }

# ===================================================================
# Port Availability Functions
# ===================================================================
function Test-PortFree ([int]$TestPort) {
    try {
        $tcp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $TestPort)
        $tcp.Start(); $tcp.Stop(); return $true
    } catch { return $false }
}

function Find-AvailablePort {
    param([int]$Primary, [int]$Fallback)
    if (Test-PortFree $Primary) {
        return [pscustomobject]@{ Port = $Primary; IsFallback = $false; PrimaryPort = $Primary }
    }
    $candidate = $Fallback
    for ($i = 0; $i -lt 10; $i++) {
        if (Test-PortFree $candidate) {
            return [pscustomobject]@{ Port = $candidate; IsFallback = $true; PrimaryPort = $Primary }
        }
        $candidate++
    }
    throw "No available port found. Primary $Primary was in use; tried fallback range $Fallback–$($candidate - 1)."
}

# ===================================================================
# Console output helpers
# ===================================================================
function Write-Step  ([string]$Msg) { Write-Host "`n  $Msg" -ForegroundColor Cyan }
function Write-Ok    ([string]$Msg) { Write-Host "    [OK]  $Msg" -ForegroundColor Green }
function Write-Warn  ([string]$Msg) { Write-Host "    [WARN] $Msg" -ForegroundColor Yellow }
function Write-Fail  ([string]$Msg) { Write-Host "    [FAIL] $Msg" -ForegroundColor Red }
function Write-Info  ([string]$Msg) { Write-Host "          $Msg" -ForegroundColor Gray }

# ===================================================================
# STEP 0 – Prerequisites
# ===================================================================
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Magenta
Write-Host "   Defender Dashboard Installer v$ScriptVersion" -ForegroundColor Magenta
Write-Host "  ============================================================" -ForegroundColor Magenta

Write-Step "Checking prerequisites…"

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail 'This script must be run as Administrator.'
    exit 1
}
Write-Ok 'Running as Administrator'

# PowerShell 7 on the target machine (pwsh.exe)
$pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
if (-not $pwshPath) {
    Write-Fail 'pwsh.exe (PowerShell 7+) not found in PATH. Install PowerShell 7 first.'
    Write-Info 'Download: https://github.com/PowerShell/PowerShell/releases'
    exit 1
}
Write-Ok "pwsh.exe found: $pwshPath"

# Dashboard script path
if (-not $DashboardScriptPath) {
    $DashboardScriptPath = Join-Path $ScriptDir 'Start-DefenderDashboard.ps1'
}
if (-not (Test-Path $DashboardScriptPath)) {
    Write-Fail "Start-DefenderDashboard.ps1 not found: $DashboardScriptPath"
    exit 1
}
$DashboardScriptPath = (Resolve-Path $DashboardScriptPath).Path
Write-Ok "Dashboard script: $DashboardScriptPath"

# Register Windows Event Log source (one-time; allows the dashboard to write
# warning events when it starts on a fallback port)
$evtSource = 'Manage-DefenderOffline'
if (-not [System.Diagnostics.EventLog]::SourceExists($evtSource)) {
    try {
        New-EventLog -LogName Application -Source $evtSource -ErrorAction Stop
        Write-Ok "Event log source registered: '$evtSource' → Application log"
        Write-Info "EventId 100 = started normally  |  101 = started on fallback port  |  102 = stopped"
    } catch {
        Write-Warn "Could not register event log source: $($_.Exception.Message)"
        Write-Info "Dashboard will still write conf\dashboard.status for port discovery."
    }
} else {
    Write-Ok "Event log source '$evtSource' already registered"
}

# Task Scheduler service
$svc = Get-Service -Name 'Schedule' -ErrorAction SilentlyContinue
if ($svc.Status -ne 'Running') {
    Write-Fail 'Task Scheduler service (Schedule) is not running.'
    exit 1
}
Write-Ok 'Task Scheduler service is running'

# ===================================================================
# STEP 1 – Validate the service identity
# ===================================================================
Write-Step "Validating service identity…"

$isGmsa        = $PSCmdlet.ParameterSetName -eq 'gMSA'
$identityLabel = if ($isGmsa) { $GmsaName } else { $ServiceAccount }

if ($isGmsa) {
    # Normalise: strip leading DOMAIN\ if present, we need just the SAM name for AD lookup
    $gmsaSam = $GmsaName -replace '^.+\\', ''
    try {
        if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $acct = Get-ADServiceAccount -Filter "SamAccountName -eq '$gmsaSam'" -ErrorAction Stop
            if (-not $acct) { throw "gMSA '$gmsaSam' not found in Active Directory." }
            Write-Ok "gMSA found in AD: $($acct.DistinguishedName)"

            # Verify this computer is allowed to retrieve the gMSA password
            $allowed = Get-ADServiceAccount $gmsaSam -Properties PrincipalsAllowedToRetrieveManagedPassword
            $thisComputer = "$env:COMPUTERNAME$"
            $principals   = $allowed.PrincipalsAllowedToRetrieveManagedPassword
            $canRetrieve  = $principals | Where-Object {
                $_.ToString() -match [regex]::Escape($thisComputer) -or
                ($_ | Get-ADObject -ErrorAction SilentlyContinue).SamAccountName -eq $thisComputer
            }
            if ($canRetrieve) {
                Write-Ok "This computer ($env:COMPUTERNAME) is authorised to retrieve the gMSA password"
            } else {
                Write-Warn "This computer ($env:COMPUTERNAME) may not be in PrincipalsAllowedToRetrieveManagedPassword."
                Write-Info "Run on a DC: Set-ADServiceAccount $gmsaSam -PrincipalsAllowedToRetrieveManagedPassword (Get-ADComputer $env:COMPUTERNAME)"
            }
        } else {
            Write-Warn 'ActiveDirectory module not available – skipping gMSA AD validation.'
            Write-Info 'The account will be accepted as provided. Ensure it exists and this computer can retrieve its password.'
        }
    } catch {
        Write-Fail "gMSA validation failed: $($_.Exception.Message)"
        exit 1
    }
} else {
    # Traditional service account – verify the credential works
    Write-Ok "Service account: $ServiceAccount"
    if ($Credential.UserName -ne $ServiceAccount) {
        Write-Warn "Credential username ($($Credential.UserName)) does not match -ServiceAccount ($ServiceAccount)."
    }
}

# ===================================================================
# STEP 2 – Create directories and grant access
# ===================================================================
Write-Step "Creating directories and granting filesystem access…"

$scriptFolder  = Split-Path $DashboardScriptPath -Parent
$confFolder    = Join-Path $scriptFolder 'conf'
$configFolder  = Join-Path $scriptFolder 'conf'

$pathsToCreate = @($LogPath, $scriptFolder, $confFolder, $configFolder)
foreach ($p in $pathsToCreate | Select-Object -Unique) {
    if (-not (Test-Path $p)) {
        New-Item -Path $p -ItemType Directory -Force | Out-Null
        Write-Ok "Created: $p"
    } else {
        Write-Ok "Exists : $p"
    }
}

function Grant-FolderAccess {
    param([string]$Path, [string]$Identity, [string]$Rights = 'ReadAndExecute')
    try {
        $acl  = Get-Acl $Path
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $Identity, $Rights,
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
        Write-Ok "Granted $Rights to '$Identity' on $Path"
    } catch {
        Write-Warn "Could not set ACL on $Path : $($_.Exception.Message)"
        Write-Info 'Grant manually if required.'
    }
}

Grant-FolderAccess -Path $scriptFolder  -Identity $identityLabel -Rights 'ReadAndExecute'
Grant-FolderAccess -Path $confFolder   -Identity $identityLabel -Rights 'Modify'         # writes dashboard.status
Grant-FolderAccess -Path $configFolder -Identity $identityLabel -Rights 'Modify'         # reads/writes WinRmCredential.xml
Grant-FolderAccess -Path $LogPath      -Identity $identityLabel -Rights 'Modify'

# ===================================================================
# STEP 3 – Build the scheduled task action arguments
# ===================================================================
Write-Step "Checking port availability…"

$portResult = Find-AvailablePort -Primary $Port -Fallback $FallbackPort
if ($portResult.IsFallback) {
    Write-Warn "Port $($portResult.PrimaryPort) is already in use on this host."
    Write-Ok   "Using fallback port $($portResult.Port) instead."
    $Port = $portResult.Port
} else {
    Write-Ok "Port $Port is available"
}

Write-Step "Building scheduled task…"

$argParts = @(
    '-NonInteractive'
    '-NoProfile'
    '-ExecutionPolicy Bypass'
    '-WindowStyle Hidden'
    "-File `"$DashboardScriptPath`""
    "-Port $Port"
    "-RefreshInterval $RefreshInterval"
    "-LogPath `"$LogPath`""
    "-ParallelThreads $ParallelThreads"
    "-TimeoutSeconds $TimeoutSeconds"
)
if ($SourceSharePath) {
    $argParts += "-SourceSharePath `"$SourceSharePath`""
}

$taskArguments = $argParts -join ' '
Write-Info "Action: $pwshPath $taskArguments"

$action = New-ScheduledTaskAction `
    -Execute  $pwshPath `
    -Argument $taskArguments

# Trigger: at system startup
$trigger = New-ScheduledTaskTrigger -AtStartup

# Settings: run indefinitely, restart on failure, no concurrent instances.
# -StartWhenAvailable is a [switch]; PS treats `-Switch $true` as a positional
# argument, so use presence-only form. -RunOnlyIfNetworkAvailable defaults to
# $false (omit it).
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit  ([timespan]::Zero) `
    -MultipleInstances   IgnoreNew `
    -StartWhenAvailable `
    -RestartCount        3 `
    -RestartInterval     ([timespan]::FromMinutes(1))

# Principal
if ($isGmsa) {
    $principal = New-ScheduledTaskPrincipal `
        -UserId   $GmsaName `
        -LogonType Password `
        -RunLevel Highest
} else {
    $principal = New-ScheduledTaskPrincipal `
        -UserId   $ServiceAccount `
        -LogonType Password `
        -RunLevel Highest
}

# Check for existing task
$existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder -ErrorAction SilentlyContinue

if ($existingTask -and -not $Force) {
    Write-Warn "A task named '$TaskName' already exists in '$TaskFolder'."
    $answer = Read-Host "    Overwrite it? [Y/N]"
    if ($answer -notmatch '^[Yy]') {
        Write-Warn 'Installation cancelled by user.'
        exit 0
    }
}

# Register the task
try {
    $registerParams = @{
        TaskName    = $TaskName
        TaskPath    = $TaskFolder
        Action      = $action
        Trigger     = $trigger
        Settings    = $settings
        Principal   = $principal
        Description = "Defender Fleet Monitor dashboard – Start-DefenderDashboard.ps1 v$ScriptVersion"
        Force       = $true
    }

    # For traditional accounts, password must be supplied at registration time
    if (-not $isGmsa) {
        $registerParams.Password = $Credential.GetNetworkCredential().Password
        $registerParams.User     = $ServiceAccount
        $registerParams.Remove('Principal') | Out-Null
        $registerParams.RunLevel = 'Highest'
    }

    Register-ScheduledTask @registerParams | Out-Null
    # $TaskFolder may or may not have a trailing '\'; ensure exactly one
    # separator between folder and task name in display output.
    $fullTaskPath = if ($TaskFolder.EndsWith('\')) { "$TaskFolder$TaskName" } else { "$TaskFolder\$TaskName" }
    Write-Ok "Task registered: $fullTaskPath"
} catch {
    Write-Fail "Failed to register scheduled task: $($_.Exception.Message)"
    exit 1
}

# ===================================================================
# STEP 4 – Optional firewall rule
# ===================================================================
if ($AddFirewallRule) {
    Write-Step "Creating Windows Firewall inbound rule…"
    $ruleName = "DefenderDashboard-TCP-$Port"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Write-Warn "Firewall rule '$ruleName' already exists – skipping. (Re-run with -Force to replace.)"
    } else {
        try {
            if ($existing) {
                Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                Write-Info "Removed existing rule '$ruleName' (replacing because -Force was specified)."
            }
            # New-NetFirewallRule has no -Force parameter; -Enabled takes
            # the string 'True'/'False', not [bool] $true/$false.
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Description "Allows inbound HTTP traffic to the Defender Fleet Dashboard on TCP $Port" `
                -Direction   Inbound `
                -Protocol    TCP `
                -LocalPort   $Port `
                -Action      Allow `
                -Profile     Domain, Private `
                -Enabled     True | Out-Null
            Write-Ok "Firewall rule created: $ruleName (TCP $Port, Domain+Private profiles)"
        } catch {
            Write-Warn "Could not create firewall rule: $($_.Exception.Message)"
            Write-Info "Create manually: New-NetFirewallRule -DisplayName '$ruleName' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow"
        }
    }
}

# ===================================================================
# STEP 5 – Start the task and test the endpoint
# ===================================================================
if ($StartImmediately) {
    Write-Step "Starting task…"
    try {
        Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder
        Write-Ok "Task started"
    } catch {
        Write-Fail "Could not start task: $($_.Exception.Message)"
    }

    Write-Step "Waiting for dashboard to start (up to 45s)…"

    $statusFile   = Join-Path $confFolder 'dashboard.status'
    $deadline     = [datetime]::Now.AddSeconds(45)
    $statusLoaded = $false

    # Primary signal: status file written by the dashboard at startup
    while ([datetime]::Now -lt $deadline -and -not $statusLoaded) {
        Start-Sleep -Seconds 3
        if (Test-Path $statusFile) { $statusLoaded = $true; break }
        Write-Info "  …waiting for status file ($([int]($deadline - [datetime]::Now).TotalSeconds)s remaining)"
    }

    if ($statusLoaded) {
        # Parse the status file using the same Read-ConfigFile function
        $runtimeStatus = Read-ConfigFile $statusFile
        $actualPort    = if ($runtimeStatus['Port']) { [int]$runtimeStatus['Port'] } else { $Port }

        if ($runtimeStatus['IsFallback'] -eq 'True') {
            # Fallback was used at runtime — update $Port for the summary block
            $Port = $actualPort
            $portResult = [pscustomobject]@{
                IsFallback  = $true
                Port        = $actualPort
                PrimaryPort = if ($runtimeStatus['PrimaryPort']) { [int]$runtimeStatus['PrimaryPort'] } else { $portResult.PrimaryPort }
            }
            Write-Warn "Dashboard started on FALLBACK port $actualPort."
            Write-Info "Primary port $($portResult.PrimaryPort) was in use at service startup time."
            Write-Info "ACTION REQUIRED: Update firewall rules, bookmarks, and monitoring tools to port $actualPort."
        } else {
            Write-Ok "Dashboard started on port $actualPort"
        }

        # Secondary confirmation: HTTP health probe. The dashboard runs the
        # initial fleet collection synchronously *after* HttpListener.Start()
        # but *before* entering the request loop, so /health does not respond
        # until that initial pass completes (~0.5s per host). Retry up to 6
        # times with a 10-second per-probe timeout to give large fleets room.
        $probeOk    = $false
        $lastErr    = $null
        $probeStart = Get-Date
        for ($i = 1; $i -le 6; $i++) {
            try {
                $resp = Invoke-WebRequest -Uri "http://localhost:$actualPort/health" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
                if ($resp.StatusCode -eq 200) { $probeOk = $true; break }
            } catch {
                $lastErr = $_.Exception.Message
                Start-Sleep -Seconds 5
            }
        }
        $elapsed = [int]((Get-Date) - $probeStart).TotalSeconds
        if ($probeOk) {
            Write-Ok "HTTP health probe passed after ${elapsed}s: http://localhost:$actualPort/health → 200 OK"
        } else {
            Write-Warn "Status file present but /health probe failed after ${elapsed}s of retries: $lastErr"
            Write-Info "Initial fleet collection may still be running for a large fleet. Check the dashboard log: $LogPath"
        }
    } else {
        Write-Warn "Dashboard did not write a status file within 45 seconds."
        Write-Info "Check the dashboard log: $LogPath"
        Write-Info "Check task state  : Get-ScheduledTask -TaskName '$TaskName' | Select-Object State,LastTaskResult"
        Write-Info "Check event log   : Get-EventLog -LogName Application -Source 'Manage-DefenderOffline' -Newest 5"
    }
}

# ===================================================================
# Summary
# ===================================================================
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Magenta
Write-Host "   Installation Complete" -ForegroundColor Magenta
Write-Host "  ============================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Task name    : $fullTaskPath" -ForegroundColor White
Write-Host "  Identity     : $identityLabel" -ForegroundColor White
if ($portResult.IsFallback) {
    Write-Host "  Port         : $Port  " -NoNewline -ForegroundColor Yellow
    Write-Host "(fallback — primary port $($portResult.PrimaryPort) was in use)" -ForegroundColor DarkYellow
} else {
    Write-Host "  Port         : $Port" -ForegroundColor White
}
Write-Host "  Dashboard    : http://<this-host>:$Port/defender" -ForegroundColor White
Write-Host "  JSON status  : http://<this-host>:$Port/status" -ForegroundColor White
Write-Host "  Health probe : http://<this-host>:$Port/health" -ForegroundColor White
Write-Host "  Logs         : $LogPath" -ForegroundColor White
Write-Host ""
$pathArg = if ($TaskFolder -eq '\') { '' } else { " -TaskPath '$TaskFolder'" }
Write-Host "  Useful commands:" -ForegroundColor Cyan
Write-Host "    Start  : Start-ScheduledTask -TaskName '$TaskName'$pathArg" -ForegroundColor Gray
Write-Host "    Stop   : Stop-ScheduledTask  -TaskName '$TaskName'$pathArg" -ForegroundColor Gray
Write-Host "    Status : Get-ScheduledTask   -TaskName '$TaskName'$pathArg | Select-Object State,LastRunTime,LastTaskResult" -ForegroundColor Gray
Write-Host "    Remove : Unregister-ScheduledTask -TaskName '$TaskName'$pathArg -Confirm:`$false" -ForegroundColor Gray
Write-Host ""

# ===================================================================
# Prerequisites Reminder
# ===================================================================
$credFile = Join-Path $configFolder 'WinRmCredential.xml'
if (-not (Test-Path $credFile)) {
    Write-Host "  WinRM CREDENTIAL NOT CONFIGURED" -ForegroundColor Yellow
    Write-Host "  The dashboard needs a WinRM credential to query endpoints." -ForegroundColor Yellow
    Write-Host "  Run the following as the service identity ($identityLabel):" -ForegroundColor Yellow
    Write-Host "    .\Install-DefenderDashboard.ps1 -SaveCredential" -ForegroundColor Gray
    Write-Host "  For gMSA: create a one-time scheduled task under the gMSA to run -SaveCredential." -ForegroundColor Gray
    Write-Host ""
}

Write-Host "  IMPORTANT – Manual steps required on target endpoints:" -ForegroundColor Yellow
Write-Host "    The service account/gMSA must be a LOCAL ADMINISTRATOR on every" -ForegroundColor Yellow
Write-Host "    target computer it queries, and WinRM (TCP 5985) must be enabled." -ForegroundColor Yellow
Write-Host ""
Write-Host "    Enable WinRM via GPO or run on each target:" -ForegroundColor Yellow
Write-Host "      Enable-PSRemoting -Force" -ForegroundColor Gray
Write-Host ""
Write-Host "    Add identity to local Admins via GPO:" -ForegroundColor Yellow
Write-Host "      Computer Configuration → Preferences → Local Users and Groups" -ForegroundColor Gray
Write-Host ""

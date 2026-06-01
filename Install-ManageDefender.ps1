<#
.SYNOPSIS
    Install-ManageDefender.ps1 — Unified installer for the Manage-DefenderOffline toolkit.

.DESCRIPTION
    Single entry point that installs one or more toolkit components as Windows Scheduled
    Tasks under a service identity (traditional account or gMSA), saves all needed
    DPAPI-encrypted credentials, and (on STIG-hardened hosts) handles the Secondary
    Logon Service enable→use→restore-Disabled dance for V-253289 compliance.

    Components (via -Component):
      • Dashboard  — Start-DefenderDashboard.ps1 scheduled task (headless HTTP dashboard).
      • Updates    — Update-DefenderOffline.ps1 scheduled task (periodic definition push).
      • All        — Dashboard + Updates on the same host (default).
      • Downloader — Reserved for v0.0.20 (Get-DefenderDefinitions.ps1 on a separate
                     internet-connected staging machine).

    For -Component Updates and All, choose how often the patch task runs via -Frequency:
      TwiceDaily | Daily | Weekly | Monthly
    Override the trigger time via -UpdateStartTime '02:00' (HH:mm 24-hour).

    Credential setup (skip with -SkipCredentialSetup):
      • WinRmCredential.xml — used by both components to authenticate to endpoint WinRM.
      • ADCredential.xml    — used by both components for AD discovery (LDAP bind / Negotiate).
      • SmtpCredential.xml  — used by Updates only when [Email] SendEmail = true in config.

    All credentials are encrypted with the service identity's DPAPI master key. On STIG
    hosts where seclogon is Disabled (V-253289), the installer temporarily enables it,
    saves credentials as the service identity, then restores Stopped+Disabled — even if
    a save throws.

.PARAMETER Component
    Which component(s) to install. One of:
      Dashboard  — headless HTTP dashboard scheduled task only.
      Updates    — periodic definition-push scheduled task only.
      All        — Dashboard + Updates (DEFAULT; does NOT include Downloader).
      Downloader — reserved for v0.0.20.
    Default: All.

.PARAMETER Frequency
    How often the Updates task runs (ignored for Component=Dashboard).
      TwiceDaily — 02:00 and 14:00 every day (override times via -UpdateStartTime, applies to both runs offset 12h).
      Daily      — once a day at -UpdateStartTime.
      Weekly     — once a week on Sunday at -UpdateStartTime.
      Monthly    — once a month on day 1 at -UpdateStartTime.
    Default: Daily.

.PARAMETER UpdateStartTime
    Trigger time for the Updates task in HH:mm 24-hour format. Default: '02:00'.
    For TwiceDaily, this is the first run; the second run is +12 hours.

.PARAMETER ServiceAccount
    Traditional service account in DOMAIN\username format. Pair with -Credential.
    Mutually exclusive with -GmsaName.

.PARAMETER GmsaName
    Group Managed Service Account in DOMAIN\name$ format (the trailing $ is required).
    No password needed. Mutually exclusive with -ServiceAccount.

.PARAMETER Credential
    PSCredential for the traditional service account. Required when -ServiceAccount is used.

.PARAMETER SkipCredentialSetup
    Don't prompt for or save any credentials. Prints follow-up instructions for setting
    them up manually after install. Use this when the operator wants to handle credentials
    out-of-band (e.g. via a separate runbook).

.PARAMETER WinRmCredential
    Pre-supplied WinRM credential (skips the interactive prompt). Saved as
    conf/WinRmCredential.xml under the service identity's DPAPI.

.PARAMETER AdCredential
    Pre-supplied AD credential (skips the interactive prompt). Saved as
    conf/ADCredential.xml under the service identity's DPAPI.

.PARAMETER SmtpCredential
    Pre-supplied SMTP credential (skips the interactive prompt). Saved as
    conf/SmtpCredential.xml under the service identity's DPAPI. Only relevant when
    [Email] SendEmail = true in conf/config.conf.

.PARAMETER WinRmUsername
    Pre-populates the username field of the WinRM credential prompt (operator just
    types the password). Priority: CLI > [Credentials] WinRmUsername in config > blank.
    Accepted formats: DOMAIN\username, username@domain.tld, or username.

.PARAMETER AdUsername
    Pre-populates the username field of the AD credential prompt. Same priority and
    format rules as -WinRmUsername.

.PARAMETER SmtpUsername
    Pre-populates the username field of the SMTP credential prompt. Same priority and
    format rules as -WinRmUsername. Only prompted when [Email] SendEmail = true.

.PARAMETER Force
    Overwrite any existing scheduled task(s) with the same name(s) without prompting.

.PARAMETER ConfigPath
    Path to conf/config.conf. Defaults to .\conf\config.conf relative to this script.

.EXAMPLE
    # Default install: Dashboard + Updates, gMSA identity, Daily updates at 02:00.
    .\Install-ManageDefender.ps1 -GmsaName 'CONTOSO\svc-defender$' -StartImmediately

.EXAMPLE
    # Dashboard only (skip the Updates task)
    .\Install-ManageDefender.ps1 -Component Dashboard -GmsaName 'CONTOSO\svc-defender$' `
                                 -UseHttps -AddFirewallRule -StartImmediately

.EXAMPLE
    # Updates only, weekly on Sundays at 03:30, traditional service account
    $cred = Get-Credential -UserName 'CONTOSO\svc-defender' -Message 'Service account password'
    .\Install-ManageDefender.ps1 -Component Updates `
        -Frequency Weekly -UpdateStartTime '03:30' `
        -ServiceAccount 'CONTOSO\svc-defender' -Credential $cred `
        -RunNowWhatIf

.EXAMPLE
    # Defer credential setup; operator will save them out-of-band later
    .\Install-ManageDefender.ps1 -GmsaName 'CONTOSO\svc-defender$' -SkipCredentialSetup

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Requires       : PowerShell 7+, run as Administrator, Task Scheduler service running
    Reference      : Get-CiscoTechSupport\Install-GetCiscoTechSupport.ps1 — seclogon pattern
    STIG           : V-253289 (Secondary Logon Service must remain disabled)
#>

[CmdletBinding(DefaultParameterSetName = 'gMSA', SupportsShouldProcess)]
param(
    # ----- Component selection -----
    [ValidateSet('Dashboard', 'Updates', 'All', 'Downloader')]
    [string]$Component = 'All',

    # ----- Updates-task frequency -----
    [ValidateSet('TwiceDaily', 'Daily', 'Weekly', 'Monthly')]
    [string]$Frequency = 'Daily',

    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$UpdateStartTime = '02:00',

    # ----- Service identity (mutually exclusive) -----
    [Parameter(ParameterSetName = 'gMSA', Mandatory)]
    [ValidatePattern('\$$')]
    [string]$GmsaName,

    [Parameter(ParameterSetName = 'ServiceAccount', Mandatory)]
    [string]$ServiceAccount,

    [Parameter(ParameterSetName = 'ServiceAccount', Mandatory)]
    [pscredential]$Credential,

    # ----- Script paths -----
    [string]$DashboardScriptPath,
    [string]$UpdateScriptPath,

    # ----- Dashboard configuration -----
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

    # ----- HTTPS support (Dashboard) -----
    [switch]$UseHttps,
    [string]$CertificateThumbprint,
    [switch]$RenewCertificate,
    [string]$AdditionalSans,

    # ----- Authentication pass-through (Dashboard) -----
    [ValidateSet('None', 'Token', 'Basic', 'ADIntegrated')]
    [string]$AuthMethod,

    [string]$AuthAllowedGroups,
    [string]$AuthBasicUsersFile,
    [string]$AuthToken,

    # ----- Dashboard task naming -----
    [string]$TaskName   = 'DefenderDashboard',
    [string]$TaskFolder = '\',

    # ----- Updates task naming -----
    [string]$UpdateTaskName   = 'DefenderUpdate',
    [string]$UpdateTaskFolder,    # blank = use $TaskFolder

    # ----- Updates-specific config -----
    [string]$CanaryComputers,
    [int]$MaxCanaryFailures,

    # ----- Options -----
    [switch]$AddFirewallRule,
    [switch]$StartImmediately,

    # Run Update-DefenderOffline.ps1 once with -WhatIfMode after task registration,
    # so the operator sees a verifying log line confirming connectivity + share access
    # without actually pushing any defs.
    [switch]$RunNowWhatIf,

    [switch]$Force,

    # ----- Credential setup -----
    [switch]$SkipCredentialSetup,
    [pscredential]$WinRmCredential,
    [pscredential]$AdCredential,
    [pscredential]$SmtpCredential,

    # Pre-population for the username field of each Get-Credential prompt.
    # Priority: CLI > [Credentials] *Username keys in config > blank.
    [string]$WinRmUsername,
    [string]$AdUsername,
    [string]$SmtpUsername,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.19'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Shared helper modules (dot-sourced; same chokepoint pattern as the other scripts).
. (Join-Path $ScriptDir 'lib\Update-ConfigValue.ps1')

# Stable application GUID used for netsh sslcert binding (Dashboard component).
# Reusing this lets the installer find and delete its own previous bindings idempotently.
$script:HttpsAppId = '{a3f9b1c2-d4e5-46f7-8901-234567890abc}'

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
if (-not $PSBoundParameters.ContainsKey('UpdateTaskName')  -and $cfg['UpdateTaskName'])  { $UpdateTaskName = $cfg['UpdateTaskName'] }
if (-not $PSBoundParameters.ContainsKey('UpdateTaskFolder') -and $cfg['UpdateTaskFolder']) { $UpdateTaskFolder = $cfg['UpdateTaskFolder'] }
if (-not $PSBoundParameters.ContainsKey('Frequency')       -and $cfg['UpdateFrequency']) { $Frequency = $cfg['UpdateFrequency'] }
if (-not $PSBoundParameters.ContainsKey('UpdateStartTime') -and $cfg['UpdateStartTime']) { $UpdateStartTime = $cfg['UpdateStartTime'] }
if (-not $PSBoundParameters.ContainsKey('CanaryComputers') -and $cfg['CanaryComputers']) { $CanaryComputers = $cfg['CanaryComputers'] }
if (-not $PSBoundParameters.ContainsKey('MaxCanaryFailures') -and $cfg['MaxCanaryFailures']) { try { $MaxCanaryFailures = [int]$cfg['MaxCanaryFailures'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('UseHttps')              -and $cfg['UseHttps'] -eq 'true')   { $UseHttps              = $true }
if (-not $PSBoundParameters.ContainsKey('CertificateThumbprint') -and $cfg['CertificateThumbprint']) { $CertificateThumbprint = $cfg['CertificateThumbprint'].Trim() }
if (-not $PSBoundParameters.ContainsKey('WinRmUsername')         -and $cfg['WinRmUsername'])         { $WinRmUsername = $cfg['WinRmUsername'] }
if (-not $PSBoundParameters.ContainsKey('AdUsername')            -and $cfg['AdUsername'])            { $AdUsername    = $cfg['AdUsername']    }
if (-not $PSBoundParameters.ContainsKey('SmtpUsername')          -and $cfg['SmtpUsername'])          { $SmtpUsername  = $cfg['SmtpUsername']  }

# Inherit Updates task folder from main TaskFolder unless explicitly set
if (-not $UpdateTaskFolder) { $UpdateTaskFolder = $TaskFolder }

# Normalise folders to end with backslash (Get-ScheduledTask -TaskPath WQL needs it)
if (-not $TaskFolder.EndsWith('\'))       { $TaskFolder       = "$TaskFolder\" }
if (-not $UpdateTaskFolder.EndsWith('\')) { $UpdateTaskFolder = "$UpdateTaskFolder\" }

# ===================================================================
# Console output helpers
# ===================================================================
function Write-Step    ([string]$Msg) { Write-Host "`n  $Msg" -ForegroundColor Cyan }
function Write-Ok      ([string]$Msg) { Write-Host "    [OK]   $Msg" -ForegroundColor Green }
function Write-Warn    ([string]$Msg) { Write-Host "    [WARN] $Msg" -ForegroundColor Yellow }
function Write-Fail    ([string]$Msg) { Write-Host "    [FAIL] $Msg" -ForegroundColor Red }
function Write-Info    ([string]$Msg) { Write-Host "           $Msg" -ForegroundColor Gray }
function Write-Section ([string]$Msg) {
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Magenta
    Write-Host "   $Msg" -ForegroundColor Magenta
    Write-Host '  ============================================================' -ForegroundColor Magenta
}

# ===================================================================
# Common helpers
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
    throw "No available port found. Primary $Primary was in use; tried fallback range $Fallback-$($candidate - 1)."
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

# ===================================================================
# STIG V-253289 — Secondary Logon Service helpers
#
# Pattern lifted from Get-CiscoTechSupport\Install-GetCiscoTechSupport.ps1
# (see memory: reference_stig_seclogon_pattern). On STIG-hardened hosts the
# seclogon service is Stopped + Disabled. Without it, Start-Process -Credential
# and runas both fail — so we can't launch the credential save helper as the
# service identity. The pattern: capture state, temporarily enable, do the
# work, restore Disabled in a finally block. Always.
# ===================================================================
function Test-SecondaryLogonService {
    try {
        $service = Get-Service -Name 'seclogon' -ErrorAction Stop
        return [pscustomobject]@{
            Exists    = $true
            Status    = $service.Status
            StartType = $service.StartType
        }
    } catch {
        return [pscustomobject]@{
            Exists    = $false
            Status    = $null
            StartType = $null
        }
    }
}

function Set-SecondaryLogonService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Manual', 'Disabled', 'Automatic')]
        [string]$StartType,

        [switch]$StopService
    )

    try {
        if ($StopService) {
            Write-Info "Stopping Secondary Logon service…"
            Stop-Service -Name 'seclogon' -Force -ErrorAction Stop

            # Wait up to 10s for the service to actually stop
            $elapsed = 0
            while ((Get-Service -Name 'seclogon').Status -ne 'Stopped' -and $elapsed -lt 10) {
                Start-Sleep -Seconds 1
                $elapsed++
            }
            if ((Get-Service -Name 'seclogon').Status -ne 'Stopped') {
                Write-Warn 'Secondary Logon service did not stop within 10 seconds.'
                return $false
            }
        }

        Set-Service -Name 'seclogon' -StartupType $StartType -ErrorAction Stop

        if ($StartType -in @('Manual', 'Automatic')) {
            try {
                Start-Service -Name 'seclogon' -ErrorAction Stop
                # Brief settle so a follow-up Start-Process -Credential actually finds it
                Start-Sleep -Seconds 2
            } catch {
                Write-Warn "Could not start Secondary Logon service after setting StartupType=$StartType : $($_.Exception.Message)"
                return $false
            }
        }

        $verify = Get-Service -Name 'seclogon'
        if ($verify.StartType -ne $StartType) {
            Write-Fail "Failed to set Secondary Logon to $StartType (actual: $($verify.StartType))."
            return $false
        }
        return $true
    } catch {
        Write-Fail "Set-SecondaryLogonService failed: $($_.Exception.Message)"
        return $false
    }
}

function Restore-SecondaryLogonService {
    # Always-attempt restore — called in finally blocks. Returns the service
    # to the state we observed at the start of the dance (not a hardcoded
    # STIG state). If we found it Running, we leave it Running. If we found
    # it Stopped+Disabled, we put it back to Stopped+Disabled. Prints
    # explicit manual cleanup commands if the restore can't complete.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Manual', 'Disabled', 'Automatic', 'AutomaticDelayedStart', 'Boot', 'System')]
        [string]$OriginalStartType,

        [Parameter(Mandatory)]
        [ValidateSet('Running', 'Stopped', 'Paused', 'StartPending', 'StopPending', 'ContinuePending', 'PausePending')]
        [string]$OriginalStatus
    )
    Write-Step "Restoring Secondary Logon to original state (Status=$OriginalStatus, StartType=$OriginalStartType)…"
    $stopFirst = $OriginalStatus -ne 'Running'
    if (Set-SecondaryLogonService -StartType $OriginalStartType -StopService:$stopFirst) {
        $final = Get-Service -Name 'seclogon'
        Write-Ok "Secondary Logon service restored (Status=$($final.Status), StartType=$($final.StartType))"
    } else {
        Write-Fail "Could not restore Secondary Logon. Manual cleanup required:"
        if ($stopFirst) { Write-Host '             Stop-Service -Name seclogon -Force' -ForegroundColor Yellow }
        Write-Host "             Set-Service  -Name seclogon -StartupType $OriginalStartType" -ForegroundColor Yellow
    }
}

# ===================================================================
# Credential save infrastructure
#
# Goal: after install, conf/ contains DPAPI-encrypted credential XMLs that
# the scheduled task can Import-Clixml at runtime. DPAPI is per-user-per-
# machine, so each XML must be written by the *service identity*, not the
# admin running the installer. Two paths:
#
#   - Traditional service account: Start-Process -Credential launches a
#     helper PowerShell process as the service account. The helper imports
#     a serialised credential blob (already in PSCredential form on disk
#     so no plaintext crosses the wire) and Export-Clixml's it.
#
#   - gMSA: no password is available for Start-Process. Register a one-shot
#     scheduled task that runs as the gMSA, action = same helper, trigger
#     = "Once" 30s from now. Wait for the task to complete, unregister.
#
# Both paths use the same helper script and credential-handoff format,
# so the per-path code surface is small.
# ===================================================================

# Path to the per-credential helper that runs in the service-identity context.
# The helper expects two arguments: <CredentialName> <SerialisedCredentialPath>.
# It imports the serialised credential from disk, re-saves it as
# conf\<CredentialName>.xml (now encrypted under the *current* DPAPI master
# key, which is the service identity's), then deletes the serialised input.
function Get-CredentialSaveHelperPath {
    Join-Path $ScriptDir 'lib\Save-ServiceCredential.ps1'
}

function Initialize-CredentialSaveHelper {
    # Verifies the bundled helper script exists. Shipped as a real file at
    # lib\Save-ServiceCredential.ps1 so it's version-controlled and reviewable;
    # this function exists only to fail fast with a clear error if the bundle
    # is incomplete.
    $helperPath = Get-CredentialSaveHelperPath
    if (-not (Test-Path -LiteralPath $helperPath)) {
        throw "Missing required helper: $helperPath`nThe install bundle appears incomplete. Re-extract the manage-defenderoffline-X.Y.Z.zip artifact and try again."
    }
}

function New-CredentialPayloadFile {
    # Writes a PSCredential to a short-lived file in conf/ in a format the
    # helper can consume: <username>`n<base64 LocalMachine-DPAPI-encrypted
    # UTF-16 password>. Returns the path. Caller deletes after use.
    #
    # WHY conf/ AND NOT THE SYSTEM TEMP FOLDER:
    # The helper runs in the SERVICE IDENTITY'S context (Start-Process
    # -Credential or one-shot gMSA scheduled task). The caller's per-user
    # temp folder (%LOCALAPPDATA%\Temp) is owner-only by default, so the
    # service identity gets ACCESS DENIED when it tries to read the
    # handoff. conf/ is already pre-granted Modify to the service identity
    # earlier in main flow, guaranteeing cross-identity readability.
    # Payload contains only the LocalMachine-DPAPI-encrypted password
    # blob (anyone on this box can decrypt it — that's intentional and is
    # why the file is deleted within seconds in the caller's finally).
    param(
        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [string]$ConfFolder
    )
    Add-Type -AssemblyName System.Security

    $plainPwd = $Credential.GetNetworkCredential().Password
    $plainBytes = [System.Text.Encoding]::Unicode.GetBytes($plainPwd)
    try {
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
            $plainBytes, $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $b64 = [Convert]::ToBase64String($encrypted)
    } finally {
        [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)
        $plainPwd = $null
    }

    $tmp = Join-Path $ConfFolder (".credpayload." + [guid]::NewGuid().ToString('N') + '.tmp')
    Set-Content -Path $tmp -Value @($Credential.UserName, $b64) -Encoding UTF8 -Force
    return $tmp
}

function Invoke-AsServiceIdentity {
    # Runs the credential-save helper script in the service identity's
    # context, abstracting traditional-vs-gMSA. Returns $true on success.
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialName',
        Justification = '$CredentialName is a tag ("WinRm"/"AD"/"Smtp"), not credential material; the analyzer false-positives on the substring match.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('WinRm','AD','Smtp')] [string]$CredentialName,
        [Parameter(Mandatory)] [string]$SourcePayloadPath,
        [Parameter(Mandatory)] [string]$DestinationPath,
        [Parameter(Mandatory)] [bool]$IsGmsa,
        [string]$ServiceAccountName,
        [pscredential]$ServiceAccountCredential,
        [string]$GmsaAccountName
    )

    $helperPath = Get-CredentialSaveHelperPath
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
    if (-not $pwshPath) {
        Write-Fail 'pwsh.exe not in PATH — cannot launch credential helper.'
        return $false
    }

    $argList = @(
        '-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$helperPath`"",
        '-CredentialName', $CredentialName,
        '-SourcePath',     "`"$SourcePayloadPath`"",
        '-DestinationPath', "`"$DestinationPath`""
    )

    if (-not $IsGmsa) {
        # Traditional service account: Start-Process -Credential synchronously.
        # Redirect stdout/stderr so we can surface the helper's failure reason
        # instead of just "exit code 1". Logs land next to the helper and are
        # deleted in finally regardless of outcome.
        $stdoutLog = Join-Path $ScriptDir ('.credhelper.{0}.out.log' -f [guid]::NewGuid().ToString('N'))
        $stderrLog = Join-Path $ScriptDir ('.credhelper.{0}.err.log' -f [guid]::NewGuid().ToString('N'))
        try {
            $proc = Start-Process -FilePath $pwshPath `
                -ArgumentList ($argList -join ' ') `
                -Credential $ServiceAccountCredential `
                -WorkingDirectory $ScriptDir `
                -WindowStyle Hidden `
                -Wait `
                -PassThru `
                -RedirectStandardOutput $stdoutLog `
                -RedirectStandardError  $stderrLog `
                -ErrorAction Stop
            if ($proc.ExitCode -ne 0) {
                Write-Fail "Credential helper exited with code $($proc.ExitCode)."
                $errText = if (Test-Path -LiteralPath $stderrLog) { (Get-Content -LiteralPath $stderrLog -Raw).Trim() } else { '' }
                $outText = if (Test-Path -LiteralPath $stdoutLog) { (Get-Content -LiteralPath $stdoutLog -Raw).Trim() } else { '' }
                $sideLog = $DestinationPath + '.err'
                $sideText = if (Test-Path -LiteralPath $sideLog) { (Get-Content -LiteralPath $sideLog -Raw).Trim() } else { '' }
                if ($errText)  { Write-Info ('Helper stderr: ' + $errText) }
                if ($outText)  { Write-Info ('Helper stdout: ' + $outText) }
                if ($sideText) { Write-Info ('Helper sidelog: ' + $sideText) }
                return $false
            }
            return $true
        } catch {
            Write-Fail "Start-Process -Credential failed: $($_.Exception.Message)"
            return $false
        } finally {
            foreach ($p in @($stdoutLog, $stderrLog, ($DestinationPath + '.err'))) {
                if ($p -and (Test-Path -LiteralPath $p)) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    # gMSA path: one-shot scheduled task. No password to supply; Task Scheduler
    # talks to LSA which retrieves the gMSA's managed password from AD.
    $taskName = "Manage-DefenderOffline-CredSave-$CredentialName-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        $action = New-ScheduledTaskAction `
            -Execute  $pwshPath `
            -Argument ($argList -join ' ') `
            -WorkingDirectory $ScriptDir

        # Trigger 30s from now to give Set-ScheduledTask + Register time to settle.
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)

        # No -DeleteExpiredTaskAfter: it requires an EndBoundary on the trigger
        # and modern Windows rejects the task XML if absent. The finally block
        # unregisters the task regardless of outcome.
        $settings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit ([timespan]::FromMinutes(5)) `
            -StartWhenAvailable `
            -DontStopIfGoingOnBatteries `
            -AllowStartIfOnBatteries

        $principal = New-ScheduledTaskPrincipal `
            -UserId   $GmsaAccountName `
            -LogonType Password `
            -RunLevel Highest

        Register-ScheduledTask `
            -TaskName    $taskName `
            -TaskPath    '\Manage-DefenderOffline\' `
            -Action      $action `
            -Trigger     $trigger `
            -Settings    $settings `
            -Principal   $principal `
            -Description "One-shot helper: save $CredentialName credential under gMSA identity." `
            -Force | Out-Null

        # Trigger immediately rather than waiting for the 30s timer
        Start-ScheduledTask -TaskName $taskName -TaskPath '\Manage-DefenderOffline\'

        # Poll for completion (up to 60s)
        $deadline = (Get-Date).AddSeconds(60)
        $lastInfo = $null
        do {
            Start-Sleep -Seconds 1
            $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\Manage-DefenderOffline\' -ErrorAction SilentlyContinue
            if ($info) {
                $lastInfo = $info
                if ($info.LastTaskResult -eq 0 -and (Test-Path -LiteralPath $DestinationPath)) {
                    return $true
                }
                # Non-zero result, non-running means it finished and failed
                $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\Manage-DefenderOffline\' -ErrorAction SilentlyContinue
                if ($task -and $task.State -ne 'Running' -and $info.LastTaskResult -ne 0 -and $info.LastTaskResult -ne 267009) {
                    Write-Fail "gMSA credential save task exited with code $($info.LastTaskResult)."
                    $sideLog = $DestinationPath + '.err'
                    if (Test-Path -LiteralPath $sideLog) {
                        $errText = (Get-Content -LiteralPath $sideLog -Raw).Trim()
                        if ($errText) { Write-Info ('Helper error: ' + $errText) }
                        Remove-Item -LiteralPath $sideLog -Force -ErrorAction SilentlyContinue
                    }
                    return $false
                }
            }
        } while ((Get-Date) -lt $deadline)

        if ($lastInfo) {
            Write-Fail "gMSA credential save task did not complete within 60s (LastTaskResult=$($lastInfo.LastTaskResult))."
        } else {
            Write-Fail 'gMSA credential save task could not be inspected.'
        }
        return $false
    } catch {
        Write-Fail "gMSA one-shot task registration failed: $($_.Exception.Message)"
        return $false
    } finally {
        # Always clean up the one-shot task, regardless of outcome
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\Manage-DefenderOffline\' -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Save-ServiceCredential {
    # Coordinates: payload file → run as service identity → cleanup → verify.
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialName',
        Justification = '$CredentialName is a tag ("WinRm"/"AD"/"Smtp"), not credential material; the analyzer false-positives on the substring match.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('WinRm','AD','Smtp')] [string]$CredentialName,
        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [string]$DestinationPath,
        [Parameter(Mandatory)] [bool]$IsGmsa,
        [string]$ServiceAccountName,
        [pscredential]$ServiceAccountCredential,
        [string]$GmsaAccountName,
        [Parameter(Mandatory)] [string]$ConfFolder
    )

    $payload = $null
    try {
        $payload = New-CredentialPayloadFile -Credential $Credential -ConfFolder $ConfFolder
        $ok = Invoke-AsServiceIdentity `
            -CredentialName            $CredentialName `
            -SourcePayloadPath         $payload `
            -DestinationPath           $DestinationPath `
            -IsGmsa                    $IsGmsa `
            -ServiceAccountName        $ServiceAccountName `
            -ServiceAccountCredential  $ServiceAccountCredential `
            -GmsaAccountName           $GmsaAccountName
        if ($ok -and (Test-Path -LiteralPath $DestinationPath)) {
            Write-Ok "$CredentialName credential saved: $DestinationPath"
            return $true
        }
        Write-Fail "$CredentialName credential save failed."
        return $false
    } catch {
        Write-Fail "Save-ServiceCredential ($CredentialName): $($_.Exception.Message)"
        return $false
    } finally {
        if ($payload -and (Test-Path -LiteralPath $payload)) {
            Remove-Item -LiteralPath $payload -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-CredentialPlanForComponent {
    # Returns the set of credentials the chosen Component(s) actually need.
    # Used to decide which prompts to issue and which XMLs to expect post-install.
    param(
        [string]$Component,
        [hashtable]$Config
    )
    $needWinRm = $false
    $needAd    = $false
    $needSmtp  = $false
    if ($Component -in @('Dashboard','All')) { $needWinRm = $true; $needAd = $true }
    if ($Component -in @('Updates','All'))   { $needWinRm = $true; $needAd = $true }
    if ($Component -in @('Updates','All')) {
        $sendEmail = "$($Config['SendEmail'])".Trim()
        if ($sendEmail -match '^(?i)true|1|yes$') { $needSmtp = $true }
    }
    return [pscustomobject]@{
        WinRm = $needWinRm
        AD    = $needAd
        Smtp  = $needSmtp
    }
}

function Show-DeferredCredentialInstructions {
    # Printed when -SkipCredentialSetup is supplied. Tells the operator
    # exactly how to save each credential as the service identity later.
    param(
        [Parameter(Mandatory)] [pscustomobject]$CredentialPlan,
        [Parameter(Mandatory)] [string]$IdentityLabel,
        [string]$ScriptDirectory
    )
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Yellow
    Write-Host '   Credential setup deferred (-SkipCredentialSetup)' -ForegroundColor Yellow
    Write-Host '  ============================================================' -ForegroundColor Yellow
    $needed = @()
    if ($CredentialPlan.WinRm) { $needed += 'WinRmCredential.xml' }
    if ($CredentialPlan.AD)    { $needed += 'ADCredential.xml'   }
    if ($CredentialPlan.Smtp)  { $needed += 'SmtpCredential.xml' }
    if ($needed.Count -eq 0) {
        Write-Info 'No credentials are required for the chosen component selection.'
        return
    }
    Write-Info "The scheduled task(s) will need the following file(s) in $ScriptDirectory\conf\:"
    foreach ($n in $needed) { Write-Info "  - $n" }
    Write-Host ''
    Write-Info 'Save each one under the service identity. Two common approaches:'
    Write-Host ''
    Write-Host '  METHOD 1 — runas (traditional service account only; needs seclogon enabled)' -ForegroundColor Cyan
    Write-Host '    1. Set-Service -Name seclogon -StartupType Manual; Start-Service seclogon' -ForegroundColor DarkGray
    Write-Host "    2. runas /user:$IdentityLabel pwsh.exe" -ForegroundColor DarkGray
    Write-Host '    3. In the elevated pwsh:' -ForegroundColor DarkGray
    Write-Host '         Get-Credential | Export-Clixml -Path .\conf\WinRmCredential.xml -Force' -ForegroundColor DarkGray
    Write-Host '         Get-Credential | Export-Clixml -Path .\conf\ADCredential.xml   -Force' -ForegroundColor DarkGray
    if ($CredentialPlan.Smtp) {
        Write-Host '         Get-Credential | Export-Clixml -Path .\conf\SmtpCredential.xml -Force' -ForegroundColor DarkGray
    }
    Write-Host '    4. Set-Service -Name seclogon -StartupType Disabled; Stop-Service seclogon -Force' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  METHOD 2 — re-run installer without -SkipCredentialSetup' -ForegroundColor Cyan
    Write-Host '    Pass the same identity parameters; the installer will handle seclogon and prompts.' -ForegroundColor DarkGray
    Write-Host ''
}

# ===================================================================
# Frequency → ScheduledTaskTrigger mapping
#
# Maps the user-facing Frequency + UpdateStartTime to one or more
# New-ScheduledTaskTrigger objects. For TwiceDaily the second run is
# 12 hours after the first; for Weekly the day is Sunday; for Monthly
# the day-of-month is 1.
# ===================================================================
function ConvertTo-UpdateTaskTrigger {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('TwiceDaily','Daily','Weekly','Monthly')]
        [string]$Frequency,

        [Parameter(Mandatory)]
        [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
        [string]$StartTime
    )

    $hh, $mm = $StartTime.Split(':')
    $today   = Get-Date -Hour ([int]$hh) -Minute ([int]$mm) -Second 0

    switch ($Frequency) {
        'TwiceDaily' {
            $secondHHmm = '{0:HH:mm}' -f $today.AddHours(12)
            return @(
                (New-ScheduledTaskTrigger -Daily -At $today),
                (New-ScheduledTaskTrigger -Daily -At $secondHHmm)
            )
        }
        'Daily'  { return @(New-ScheduledTaskTrigger -Daily  -At $today) }
        'Weekly' { return @(New-ScheduledTaskTrigger -Weekly -At $today -DaysOfWeek Sunday) }
        'Monthly' {
            # New-ScheduledTaskTrigger has no -Monthly; build the CIM
            # MSFT_TaskMonthlyTrigger directly. Day-of-month 1, all 12 months
            # (DaysOfMonth bit 0 = day 1; months bitmask 4095 = Jan..Dec).
            #
            # Property naming varies across Windows builds:
            #   - Historical: MonthsOfYear (plural)
            #   - Windows 11 26200+: MonthOfYear (singular)
            # Detect the actual name from the CIM schema at runtime rather
            # than hardcoding either.
            $class = Get-CimClass -Namespace ROOT/Microsoft/Windows/TaskScheduler `
                                  -ClassName MSFT_TaskMonthlyTrigger -ErrorAction Stop
            $propNames = $class.CimClassProperties.Name
            $monthsKey = if     ($propNames -contains 'MonthsOfYear') { 'MonthsOfYear' }
                         elseif ($propNames -contains 'MonthOfYear')  { 'MonthOfYear'  }
                         else { throw "MSFT_TaskMonthlyTrigger on this host has neither MonthsOfYear nor MonthOfYear. Properties: $($propNames -join ', ')" }

            $properties = @{
                Enabled       = $true
                StartBoundary = $today.ToString('s')
                DaysOfMonth   = [uint16]1
            }
            $properties[$monthsKey] = [uint16]4095
            $trig = New-CimInstance -CimClass $class -ClientOnly -Property $properties
            return @($trig)
        }
    }
}

function Initialize-ServiceCredentials {
    # Top-level orchestrator. Returns $true on overall success (no required
    # credential failed). Handles -SkipCredentialSetup, STIG seclogon
    # state, prompting, saving, and restoration.
    param(
        [Parameter(Mandatory)] [string]$Component,
        [Parameter(Mandatory)] [string]$IdentityLabel,
        [Parameter(Mandatory)] [bool]$IsGmsa,
        [string]$ServiceAccountName,
        [pscredential]$ServiceAccountCredential,
        [string]$GmsaAccountName,
        [string]$ConfFolder,
        [hashtable]$Config,
        [pscredential]$PreSuppliedWinRm,
        [pscredential]$PreSuppliedAd,
        [pscredential]$PreSuppliedSmtp,
        [string]$WinRmUsername,
        [string]$AdUsername,
        [string]$SmtpUsername,
        [bool]$Skip,
        [bool]$Force
    )

    $plan = Get-CredentialPlanForComponent -Component $Component -Config $Config

    if ($Skip) {
        Show-DeferredCredentialInstructions -CredentialPlan $plan -IdentityLabel $IdentityLabel -ScriptDirectory $ScriptDir
        return $true
    }

    if (-not ($plan.WinRm -or $plan.AD -or $plan.Smtp)) {
        Write-Ok 'No credentials need to be saved for the chosen component selection.'
        return $true
    }

    Write-Section "Credential Setup ($IdentityLabel)"

    # ----- Surface which prompts will be pre-populated and which won't -----
    $prefillRows = @()
    if ($plan.WinRm) { $prefillRows += [pscustomobject]@{ Type='WinRM'; User = $(if ($WinRmUsername) { $WinRmUsername } else { '(blank — operator will type)' }) } }
    if ($plan.AD)    { $prefillRows += [pscustomobject]@{ Type='AD';    User = $(if ($AdUsername)    { $AdUsername    } else { '(blank — operator will type)' }) } }
    if ($plan.Smtp)  { $prefillRows += [pscustomobject]@{ Type='SMTP';  User = $(if ($SmtpUsername)  { $SmtpUsername  } else { '(blank — operator will type)' }) } }
    if ($prefillRows.Count -gt 0) {
        Write-Info 'Prompt username pre-fills (from -*Username CLI / [Credentials] config):'
        foreach ($row in $prefillRows) { Write-Info ("  {0,-6} -> {1}" -f $row.Type, $row.User) }
        Write-Host ''
    }

    # ----- Gather (prompt or use pre-supplied) -----
    # Prompts pre-populate the username field from -*Username (CLI) or the
    # [Credentials] *Username keys in conf/config.conf. Format hints in the
    # prompt message: DOMAIN\username or username@domain.tld.
    $toSave = [System.Collections.Generic.List[object]]::new()
    $fmtHint = '  (format: DOMAIN\username or username@domain.tld)'
    if ($plan.WinRm) {
        $c = if ($PreSuppliedWinRm) { $PreSuppliedWinRm } else {
            $msg = "WinRM credential - used by the scheduled tasks to query endpoint Defender state.$fmtHint"
            if ($WinRmUsername) { Get-Credential -UserName $WinRmUsername -Message $msg }
            else                 { Get-Credential                          -Message $msg }
        }
        if (-not $c) { Write-Fail 'WinRM credential prompt cancelled.'; return $false }
        $toSave.Add([pscustomobject]@{
            Name = 'WinRm'; Credential = $c
            Destination = Join-Path $ConfFolder 'WinRmCredential.xml'
        })
    }
    if ($plan.AD) {
        $c = if ($PreSuppliedAd) { $PreSuppliedAd } else {
            $msg = "AD credential - used for AD-based fleet discovery and Negotiate auth context.$fmtHint"
            if ($AdUsername) { Get-Credential -UserName $AdUsername -Message $msg }
            else              { Get-Credential                       -Message $msg }
        }
        if (-not $c) { Write-Fail 'AD credential prompt cancelled.'; return $false }
        $toSave.Add([pscustomobject]@{
            Name = 'AD'; Credential = $c
            Destination = Join-Path $ConfFolder 'ADCredential.xml'
        })
    }
    if ($plan.Smtp) {
        $c = if ($PreSuppliedSmtp) { $PreSuppliedSmtp } else {
            # SMTP format varies by relay (often user@domain.tld); show a relay-aware hint.
            $smtpHint = '  (format: depends on your SMTP relay - often user@domain.tld)'
            $msg = "SMTP credential - used by the Updates task to send notification emails.$smtpHint"
            if ($SmtpUsername) { Get-Credential -UserName $SmtpUsername -Message $msg }
            else                { Get-Credential                         -Message $msg }
        }
        if (-not $c) { Write-Fail 'SMTP credential prompt cancelled.'; return $false }
        $toSave.Add([pscustomobject]@{
            Name = 'Smtp'; Credential = $c
            Destination = Join-Path $ConfFolder 'SmtpCredential.xml'
        })
    }

    # ----- Make sure the helper script exists -----
    Initialize-CredentialSaveHelper

    # ----- STIG V-253289 seclogon dance -----
    $seclogonInfo = Test-SecondaryLogonService
    $needsRestore = $false
    $originalSeclogonStatus    = $null
    $originalSeclogonStartType = $null

    if (-not $seclogonInfo.Exists) {
        Write-Fail 'Secondary Logon service (seclogon) not found on this host. Cannot save credentials automatically.'
        Write-Info 'Re-run with -SkipCredentialSetup and save credentials manually.'
        return $false
    }

    # Only traditional service accounts use seclogon (via Start-Process -Credential).
    # gMSA path goes through a scheduled task which doesn't need seclogon, so skip
    # the dance entirely for gMSA.
    #
    # For traditional accounts, the question is: can Start-Process -Credential
    # launch processes right now? It can iff seclogon is Running — independent
    # of StartType. So we use Status as the primary signal:
    #   - Status = Running                       → leverage as-is, no dance
    #   - Status = Stopped, StartType = Disabled → flip Manual, Start, save,
    #                                              restore to Stopped+Disabled
    #   - Status = Stopped, StartType = Manual/Auto → Start, save, restore to
    #                                                 Stopped (StartType unchanged)
    if (-not $IsGmsa) {
        $originalSeclogonStatus    = "$($seclogonInfo.Status)"
        $originalSeclogonStartType = "$($seclogonInfo.StartType)"

        if ($seclogonInfo.Status -eq 'Running') {
            Write-Info "Secondary Logon service: StartupType=$($seclogonInfo.StartType), Status=Running. No state change needed."
        } else {
            Write-Step "Secondary Logon Service needs to be started for credential save (current: Status=$($seclogonInfo.Status), StartType=$($seclogonInfo.StartType))."
            Write-Info "After save, the installer will restore the service to its original state (Status=$originalSeclogonStatus, StartType=$originalSeclogonStartType)."
            if (-not $Force) {
                $answer = Read-Host '    Continue? [Y/N]'
                if ($answer -notmatch '^[Yy]') {
                    Write-Warn 'Credential setup cancelled. Re-run with -Force or -SkipCredentialSetup.'
                    return $false
                }
            }
            # Flip StartType to Manual only if it's currently Disabled
            # (otherwise the service is already startable as-is).
            if ($seclogonInfo.StartType -eq 'Disabled') {
                Write-Info 'Enabling Secondary Logon (StartupType=Manual)…'
                if (-not (Set-SecondaryLogonService -StartType Manual)) {
                    Write-Fail 'Could not enable Secondary Logon service. Aborting credential save.'
                    return $false
                }
            }
            try {
                Start-Service -Name seclogon -ErrorAction Stop
            } catch {
                Write-Fail "Could not start Secondary Logon service: $($_.Exception.Message)"
                # Revert the StartType change we just made if applicable
                if ($seclogonInfo.StartType -eq 'Disabled') {
                    Set-SecondaryLogonService -StartType Disabled | Out-Null
                }
                return $false
            }
            $needsRestore = $true
            Write-Ok 'Secondary Logon service is now Running (temporary)'
        }
    }

    # ----- Save each credential -----
    $allOk = $true
    try {
        foreach ($item in $toSave) {
            Write-Step "Saving $($item.Name) credential as $IdentityLabel…"
            $ok = Save-ServiceCredential `
                -CredentialName            $item.Name `
                -Credential                $item.Credential `
                -DestinationPath           $item.Destination `
                -IsGmsa                    $IsGmsa `
                -ServiceAccountName        $ServiceAccountName `
                -ServiceAccountCredential  $ServiceAccountCredential `
                -GmsaAccountName           $GmsaAccountName `
                -ConfFolder                $ConfFolder
            if (-not $ok) { $allOk = $false }
        }
    } finally {
        if ($needsRestore) {
            Restore-SecondaryLogonService `
                -OriginalStartType $originalSeclogonStartType `
                -OriginalStatus    $originalSeclogonStatus
        }
    }
    return $allOk
}

# ===================================================================
# Service-identity validation (shared across components)
# ===================================================================
function Test-ServiceIdentityForInstall {
    param(
        [bool]$IsGmsa,
        [string]$GmsaAccountName,
        [string]$ServiceAccountName,
        [pscredential]$ServiceAccountCredential
    )

    if ($IsGmsa) {
        $gmsaSam = $GmsaAccountName -replace '^.+\\', ''
        try {
            if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
                Import-Module ActiveDirectory -ErrorAction Stop
                $acct = Get-ADServiceAccount -Filter "SamAccountName -eq '$gmsaSam'" -ErrorAction Stop
                if (-not $acct) { throw "gMSA '$gmsaSam' not found in Active Directory." }
                Write-Ok "gMSA found in AD: $($acct.DistinguishedName)"

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
            return $false
        }
    } else {
        Write-Ok "Service account: $ServiceAccountName"
        if ($ServiceAccountCredential.UserName -ne $ServiceAccountName) {
            Write-Warn "Credential username ($($ServiceAccountCredential.UserName)) does not match -ServiceAccount ($ServiceAccountName)."
        }
    }
    return $true
}

# ===================================================================
# Common Windows Event Log source registration (used by Dashboard)
# ===================================================================
function Register-DashboardEventLogSource {
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
}

# ===================================================================
# Dashboard component install
# Encapsulates the Dashboard scheduled-task install logic:
#   - identity already validated by caller
#   - directory creation/ACL deduped against the shared script folder
#   - no embedded credential helper (handled by Initialize-ServiceCredentials)
# ===================================================================
function Install-DashboardComponent {
    param(
        [Parameter(Mandatory)] [string]$DashboardScriptPath,
        [Parameter(Mandatory)] [bool]$IsGmsa,
        [string]$ServiceAccountName,
        [pscredential]$ServiceAccountCredential,
        [string]$GmsaAccountName,
        [Parameter(Mandatory)] [string]$IdentityLabel,
        [Parameter(Mandatory)] [string]$TaskName,
        [Parameter(Mandatory)] [string]$TaskFolder,
        [Parameter(Mandatory)] [int]$Port,
        [Parameter(Mandatory)] [int]$FallbackPort,
        [Parameter(Mandatory)] [int]$RefreshInterval,
        [Parameter(Mandatory)] [string]$LogPath,
        [Parameter(Mandatory)] [int]$ParallelThreads,
        [Parameter(Mandatory)] [int]$TimeoutSeconds,
        [string]$SourceSharePath,
        [switch]$UseHttps,
        [string]$CertificateThumbprint,
        [switch]$RenewCertificate,
        [string]$AdditionalSans,
        [string]$AuthMethod,
        [string]$AuthAllowedGroups,
        [string]$AuthBasicUsersFile,
        [string]$AuthToken,
        [Parameter(Mandatory)] [string]$ConfigPath,
        [hashtable]$ConfigSnapshot,
        [switch]$AddFirewallRule,
        [switch]$StartImmediately,
        [switch]$Force,
        [Parameter(Mandatory)] [string]$PwshPath,
        [Parameter(Mandatory)] [string]$ConfFolder
    )

    Write-Section "Component: Dashboard"

    # ----- Sanity checks -----
    if ($RenewCertificate -and -not $UseHttps) {
        Write-Fail '-RenewCertificate requires -UseHttps (cert regeneration only makes sense in HTTPS mode).'
        return $false
    }
    if ($CertificateThumbprint -and -not $UseHttps) {
        Write-Warn '-CertificateThumbprint supplied without -UseHttps; the thumbprint will not be persisted or bound.'
    }

    Write-Step "Creating directories and granting filesystem access…"
    $scriptFolder = Split-Path $DashboardScriptPath -Parent
    foreach ($p in @($LogPath, $scriptFolder, $ConfFolder) | Select-Object -Unique) {
        if (-not (Test-Path $p)) {
            New-Item -Path $p -ItemType Directory -Force | Out-Null
            Write-Ok "Created: $p"
        } else {
            Write-Ok "Exists : $p"
        }
    }
    Grant-FolderAccess -Path $scriptFolder -Identity $IdentityLabel -Rights 'ReadAndExecute'
    Grant-FolderAccess -Path $ConfFolder   -Identity $IdentityLabel -Rights 'Modify'
    Grant-FolderAccess -Path $LogPath      -Identity $IdentityLabel -Rights 'Modify'

    Register-DashboardEventLogSource

    # ----- HTTPS setup -----
    if ($UseHttps) {
        Write-Step "Configuring HTTPS…"

        $certShouldGenerate = $RenewCertificate -or -not $CertificateThumbprint
        if (-not $RenewCertificate -and $CertificateThumbprint) {
            $existing = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            if (-not $existing) {
                Write-Warn "CertificateThumbprint $CertificateThumbprint not found in Cert:\LocalMachine\My — will generate a new self-signed cert."
                $certShouldGenerate = $true
            } elseif ($existing.NotAfter -lt (Get-Date)) {
                Write-Warn "Existing cert $CertificateThumbprint expired on $($existing.NotAfter.ToString('yyyy-MM-dd')) — will generate a replacement."
                $certShouldGenerate = $true
            } else {
                Write-Ok "Reusing existing cert: $($existing.Subject) (expires $($existing.NotAfter.ToString('yyyy-MM-dd')))"
                $existingSans = if ($existing.DnsNameList) {
                    @($existing.DnsNameList | ForEach-Object { $_.Punycode }) -join ', '
                } else { '(none)' }
                Write-Info "  Subject Alt Names: $existingSans"
                if ($AdditionalSans) {
                    Write-Warn "  -AdditionalSans was supplied but is ignored when reusing an existing cert."
                    Write-Warn "  To apply additional SANs, re-run with -RenewCertificate."
                }
            }
        }

        if ($certShouldGenerate) {
            try {
                $fqdn = if ($env:USERDNSDOMAIN) { "$env:COMPUTERNAME.$env:USERDNSDOMAIN" } else { $env:COMPUTERNAME }
                $primaryIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and
                        $_.PrefixOrigin -ne 'WellKnown'
                    } |
                    Sort-Object InterfaceIndex |
                    Select-Object -First 1 -ExpandProperty IPAddress)

                $sanList = New-Object 'System.Collections.Generic.List[string]'
                [void]$sanList.Add($env:COMPUTERNAME)
                if ($fqdn -ne $env:COMPUTERNAME) { [void]$sanList.Add($fqdn) }
                [void]$sanList.Add('localhost')
                if ($primaryIp) { [void]$sanList.Add($primaryIp) }
                if ($AdditionalSans) {
                    foreach ($extra in ($AdditionalSans -split ',')) {
                        $e = $extra.Trim()
                        if ($e -and -not $sanList.Contains($e)) { [void]$sanList.Add($e) }
                    }
                }

                $newCert = New-SelfSignedCertificate `
                    -Subject "CN=$env:COMPUTERNAME" `
                    -DnsName $sanList.ToArray() `
                    -CertStoreLocation 'Cert:\LocalMachine\My' `
                    -NotAfter (Get-Date).AddYears(2) `
                    -KeyAlgorithm RSA -KeyLength 2048 `
                    -KeyExportPolicy NonExportable `
                    -KeyUsage DigitalSignature, KeyEncipherment `
                    -ErrorAction Stop
                $CertificateThumbprint = $newCert.Thumbprint
                Write-Ok "Generated self-signed certificate"
                Write-Info "  Subject     : $($newCert.Subject)"
                Write-Info "  SANs        : $($sanList -join ', ')"
                Write-Info "  Thumbprint  : $CertificateThumbprint"
                Write-Info "  Expires     : $($newCert.NotAfter.ToString('yyyy-MM-dd')) (2 years)"
            } catch {
                Write-Fail "Self-signed certificate generation failed: $($_.Exception.Message)"
                return $false
            }
        }

        # netsh sslcert binding
        try {
            $existingBinding = & netsh http show sslcert "ipport=0.0.0.0:$Port" 2>&1
            if ($LASTEXITCODE -eq 0 -and $existingBinding -match 'Certificate Hash') {
                $null = & netsh http delete sslcert "ipport=0.0.0.0:$Port" 2>&1
                Write-Info "Removed prior netsh sslcert binding on 0.0.0.0:$Port"
            }
            $netshOut = & netsh http add sslcert "ipport=0.0.0.0:$Port" "certhash=$CertificateThumbprint" "appid=$script:HttpsAppId" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Fail "netsh sslcert binding failed: $($netshOut -join ' ')"
                return $false
            }
            Write-Ok "Bound certificate to 0.0.0.0:$Port via netsh sslcert"
        } catch {
            Write-Fail "netsh sslcert binding error: $($_.Exception.Message)"
            return $false
        }

        # URL ACL
        try {
            $null = & netsh http delete urlacl "url=https://+:$Port/" 2>&1
            $netshOut = & netsh http add urlacl "url=https://+:$Port/" "user=$IdentityLabel" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Fail "netsh urlacl add failed: $($netshOut -join ' ')"
                return $false
            }
            Write-Ok "URL ACL granted: https://+:$Port/ -> $IdentityLabel"
        } catch {
            Write-Fail "netsh urlacl error: $($_.Exception.Message)"
            return $false
        }

        try {
            Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'UseHttps'              -Value 'true'
            Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'CertificateThumbprint' -Value $CertificateThumbprint
            Write-Ok "Persisted UseHttps=true and CertificateThumbprint to conf/config.conf"
        } catch {
            Write-Fail "Failed to update config.conf: $($_.Exception.Message)"
            return $false
        }
    }

    # Always persist the effective Port to config.conf
    try {
        Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'Port' -Value $Port | Out-Null
    } catch {
        Write-Warn "Could not persist Port=$Port to config.conf: $($_.Exception.Message)"
    }

    # ----- Auth pass-through -----
    if ($AuthMethod -or $AuthAllowedGroups -or $AuthBasicUsersFile -or $AuthToken) {
        Write-Step "Configuring authentication…"
        try {
            if ($AuthMethod)         { Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthMethod' -Value $AuthMethod;          Write-Ok "Persisted AuthMethod=$AuthMethod" }
            if ($AuthAllowedGroups)  { Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthAllowedGroups' -Value $AuthAllowedGroups;     Write-Ok "Persisted AuthAllowedGroups=$AuthAllowedGroups" }
            if ($AuthBasicUsersFile) { Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthBasicUsersFile' -Value $AuthBasicUsersFile;   Write-Ok "Persisted AuthBasicUsersFile=$AuthBasicUsersFile" }
            if ($AuthToken)          { Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthToken' -Value $AuthToken;                     Write-Ok 'Persisted AuthToken (value not displayed)' }
        } catch {
            Write-Fail "Failed to update config.conf: $($_.Exception.Message)"
            return $false
        }
        if ($AuthMethod -eq 'Basic' -and -not $UseHttps) {
            Write-Fail "AuthMethod=Basic without -UseHttps would send credentials in cleartext on every request."
            return $false
        }
    }

    # ----- Stop existing instance + port check -----
    $existingTaskPre = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder -ErrorAction SilentlyContinue
    if ($existingTaskPre -and $existingTaskPre.State -eq 'Running') {
        Write-Step "Stopping previously installed dashboard task…"
        try {
            Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder -ErrorAction Stop
            for ($wait = 0; $wait -lt 10; $wait++) {
                if (Test-PortFree $Port) { break }
                Start-Sleep -Milliseconds 500
            }
            Write-Ok "Previous instance stopped"
        } catch {
            Write-Warn "Could not stop existing task: $($_.Exception.Message)"
        }
    }

    Write-Step "Checking port availability…"
    if ($UseHttps) {
        if (-not (Test-PortFree $Port)) {
            Write-Fail "Port $Port is in use and HTTPS does not support fallback (cert binding is per-port)."
            return $false
        }
        $portResult = [pscustomobject]@{ Port = $Port; IsFallback = $false; PrimaryPort = $Port }
        Write-Ok "Port $Port is available (HTTPS)"
    } else {
        $portResult = Find-AvailablePort -Primary $Port -Fallback $FallbackPort
        if ($portResult.IsFallback) {
            Write-Warn "Port $($portResult.PrimaryPort) is already in use on this host."
            Write-Ok   "Using fallback port $($portResult.Port) instead."
            $Port = $portResult.Port
        } else {
            Write-Ok "Port $Port is available"
        }
    }

    # ----- Build action -----
    Write-Step "Building scheduled task…"
    $argParts = @(
        '-NonInteractive', '-NoProfile', '-ExecutionPolicy Bypass', '-WindowStyle Hidden',
        "-File `"$DashboardScriptPath`"",
        "-Port $Port", "-RefreshInterval $RefreshInterval",
        "-LogPath `"$LogPath`"",
        "-ParallelThreads $ParallelThreads", "-TimeoutSeconds $TimeoutSeconds"
    )
    if ($SourceSharePath) { $argParts += "-SourceSharePath `"$SourceSharePath`"" }
    $taskArguments = $argParts -join ' '
    Write-Info "Action: $PwshPath $taskArguments"

    $action  = New-ScheduledTaskAction -Execute $PwshPath -Argument $taskArguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit  ([timespan]::Zero) `
        -MultipleInstances   IgnoreNew `
        -StartWhenAvailable `
        -RestartCount        3 `
        -RestartInterval     ([timespan]::FromMinutes(1)) `
        -DontStopIfGoingOnBatteries `
        -AllowStartIfOnBatteries

    if ($IsGmsa) {
        $principal = New-ScheduledTaskPrincipal -UserId $GmsaAccountName -LogonType Password -RunLevel Highest
    } else {
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccountName -LogonType Password -RunLevel Highest
    }

    $existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder -ErrorAction SilentlyContinue
    if ($existingTask -and -not $Force) {
        Write-Warn "A task named '$TaskName' already exists in '$TaskFolder'."
        $answer = Read-Host "    Overwrite it? [Y/N]"
        if ($answer -notmatch '^[Yy]') {
            Write-Warn 'Dashboard install cancelled by user.'
            return $false
        }
    }

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
        if (-not $IsGmsa) {
            $registerParams.Password = $ServiceAccountCredential.GetNetworkCredential().Password
            $registerParams.User     = $ServiceAccountName
            $registerParams.Remove('Principal') | Out-Null
            $registerParams.RunLevel = 'Highest'
        }
        Register-ScheduledTask @registerParams | Out-Null
        $fullTaskPath = if ($TaskFolder.EndsWith('\')) { "$TaskFolder$TaskName" } else { "$TaskFolder\$TaskName" }
        Write-Ok "Task registered: $fullTaskPath"
    } catch {
        Write-Fail "Failed to register Dashboard task: $($_.Exception.Message)"
        return $false
    }

    # ----- Firewall -----
    if ($AddFirewallRule) {
        Write-Step "Creating Windows Firewall inbound rule(s)…"
        $proto   = if ($UseHttps) { 'HTTPS' } else { 'HTTP' }
        $purpose = if ($UseHttps) { 'HTTPS traffic' } else { 'HTTP traffic' }
        Add-DashboardFirewallRule -RulePort $Port -Protocol $proto -Purpose $purpose -Force:$Force
        if ($UseHttps) {
            $redirectEnabled = ($ConfigSnapshot['RedirectHttpToHttps'] -ne 'false')
            $redirectPort    = if ($ConfigSnapshot['RedirectHttpPort']) { [int]$ConfigSnapshot['RedirectHttpPort'] } else { 8080 }
            if ($redirectEnabled -and $redirectPort -ne $Port) {
                Add-DashboardFirewallRule -RulePort $redirectPort -Protocol 'HTTP-Redirect' -Purpose 'HTTP traffic (301-redirected to HTTPS)' -Force:$Force
            }
        }
    }

    # ----- Start + verify -----
    if ($StartImmediately) {
        Write-Step "Starting task…"
        try {
            Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder
            Write-Ok "Task started"
        } catch {
            Write-Fail "Could not start task: $($_.Exception.Message)"
        }

        Write-Step "Waiting for dashboard to start (up to 45s)…"
        $statusFile   = Join-Path $ConfFolder 'dashboard.status'
        $deadline     = [datetime]::Now.AddSeconds(45)
        $statusLoaded = $false
        while ([datetime]::Now -lt $deadline -and -not $statusLoaded) {
            Start-Sleep -Seconds 3
            if (Test-Path $statusFile) { $statusLoaded = $true; break }
            Write-Info "  …waiting for status file ($([int]($deadline - [datetime]::Now).TotalSeconds)s remaining)"
        }

        if ($statusLoaded) {
            $runtimeStatus = Read-ConfigFile $statusFile
            $actualPort    = if ($runtimeStatus['Port']) { [int]$runtimeStatus['Port'] } else { $Port }
            if ($runtimeStatus['IsFallback'] -eq 'True') {
                Write-Warn "Dashboard started on FALLBACK port $actualPort."
                Write-Info "ACTION REQUIRED: Update firewall rules, bookmarks, and monitoring tools to port $actualPort."
                $Port = $actualPort
            } else {
                Write-Ok "Dashboard started on port $actualPort"
            }

            $probeScheme = if ($UseHttps) { 'https' } else { 'http' }
            $probeUrl    = "${probeScheme}://localhost:$actualPort/health"
            $probeOk     = $false
            $lastErr     = $null
            $probeStart  = Get-Date
            for ($i = 1; $i -le 6; $i++) {
                try {
                    $iwrParams = @{ Uri = $probeUrl; TimeoutSec = 10; UseBasicParsing = $true; ErrorAction = 'Stop' }
                    if ($UseHttps) { $iwrParams.SkipCertificateCheck = $true }
                    $resp = Invoke-WebRequest @iwrParams
                    if ($resp.StatusCode -eq 200) { $probeOk = $true; break }
                } catch {
                    $lastErr = $_.Exception.Message
                    Start-Sleep -Seconds 5
                }
            }
            $elapsed = [int]((Get-Date) - $probeStart).TotalSeconds
            if ($probeOk) {
                Write-Ok "$($probeScheme.ToUpper()) health probe passed after ${elapsed}s: $probeUrl → 200 OK"
            } else {
                Write-Warn "Status file present but /health probe failed after ${elapsed}s of retries: $lastErr"
            }
        } else {
            Write-Warn "Dashboard did not write a status file within 45 seconds."
            Write-Info "Check the dashboard log: $LogPath"
        }
    }

    return $true
}

function Add-DashboardFirewallRule {
    param([int]$RulePort, [string]$Protocol, [string]$Purpose, [switch]$Force)
    $ruleName = "DefenderDashboard-${Protocol}-$RulePort"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Write-Warn "Firewall rule '$ruleName' already exists – skipping. (Re-run with -Force to replace.)"
        return
    }
    try {
        if ($existing) {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
            Write-Info "Removed existing rule '$ruleName' (replacing because -Force was specified)."
        }
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Description "Allows inbound $Purpose to the Defender Fleet Dashboard on TCP $RulePort" `
            -Direction   Inbound -Protocol TCP `
            -LocalPort   $RulePort -Action Allow `
            -Profile     Domain, Private -Enabled True | Out-Null
        Write-Ok "Firewall rule created: $ruleName (TCP $RulePort, Domain+Private profiles)"
    } catch {
        Write-Warn "Could not create firewall rule '$ruleName': $($_.Exception.Message)"
    }
}

# ===================================================================
# Updates component install
# ===================================================================
function Install-UpdatesComponent {
    param(
        [Parameter(Mandatory)] [string]$UpdateScriptPath,
        [Parameter(Mandatory)] [bool]$IsGmsa,
        [string]$ServiceAccountName,
        [pscredential]$ServiceAccountCredential,
        [string]$GmsaAccountName,
        [Parameter(Mandatory)] [string]$IdentityLabel,
        [Parameter(Mandatory)] [string]$TaskName,
        [Parameter(Mandatory)] [string]$TaskFolder,
        [Parameter(Mandatory)] [string]$Frequency,
        [Parameter(Mandatory)] [string]$UpdateStartTime,
        [Parameter(Mandatory)] [string]$ConfigPath,
        [string]$CanaryComputers,
        [int]$MaxCanaryFailures,
        [switch]$RunNowWhatIf,
        [switch]$Force,
        [Parameter(Mandatory)] [string]$PwshPath,
        [Parameter(Mandatory)] [string]$ConfFolder
    )

    Write-Section "Component: Updates"

    # Persist frequency + time to config so re-runs without -Frequency/-UpdateStartTime
    # don't silently revert to defaults.
    try {
        Update-ConfigValue -Path $ConfigPath -Section 'Install' -Key 'UpdateTaskName'   -Value $TaskName        | Out-Null
        Update-ConfigValue -Path $ConfigPath -Section 'Install' -Key 'UpdateFrequency'  -Value $Frequency       | Out-Null
        Update-ConfigValue -Path $ConfigPath -Section 'Install' -Key 'UpdateStartTime'  -Value $UpdateStartTime | Out-Null
        if ($PSBoundParameters.ContainsKey('CanaryComputers')) {
            Update-ConfigValue -Path $ConfigPath -Section 'Update' -Key 'CanaryComputers' -Value $CanaryComputers | Out-Null
        }
        if ($PSBoundParameters.ContainsKey('MaxCanaryFailures')) {
            Update-ConfigValue -Path $ConfigPath -Section 'Update' -Key 'MaxCanaryFailures' -Value $MaxCanaryFailures | Out-Null
        }
        Write-Ok "Persisted Updates task settings to conf/config.conf"
    } catch {
        Write-Warn "Could not persist Updates task settings to config: $($_.Exception.Message)"
    }

    # ----- Directory + ACL (LogPath defaults handled by Update script; we just ensure
    #       the conf and script folders are reachable for the service identity) -----
    $scriptFolder = Split-Path $UpdateScriptPath -Parent
    foreach ($p in @($scriptFolder, $ConfFolder) | Select-Object -Unique) {
        if (-not (Test-Path $p)) {
            New-Item -Path $p -ItemType Directory -Force | Out-Null
            Write-Ok "Created: $p"
        }
    }
    Grant-FolderAccess -Path $scriptFolder -Identity $IdentityLabel -Rights 'ReadAndExecute'
    Grant-FolderAccess -Path $ConfFolder   -Identity $IdentityLabel -Rights 'Modify'

    # ----- Action: pwsh.exe -File Update-DefenderOffline.ps1 -ConfigPath … -----
    Write-Step "Building scheduled task…"
    $argParts = @(
        '-NonInteractive', '-NoProfile', '-ExecutionPolicy Bypass', '-WindowStyle Hidden',
        "-File `"$UpdateScriptPath`"",
        "-ConfigPath `"$ConfigPath`""
    )
    $taskArguments = $argParts -join ' '
    Write-Info "Action: $PwshPath $taskArguments"

    $action  = New-ScheduledTaskAction -Execute $PwshPath -Argument $taskArguments

    $triggers = ConvertTo-UpdateTaskTrigger -Frequency $Frequency -StartTime $UpdateStartTime

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit  ([timespan]::FromHours(4)) `
        -MultipleInstances   IgnoreNew `
        -StartWhenAvailable `
        -RestartCount        2 `
        -RestartInterval     ([timespan]::FromMinutes(15)) `
        -DontStopIfGoingOnBatteries `
        -AllowStartIfOnBatteries

    if ($IsGmsa) {
        $principal = New-ScheduledTaskPrincipal -UserId $GmsaAccountName -LogonType Password -RunLevel Highest
    } else {
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccountName -LogonType Password -RunLevel Highest
    }

    $existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder -ErrorAction SilentlyContinue
    if ($existingTask -and -not $Force) {
        Write-Warn "A task named '$TaskName' already exists in '$TaskFolder'."
        $answer = Read-Host "    Overwrite it? [Y/N]"
        if ($answer -notmatch '^[Yy]') {
            Write-Warn 'Updates install cancelled by user.'
            return $false
        }
    }

    try {
        if ($Frequency -eq 'Monthly') {
            # The MSFT_TaskMonthlyTrigger CIM schema differs across Windows
            # builds — property name (MonthsOfYear vs MonthOfYear) and
            # semantics (bitmask vs single-month index) vary. The Task
            # Scheduler XML schema is stable and documented, so use it
            # directly for the Monthly path instead.
            $description    = "Periodic Defender definition push - Update-DefenderOffline.ps1 v$ScriptVersion ($Frequency $UpdateStartTime)"
            $startBoundary  = (Get-Date $UpdateStartTime).ToString('yyyy-MM-ddTHH:mm:ss')
            $descXml        = [System.Security.SecurityElement]::Escape($description)
            $execXml        = [System.Security.SecurityElement]::Escape($PwshPath)
            $argXml         = [System.Security.SecurityElement]::Escape($taskArguments)
            $identityForXml = if ($IsGmsa) { $GmsaAccountName } else { $ServiceAccountName }
            $userXml        = [System.Security.SecurityElement]::Escape($identityForXml)

            $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>$descXml</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>$startBoundary</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByMonth>
        <DaysOfMonth><Day>1</Day></DaysOfMonth>
        <Months>
          <January /><February /><March /><April /><May /><June />
          <July /><August /><September /><October /><November /><December />
        </Months>
      </ScheduleByMonth>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$userXml</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT15M</Interval>
      <Count>2</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$execXml</Command>
      <Arguments>$argXml</Arguments>
    </Exec>
  </Actions>
</Task>
"@
            $regXmlParams = @{
                TaskName    = $TaskName
                TaskPath    = $TaskFolder
                Xml         = $taskXml
                Force       = $true
                ErrorAction = 'Stop'
            }
            if ($IsGmsa) {
                $regXmlParams.User = $GmsaAccountName
            } else {
                $regXmlParams.User     = $ServiceAccountName
                $regXmlParams.Password = $ServiceAccountCredential.GetNetworkCredential().Password
            }
            Register-ScheduledTask @regXmlParams | Out-Null
        } else {
            $registerParams = @{
                TaskName    = $TaskName
                TaskPath    = $TaskFolder
                Action      = $action
                Trigger     = $triggers
                Settings    = $settings
                Principal   = $principal
                Description = "Periodic Defender definition push - Update-DefenderOffline.ps1 v$ScriptVersion ($Frequency $UpdateStartTime)"
                Force       = $true
                ErrorAction = 'Stop'
            }
            if (-not $IsGmsa) {
                $registerParams.Password = $ServiceAccountCredential.GetNetworkCredential().Password
                $registerParams.User     = $ServiceAccountName
                $registerParams.Remove('Principal') | Out-Null
                $registerParams.RunLevel = 'Highest'
            }
            Register-ScheduledTask @registerParams | Out-Null
        }
        $fullTaskPath = if ($TaskFolder.EndsWith('\')) { "$TaskFolder$TaskName" } else { "$TaskFolder\$TaskName" }
        Write-Ok "Task registered: $fullTaskPath"
        Write-Info "Schedule: $Frequency at $UpdateStartTime$(if ($Frequency -eq 'TwiceDaily') { " + 12h" })"
    } catch {
        Write-Fail "Failed to register Updates task: $($_.Exception.Message)"
        return $false
    }

    # ----- Optional WhatIf smoke test -----
    # MUST run as the service identity (for DPAPI decrypt) AND elevated
    # (for the Update script's admin check). Start-Process -Credential
    # cannot satisfy both: it launches as the service identity but with
    # the standard token (UAC token-splitting). The actual scheduled task
    # at 02:00 uses -RunLevel Highest so Task Scheduler auto-elevates;
    # we use the same mechanism here via a one-shot scheduled task.
    if ($RunNowWhatIf) {
        Write-Step "Running Update-DefenderOffline.ps1 -WhatIfMode as $IdentityLabel (smoke test)…"
        $whatifArgs = @(
            '-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', "`"$UpdateScriptPath`"",
            '-ConfigPath', "`"$ConfigPath`"",
            '-WhatIfMode'
        )
        $scriptFolder = Split-Path $UpdateScriptPath -Parent
        $smokeName    = "Manage-DefenderOffline-WhatIfSmoke-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        $smokeStart   = Get-Date

        try {
            $smokeAction = New-ScheduledTaskAction `
                -Execute $PwshPath `
                -Argument ($whatifArgs -join ' ') `
                -WorkingDirectory $scriptFolder
            # Trigger is in the future as a fallback; we call Start-ScheduledTask
            # to fire immediately. NO -DeleteExpiredTaskAfter on settings: that
            # requires an EndBoundary on the trigger, and modern Windows rejects
            # the task XML if the boundary is missing. The finally block
            # unregisters the task anyway.
            $smokeTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15)
            $smokeSettings = New-ScheduledTaskSettingsSet `
                -ExecutionTimeLimit ([timespan]::FromMinutes(10)) `
                -StartWhenAvailable `
                -DontStopIfGoingOnBatteries `
                -AllowStartIfOnBatteries

            $registerParams = @{
                TaskName    = $smokeName
                TaskPath    = '\Manage-DefenderOffline\'
                Action      = $smokeAction
                Trigger     = $smokeTrigger
                Settings    = $smokeSettings
                Description = "WhatIf smoke test for Updates component"
                Force       = $true
                ErrorAction = 'Stop'
            }
            if ($IsGmsa) {
                $registerParams.Principal = New-ScheduledTaskPrincipal `
                    -UserId $GmsaAccountName -LogonType Password -RunLevel Highest
            } else {
                # Traditional account: pass User+Password+RunLevel so the task
                # principal is built with token elevation enabled.
                $registerParams.User     = $ServiceAccountName
                $registerParams.Password = $ServiceAccountCredential.GetNetworkCredential().Password
                $registerParams.RunLevel = 'Highest'
            }
            Register-ScheduledTask @registerParams | Out-Null
            Start-ScheduledTask -TaskName $smokeName -TaskPath '\Manage-DefenderOffline\' -ErrorAction Stop

            $deadline    = (Get-Date).AddMinutes(10)
            $finalResult = $null
            do {
                Start-Sleep -Seconds 2
                $info = Get-ScheduledTaskInfo -TaskName $smokeName -TaskPath '\Manage-DefenderOffline\' -ErrorAction SilentlyContinue
                $task = Get-ScheduledTask     -TaskName $smokeName -TaskPath '\Manage-DefenderOffline\' -ErrorAction SilentlyContinue
                if ($info -and $task -and $task.State -ne 'Running' `
                        -and $info.LastTaskResult -ne 267009 `
                        -and $null -ne $info.LastRunTime `
                        -and $info.LastRunTime -gt $smokeStart) {
                    $finalResult = $info.LastTaskResult
                    break
                }
            } while ((Get-Date) -lt $deadline)

            # Surface the Update script's own log (it writes to C:\Logs\
            # regardless of how it was launched). Find the newest log created
            # during the smoke test window.
            Start-Sleep -Milliseconds 500   # let any final log flush complete
            $logFile = Get-ChildItem 'C:\Logs\Update-DefenderOffline_*.log' -ErrorAction SilentlyContinue |
                       Where-Object { $_.LastWriteTime -gt $smokeStart } |
                       Sort-Object LastWriteTime -Descending |
                       Select-Object -First 1
            if ($logFile) {
                $logRaw = Get-Content -LiteralPath $logFile.FullName -Raw -ErrorAction SilentlyContinue
                if ($logRaw) {
                    Write-Host ''
                    Write-Host "  --- WhatIf smoke test log ($($logFile.Name)) ---" -ForegroundColor DarkGray
                    Write-Host $logRaw.TrimEnd() -ForegroundColor Gray
                    Write-Host '  --- end smoke test log ---' -ForegroundColor DarkGray
                    Write-Host ''
                }
            }

            if ($finalResult -eq 0) {
                Write-Ok "WhatIf smoke test exited cleanly (code 0)."
            } elseif ($null -ne $finalResult) {
                Write-Warn "WhatIf smoke test exited with code $finalResult. Inspect the log above."
            } else {
                Write-Warn 'WhatIf smoke test did not complete within 10 minutes.'
            }
            if (-not $logFile) {
                Write-Info 'No Update script log found under C:\Logs\Update-DefenderOffline_*.log. Task may have failed before reaching the script entry point.'
            }
        } catch {
            Write-Warn "Could not run WhatIf smoke test: $($_.Exception.Message)"
        } finally {
            Unregister-ScheduledTask -TaskName $smokeName -TaskPath '\Manage-DefenderOffline\' -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    return $true
}

# ===================================================================
# Main-flow guard (dot-source for Pester)
# ===================================================================
if ($MyInvocation.InvocationName -eq '.') { return }

# ===================================================================
# Administrative Privilege Check
# ===================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail 'This script must be run as Administrator.'
    exit 1
}

# ===================================================================
# Banner
# ===================================================================
Write-Section "Manage-DefenderOffline Installer v$ScriptVersion"

if ($Component -eq 'Downloader') {
    Write-Fail "Component 'Downloader' is reserved for v0.0.20 (internet-connected staging machine install of Get-DefenderDefinitions.ps1)."
    Write-Info  "Pick one of: Dashboard | Updates | All."
    exit 1
}

Write-Step "Component selection: $Component"
if ($Component -in @('Updates','All')) {
    Write-Info "Updates frequency : $Frequency"
    Write-Info "Updates start time: $UpdateStartTime"
}

# ===================================================================
# Prereqs
# ===================================================================
Write-Step "Checking prerequisites…"

Write-Ok 'Running as Administrator'

$pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
if (-not $pwshPath) {
    Write-Fail 'pwsh.exe (PowerShell 7+) not found in PATH. Install PowerShell 7 first.'
    exit 1
}
Write-Ok "pwsh.exe found: $pwshPath"

$svc = Get-Service -Name 'Schedule' -ErrorAction SilentlyContinue
if ($svc.Status -ne 'Running') {
    Write-Fail 'Task Scheduler service (Schedule) is not running.'
    exit 1
}
Write-Ok 'Task Scheduler service is running'

# Script paths
if (-not $DashboardScriptPath) { $DashboardScriptPath = Join-Path $ScriptDir 'Start-DefenderDashboard.ps1' }
if (-not $UpdateScriptPath)    { $UpdateScriptPath    = Join-Path $ScriptDir 'Update-DefenderOffline.ps1' }

if ($Component -in @('Dashboard','All')) {
    if (-not (Test-Path $DashboardScriptPath)) {
        Write-Fail "Start-DefenderDashboard.ps1 not found: $DashboardScriptPath"
        exit 1
    }
    $DashboardScriptPath = (Resolve-Path $DashboardScriptPath).Path
    Write-Ok "Dashboard script: $DashboardScriptPath"
}
if ($Component -in @('Updates','All')) {
    if (-not (Test-Path $UpdateScriptPath)) {
        Write-Fail "Update-DefenderOffline.ps1 not found: $UpdateScriptPath"
        exit 1
    }
    $UpdateScriptPath = (Resolve-Path $UpdateScriptPath).Path
    Write-Ok "Updates script: $UpdateScriptPath"
}

# ===================================================================
# Service identity validation
# ===================================================================
$isGmsa        = $PSCmdlet.ParameterSetName -eq 'gMSA'
$identityLabel = if ($isGmsa) { $GmsaName } else { $ServiceAccount }

Write-Step "Validating service identity…"
$identityOk = Test-ServiceIdentityForInstall `
    -IsGmsa                    $isGmsa `
    -GmsaAccountName           $GmsaName `
    -ServiceAccountName        $ServiceAccount `
    -ServiceAccountCredential  $Credential
if (-not $identityOk) { exit 1 }

# ===================================================================
# Ensure the conf folder exists AND the service identity can write to it
# BEFORE credential setup runs. Components grant ACLs later for their own
# needs, but the credential-save helper runs as the service identity and
# needs Modify on conf/ to land the .xml files. Without this pre-grant the
# save would fail for both traditional accounts (Start-Process -Credential
# creates a non-elevated logon) and gMSA (one-shot task runs as gMSA).
# ===================================================================
$confFolder = Join-Path $ScriptDir 'conf'
if (-not (Test-Path $confFolder)) {
    New-Item -Path $confFolder -ItemType Directory -Force | Out-Null
}
if (-not $SkipCredentialSetup) {
    Write-Step "Pre-granting conf folder access to the service identity (needed for credential save)…"
    Grant-FolderAccess -Path $confFolder -Identity $identityLabel -Rights 'Modify'
    # Also pre-grant ReadAndExecute on the script folder so the gMSA one-shot
    # task can load lib\Save-ServiceCredential.ps1. Traditional accounts
    # could rely on Start-Process inheriting the helper path, but the gMSA
    # path is a Task Scheduler action so the process needs filesystem read
    # rights on its working directory.
    Grant-FolderAccess -Path $ScriptDir -Identity $identityLabel -Rights 'ReadAndExecute'
}

# ===================================================================
# Credential setup (gated by -SkipCredentialSetup)
# ===================================================================
$cfgHashtable = @{}
foreach ($k in $cfg.Keys) { $cfgHashtable[$k] = $cfg[$k] }

$credentialsOk = Initialize-ServiceCredentials `
    -Component                 $Component `
    -IdentityLabel             $identityLabel `
    -IsGmsa                    $isGmsa `
    -ServiceAccountName        $ServiceAccount `
    -ServiceAccountCredential  $Credential `
    -GmsaAccountName           $GmsaName `
    -ConfFolder                $confFolder `
    -Config                    $cfgHashtable `
    -PreSuppliedWinRm          $WinRmCredential `
    -PreSuppliedAd             $AdCredential `
    -PreSuppliedSmtp           $SmtpCredential `
    -WinRmUsername             $WinRmUsername `
    -AdUsername                $AdUsername `
    -SmtpUsername              $SmtpUsername `
    -Skip                      $SkipCredentialSetup.IsPresent `
    -Force                     $Force.IsPresent
if (-not $credentialsOk) {
    Write-Fail 'One or more credential saves failed. Aborting before scheduled task registration.'
    exit 1
}

# ===================================================================
# Component dispatch
# ===================================================================
$dashOk    = $true
$updatesOk = $true

if ($Component -in @('Dashboard','All')) {
    $dashOk = Install-DashboardComponent `
        -DashboardScriptPath       $DashboardScriptPath `
        -IsGmsa                    $isGmsa `
        -ServiceAccountName        $ServiceAccount `
        -ServiceAccountCredential  $Credential `
        -GmsaAccountName           $GmsaName `
        -IdentityLabel             $identityLabel `
        -TaskName                  $TaskName `
        -TaskFolder                $TaskFolder `
        -Port                      $Port `
        -FallbackPort              $FallbackPort `
        -RefreshInterval           $RefreshInterval `
        -LogPath                   $LogPath `
        -ParallelThreads           $ParallelThreads `
        -TimeoutSeconds            $TimeoutSeconds `
        -SourceSharePath           $SourceSharePath `
        -UseHttps:$UseHttps `
        -CertificateThumbprint     $CertificateThumbprint `
        -RenewCertificate:$RenewCertificate `
        -AdditionalSans            $AdditionalSans `
        -AuthMethod                $AuthMethod `
        -AuthAllowedGroups         $AuthAllowedGroups `
        -AuthBasicUsersFile        $AuthBasicUsersFile `
        -AuthToken                 $AuthToken `
        -ConfigPath                $ConfigPath `
        -ConfigSnapshot            $cfgHashtable `
        -AddFirewallRule:$AddFirewallRule `
        -StartImmediately:$StartImmediately `
        -Force:$Force `
        -PwshPath                  $pwshPath `
        -ConfFolder                $confFolder
}

if ($Component -in @('Updates','All')) {
    $updatesOk = Install-UpdatesComponent `
        -UpdateScriptPath          $UpdateScriptPath `
        -IsGmsa                    $isGmsa `
        -ServiceAccountName        $ServiceAccount `
        -ServiceAccountCredential  $Credential `
        -GmsaAccountName           $GmsaName `
        -IdentityLabel             $identityLabel `
        -TaskName                  $UpdateTaskName `
        -TaskFolder                $UpdateTaskFolder `
        -Frequency                 $Frequency `
        -UpdateStartTime           $UpdateStartTime `
        -ConfigPath                $ConfigPath `
        -CanaryComputers           $CanaryComputers `
        -MaxCanaryFailures         $MaxCanaryFailures `
        -RunNowWhatIf:$RunNowWhatIf `
        -Force:$Force `
        -PwshPath                  $pwshPath `
        -ConfFolder                $confFolder
}

# ===================================================================
# Final summary
# ===================================================================
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Magenta
Write-Host '   Installation Complete' -ForegroundColor Magenta
Write-Host '  ============================================================' -ForegroundColor Magenta
Write-Host ''
Write-Host "  Identity     : $identityLabel" -ForegroundColor White
Write-Host "  Component(s) : $Component" -ForegroundColor White
if ($Component -in @('Dashboard','All')) {
    $dashStatus = if ($dashOk) { 'OK' } else { 'FAILED' }
    Write-Host "  Dashboard    : $dashStatus  (task: $TaskFolder$TaskName)" -ForegroundColor White
}
if ($Component -in @('Updates','All')) {
    $upStatus = if ($updatesOk) { 'OK' } else { 'FAILED' }
    Write-Host "  Updates      : $upStatus  (task: $UpdateTaskFolder$UpdateTaskName, $Frequency at $UpdateStartTime)" -ForegroundColor White
}
Write-Host ''

if (-not ($dashOk -and $updatesOk)) {
    exit 1
}
exit 0


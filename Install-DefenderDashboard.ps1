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

    # --- HTTPS support ---
    [switch]$UseHttps,

    # Existing cert in Cert:\LocalMachine\My to reuse. When omitted and -UseHttps
    # is supplied, the installer generates a self-signed cert and persists the
    # thumbprint to config.conf.
    [string]$CertificateThumbprint,

    # Regenerate the cert (and rebind via netsh sslcert) even if a thumbprint
    # is already set. Requires -UseHttps.
    [switch]$RenewCertificate,

    # Additional Subject Alternative Names (SANs) to include in a generated
    # self-signed cert. Comma-separated. Accepts DNS names and IP addresses.
    # Use this when operators access the dashboard via a CNAME, load-balancer
    # VIP, alternate hostname, or extra IP that isn't the host's primary.
    # The installer already auto-includes: $env:COMPUTERNAME, the FQDN,
    # 'localhost', and the host's primary IPv4 address — so this is for
    # everything beyond that. Ignored when reusing an existing cert; pair
    # with -RenewCertificate to actually rebuild the cert with new SANs.
    # Example: -AdditionalSans 'dashboard.contoso.com,10.0.0.50,my-alias'
    [string]$AdditionalSans,

    # --- Options ---
    [switch]$AddFirewallRule,
    [switch]$StartImmediately,
    [switch]$Force,

    # Save WinRM credential for the dashboard service account (DPAPI-encrypted)
    [switch]$SaveCredential,

    # --- Authentication (pass-through to dashboard via config.conf) ---
    # When any of these are provided, the installer writes them to the
    # [Dashboard] section of config.conf so the scheduled task picks them
    # up at startup. Omitted parameters leave the existing config values
    # alone.
    [ValidateSet('None', 'Token', 'Basic', 'ADIntegrated')]
    [string]$AuthMethod,

    # ADIntegrated only. Comma-separated; entries prefixed '!' are denies.
    [string]$AuthAllowedGroups,

    # Basic only. Path to the users file (PBKDF2 hashes), relative paths
    # resolve against the dashboard script directory.
    [string]$AuthBasicUsersFile,

    # Token only. Leave blank to let the dashboard auto-generate one.
    [string]$AuthToken,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.14'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Shared helper modules (dot-sourced; same chokepoint pattern as the other scripts).
. (Join-Path $ScriptDir 'lib\Update-ConfigValue.ps1')

# Stable application GUID used for netsh sslcert binding. Reusing this lets
# the installer find and delete its own previous bindings idempotently.
$script:HttpsAppId = '{a3f9b1c2-d4e5-46f7-8901-234567890abc}'

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
# HTTPS settings. The installer can be re-run without -UseHttps after an
# initial install; config.conf carries the persisted state.
if (-not $PSBoundParameters.ContainsKey('UseHttps')              -and $cfg['UseHttps'] -eq 'true')   { $UseHttps              = $true }
if (-not $PSBoundParameters.ContainsKey('CertificateThumbprint') -and $cfg['CertificateThumbprint']) { $CertificateThumbprint = $cfg['CertificateThumbprint'].Trim() }

# Normalize: Get-ScheduledTask -TaskPath uses CIM WQL exact matching and will
# return nothing for '\HOME' unless the trailing backslash is present
# ('\HOME\'). Register-ScheduledTask is more forgiving but the asymmetry
# breaks the Useful-commands hints printed to the operator. Force trailing
# slash on every code path.
if (-not $TaskFolder.EndsWith('\')) { $TaskFolder = "$TaskFolder\" }

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
# Main-flow guard
#
# When this script is dot-sourced (Pester or interactive testing of
# individual functions), return here so the installer banner and
# main flow below do not run.  Direct invocation continues normally.
# ===================================================================
if ($MyInvocation.InvocationName -eq '.') { return }

# ===================================================================
# Administrative Privilege Check
#
# Placed AFTER the main-flow guard so dot-source (Pester) does not
# trip the elevation requirement.
# ===================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail 'This script must be run as Administrator.'
    exit 1
}
Write-Ok 'Running as Administrator'

# ===================================================================
# STEP 0 – Prerequisites
# ===================================================================
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Magenta
Write-Host "   Defender Dashboard Installer v$ScriptVersion" -ForegroundColor Magenta
Write-Host "  ============================================================" -ForegroundColor Magenta

Write-Step "Checking prerequisites…"

# HTTPS parameter sanity check (before any side-effects)
if ($RenewCertificate -and -not $UseHttps) {
    Write-Fail '-RenewCertificate requires -UseHttps (cert regeneration only makes sense in HTTPS mode).'
    exit 1
}
if ($CertificateThumbprint -and -not $UseHttps) {
    Write-Warn '-CertificateThumbprint supplied without -UseHttps; the thumbprint will not be persisted or bound.'
}

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

$scriptFolder = Split-Path $DashboardScriptPath -Parent
$confFolder   = Join-Path $scriptFolder 'conf'

$pathsToCreate = @($LogPath, $scriptFolder, $confFolder)
foreach ($p in $pathsToCreate | Select-Object -Unique) {
    if (-not (Test-Path $p)) {
        New-Item -Path $p -ItemType Directory -Force | Out-Null
        Write-Ok "Created: $p"
    } else {
        Write-Ok "Exists : $p"
    }
}


Grant-FolderAccess -Path $scriptFolder -Identity $identityLabel -Rights 'ReadAndExecute'
Grant-FolderAccess -Path $confFolder   -Identity $identityLabel -Rights 'Modify'   # writes dashboard.status + reads/writes WinRmCredential.xml
Grant-FolderAccess -Path $LogPath      -Identity $identityLabel -Rights 'Modify'

# ===================================================================
# STEP 2.5 – HTTPS setup (cert generation + netsh binding + URL ACL)
# Only runs when -UseHttps is supplied. Persists state back to config.conf
# so the dashboard scheduled task (which has no access to the installer's
# CLI args) finds everything via Read-ConfigFile at startup.
# ===================================================================
if ($UseHttps) {
    Write-Step "Configuring HTTPS…"

    # 1. Cert: reuse, regenerate, or create new
    $certShouldGenerate = $RenewCertificate -or -not $CertificateThumbprint
    if (-not $RenewCertificate -and $CertificateThumbprint) {
        # Reuse existing — validate it exists and isn't expired
        $existing = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
        if (-not $existing) {
            Write-Warn "CertificateThumbprint $CertificateThumbprint not found in Cert:\LocalMachine\My — will generate a new self-signed cert."
            $certShouldGenerate = $true
        } elseif ($existing.NotAfter -lt (Get-Date)) {
            Write-Warn "Existing cert $CertificateThumbprint expired on $($existing.NotAfter.ToString('yyyy-MM-dd')) — will generate a replacement."
            $certShouldGenerate = $true
        } else {
            Write-Ok "Reusing existing cert: $($existing.Subject) (expires $($existing.NotAfter.ToString('yyyy-MM-dd')))"
            # Surface SAN coverage so the operator can see whether the existing
            # cert covers the URL they'll be hitting (FQDN, IP, alias). This is
            # the most common source of "Not secure" browser warnings during
            # remote access.
            $existingSans = if ($existing.DnsNameList) {
                @($existing.DnsNameList | ForEach-Object { $_.Punycode }) -join ', '
            } else { '(none)' }
            Write-Info "  Subject Alt Names: $existingSans"
            if ($AdditionalSans) {
                Write-Warn "  -AdditionalSans was supplied but is ignored when reusing an existing cert."
                Write-Warn "  To apply additional SANs, re-run with -RenewCertificate (regenerates + rebinds via netsh sslcert)."
            }
        }
    }
    if ($certShouldGenerate) {
        try {
            $fqdn = if ($env:USERDNSDOMAIN) { "$env:COMPUTERNAME.$env:USERDNSDOMAIN" } else { $env:COMPUTERNAME }

            # Auto-include the host's primary non-loopback non-APIPA IPv4 so
            # cert-by-IP access (lab common) doesn't trip the "Not secure"
            # browser warning. Same selection logic Update-DefenderOffline uses
            # for its audit RunFromIP field.
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
            exit 1
        }
    }

    # 2. netsh sslcert binding (idempotent: delete any prior binding on this port first)
    try {
        $existingBinding = & netsh http show sslcert "ipport=0.0.0.0:$Port" 2>&1
        if ($LASTEXITCODE -eq 0 -and $existingBinding -match 'Certificate Hash') {
            $null = & netsh http delete sslcert "ipport=0.0.0.0:$Port" 2>&1
            Write-Info "Removed prior netsh sslcert binding on 0.0.0.0:$Port"
        }
        $netshOut = & netsh http add sslcert "ipport=0.0.0.0:$Port" "certhash=$CertificateThumbprint" "appid=$script:HttpsAppId" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "netsh sslcert binding failed: $($netshOut -join ' ')"
            exit 1
        }
        Write-Ok "Bound certificate to 0.0.0.0:$Port via netsh sslcert"
    } catch {
        Write-Fail "netsh sslcert binding error: $($_.Exception.Message)"
        exit 1
    }

    # 3. URL ACL — required so non-admin service accounts can bind https:// prefixes
    $serviceIdentityForUrlAcl = if ($isGmsa) { $GmsaName } else { $ServiceAccount }
    try {
        # Idempotent delete-then-add. The 'not found' error on delete is harmless.
        $null = & netsh http delete urlacl "url=https://+:$Port/" 2>&1
        $netshOut = & netsh http add urlacl "url=https://+:$Port/" "user=$serviceIdentityForUrlAcl" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "netsh urlacl add failed: $($netshOut -join ' ')"
            exit 1
        }
        Write-Ok "URL ACL granted: https://+:$Port/ -> $serviceIdentityForUrlAcl"
    } catch {
        Write-Fail "netsh urlacl error: $($_.Exception.Message)"
        exit 1
    }

    # 4. Persist HTTPS state to config.conf so the scheduled task picks it up
    try {
        if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'conf\config.conf' }
        Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'UseHttps'              -Value 'true'
        Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'CertificateThumbprint' -Value $CertificateThumbprint
        Write-Ok "Persisted UseHttps=true and CertificateThumbprint to conf/config.conf"
    } catch {
        Write-Fail "Failed to update config.conf: $($_.Exception.Message)"
        Write-Info "Manually set in [Dashboard]:  UseHttps = true  /  CertificateThumbprint = $CertificateThumbprint"
        exit 1
    }
}

# Always persist the effective Port to config.conf. Without this, a re-run of
# the installer that omits -Port would read the *release default* (8080) from
# the un-persisted config, silently rebind the cert to that port, and stomp
# the previous install's port. Surfaced during PR-D2b live-fire when a
# follow-up install meant only to flip AuthMethod ended up moving the
# HTTPS listener from 8444 back to 8080.
try {
    if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'conf\config.conf' }
    Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'Port' -Value $Port | Out-Null
} catch {
    Write-Warn "Could not persist Port=$Port to config.conf: $($_.Exception.Message). The task action still uses -Port $Port, but a later installer re-run without -Port may revert to the config's previous value."
}

# ===================================================================
# STEP 2.6 – Authentication pass-through
# Persists any -Auth* parameter that was supplied on the CLI to the
# [Dashboard] section of config.conf so the scheduled task picks it
# up at startup. Omitted parameters leave existing config alone.
# For ADIntegrated, also tries to resolve each allow-list entry to
# an SID and warns (doesn't block) on unresolvable ones.
# ===================================================================
$authBound = @($PSBoundParameters.Keys | Where-Object { $_ -in 'AuthMethod','AuthAllowedGroups','AuthBasicUsersFile','AuthToken' })
if ($authBound.Count -gt 0) {
    Write-Step "Configuring authentication…"
    if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'conf\config.conf' }
    try {
        if ($PSBoundParameters.ContainsKey('AuthMethod')) {
            Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthMethod' -Value $AuthMethod
            Write-Ok "Persisted AuthMethod=$AuthMethod"
        }
        if ($PSBoundParameters.ContainsKey('AuthAllowedGroups')) {
            Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthAllowedGroups' -Value $AuthAllowedGroups
            Write-Ok "Persisted AuthAllowedGroups=$AuthAllowedGroups"
        }
        if ($PSBoundParameters.ContainsKey('AuthBasicUsersFile')) {
            Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthBasicUsersFile' -Value $AuthBasicUsersFile
            Write-Ok "Persisted AuthBasicUsersFile=$AuthBasicUsersFile"
        }
        if ($PSBoundParameters.ContainsKey('AuthToken')) {
            Update-ConfigValue -Path $ConfigPath -Section 'Dashboard' -Key 'AuthToken' -Value $AuthToken
            Write-Ok 'Persisted AuthToken (value not displayed)'
        }
    } catch {
        Write-Fail "Failed to update config.conf: $($_.Exception.Message)"
        exit 1
    }

    # Warn-only validation: with ADIntegrated + an allow-list, try to resolve
    # each entry to a SID so typos surface here rather than first request.
    if ($AuthMethod -eq 'ADIntegrated' -and $AuthAllowedGroups) {
        foreach ($entry in ($AuthAllowedGroups -split ',')) {
            $e = $entry.Trim()
            if (-not $e) { continue }
            $name = if ($e.StartsWith('!')) { $e.Substring(1).Trim() } else { $e }
            if (-not $name) { continue }
            try {
                [void]([System.Security.Principal.NTAccount]::new($name)).Translate(
                    [System.Security.Principal.SecurityIdentifier])
            } catch {
                Write-Warn "AuthAllowedGroups entry '$e' could not be resolved to an SID on this host. The dashboard will ignore it. Check spelling / domain reachability."
            }
        }
    }

    # Cleartext-Basic protection mirrors the dashboard's own startup check
    # so an operator can't accidentally install a misconfigured task.
    if ($AuthMethod -eq 'Basic' -and -not $UseHttps) {
        Write-Fail "AuthMethod=Basic without -UseHttps would send credentials in cleartext on every request. Re-run with -UseHttps, or pick a different AuthMethod."
        exit 1
    }
}

# ===================================================================
# STEP 3 – Stop any existing dashboard task, then check port availability
# ===================================================================
# Stop any prior instance of our scheduled task BEFORE the port check.
# Re-installs (especially -RenewCertificate) would otherwise fail here:
# the still-running dashboard owns the port we're about to verify is free.
$existingTaskPre = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder -ErrorAction SilentlyContinue
if ($existingTaskPre -and $existingTaskPre.State -eq 'Running') {
    Write-Step "Stopping previously installed dashboard task…"
    try {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskFolder -ErrorAction Stop
        # Wait briefly for the OS to release the bound port. HttpListener
        # sometimes lingers in TIME_WAIT for a second or two.
        for ($wait = 0; $wait -lt 10; $wait++) {
            if (Test-PortFree $Port) { break }
            Start-Sleep -Milliseconds 500
        }
        Write-Ok "Previous instance stopped"
    } catch {
        Write-Warn "Could not stop existing task: $($_.Exception.Message)"
        Write-Info "If install fails at port check, stop the task manually and re-run."
    }
}

Write-Step "Checking port availability…"

# HTTPS does NOT use fallback (cert is bound to a specific port). HTTP keeps the
# existing fallback walk.
if ($UseHttps) {
    if (-not (Test-PortFree $Port)) {
        Write-Fail "Port $Port is in use and HTTPS does not support fallback (cert binding is per-port)."
        Write-Info "Stop the conflicting service or change Port in config.conf, then re-run with -RenewCertificate."
        exit 1
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
#
# -DontStopIfGoingOnBatteries / -AllowStartIfOnBatteries override the cmdlet's
# defaults (which are TRUE for both StopIfGoingOnBatteries and
# DisallowStartIfOnBatteries). Without these overrides, Task Scheduler will
# gracefully kill the dashboard on any battery-state transition — even on a
# desktop with no battery, if a UPS sends a battery event, a power management
# driver glitches, or a hypervisor signals battery to a VM guest. The user
# observation that prompted this fix: dashboard cleanly exiting (return code 0)
# after ~17 min of healthy operation, with no errors in the dashboard log.
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit  ([timespan]::Zero) `
    -MultipleInstances   IgnoreNew `
    -StartWhenAvailable `
    -RestartCount        3 `
    -RestartInterval     ([timespan]::FromMinutes(1)) `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries

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
# STEP 4 – Optional firewall rule(s)
# ===================================================================
function Add-DashboardFirewallRule {
    param([int]$RulePort, [string]$Protocol, [string]$Purpose)
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
        # New-NetFirewallRule has no -Force parameter; -Enabled takes the
        # string 'True'/'False', not [bool] $true/$false.
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Description "Allows inbound $Purpose to the Defender Fleet Dashboard on TCP $RulePort" `
            -Direction   Inbound `
            -Protocol    TCP `
            -LocalPort   $RulePort `
            -Action      Allow `
            -Profile     Domain, Private `
            -Enabled     True | Out-Null
        Write-Ok "Firewall rule created: $ruleName (TCP $RulePort, Domain+Private profiles)"
    } catch {
        Write-Warn "Could not create firewall rule '$ruleName': $($_.Exception.Message)"
        Write-Info "Create manually: New-NetFirewallRule -DisplayName '$ruleName' -Direction Inbound -Protocol TCP -LocalPort $RulePort -Action Allow"
    }
}

if ($AddFirewallRule) {
    Write-Step "Creating Windows Firewall inbound rule(s)…"
    if ($UseHttps) {
        Add-DashboardFirewallRule -RulePort $Port -Protocol 'HTTPS' -Purpose 'HTTPS traffic'
        # If the dashboard's HTTP redirect listener is enabled and uses a
        # different port, open that one too. We read the value from config.conf
        # because the installer doesn't carry RedirectHttpToHttps as a param.
        $redirectEnabled = ($cfg['RedirectHttpToHttps'] -ne 'false')   # default true
        $redirectPort    = if ($cfg['RedirectHttpPort']) { [int]$cfg['RedirectHttpPort'] } else { 8080 }
        if ($redirectEnabled -and $redirectPort -ne $Port) {
            Add-DashboardFirewallRule -RulePort $redirectPort -Protocol 'HTTP-Redirect' -Purpose 'HTTP traffic (301-redirected to HTTPS)'
        }
    } else {
        Add-DashboardFirewallRule -RulePort $Port -Protocol 'HTTP' -Purpose 'HTTP traffic'
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
        $probeScheme = if ($UseHttps) { 'https' } else { 'http' }
        $probeUrl    = "${probeScheme}://localhost:$actualPort/health"
        $probeOk     = $false
        $lastErr     = $null
        $probeStart  = Get-Date
        for ($i = 1; $i -le 6; $i++) {
            try {
                # For HTTPS with the installer's self-signed cert, the local
                # cert chain won't validate. -SkipCertificateCheck bypasses
                # validation only for this localhost probe (PS7+ only).
                $iwrParams = @{
                    Uri             = $probeUrl
                    TimeoutSec      = 10
                    UseBasicParsing = $true
                    ErrorAction     = 'Stop'
                }
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
$summaryScheme = if ($UseHttps) { 'https' } else { 'http' }
Write-Host "  Dashboard    : ${summaryScheme}://<this-host>:$Port/defender" -ForegroundColor White
Write-Host "  JSON status  : ${summaryScheme}://<this-host>:$Port/status" -ForegroundColor White
Write-Host "  Health probe : ${summaryScheme}://<this-host>:$Port/health" -ForegroundColor White
if ($UseHttps) {
    $redirectEnabled = ($cfg['RedirectHttpToHttps'] -ne 'false')
    $redirectPort    = if ($cfg['RedirectHttpPort']) { [int]$cfg['RedirectHttpPort'] } else { 8080 }
    if ($redirectEnabled -and $redirectPort -ne $Port) {
        Write-Host "  HTTP redirect: http://<this-host>:$redirectPort/  (301 → https)" -ForegroundColor White
    }
    Write-Host "  Certificate  : $CertificateThumbprint" -ForegroundColor White
}
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
$credFile = Join-Path $confFolder 'WinRmCredential.xml'
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

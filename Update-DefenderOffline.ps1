<#
.SYNOPSIS
    Update-DefenderOffline.ps1 – Automated Microsoft Defender Antivirus Definitions Deployment

.DESCRIPTION
    Deploys Microsoft Defender antivirus definition updates to Windows 10/11 and
    Windows Server 2016+ endpoints in air-gapped or network-segmented environments
    using PowerShell Remoting (WinRM).

    Source share structure (required):
        <SourceSharePath>\<YYYYMMDD>\v#.###.###.#\mpam-fe.exe
    Example:
        \\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender\20260518\v1.449.681.0\mpam-fe.exe

    The script automatically identifies the highest available version, compares it to
    each endpoint's installed version, and skips systems that are already current or ahead.
    PowerShell 7+ enables parallel processing; PS 5.1 falls back to serial.

.PARAMETER SourceSharePath
    Base UNC path containing versioned definition subfolders. No trailing slash.
    Example: \\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender

.PARAMETER ComputerName
    Manual list of target computers. Bypasses hosts.conf and Active Directory discovery.

.PARAMETER TempFolderOnTarget
    Temporary directory created on each remote system during update. Removed after completion.
    Default: C:\Temp\Update-DefenderOffline

.PARAMETER LogSharePath
    Optional UNC path for centralized install log collection. A per-computer subfolder is created.

.PARAMETER LogPath
    Local path for script execution logs. Default: C:\Logs

.PARAMETER ReportPath
    Local path for HTML and CSV reports. Default: .\Reports

.PARAMETER ParallelThreads
    Maximum concurrent update jobs in PS 7+ parallel mode. Range: 1-32. Default: 16

.PARAMETER WhatIfMode
    Dry-run. Tests connectivity and compares versions but makes no changes.

.PARAMETER SendEmail
    Enable email notification with HTML report and CSV attached.

.PARAMETER SmtpServer
    SMTP server hostname or IP. Required when -SendEmail is used.

.PARAMETER SmtpPort
    SMTP port. Default: 25

.PARAMETER From
    Sender email address. Default: DefenderUpdate@contoso.com

.PARAMETER To
    One or more recipient email addresses. Required when -SendEmail is used.

.PARAMETER SmtpUseSsl
    Use SSL/TLS for SMTP connection.

.PARAMETER SmtpCredential
    PSCredential for SMTP authentication. Use -SaveSmtpCredential to create one interactively.

.PARAMETER SaveSmtpCredential
    Interactive helper that saves encrypted SMTP credentials to .\Config\SmtpCredential.xml.
    The file is encrypted per-user and per-machine via DPAPI (safe for scheduled tasks / gMSA).

.PARAMETER Credential
    Single PSCredential used for all WinRM connections. Acts as a fallback when no
    tier-specific credential is supplied. Auto-loaded from .\Config\WinRmCredential.xml
    if the file exists and -Credential is not passed explicitly.

.PARAMETER WorkstationCredential
    PSCredential for workstation-tier endpoints. Takes precedence over -Credential for
    hosts classified as Workstation. Auto-loaded from .\Config\WorkstationCredential.xml.

.PARAMETER ServerCredential
    PSCredential for member-server-tier endpoints. Takes precedence over -Credential for
    hosts classified as MemberServer. Auto-loaded from .\Config\ServerCredential.xml.

.PARAMETER DomainControllerCredential
    PSCredential for domain controller endpoints. Takes precedence over -Credential for
    hosts classified as DomainController. Auto-loaded from .\Config\DomainControllerCredential.xml.

.PARAMETER SaveCredential
    Interactive helper that saves WinRM credentials to .\Config\ (DPAPI-encrypted).
    Prompts for which tier(s) to save. Exits after saving.

.PARAMETER ClassificationMethod
    Controls how endpoints are assigned to credential tiers.
    AD      - Queries Active Directory OperatingSystem attribute and DC flag (default when domain-joined).
    Pattern - Matches computer names against -WorkstationPattern and -DomainControllerPattern.
    Single  - All endpoints use one credential; no classification (default when not domain-joined).
    Auto-detected if omitted.

.PARAMETER WorkstationPattern
    Regex matched case-insensitively against computer names when ClassificationMethod = Pattern.
    Hosts that match are classified as Workstation and use -WorkstationCredential.
    Example: ^(DESKTOP|LAPTOP|WS|WIN10|WIN11)
    IMPORTANT: This is an example only. Customise it for your naming convention.

.PARAMETER DomainControllerPattern
    Regex matched case-insensitively against computer names when ClassificationMethod = Pattern.
    Hosts that match are classified as DomainController and use -DomainControllerCredential.
    Example: ^DC
    IMPORTANT: This is an example only. Customise it for your naming convention.

.EXAMPLE
    # First run – auto-discovers domain computers via AD and creates hosts.conf
    .\Update-DefenderOffline.ps1 -SourceSharePath "\\NAS01\Share\_AVDefinitions\Microsoft_Defender"

.EXAMPLE
    # Weekly production run with email
    $cred = Import-Clixml ".\Config\SmtpCredential.xml"
    .\Update-DefenderOffline.ps1 `
        -SourceSharePath "\\NAS01\Share\_AVDefinitions\Microsoft_Defender" `
        -SendEmail -SmtpServer "smtp.contoso.com" -SmtpPort 587 -SmtpUseSsl `
        -From "defender@contoso.com" -To "security@contoso.com" `
        -SmtpCredential $cred

.EXAMPLE
    # Dry-run against specific computers
    .\Update-DefenderOffline.ps1 `
        -SourceSharePath "\\NAS01\Share\_AVDefinitions\Microsoft_Defender" `
        -ComputerName "WS01","WS02","SRV01" -WhatIfMode

.EXAMPLE
    # One-time: save SMTP credentials
    .\Update-DefenderOffline.ps1 -SaveSmtpCredential

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Supported OS   : Windows 10/11, Windows Server 2016/2019/2022/2025
    Prerequisites  : PowerShell 5.1+ (7+ strongly recommended)
                     WinRM enabled on all target computers (TCP 5985)
                     Local administrator privileges on the machine running this script
                     Administrative rights on all target computers
                     Read access to SourceSharePath share
    Version        : 0.0.6
    Created        : 2025-11-27
    Last Updated   : 2026-05-19
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0)]
    [string]$SourceSharePath,

    [Parameter(ValueFromPipeline)]
    [string[]]$ComputerName,

    [string]$TempFolderOnTarget = 'C:\Temp\Update-DefenderOffline',

    [string]$LogSharePath,

    # Output locations
    [string]$LogPath,
    [string]$ReportPath,

    # Performance
    [ValidateRange(1, 32)]
    [int]$ParallelThreads = 16,

    # Safety
    [switch]$WhatIfMode,

    # Email
    [switch]$SendEmail,
    [string]$SmtpServer,
    [int]$SmtpPort = 25,
    [string]$From  = 'DefenderUpdate@contoso.com',
    [string[]]$To,
    [switch]$SmtpUseSsl,
    [pscredential]$SmtpCredential,

    # Credential helper
    [switch]$SaveSmtpCredential,

    # WinRM credentials
    [pscredential]$Credential,
    [pscredential]$WorkstationCredential,
    [pscredential]$ServerCredential,
    [pscredential]$DomainControllerCredential,

    # WinRM credential helper
    [switch]$SaveCredential,

    # AD discovery credential (used only for the LDAP bind when reading
    # the computer list; not used for WinRM connections)
    [pscredential]$ADCredential,
    [switch]$SaveADCredential,

    # Restrict AD auto-discovery to one or more OU subtrees. Distinguished-name
    # format; multiple DNs separated by semicolons (commas are valid inside DNs).
    # Empty = whole-domain search (default).
    #   Example: 'OU=Workstations,OU=Endpoints,DC=contoso,DC=com;OU=ServersUS,DC=contoso,DC=com'
    [string]$ADSearchBase,

    # Endpoint classification
    [ValidateSet('AD','Pattern','Single')]
    [string]$ClassificationMethod,
    [string]$WorkstationPattern,
    [string]$DomainControllerPattern,

    # Skip IPv6 in endpoint reachability tests. See conf/config.conf for details.
    [bool]$DisableIPv6 = $true,

    # Force a specific architecture for ALL hosts instead of auto-detecting
    # per-host via WinRM. Default is empty = auto-detect per host. Use this
    # when you want to roll a specific arch out to a subset of the fleet,
    # or when the per-host CIM call is unreliable.
    [ValidateSet('', 'x64', 'x86', 'arm64')]
    [string]$Architecture,

    # Staged rollout — when -CanaryComputers is supplied, the script runs that
    # subset first ("Canary" wave), waits -HealthSettleSeconds, then evaluates
    # the post-update health probe results. If the number of Degraded/ProbeFailed
    # canary hosts exceeds -MaxCanaryFailures the "Production" wave is skipped
    # and its hosts are recorded as Status='Skipped' in the report.
    # Install failures, ThreatsDetected, and Healthy rows do not count against
    # the gate (see lib/Test-CanaryGate.ps1).
    [string[]]$CanaryComputers,
    [ValidateRange(0, 10000)]
    [int]$MaxCanaryFailures = 0,
    [ValidateRange(0, 3600)]
    [int]$HealthSettleSeconds = 60,

    # Path to configuration file. Defaults to .\conf\config.conf relative to the script.
    [string]$ConfigPath
)

# ===================================================================
# Constants
# ===================================================================
$ScriptVersion   = '0.0.11'
$ScriptStartTime = Get-Date
$ScriptDir       = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$HostsFile       = Join-Path $ScriptDir 'hosts.conf'

# Single chokepoint for all WinRM execution. Path is also passed into thread
# runspaces (Invoke-DefenderUpdate runs as a Start-ThreadJob) so the wrapper
# is available there too.
$LibInvokeDefenderRemote = Join-Path $ScriptDir 'lib\Invoke-DefenderRemote.ps1'
. $LibInvokeDefenderRemote
$LibGetDefenderComputers = Join-Path $ScriptDir 'lib\Get-DefenderComputers.ps1'
. $LibGetDefenderComputers
$LibGetDefenderHealthProbe = Join-Path $ScriptDir 'lib\Get-DefenderHealthProbe.ps1'
$LibTestCanaryGate         = Join-Path $ScriptDir 'lib\Test-CanaryGate.ps1'
. $LibTestCanaryGate
. $LibGetDefenderHealthProbe
$RunAsUser       = "$env:USERDOMAIN\$env:USERNAME"
$RunFromHost     = $env:COMPUTERNAME
$RunFromIP       = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                       Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' } |
                       Sort-Object InterfaceIndex | Select-Object -First 1 -ExpandProperty IPAddress) ?? 'Unknown'
$script:SuppressConsoleOutput = $false

# ===================================================================
# Credential Helper Mode  (exits after completion)
# ===================================================================
if ($SaveSmtpCredential) {
    Write-Host "`n=== SMTP Credential Setup ===" -ForegroundColor Cyan
    $configDir = Join-Path $ScriptDir 'conf'
    $credPath  = Join-Path $configDir 'SmtpCredential.xml'
    if (-not (Test-Path $configDir)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
    }
    try {
        $cred = Get-Credential -Message 'Enter SMTP username and password (e.g. smtp-user@contoso.com)'
        if ($cred) {
            $cred | Export-Clixml -Path $credPath -Force
            Write-Host "Credentials saved to: $credPath" -ForegroundColor Green
            Write-Host "`nTo use:"
            Write-Host "  `$cred = Import-Clixml '$credPath'"
            Write-Host "  .\Update-DefenderOffline.ps1 -SendEmail -SmtpCredential `$cred ..."
        } else {
            Write-Host 'Cancelled.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    exit 0
}

# ===================================================================
# WinRM Credential Helper Mode  (exits after completion)
# ===================================================================
if ($SaveCredential) {
    Write-Host "`n=== WinRM Credential Setup ===" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Credentials are encrypted per-user per-machine (DPAPI) and stored under' -ForegroundColor Gray
    Write-Host "  Config\ in the script directory. Run this helper as the account that will" -ForegroundColor Gray
    Write-Host '  actually execute the script (or the service account for scheduled tasks).' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Which credential(s) to save?' -ForegroundColor White
    Write-Host '  [1] Single / management account  (WinRmCredential.xml)          – fallback for all tiers'
    Write-Host '  [2] Workstation admin             (WorkstationCredential.xml)'
    Write-Host '  [3] Server / member server admin  (ServerCredential.xml)'
    Write-Host '  [4] Domain admin / DC credential  (DomainControllerCredential.xml)'
    Write-Host '  [A] All of the above'
    Write-Host ''
    $choice = (Read-Host '  Enter choice [1/2/3/4/A]').ToUpper().Trim()

    $slots = switch ($choice) {
        '1' { @(@{ File = 'WinRmCredential.xml';           Label = 'Single / management account' }) }
        '2' { @(@{ File = 'WorkstationCredential.xml';     Label = 'Workstation admin' }) }
        '3' { @(@{ File = 'ServerCredential.xml';          Label = 'Server / member server admin' }) }
        '4' { @(@{ File = 'DomainControllerCredential.xml'; Label = 'Domain admin / DC credential' }) }
        'A' { @(
                @{ File = 'WinRmCredential.xml';           Label = 'Single / management account' }
                @{ File = 'WorkstationCredential.xml';     Label = 'Workstation admin' }
                @{ File = 'ServerCredential.xml';          Label = 'Server / member server admin' }
                @{ File = 'DomainControllerCredential.xml'; Label = 'Domain admin / DC credential' }
              ) }
        default { Write-Host "  Invalid choice '$choice'. Exiting." -ForegroundColor Red; exit 1 }
    }

    $cfgDir = Join-Path $ScriptDir 'conf'
    if (-not (Test-Path $cfgDir)) { New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null }

    foreach ($slot in $slots) {
        Write-Host ''
        try {
            $cred = Get-Credential -Message "Enter credentials for: $($slot.Label)"
            if ($cred) {
                $cred | Export-Clixml -Path (Join-Path $cfgDir $slot.File) -Force
                Write-Host "  Saved: $(Join-Path $cfgDir $slot.File)" -ForegroundColor Green
            } else {
                Write-Host "  Cancelled: $($slot.Label)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  ERROR saving $($slot.File): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    exit 0
}

# ===================================================================
# AD Credential Helper Mode  (exits after completion)
# ===================================================================
if ($SaveADCredential) {
    Write-Host "`n=== AD Discovery Credential Setup ===" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Used ONLY for the LDAP bind that reads the computer list when no' -ForegroundColor Gray
    Write-Host '  hosts.conf is present and -ComputerName is not used.  This is not the' -ForegroundColor Gray
    Write-Host '  same as the WinRM credential.  In STIG-hardened environments the' -ForegroundColor Gray
    Write-Host '  interactive operator often cannot bind to AD; saving a domain account' -ForegroundColor Gray
    Write-Host '  with read permission here lets auto-discovery succeed.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Encrypted per-user per-machine (DPAPI). Saved to conf\ADCredential.xml.' -ForegroundColor Gray
    Write-Host ''
    $cfgDir = Join-Path $ScriptDir 'conf'
    if (-not (Test-Path $cfgDir)) { New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null }
    try {
        $cred = Get-Credential -Message 'Enter AD credential (account with read on the domain naming context)'
        if ($cred) {
            $cred | Export-Clixml -Path (Join-Path $cfgDir 'ADCredential.xml') -Force
            Write-Host "  Saved: $(Join-Path $cfgDir 'ADCredential.xml')" -ForegroundColor Green
        } else {
            Write-Host '  Cancelled.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
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

# Apply config values for parameters not explicitly passed on the command line.
# Command-line parameters always win; config fills in what was omitted.
if (-not $PSBoundParameters.ContainsKey('SourceSharePath')    -and $cfg['SourceSharePath'])    { $SourceSharePath    = $cfg['SourceSharePath'] }
if (-not $PSBoundParameters.ContainsKey('ADSearchBase')       -and $cfg['ADSearchBase'])       { $ADSearchBase       = $cfg['ADSearchBase'] }
if (-not $PSBoundParameters.ContainsKey('Architecture')       -and $cfg['Architecture'])       { $Architecture       = $cfg['Architecture'].Trim() }
if (-not $PSBoundParameters.ContainsKey('LogPath')            -and $cfg['LogPath'])            { $LogPath            = $cfg['LogPath'] }
if (-not $PSBoundParameters.ContainsKey('ReportPath')         -and $cfg['ReportPath'])         { $ReportPath         = $cfg['ReportPath'] }
if (-not $PSBoundParameters.ContainsKey('TempFolderOnTarget') -and $cfg['TempFolderOnTarget']) { $TempFolderOnTarget = $cfg['TempFolderOnTarget'] }
if (-not $PSBoundParameters.ContainsKey('LogSharePath')       -and $cfg['LogSharePath'])       { $LogSharePath       = $cfg['LogSharePath'] }
if (-not $PSBoundParameters.ContainsKey('ParallelThreads')    -and $cfg['ParallelThreads'])    { try { $ParallelThreads = [int]$cfg['ParallelThreads'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('CanaryComputers')    -and $cfg['CanaryComputers']) {
    $CanaryComputers = $cfg['CanaryComputers'] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
if (-not $PSBoundParameters.ContainsKey('MaxCanaryFailures')  -and $cfg['MaxCanaryFailures'])  { try { $MaxCanaryFailures   = [int]$cfg['MaxCanaryFailures'] }   catch {} }
if (-not $PSBoundParameters.ContainsKey('HealthSettleSeconds') -and $cfg['HealthSettleSeconds']) { try { $HealthSettleSeconds = [int]$cfg['HealthSettleSeconds'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('SendEmail')          -and $cfg['SendEmail'] -eq 'true')  { $SendEmail   = $true }
if (-not $PSBoundParameters.ContainsKey('SmtpServer')         -and $cfg['SmtpServer'])         { $SmtpServer         = $cfg['SmtpServer'] }
if (-not $PSBoundParameters.ContainsKey('SmtpPort')           -and $cfg['SmtpPort'])           { try { $SmtpPort = [int]$cfg['SmtpPort'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('SmtpUseSsl')         -and $cfg['SmtpUseSsl'] -eq 'true') { $SmtpUseSsl = $true }
if (-not $PSBoundParameters.ContainsKey('From')               -and $cfg['EmailFrom'])          { $From               = $cfg['EmailFrom'] }
if (-not $PSBoundParameters.ContainsKey('To')                 -and $cfg['EmailTo'])            {
    $To = $cfg['EmailTo'] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
if (-not $PSBoundParameters.ContainsKey('ClassificationMethod')    -and $cfg['ClassificationMethod'])    { $ClassificationMethod    = $cfg['ClassificationMethod'] }
$ExcludeList = @()
if ($cfg['ExcludeComputers']) {
    $ExcludeList = $cfg['ExcludeComputers'] -split ',' | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ }
}
if (-not $PSBoundParameters.ContainsKey('WorkstationPattern')      -and $cfg['WorkstationPattern'])      { $WorkstationPattern      = $cfg['WorkstationPattern'] }
if (-not $PSBoundParameters.ContainsKey('DomainControllerPattern') -and $cfg['DomainControllerPattern']) { $DomainControllerPattern = $cfg['DomainControllerPattern'] }
if (-not $PSBoundParameters.ContainsKey('DisableIPv6')              -and $cfg['DisableIPv6'])              { $DisableIPv6 = ($cfg['DisableIPv6'] -match '^(?i)true|1|yes$') }

# ===================================================================
# WinRM Credential Auto-Load
# Loads DPAPI-encrypted XMLs from Config\ if not passed on the CLI.
# ===================================================================
$configDir = Join-Path $ScriptDir 'conf'

function Import-SavedCredential ([string]$FileName) {
    $p = Join-Path $configDir $FileName
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        try { return Import-Clixml $p }
        catch { Write-Warning "Could not load credential from '$p': $($_.Exception.Message)" }
    }
    return $null
}

if (-not $PSBoundParameters.ContainsKey('Credential'))                 { $Credential                = Import-SavedCredential 'WinRmCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('WorkstationCredential'))      { $WorkstationCredential     = Import-SavedCredential 'WorkstationCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('ServerCredential'))           { $ServerCredential          = Import-SavedCredential 'ServerCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('DomainControllerCredential')) { $DomainControllerCredential = Import-SavedCredential 'DomainControllerCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('SmtpCredential'))             { $SmtpCredential            = Import-SavedCredential 'SmtpCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('ADCredential'))               { $ADCredential              = Import-SavedCredential 'ADCredential.xml' }

# ===================================================================
# Classification Method Resolution
# ===================================================================
if (-not $ClassificationMethod) {
    $partOfDomain = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
    $ClassificationMethod = if ($partOfDomain) { 'AD' } else { 'Single' }
}

# ===================================================================
# Output Folders and Log File
# ===================================================================
if (-not $LogPath)    { $LogPath    = Join-Path $env:SystemDrive 'Logs' }
if (-not $ReportPath) { $ReportPath = Join-Path $ScriptDir 'Reports' }

foreach ($folder in $LogPath, $ReportPath) {
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }
}

$LogFile        = Join-Path $LogPath "Update-DefenderOffline_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Global:LogMutex = [System.Threading.Mutex]::new($false, 'DefenderUpdateLogMutex')

# ===================================================================
# Write-Log
# ===================================================================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','HEADER')]
        [string]$Level = 'INFO'
    )
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    try {
        $Global:LogMutex.WaitOne() | Out-Null
        $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    } finally {
        $Global:LogMutex.ReleaseMutex()
    }

    # ThreadJob runspaces don't inherit Write-Log from the parent scope, so
    # there's no risk of stray console output from worker threads. The
    # $script:SuppressConsoleOutput flag is toggled $true during the parallel
    # wave loop and back to $false before/after — that's the only gate
    # needed. The earlier ManagedThreadId -eq 1 check broke console output
    # entirely on terminals where the main script flow runs on a non-1
    # thread (e.g. VS Code's PS7 integrated terminal).
    if (-not $script:SuppressConsoleOutput) {
        $color = switch ($Level) {
            'INFO'    { 'Cyan'    }
            'WARN'    { 'Yellow'  }
            'ERROR'   { 'Red'     }
            'SUCCESS' { 'Green'   }
            'HEADER'  { 'Magenta' }
            default   { 'White'   }
        }
        Write-Host $line -ForegroundColor $color
    }
}

# ===================================================================
# Target Computer Resolution
# ===================================================================
function Resolve-TargetComputers {
    # 1. Manual list via parameter
    if ($ComputerName) {
        $list = $ComputerName |
            Where-Object { $_ -match '\S' } |
            ForEach-Object { $_.Trim().ToUpper() }
        Write-Log "Using manually provided list ($($list.Count) computers)" 'INFO'
        return $list
    }

    # 2. hosts.conf in script directory.
    #    Skipped when -ADSearchBase is set: the operator is explicitly asking
    #    for a scoped AD query, so a cached snapshot from a previous (possibly
    #    differently-scoped) run is semantically wrong. Otherwise hosts.conf
    #    is the preferred path because it's both faster and lets operators
    #    manually curate the list (exclude lab boxes, add workgroup hosts).
    $hostsExists = Test-Path $HostsFile
    if (-not $ADSearchBase -and $hostsExists) {
        $list = Get-Content $HostsFile |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
            ForEach-Object { $_.Trim().ToUpper() }
        Write-Log "Loaded $($list.Count) computers from hosts.conf" 'SUCCESS'
        return $list
    }
    if ($ADSearchBase -and $hostsExists) {
        Write-Log "Ignoring hosts.conf because ADSearchBase is set; querying AD with that scope." 'INFO'
    }

    # 3. Active Directory auto-discovery
    if (-not $hostsExists) {
        Write-Log 'hosts.conf not found – attempting Active Directory auto-discovery...' 'WARN'
    }
    $hasAdModule = [bool](Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue)
    if (-not $hasAdModule) {
        Write-Log 'ActiveDirectory PowerShell module is not installed; trying ADSI fallback.' 'INFO'
    }
    if ($ADCredential) {
        Write-Log "Using -ADCredential for LDAP bind: $($ADCredential.UserName)" 'INFO'
    }
    if ($ADSearchBase) {
        Write-Log "Restricting AD discovery to: $ADSearchBase" 'INFO'
    }
    try {
        $discovery = Get-DefenderComputers -SearchBase $ADSearchBase -ADCredential $ADCredential

        # Log per-DN status (hybrid validation reporting)
        if ($discovery.WasFiltered) {
            foreach ($s in $discovery.SearchBases) {
                if ($s.Resolved) {
                    Write-Log "  AD search base '$($s.DN)' -> $($s.Count) computer(s)" 'INFO'
                } else {
                    Write-Log "  AD search base '$($s.DN)' could not be resolved: $($s.Error)" 'WARN'
                }
            }
            $resolved = @($discovery.SearchBases | Where-Object Resolved).Count
            $total    = $discovery.SearchBases.Count
            if ($resolved -eq 0) {
                throw "All $total AD search base(s) failed to resolve. Check ADSearchBase syntax / AD reachability."
            }
            if ($resolved -lt $total) {
                Write-Log "Partial AD search-base resolution: $resolved of $total succeeded. Continuing with the resolved subset." 'WARN'
            }
        }

        $computers = $discovery.Computers
        if (-not $computers -or $computers.Count -eq 0) {
            throw 'AD discovery returned no computers.'
        }

        # Auto-write hosts.conf only when this run was an UNFILTERED
        # whole-domain discovery. Caching a scoped (ADSearchBase) result would
        # silently override a later whole-domain run, and operators changing
        # ADSearchBase between runs would see stale results until they
        # remembered to delete the cache.
        if (-not $ADSearchBase) {
            $header = @"
# =============================================================================
# hosts.conf – AUTO-GENERATED by Update-DefenderOffline.ps1 v$ScriptVersion
# Generated  : $(Get-Date)
# Domain     : $((Get-CimInstance Win32_ComputerSystem).Domain)
# Systems    : $($computers.Count)
# Edit this file to exclude lab/test machines or add workgroup systems.
# Lines beginning with # are ignored. One hostname or FQDN per line.
# =============================================================================

"@
            ($header + ($computers -join "`r`n")) |
                Out-File -FilePath $HostsFile -Encoding UTF8 -Force
            Write-Log "Auto-generated hosts.conf with $($computers.Count) computers" 'SUCCESS'
        } else {
            Write-Log "hosts.conf was NOT auto-written because ADSearchBase is set (would cache a scoped result)." 'INFO'
        }
        return $computers

    } catch {
        $adErr = $_.Exception.Message
        Write-Log "AD auto-discovery failed: $adErr" 'ERROR'
        $help = @"

==============================================================================
 Active Directory auto-discovery failed.
 Reason: $adErr
==============================================================================

Auto-discovery uses the credentials of the user running this script.  A
common cause is running under a local or workstation-admin account that
cannot bind to AD (e.g. STIG-hardened environments where Workstation Admin
is local-only).

You have four ways to proceed:

  1. Save a domain account with AD read permission and re-run (the
     recommended path for STIG environments where the interactive
     operator cannot bind to AD):

       .\Update-DefenderOffline.ps1 -SaveADCredential
       .\Update-DefenderOffline.ps1                # auto-loads it next run

  2. Create hosts.conf manually next to the script (one hostname per
     line, '#' lines are ignored):

       notepad "$HostsFile"

  3. Pass the targets explicitly on the command line:

       .\Update-DefenderOffline.ps1 -ComputerName SRV01,WS02

  4. Re-run from a session whose user already has AD read permission.
     To use Get-ADComputer instead of the ADSI fallback, install the
     RSAT ActiveDirectory PowerShell module:

       # Windows 10/11 client:
       Add-WindowsCapability -Online ``
         -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'

       # Windows Server:
       Install-WindowsFeature RSAT-AD-PowerShell

==============================================================================
"@
        Write-Host $help -ForegroundColor Yellow
        # exit (not throw): the friendly help block above is the operator-facing
        # message — letting throw bubble up would print the exception text on top
        # of that, doubling the noise. Exit 1 preserves the non-zero status for
        # scheduled-task wrappers without the duplicated error display.
        exit 1
    }
}

# ===================================================================
# Source File Discovery
#
# Supports two share layouts:
#   Flat (legacy)   : <SourceSharePath>\<YYYYMMDD>\v#.#.#.#\mpam-fe.exe
#   Per-arch (v0.0.8): <SourceSharePath>\<YYYYMMDD>\v#.#.#.#\<arch>\mpam-fe.exe
#                       where <arch> is x64, x86, or arm64
#
# Flat-layout files are classified as x64 so existing shares keep working.
# Get-AvailableMpamFiles returns every file found (one per arch per version);
# Get-LatestMpamFile is a thin wrapper that returns the single latest entry,
# optionally filtered by architecture (used for per-host dispatch).
# ===================================================================
function Get-AvailableMpamFiles {
    [OutputType([pscustomobject[]])]
    param([string]$Root)

    $files = Get-ChildItem -Path $Root -Recurse -Filter 'mpam-fe.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '(?i)[/\\]_?archive[/\\]' }

    if (-not $files) {
        throw "No mpam-fe.exe files found under '$Root'. " +
              "Expected: <base>\<YYYYMMDD>\v#.#.#.#\[<arch>\]mpam-fe.exe (arch = x64|x86|arm64)"
    }

    $entries = foreach ($f in $files) {
        $parent      = $f.Directory.Name
        $grandparent = if ($f.Directory.Parent) { $f.Directory.Parent.Name } else { '' }

        # Per-arch layout: <version>\<arch>\mpam-fe.exe
        if ($parent -match '^(?i)(x64|x86|arm64)$' -and
            $grandparent -match '^v(\d+\.\d+\.\d+\.\d+)$') {
            [pscustomobject]@{
                File         = $f.FullName
                Version      = [version]$Matches[1]
                Architecture = $parent.ToLower()
                IsFlatLayout = $false
            }
        }
        # Flat legacy layout: <version>\mpam-fe.exe (classified as x64)
        elseif ($parent -match '^v(\d+\.\d+\.\d+\.\d+)$') {
            [pscustomobject]@{
                File         = $f.FullName
                Version      = [version]$Matches[1]
                Architecture = 'x64'
                IsFlatLayout = $true
            }
        }
    }

    if (-not $entries) {
        throw "mpam-fe.exe files were found but none reside in a 'v#.#.#.#' versioned folder. " +
              "Rename the containing folder to match the pattern (e.g. v1.449.681.0)."
    }

    return $entries | Sort-Object Version -Descending
}

function Get-LatestMpamFile {
    param(
        [string]$Root,
        # Optional. When supplied returns the latest file FOR THAT ARCHITECTURE
        # (caller pattern: per-host dispatch). When omitted returns the absolute
        # latest across all architectures (preserves v0.0.7 behavior).
        [ValidateSet('', 'x64', 'x86', 'arm64')]
        [string]$Architecture = ''
    )
    $all = Get-AvailableMpamFiles -Root $Root
    if ($Architecture) {
        $all = @($all | Where-Object Architecture -eq $Architecture)
        if (-not $all -or $all.Count -eq 0) {
            throw "No mpam-fe.exe found for architecture '$Architecture' under '$Root'."
        }
    }
    return $all | Select-Object -First 1
}

# ===================================================================
# Endpoint Classification
# ===================================================================
function Get-EndpointClassification {
    param(
        [string[]]$Computers,
        [string]$Method,
        [string]$WsPattern,
        [string]$DcPattern,
        [System.Management.Automation.PSCredential]$ADCredential
    )

    $tiers = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Computers) { $tiers[$c] = 'MemberServer' }

    if ($Method -eq 'Single') { return $tiers }

    if ($Method -eq 'AD') {
        try {
            $adMap = [System.Collections.Generic.Dictionary[string,pscustomobject]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
                Import-Module ActiveDirectory -ErrorAction Stop
                $adParams = @{
                    Filter      = 'Enabled -eq $true'
                    Properties  = 'Name','OperatingSystem','userAccountControl'
                    ErrorAction = 'SilentlyContinue'
                }
                if ($ADCredential) { $adParams.Credential = $ADCredential }
                Get-ADComputer @adParams | ForEach-Object {
                    $adMap[$_.Name] = [pscustomobject]@{
                        OS   = $_.OperatingSystem
                        IsDC = ($_.userAccountControl -band 0x2000) -ne 0
                    }
                }
            } else {
                # ADSI fallback.  Use DirectoryEntry with explicit creds when
                # ADCredential is set, mirroring Resolve-TargetComputers.
                $domain = (Get-CimInstance Win32_ComputerSystem).Domain
                if ($ADCredential) {
                    $de = [System.DirectoryServices.DirectoryEntry]::new(
                        "LDAP://$domain",
                        $ADCredential.UserName,
                        $ADCredential.GetNetworkCredential().Password)
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new($de)
                    $searcher.Filter = '(objectCategory=computer)'
                } else {
                    $searcher = [adsisearcher]'(objectCategory=computer)'
                    $searcher.SearchRoot = "LDAP://$domain"
                }
                $searcher.PropertiesToLoad.AddRange(@('name','operatingsystem','useraccountcontrol'))
                $searcher.PageSize = 1000
                $searcher.FindAll() | ForEach-Object {
                    $n   = $_.Properties['name'][0]
                    $os  = $_.Properties['operatingsystem'][0]
                    $uac = [int]($_.Properties['useraccountcontrol'][0])
                    if ($n) {
                        $adMap[$n] = [pscustomobject]@{ OS = $os; IsDC = ($uac -band 0x2000) -ne 0 }
                    }
                }
                if ($ADCredential) { $de.Dispose() }
            }
            foreach ($c in $Computers) {
                if ($adMap.ContainsKey($c)) {
                    $info = $adMap[$c]
                    if ($info.IsDC) { $tiers[$c] = 'DomainController' }
                    elseif ($info.OS -match 'Windows (10|11|7|8|Vista|XP)') { $tiers[$c] = 'Workstation' }
                }
            }
        } catch {
            Write-Log "AD classification failed: $($_.Exception.Message). All hosts treated as MemberServer." 'WARN'
        }
        return $tiers
    }

    # Pattern method
    foreach ($c in $Computers) {
        if ($DcPattern -and $c -imatch $DcPattern)     { $tiers[$c] = 'DomainController' }
        elseif ($WsPattern -and $c -imatch $WsPattern) { $tiers[$c] = 'Workstation' }
    }
    return $tiers
}

function Resolve-WinRmCredential ([string]$Tier) {
    switch ($Tier) {
        'Workstation'      { if ($WorkstationCredential)       { return $WorkstationCredential }       }
        'DomainController' { if ($DomainControllerCredential)  { return $DomainControllerCredential }  }
    }
    if ($ServerCredential) { return $ServerCredential }
    return $Credential   # $null = run as calling user
}

# ===================================================================
# Core Update Function  (single implementation used by both modes)
# ===================================================================
function Invoke-DefenderUpdate {
    param(
        [string]$Computer,
        # Map of architecture (x64|x86|arm64) -> [pscustomobject]@{ File; Version }.
        # The right entry is selected per host using either WinRM-detected OS
        # architecture or the operator-supplied $ForcedArchitecture override.
        [hashtable]$AvailableByArch,
        # Optional. When set, ALL hosts use this architecture (no per-host
        # CIM call). Empty string = auto-detect per host.
        [string]$ForcedArchitecture,
        [string]$TempFolderOnTarget,
        [bool]$WhatIfMode,
        [string]$LogSharePath,
        [System.Management.Automation.PSCredential]$WinRmCredential,
        [bool]$DisableIPv6 = $true,
        [string[]]$LibPaths            # Paths to lib/*.ps1 helpers (Invoke-DefenderRemote,
                                       # Get-DefenderHealthProbe, etc.). Required when this
                                       # function runs inside a Start-ThreadJob runspace
                                       # (PS7 parallel mode) since runspaces don't inherit
                                       # functions from the parent.
    )

    $WarningPreference = 'SilentlyContinue'

    # Make wrapper functions available in this runspace. The Start-ThreadJob
    # runspace doesn't inherit functions from the parent, so we re-import here.
    foreach ($lib in $LibPaths) {
        if ($lib -and (Test-Path $lib)) { . $lib }
    }

    $result = [pscustomobject]@{
        ComputerName       = $Computer
        Status             = 'Unknown'
        OldVersion         = ''
        NewVersion         = ''
        DurationSec        = 0
        Details            = ''
        Attempt            = 1
        Timeout            = $false
        HealthStatus       = ''
        HealthReason       = ''
        RecentThreatCount  = 0
        Wave               = ''
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        # --- Dry-run ---
        if ($WhatIfMode) {
            $result.Status  = 'WhatIf'
            $result.Details = 'Dry-run mode – no changes made'
            return $result
        }

        # --- Connectivity ---
        $pingOk = Test-Connection -ComputerName $Computer -Count 1 -Quiet `
            -TimeoutSeconds 2 -ErrorAction SilentlyContinue

        # WinRM TCP test.  When DisableIPv6 is set (LAN default), resolve to
        # IPv4 only and connect directly — avoids the ~21s Test-NetConnection
        # timeout on DNS AAAA records whose IPv6 routes aren't actually live.
        $winrmOk = $false
        if ($DisableIPv6) {
            try {
                $addrs = [System.Net.Dns]::GetHostAddresses($Computer) |
                    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
                if ($addrs) {
                    $client = [System.Net.Sockets.TcpClient]::new()
                    $task   = $client.ConnectAsync($addrs[0], 5985)
                    $winrmOk = $task.Wait(3000) -and -not $task.IsFaulted -and $client.Connected
                    try { $client.Close() } catch {}
                }
            } catch { $winrmOk = $false }
        } else {
            $winrmOk = [bool](Test-NetConnection -ComputerName $Computer -Port 5985 `
                -InformationLevel Quiet -WarningAction SilentlyContinue)
        }

        if (-not $winrmOk) {
            throw $(if ($pingOk) { 'Online but WinRM (5985) not reachable — may be blocked or disabled' }
                    else          { 'Host offline (no ping response; WinRM 5985 not reachable)' })
        }

        $sessionParams = @{ ComputerName = $Computer }
        if ($WinRmCredential) { $sessionParams.Credential = $WinRmCredential }
        $session = New-DefenderRemoteSession @sessionParams

        try {
            # --- Pre-update health check ---
            $svcStatus = Invoke-DefenderRemote -Session $session -ScriptBlock {
                $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                if ($svc) { $svc.Status.ToString() } else { 'NotFound' }
            }
            if ($svcStatus -ne 'Running') {
                throw "Windows Defender service is not running (Status: $svcStatus)"
            }

            # --- Combined pre-transfer probe: current Defender signature + OS arch ---
            # One WinRM round-trip instead of two: we need the host's OS
            # architecture to pick the right mpam-fe.exe variant before
            # comparing versions, so we fold both queries into one call.
            $probe = Invoke-DefenderRemote -Session $session -ScriptBlock {
                $sig = try { (Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureVersion } catch { $null }
                $osa = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).OSArchitecture } catch { $null }
                @{ SignatureVersion = $sig; OSArchitecture = $osa }
            }
            $currentVerStr = $probe.SignatureVersion
            $result.OldVersion = $currentVerStr

            # --- Per-host architecture dispatch ---
            # If the operator forced a specific arch, use that. Otherwise map
            # Win32_OperatingSystem.OSArchitecture to the share's subfolder
            # convention. Fail fast and clearly if either step yields nothing.
            $archMap = @{ '64-bit' = 'x64'; '32-bit' = 'x86'; 'ARM 64-bit' = 'arm64' }
            $hostArch = if ($ForcedArchitecture) {
                $ForcedArchitecture
            } elseif ($probe.OSArchitecture -and $archMap.ContainsKey($probe.OSArchitecture)) {
                $archMap[$probe.OSArchitecture]
            } else {
                $null
            }

            if (-not $hostArch) {
                throw "Could not determine host architecture (OSArchitecture: '$($probe.OSArchitecture)')"
            }
            if (-not $AvailableByArch.ContainsKey($hostArch)) {
                throw "No mpam-fe.exe found for architecture '$hostArch' in the source share. Run Get-DefenderDefinitions.ps1 with -Architecture $hostArch on the staging host."
            }

            $archInfo = $AvailableByArch[$hostArch]
            $SourceFile          = $archInfo.File
            $AvailableVersionStr = $archInfo.Version.ToString()

            if ($currentVerStr -and $AvailableVersionStr) {
                try {
                    if ([version]$currentVerStr -ge [version]$AvailableVersionStr) {
                        $result.Status     = 'No Update Needed'
                        $result.NewVersion = $currentVerStr
                        $result.Details    = "Already at v$currentVerStr ($hostArch available: v$AvailableVersionStr)"
                        # Probe before returning — session is still active, host
                        # is in a deterministic state (no install attempted, so
                        # the probe captures the steady-state health).
                        try {
                            $probe = Get-DefenderHealthProbe -Session $session
                            $result.HealthStatus      = $probe.OverallStatus
                            $result.HealthReason      = if ($probe.StatusReason) { $probe.StatusReason } else { '' }
                            $result.RecentThreatCount = $probe.RecentThreatCount
                        } catch {
                            $result.HealthStatus = 'ProbeFailed'
                            $result.HealthReason = ($_.Exception.Message -replace "`r`n", ' ').Trim()
                        }
                        return $result
                    }
                } catch {
                    # Version parse failed – proceed with install and let it determine the outcome
                }
            }

            # --- File transfer ---
            $mpamFileName = Split-Path $SourceFile -Leaf
            Invoke-DefenderRemote -Session $session -ScriptBlock {
                New-Item -Path $using:TempFolderOnTarget -ItemType Directory -Force | Out-Null
            }
            $remoteFile = Join-Path $TempFolderOnTarget $mpamFileName
            Copy-Item -Path $SourceFile -Destination $remoteFile -ToSession $session -Force

            # --- Silent install ---
            $install = Invoke-DefenderRemote -Session $session -ScriptBlock {
                $logFile = Join-Path $using:TempFolderOnTarget "install_$(Get-Date -f 'yyyyMMdd_HHmmss').log"
                $errFile = $logFile + '.err'
                $p = Start-Process `
                    -FilePath    $using:remoteFile `
                    -ArgumentList '/q' `
                    -Wait -PassThru -NoNewWindow `
                    -RedirectStandardOutput $logFile `
                    -RedirectStandardError  $errFile
                [pscustomobject]@{
                    ExitCode = $p.ExitCode
                    LogFile  = $logFile
                    ErrFile  = $errFile
                }
            }

            # --- Post-install version ---
            $newVerStr = Invoke-DefenderRemote -Session $session -ScriptBlock {
                try { (Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureVersion }
                catch { $null }
            }
            $result.NewVersion = $newVerStr

            # --- Optional log collection ---
            if ($LogSharePath -and (Test-Path $LogSharePath -ErrorAction SilentlyContinue)) {
                try {
                    $hostLogDir = Join-Path $LogSharePath $Computer
                    if (-not (Test-Path $hostLogDir)) {
                        New-Item -Path $hostLogDir -ItemType Directory -Force | Out-Null
                    }
                    foreach ($lf in @($install.LogFile, $install.ErrFile)) {
                        Copy-Item -Path $lf -Destination $hostLogDir `
                            -FromSession $session -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }

            # --- Cleanup remote temp ---
            Invoke-DefenderRemote -Session $session -ScriptBlock {
                Remove-Item $using:TempFolderOnTarget -Recurse -Force -ErrorAction SilentlyContinue
            }

            # --- Determine outcome ---
            if ($install.ExitCode -eq 0 -and $newVerStr -and $newVerStr -ne $currentVerStr) {
                $result.Status  = 'Success'
                $result.Details = "$currentVerStr → $newVerStr"
            } elseif ($install.ExitCode -eq 0) {
                $result.Status     = 'No Update Needed'
                $result.NewVersion = $currentVerStr
                $result.Details    = 'Installer confirmed: already current'
            } else {
                $result.Status  = 'Failed'
                $result.Details = "Installer exit code: $($install.ExitCode)"
            }

            # --- Post-install health probe ---
            # Runs only when the host completed its update path (Success, or
            # already current). On Failed we don't probe — the host state may
            # be transient and the operator already has a clear failure signal.
            if ($result.Status -in 'Success','No Update Needed') {
                try {
                    $probe = Get-DefenderHealthProbe -Session $session
                    $result.HealthStatus      = $probe.OverallStatus
                    $result.HealthReason      = if ($probe.StatusReason) { $probe.StatusReason } else { '' }
                    $result.RecentThreatCount = $probe.RecentThreatCount
                } catch {
                    $result.HealthStatus = 'ProbeFailed'
                    $result.HealthReason = ($_.Exception.Message -replace "`r`n", ' ').Trim()
                }
            }

        } finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }

    } catch {
        $result.Status  = 'Failed'
        $result.Details = ($_.Exception.Message -replace "`r`n", ' ').Trim()
    } finally {
        $sw.Stop()
        $result.DurationSec = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    }

    return $result
}

# ===================================================================
# HTML Report Generation
# ===================================================================
function New-HtmlReport {
    param(
        [System.Collections.Generic.List[pscustomobject]]$Data,
        [timespan]$RunTime
    )

    $successCount  = @($Data | Where-Object Status -eq 'Success').Count
    $failCount     = @($Data | Where-Object Status -eq 'Failed').Count
    $skipCount     = @($Data | Where-Object Status -eq 'No Update Needed').Count
    $whatifCount   = @($Data | Where-Object Status -eq 'WhatIf').Count
    $excludedCount = @($Data | Where-Object Status -eq 'Excluded').Count
    $gateHaltCount = @($Data | Where-Object Status -eq 'Skipped').Count

    $css = @'
<style>
  *   { box-sizing: border-box; }
  body{ font-family: "Segoe UI", Arial, sans-serif; margin: 40px; background: #f5f7fa; color: #333; }
  h1  { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; margin-bottom: 4px; }
  h2  { color: #005a9e; margin-top: 32px; }
  p   { line-height: 1.6; }
  table          { width: 100%; border-collapse: collapse; margin: 16px 0; background: #fff;
                   box-shadow: 0 4px 12px rgba(0,0,0,.1); border-radius: 8px; overflow: hidden; }
  th             { background: #0078d4; color: #fff; padding: 13px 12px; text-align: left; font-weight: 600; }
  td             { padding: 11px 12px; border-bottom: 1px solid #e8e8e8; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:nth-child(even) td { background: #f9f9f9; }
  .tag           { display: inline-block; padding: 2px 10px; border-radius: 12px;
                   font-size: .85em; font-weight: 600; color: #fff; }
  .success       { background: #107c10; }
  .failed        { background: #d13438; }
  .skipped       { background: #9c5100; }
  .whatif        { background: #0078d4; }
  .excluded      { background: #6b7280; }
  .gate-halt     { background: #6b21a8; }
  .h-healthy     { background: #107c10; }
  .h-degraded    { background: #ca5010; }
  .h-threats     { background: #d13438; }
  .h-probefail   { background: #4b5563; }
  .stat-card     { display: inline-block; padding: 14px 28px; border-radius: 10px; margin: 6px 8px 6px 0;
                   font-size: 1.1em; font-weight: 700; color: #fff; min-width: 120px; text-align: center;
                   cursor: pointer; user-select: none; }
  .stat-card.active-filter { outline: 3px solid rgba(255,255,255,.85); outline-offset: -3px; }
  .sc-ok         { background: #107c10; }
  .sc-fail       { background: #d13438; }
  .sc-skip       { background: #9c5100; }
  .sc-info       { background: #0078d4; }
  /* Use <table> for the version summary layout, not CSS Grid — Gmail's
     CSS sanitizer strips 'display: grid' so the cards stack vertically
     when the report is sent as the email body. */
  .version-table  { width: 100%; border-collapse: separate; border-spacing: 8px 0; margin: 16px 0; }
  .version-table td { width: 33.33%; padding: 0; vertical-align: top; }
  .vcard          { background: #fff; border-radius: 8px; padding: 16px 20px;
                    box-shadow: 0 2px 8px rgba(0,0,0,.08);
                    border-top: 4px solid #0078d4; }
  .vcard .label   { font-size: .85em; color: #666; margin-bottom: 4px; }
  .vcard .value   { font-size: 1.4em; font-weight: 700; color: #0078d4; }
  .vcard-oldest        { border-top-color: #b45309; }
  .vcard-oldest .value { color: #b45309; }
  .vcard-newest        { border-top-color: #107c10; }
  .vcard-newest .value { color: #107c10; }
  .vcard-hosts         { border-top-color: #0078d4; }
  .vcard-hosts  .value { color: #0078d4; }
  .footer        { margin-top: 48px; color: #888; font-size: .85em; text-align: center;
                   border-top: 1px solid #ddd; padding-top: 16px; }
  a              { color: #0078d4; }
</style>
'@

    # Build table rows and inject status badges
    $reportStaged = $false
    if ($Data -and ($Data | Where-Object { $_.Wave -and $_.Wave -ne 'All' -and $_.Wave -ne '' } | Select-Object -First 1)) {
        $reportStaged = $true
    }
    $reportProps = if ($reportStaged) {
        @('ComputerName', 'Wave', 'Status', 'OldVersion', 'NewVersion', 'DurationSec', 'Delta', 'Attempt', 'Timeout', 'HealthStatus', 'RecentThreatCount', 'Details')
    } else {
        @('ComputerName', 'Status', 'OldVersion', 'NewVersion', 'DurationSec', 'Delta', 'Attempt', 'Timeout', 'HealthStatus', 'RecentThreatCount', 'Details')
    }
    $rows = $Data | Sort-Object ComputerName |
        ConvertTo-Html -Fragment -Property $reportProps

    # Add table id for the JS badge filter
    if ($rows.Count -gt 0) { $rows[0] = $rows[0] -replace '<table>', '<table id="resultsTable">' }

    foreach ($i in 0..($rows.Count - 1)) {
        $rows[$i] = $rows[$i] `
            -replace '<td>Success</td>',          '<td><span class="tag success">Success</span></td>' `
            -replace '<td>Failed</td>',           '<td><span class="tag failed">Failed</span></td>' `
            -replace '<td>No Update Needed</td>', '<td><span class="tag skipped">No Update Needed</span></td>' `
            -replace '<td>WhatIf</td>',           '<td><span class="tag whatif">WhatIf</span></td>' `
            -replace '<td>Excluded</td>',         '<td><span class="tag excluded">Excluded</span></td>' `
            -replace '<td>Skipped</td>',          '<td><span class="tag gate-halt">Skipped (gate)</span></td>' `
            -replace '<td>Healthy</td>',          '<td><span class="tag h-healthy">Healthy</span></td>' `
            -replace '<td>Degraded</td>',         '<td><span class="tag h-degraded">Degraded</span></td>' `
            -replace '<td>ThreatsDetected</td>',  '<td><span class="tag h-threats">Threats Detected</span></td>' `
            -replace '<td>ProbeFailed</td>',      '<td><span class="tag h-probefail">Probe Failed</span></td>' `
            -replace '<td>True</td>',             '<td><strong style="color:#d13438">Yes</strong></td>' `
            -replace '<td>False</td>',            '<td>No</td>'
    }
    # Rename column headers to operator-friendly labels (after badge injection so the
    # <th>HealthStatus</th> doesn't match the row-level pattern).
    if ($rows.Count -gt 0) {
        $rows[0] = $rows[0] `
            -replace '<th>HealthStatus</th>',      '<th>Health</th>' `
            -replace '<th>RecentThreatCount</th>', '<th>Threats (24h)</th>'
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Defender Update Report – $(Get-Date -f 'yyyy-MM-dd')</title>
  $css
</head>
<body>
  <h1>Microsoft Defender Antivirus – Definitions Update Report</h1>
  <p>
    <strong>Run Date:</strong> $ScriptStartTime &nbsp;|&nbsp;
    <strong>Available Version:</strong> v$AvailableVersionStr$(
        if ($AvailableByArch -and $AvailableByArch.Keys.Count -gt 1) {
            ' (' + (@($AvailableByArch.Keys | Sort-Object | ForEach-Object {
                "$_=v$($AvailableByArch[$_].Version)"
            }) -join ' · ') + ')'
        }
    ) &nbsp;|&nbsp;
    <strong>Total Duration:</strong> $($RunTime.ToString('hh\:mm\:ss')) &nbsp;|&nbsp;
    <strong>Run By:</strong> $RunAsUser @ $RunFromHost ($RunFromIP)
  </p>
  <p style="font-size:.9em; color:#555; margin-top:-6px;">
    <strong>Source Share:</strong> $SourceSharePath
  </p>

  <div id="statusCards">
    <span class="stat-card sc-ok"    data-filter="Success"        onclick="filterByStatus(this)">Success<br>$successCount</span>
    <span class="stat-card sc-fail"  data-filter="Failed"         onclick="filterByStatus(this)">Failed<br>$failCount</span>
    <span class="stat-card sc-skip"  data-filter="No Update Needed" onclick="filterByStatus(this)">Skipped<br>$skipCount</span>$(if ($whatifCount   -gt 0) { "`n    <span class='stat-card sc-info'  data-filter='WhatIf'   onclick='filterByStatus(this)'>WhatIf<br>$whatifCount</span>" })$(if ($excludedCount -gt 0) { "`n    <span class='stat-card' style='background:#6b7280' data-filter='Excluded'  onclick='filterByStatus(this)'>Excluded<br>$excludedCount</span>" })$(if ($gateHaltCount -gt 0) { "`n    <span class='stat-card' style='background:#6b21a8' data-filter='Skipped' onclick='filterByStatus(this)'>Gate Halt<br>$gateHaltCount</span>" })
  </div>
  <p style="font-size:.8em; color:#888; margin-top:4px;">Click a badge to filter the results table. Click again to clear.</p>

  <h2>Fleet Version Summary</h2>
  <table class="version-table" role="presentation">
    <tr>
      <td><div class="vcard vcard-oldest"><div class="label">Oldest Version Found</div><div class="value">$OldestVersion</div></div></td>
      <td><div class="vcard vcard-newest"><div class="label">Newest Version Applied</div><div class="value">$NewestVersion</div></div></td>
      <td><div class="vcard vcard-hosts"><div class="label">Hosts Updated</div><div class="value">$HostsUpdated</div></div></td>
    </tr>
  </table>

  <h2>Detailed Results ($($Data.Count) computers)</h2>
  $($rows -join "`n")

  <div class="footer">
    Generated by Update-DefenderOffline.ps1 v$ScriptVersion &nbsp;|&nbsp;
    Run by <strong>$RunAsUser</strong> from <strong>$RunFromHost</strong> ($RunFromIP) &nbsp;|&nbsp;
    <a href="file:///$([uri]::EscapeUriString($LogFile.Replace('\','/')))">View Full Log</a>
  </div>

  <script>
    var _activeFilter = null;
    function filterByStatus(el) {
      var status = el.dataset.filter;
      var rows   = document.querySelectorAll('#resultsTable tbody tr');
      if (_activeFilter === status) {
        _activeFilter = null;
        rows.forEach(function(r) { r.style.display = ''; });
        document.querySelectorAll('.stat-card').forEach(function(c) { c.classList.remove('active-filter'); });
      } else {
        _activeFilter = status;
        rows.forEach(function(r) {
          var badge = r.querySelector('.tag');
          // ConvertTo-Html -Fragment emits header <tr> and data <tr>s as
          // siblings (no <thead>/<tbody>); browsers auto-wrap all of them
          // in an implicit <tbody>, so this selector matches the header
          // row too.  Skip rows without a .tag (header / non-data rows).
          if (!badge) return;
          r.style.display = badge.textContent.trim() === status ? '' : 'none';
        });
        document.querySelectorAll('.stat-card').forEach(function(c) { c.classList.remove('active-filter'); });
        el.classList.add('active-filter');
      }
    }
  </script>
</body>
</html>
"@
}

# ===================================================================
# Main-flow guard
#
# When this script is dot-sourced (Pester or interactive testing of
# individual functions), return here so the banner and execution
# engine below do not run.  Direct invocation continues normally.
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
    throw 'This script requires administrative privileges. Run PowerShell as Administrator.'
}

# ===================================================================
# Startup Banner
# ===================================================================
Write-Log "=== Microsoft Defender Offline Update v$ScriptVersion ===" 'HEADER'
Write-Log "Started       : $(Get-Date)"
Write-Log "PowerShell    : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Write-Log "Parallel Mode : $(if ($PSVersionTable.PSVersion.Major -ge 7) { "ENABLED ($ParallelThreads threads)" } else { 'DISABLED (PS 5.1 serial)' })"
Write-Log "Log File      : $LogFile"
Write-Log "Report Folder : $ReportPath"
Write-Log "WhatIf Mode   : $WhatIfMode"
if ($SendEmail) { Write-Log "Email         : $SmtpServer → $($To -join ', ')" }
$credParts = @()
if ($DomainControllerCredential) { $credParts += "DC=$($DomainControllerCredential.UserName)" }
if ($ServerCredential)           { $credParts += "Server=$($ServerCredential.UserName)" }
if ($WorkstationCredential)      { $credParts += "WS=$($WorkstationCredential.UserName)" }
if ($Credential)                 { $credParts += "Single=$($Credential.UserName)" }
Write-Log "WinRM Auth    : $(if ($credParts) { $credParts -join ' | ' } else { "caller context ($env:USERDOMAIN\$env:USERNAME)" })"
Write-Log "Classification: $ClassificationMethod"

# ===================================================================
# Resolve Targets and Source
# ===================================================================
$TargetComputers = Resolve-TargetComputers
if (-not $TargetComputers -or $TargetComputers.Count -eq 0) {
    Write-Log 'No target computers found. Exiting.' 'ERROR'
    return
}
Write-Log "Will process $($TargetComputers.Count) computers" 'HEADER'

$Results = [System.Collections.Generic.List[pscustomobject]]::new()

# ===================================================================
# Apply administrative exclusions
# ===================================================================
if ($ExcludeList.Count -gt 0) {
    foreach ($ex in $ExcludeList) {
        if ($TargetComputers -contains $ex) {
            Write-Log "EXCLUDED (administrative): $ex — listed in ExcludeComputers in config.conf" 'WARN'
            $Results.Add([pscustomobject]@{
                ComputerName      = $ex
                Status            = 'Excluded'
                OldVersion        = ''
                NewVersion        = ''
                DurationSec       = 0
                Details           = 'Administrative exclusion (ExcludeComputers in config.conf)'
                Attempt           = 0
                Timeout           = $false
                HealthStatus      = ''
                HealthReason      = ''
                RecentThreatCount = 0
                Wave              = ''
            })
        }
    }
    $TargetComputers = $TargetComputers | Where-Object { $ExcludeList -notcontains $_ }
    if ($ExcludeList.Count -gt 0) {
        Write-Log "After exclusions: $($TargetComputers.Count) computers to process" 'INFO'
    }
}

# ===================================================================
# Classify endpoints and pre-compute per-host credentials
# ===================================================================
Write-Log "Classifying endpoints (method: $ClassificationMethod)..." 'INFO'
$EndpointTiers = Get-EndpointClassification `
    -Computers    $TargetComputers `
    -Method       $ClassificationMethod `
    -WsPattern    $WorkstationPattern `
    -DcPattern    $DomainControllerPattern `
    -ADCredential $ADCredential

$tierGroups = $EndpointTiers.Values | Group-Object | ForEach-Object { "$($_.Count) $($_.Name)" }
Write-Log "Tier breakdown : $($tierGroups -join ' | ')" 'INFO'

$HostCredentials = [System.Collections.Generic.Dictionary[string,System.Management.Automation.PSCredential]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($c in $TargetComputers) {
    $HostCredentials[$c] = Resolve-WinRmCredential -Tier ($EndpointTiers.ContainsKey($c) ? $EndpointTiers[$c] : 'MemberServer')
}

if (-not $SourceSharePath) {
    throw '-SourceSharePath is required. Pass it as a parameter or set SourceSharePath in conf\config.conf.'
}
if (-not (Test-Path $SourceSharePath -PathType Container)) {
    throw "SourceSharePath not found or inaccessible: $SourceSharePath"
}

# Build the per-architecture index. For each architecture present in the
# share we keep the latest version available. The script-scope $AvailableByArch
# is consumed by Invoke-DefenderUpdate at per-host dispatch time.
$AvailableFiles  = @(Get-AvailableMpamFiles -Root $SourceSharePath)
$AvailableByArch = @{}
foreach ($arch in 'x64','x86','arm64') {
    $forArch = @($AvailableFiles | Where-Object Architecture -eq $arch) | Sort-Object Version -Descending
    if ($forArch.Count -gt 0) {
        $AvailableByArch[$arch] = $forArch[0]
    }
}

# Headline version = absolute latest across all archs (used in HTML report,
# email subject, log banner). Per-host comparisons use the host's own arch's
# latest, not this value.
$latest              = $AvailableFiles | Sort-Object Version -Descending | Select-Object -First 1
$SourceFile          = $latest.File
$AvailableVersionStr = $latest.Version.ToString()

Write-Log 'Available definition versions (per architecture):' 'SUCCESS'
foreach ($arch in 'x64','x86','arm64') {
    if ($AvailableByArch.ContainsKey($arch)) {
        $entry = $AvailableByArch[$arch]
        $note  = if ($entry.IsFlatLayout) { ' (flat layout — classified as x64)' } else { '' }
        Write-Log ("  {0,-5} = v{1,-12}  -> {2}{3}" -f $arch, $entry.Version, $entry.File, $note) 'INFO'
    }
}

if ($Architecture) {
    if (-not $AvailableByArch.ContainsKey($Architecture)) {
        Write-Log "CRITICAL: -Architecture $Architecture forced, but no mpam-fe.exe found for that architecture under '$SourceSharePath'." 'ERROR'
        exit 1
    }
    Write-Log "Forcing architecture '$Architecture' for all hosts (auto-detection disabled)." 'WARN'
}

if (-not (Test-Path $SourceFile)) {
    Write-Log "CRITICAL: Source file is not accessible: $SourceFile" 'ERROR'
    exit 1
}

# ===================================================================
# Wave partitioning  (Staged Rollout)
# ===================================================================
# When -CanaryComputers is supplied, partition $TargetComputers into a
# Canary wave (runs first) and a Production wave (runs only if the
# canary health gate passes). When the param is empty, a single 'All'
# wave is queued — behavior is identical to pre-v0.0.10.
$Waves = [System.Collections.Generic.List[hashtable]]::new()
if ($CanaryComputers -and $CanaryComputers.Count -gt 0) {
    $fleetByLower = @{}
    foreach ($t in $TargetComputers) { $fleetByLower[$t.ToLower()] = $t }
    $validCanary = New-Object 'System.Collections.Generic.List[string]'
    $unknownList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($c in $CanaryComputers) {
        $k = $c.ToLower()
        if ($fleetByLower.ContainsKey($k)) {
            $canonical = $fleetByLower[$k]
            if (-not ($validCanary -contains $canonical)) { $validCanary.Add($canonical) }
        } else {
            $unknownList.Add($c)
        }
    }
    if ($unknownList.Count -gt 0) {
        Write-Log "Canary list: $($unknownList.Count) host(s) not in target fleet — dropped: $($unknownList -join ', ')" 'WARN'
    }
    if ($validCanary.Count -eq 0) {
        Write-Log 'Canary list resolved to empty — proceeding without staging.' 'WARN'
        $Waves.Add(@{ Name = 'All'; Computers = $TargetComputers; IsGate = $false })
    } elseif ($validCanary.Count -ge $TargetComputers.Count) {
        Write-Log "Canary list covers all $($TargetComputers.Count) targets — no production wave, proceeding as single wave." 'WARN'
        $Waves.Add(@{ Name = 'All'; Computers = $TargetComputers; IsGate = $false })
    } else {
        $remainder = @($TargetComputers | Where-Object { $validCanary -notcontains $_ })
        $Waves.Add(@{ Name = 'Canary';     Computers = $validCanary.ToArray(); IsGate = $true  })
        $Waves.Add(@{ Name = 'Production'; Computers = $remainder;             IsGate = $false })
        Write-Log ("Staged rollout: Wave 1 (Canary) = {0} host(s), Wave 2 (Production) = {1} host(s)" -f $validCanary.Count, $remainder.Count) 'HEADER'
        Write-Log ("Canary hosts : {0}" -f ($validCanary -join ', ')) 'INFO'
        Write-Log ("Gate         : halt if (Degraded + ProbeFailed) > {0}" -f $MaxCanaryFailures) 'INFO'
        Write-Log ("Settle       : {0}s pause after canary wave before evaluating health" -f $HealthSettleSeconds) 'INFO'
    }
} else {
    $Waves.Add(@{ Name = 'All'; Computers = $TargetComputers; IsGate = $false })
}
$Staged = ($Waves.Count -gt 1)

# ===================================================================
# Execution Engine
# ===================================================================
foreach ($wave in $Waves) {
    $WaveTargets  = @($wave.Computers)
    $WaveStartIdx = $Results.Count

    if ($Staged) {
        Write-Log ("=== Wave: {0} ({1} host(s)) ===" -f $wave.Name, $WaveTargets.Count) 'HEADER'
    }

if ($PSVersionTable.PSVersion.Major -ge 7) {
    # -----------------------------------------------------------
    # PARALLEL MODE  (PS 7+)
    # -----------------------------------------------------------
    $MaxConcurrent  = $ParallelThreads
    $TimeoutSeconds = 300   # 5 minutes per computer
    $RetryLimit     = 3

    $PerHostLogDir = Join-Path $LogPath 'PerHost'
    if (-not (Test-Path $PerHostLogDir)) {
        New-Item -Path $PerHostLogDir -ItemType Directory -Force | Out-Null
    }

    # Queue as a generic Queue for O(1) Dequeue
    $Queue = [System.Collections.Generic.Queue[pscustomobject]]::new()
    foreach ($comp in $WaveTargets) {
        $Queue.Enqueue([pscustomobject]@{ Computer = $comp; Attempt = 1; Credential = $HostCredentials[$comp] })
    }

    # Active jobs: keyed by Job.Id
    $ActiveJobs = [System.Collections.Generic.Dictionary[int, hashtable]]::new()

    Write-Log "Executing in PARALLEL mode ($MaxConcurrent concurrent threads)" 'HEADER'

    $script:SuppressConsoleOutput = $true
    $savedWarningPref = $WarningPreference
    $WarningPreference = 'SilentlyContinue'
    $DashTimer    = [System.Diagnostics.Stopwatch]::StartNew()
    $DashAnchor   = $null
    $FirstDashTick = $true

    while ($Queue.Count -gt 0 -or $ActiveJobs.Count -gt 0) {

        # Dashboard refresh: print immediately on first iteration so the
        # operator gets visible feedback, then every 5 seconds after.
        if (-not $DashAnchor) { $DashAnchor = $Host.UI.RawUI.CursorPosition }

        if ($FirstDashTick -or $DashTimer.Elapsed.TotalSeconds -ge 5) {
            $FirstDashTick = $false
            $DashTimer.Restart()
            $Host.UI.RawUI.CursorPosition = $DashAnchor

            $activeNames = if ($ActiveJobs.Count -gt 0) {
                ($ActiveJobs.Values | ForEach-Object { $_.Computer } | Select-Object -First 8) -join ', '
            } else { 'None' }

            $elapsed = [string]::Format('{0:hh\:mm\:ss}', (Get-Date) - $ScriptStartTime)

            Write-Host ('=== Defender Update Dashboard ' + ('=' * 24)) -ForegroundColor Cyan
            Write-Host "Running:    $($ActiveJobs.Count)                    "
            Write-Host "Pending:    $($Queue.Count)                    "
            Write-Host "Completed:  $($Results.Count)                    "
            Write-Host "Active:     $activeNames                    "
            Write-Host "Elapsed:    $elapsed                    "
            Write-Host (' ' * 80)
        }

        # Launch jobs up to capacity
        while ($ActiveJobs.Count -lt $MaxConcurrent -and $Queue.Count -gt 0) {
            $item = $Queue.Dequeue()
            $job  = Start-ThreadJob -ScriptBlock ${function:Invoke-DefenderUpdate} -ArgumentList @(
                $item.Computer,
                $AvailableByArch,
                $Architecture,
                $TempFolderOnTarget,
                [bool]$WhatIfMode,
                $LogSharePath,
                $item.Credential,
                [bool]$DisableIPv6,
                @($LibInvokeDefenderRemote, $LibGetDefenderHealthProbe)
            )
            $ActiveJobs[$job.Id] = @{
                Job        = $job
                Computer   = $item.Computer
                Attempt    = $item.Attempt
                Credential = $item.Credential
                StartTime  = [datetime]::UtcNow
            }
        }

        # Collect finished jobs
        foreach ($id in @($ActiveJobs.Keys)) {
            $meta = $ActiveJobs[$id]
            $job  = $meta.Job

            if ($job.State -notin 'Running','NotStarted') {
                $r = Receive-Job $job -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                if (-not $r) {
                    $r = [pscustomobject]@{
                        ComputerName = $meta.Computer; Status = 'Failed'
                        OldVersion = ''; NewVersion = ''; DurationSec = 0
                        Details = 'Job produced no output'; Attempt = $meta.Attempt; Timeout = $false
                        HealthStatus = ''; HealthReason = ''; RecentThreatCount = 0
                        Wave = ''
                    }
                } elseif ($r -is [array]) {
                    $r = $r[-1]
                }

                $r.Attempt = $meta.Attempt
                Add-Content -Path (Join-Path $PerHostLogDir "$($meta.Computer).log") `
                    -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Attempt $($meta.Attempt): $($r.Status) – $($r.Details)"

                # Classify failure: hard (no retry) vs soft (retryable)
                $det = ($r.Details ?? '').ToLower()
                $isHardFail = $det -match 'winrm|not reachable|offline|unreachable|no ping|access.{0,10}denied|authentication|cannot.?find|dns' `
                    -or $r.Timeout

                if ($r.Status -eq 'Failed' -and -not $isHardFail -and $meta.Attempt -lt $RetryLimit) {
                    Write-Log "Retry scheduled: $($meta.Computer) (attempt $($meta.Attempt) → $($meta.Attempt + 1))" 'WARN'
                    $Queue.Enqueue([pscustomobject]@{
                        Computer   = $meta.Computer
                        Attempt    = $meta.Attempt + 1
                        Credential = $meta.Credential
                    })
                } else {
                    $Results.Add($r)
                }

                Remove-Job $job -Force -ErrorAction SilentlyContinue
                [void]$ActiveJobs.Remove($id)
            }
        }

        # Timeout enforcement
        foreach ($id in @($ActiveJobs.Keys)) {
            $meta    = $ActiveJobs[$id]
            $elapsed = ([datetime]::UtcNow - $meta.StartTime).TotalSeconds

            if ($elapsed -gt $TimeoutSeconds) {
                Write-Log "TIMEOUT: $($meta.Computer) exceeded ${TimeoutSeconds}s (attempt $($meta.Attempt))" 'ERROR'
                Stop-Job $meta.Job -Force -ErrorAction SilentlyContinue
                $Results.Add([pscustomobject]@{
                    ComputerName = $meta.Computer; Status = 'Failed'
                    OldVersion = ''; NewVersion = ''
                    DurationSec = [math]::Round($elapsed, 2)
                    Details = 'Timeout'; Attempt = $meta.Attempt; Timeout = $true
                    HealthStatus = ''; HealthReason = ''; RecentThreatCount = 0
                    Wave = ''
                })
                Remove-Job $meta.Job -Force -ErrorAction SilentlyContinue
                [void]$ActiveJobs.Remove($id)
            }
        }

        Start-Sleep -Milliseconds 500
    }

    $script:SuppressConsoleOutput = $false
    $WarningPreference = $savedWarningPref

} else {
    # -----------------------------------------------------------
    # SERIAL MODE  (PS 5.1)
    # -----------------------------------------------------------
    Write-Log 'Executing in SERIAL mode (PowerShell 5.1 detected; upgrade to PS 7+ for parallel)' 'WARN'
    $i = 0
    foreach ($comp in $WaveTargets) {
        $i++
        $pct = [math]::Round(($i / $WaveTargets.Count) * 100, 1)
        Write-Progress -Activity 'Updating Defender Definitions' `
            -Status "Processing $i of $($WaveTargets.Count): $comp" `
            -PercentComplete $pct

        $r = Invoke-DefenderUpdate `
            -Computer            $comp `
            -AvailableByArch     $AvailableByArch `
            -ForcedArchitecture  $Architecture `
            -TempFolderOnTarget  $TempFolderOnTarget `
            -WhatIfMode          ([bool]$WhatIfMode) `
            -LogSharePath        $LogSharePath `
            -WinRmCredential     $HostCredentials[$comp] `
            -DisableIPv6         $DisableIPv6 `
            -LibPaths            @($LibInvokeDefenderRemote, $LibGetDefenderHealthProbe)
        $Results.Add($r)
    }
    Write-Progress -Activity 'Done' -Completed
}

    # ---- Tag results from this wave with the wave name ----
    for ($i = $WaveStartIdx; $i -lt $Results.Count; $i++) {
        if (-not $Results[$i].Wave) {
            $Results[$i].Wave = $wave.Name
        }
    }

    # ---- Wave summary ----
    $waveRows  = @()
    if ($Results.Count -gt $WaveStartIdx) {
        $waveRows = @($Results[$WaveStartIdx..($Results.Count - 1)])
    }
    if ($Staged) {
        $byHealth = $waveRows | Group-Object HealthStatus | Sort-Object Name
        $summary  = ($byHealth | ForEach-Object {
            $label = if ([string]::IsNullOrEmpty($_.Name)) { '(no-probe)' } else { $_.Name }
            "$($_.Count) $label"
        }) -join ', '
        if (-not $summary) { $summary = '(no rows)' }
        Write-Log ("Wave '{0}' complete: {1} host(s) — {2}" -f $wave.Name, $waveRows.Count, $summary) 'SUCCESS'
    }

    # ---- Canary gate ----
    if ($wave.IsGate) {
        if ($HealthSettleSeconds -gt 0) {
            Write-Log ("Health settle: pausing {0}s for canary status to stabilize..." -f $HealthSettleSeconds) 'INFO'
            # Heartbeat the settle pause so the operator can see the script
            # is alive while waiting. Tick every 5s (or 1s for the last 10s)
            # to give a tighter countdown near the end. Pure UX — does not
            # affect gate evaluation.
            $settleEnd = (Get-Date).AddSeconds($HealthSettleSeconds)
            while ($true) {
                $remaining = [int][math]::Ceiling(($settleEnd - (Get-Date)).TotalSeconds)
                if ($remaining -le 0) { break }
                $tick = if ($remaining -le 10) { 1 } else { 5 }
                $step = [math]::Min($tick, $remaining)
                Start-Sleep -Seconds $step
                $remaining = [int][math]::Ceiling(($settleEnd - (Get-Date)).TotalSeconds)
                if ($remaining -gt 0) {
                    Write-Host ("  ...settling ({0}s remaining)" -f $remaining) -ForegroundColor DarkGray
                }
            }
        }
        $gate = Test-CanaryGate -WaveResults $waveRows -MaxFailures $MaxCanaryFailures
        Write-Log ("Canary gate : Healthy={0}, Degraded={1}, ProbeFailed={2}, ThreatsDetected={3}, InstallFailed={4} (threshold {5})" `
            -f $gate.HealthyCount, $gate.DegradedCount, $gate.ProbeFailedCount, $gate.ThreatsCount, $gate.InstallFailedCount, $gate.Threshold) 'INFO'
        if ($gate.Pass) {
            Write-Log 'Canary gate : PASS — proceeding with production wave.' 'SUCCESS'
        } else {
            $failedHosts = (@($gate.DegradedHosts) + @($gate.ProbeFailedHosts)) -join ', '
            Write-Log ("Canary gate : HALT — {0} health failure(s) exceeded threshold {1}. Failing hosts: {2}" `
                -f $gate.FailureCount, $gate.Threshold, $failedHosts) 'ERROR'
            $haltReason = "Canary gate halted rollout ($($gate.FailureCount) health failure(s) > threshold $($gate.Threshold))"
            $waveIdx = $Waves.IndexOf($wave)
            for ($wi = ($waveIdx + 1); $wi -lt $Waves.Count; $wi++) {
                foreach ($skip in $Waves[$wi].Computers) {
                    $Results.Add([pscustomobject]@{
                        ComputerName      = $skip
                        Status            = 'Skipped'
                        OldVersion        = ''
                        NewVersion        = ''
                        DurationSec       = 0
                        Details           = $haltReason
                        Attempt           = 0
                        Timeout           = $false
                        HealthStatus      = ''
                        HealthReason      = ''
                        RecentThreatCount = 0
                        Wave              = $Waves[$wi].Name
                    })
                }
            }
            break
        }
    }
}

Write-Host ''
Write-Host '=== Final Results ===' -ForegroundColor Magenta
$finalCols = @('ComputerName')
if ($Staged) { $finalCols += @{n='Wave'; e={ $_.Wave }} }
$finalCols += @(
    'Status',
    @{n='Health';     e={ $_.HealthStatus }},
    @{n='Threats24h'; e={ $_.RecentThreatCount }},
    'OldVersion', 'NewVersion', 'DurationSec',
    @{n='Attempt#'; e={ $_.Attempt }},
    @{n='Timeout?'; e={ $_.Timeout }},
    'Details'
)
$Results | Sort-Object ComputerName | Select-Object $finalCols | Format-Table -AutoSize -Wrap

# ===================================================================
# Version Analytics
# ===================================================================
foreach ($r in $Results) {
    $delta = 'Unknown'
    if ($r.OldVersion -and $r.NewVersion) {
        try {
            $vOld = [version]$r.OldVersion
            $vNew = [version]$r.NewVersion
            # Build delta is only meaningful when the minor version did not change;
            # a minor-version advance resets the build number, making the difference negative and misleading.
            if ($vOld.Minor -eq $vNew.Minor) {
                $delta = $vNew.Build - $vOld.Build
            } else {
                $delta = 'N/A'
            }
        } catch {}
    }
    $r | Add-Member -NotePropertyName Delta -NotePropertyValue $delta -Force
    Write-Log "VersionHistory: $($r.ComputerName) | Old=$($r.OldVersion) | New=$($r.NewVersion) | Delta=$delta" 'INFO'
}

$OldestVersion = ($Results | Where-Object OldVersion |
    Sort-Object { try { [version]$_.OldVersion } catch { [version]'0.0.0.0' } } |
    Select-Object -First 1).OldVersion
$NewestVersion = ($Results | Where-Object NewVersion |
    Sort-Object { try { [version]$_.NewVersion } catch { [version]'0.0.0.0' } } -Descending |
    Select-Object -First 1).NewVersion
$HostsUpdated  = @($Results | Where-Object Status -eq 'Success').Count

# ===================================================================
# Write Reports
# ===================================================================
$TotalDuration = (Get-Date) - $ScriptStartTime
$Stamp         = Get-Date -Format 'yyyyMMdd_HHmmss'
$ReportFile    = Join-Path $ReportPath "DefenderUpdateReport_$Stamp.html"
$CsvFile       = Join-Path $ReportPath "DefenderUpdateReport_$Stamp.csv"

(New-HtmlReport -Data $Results -RunTime $TotalDuration) | Out-File -FilePath $ReportFile -Encoding utf8
$Results | Export-Csv -Path $CsvFile -NoTypeInformation

Write-Log "HTML report   : $ReportFile" 'SUCCESS'
Write-Log "CSV export    : $CsvFile"    'SUCCESS'

# ===================================================================
# Final Summary
# ===================================================================
$successCount  = @($Results | Where-Object Status -eq 'Success').Count
$failCount     = @($Results | Where-Object Status -eq 'Failed').Count
$skipCount     = @($Results | Where-Object Status -eq 'No Update Needed').Count
$excludedCount = @($Results | Where-Object Status -eq 'Excluded').Count
$gateHaltCount = @($Results | Where-Object Status -eq 'Skipped').Count

Write-Log "UPDATE COMPLETE in $($TotalDuration.ToString('hh\:mm\:ss'))" 'HEADER'
$summaryLine = "Success: $successCount  |  Failed: $failCount  |  Skipped: $skipCount  |  Excluded: $excludedCount"
if ($gateHaltCount -gt 0) { $summaryLine += "  |  GateHalt: $gateHaltCount" }
$summaryLine += "  |  Total: $($Results.Count)"
Write-Log $summaryLine 'HEADER'

if ($successCount -gt 0) {
    Write-Log "Oldest version found   : $OldestVersion" 'INFO'
    Write-Log "Newest version applied : $NewestVersion" 'INFO'
    Write-Log "Hosts updated          : $HostsUpdated"  'INFO'
}

# ===================================================================
# Optional Email Notification
# ===================================================================
if ($SendEmail -and $To -and $SmtpServer -and -not $WhatIfMode) {
    $subject = "Defender Update $(Get-Date -f 'yyyy-MM-dd') - $successCount/$($Results.Count) OK | v$AvailableVersionStr"

    # Use System.Net.Mail.SmtpClient directly instead of Send-MailMessage.
    # Send-MailMessage was marked [Obsolete] in PowerShell 7 and emits a
    # WARNING during command resolution — i.e., every script run, even
    # ones that don't actually send email.  SmtpClient ships in .NET and
    # does not emit any such warning at runtime.
    $smtp = $null
    $msg  = $null
    try {
        $smtp = [System.Net.Mail.SmtpClient]::new($SmtpServer, $SmtpPort)
        $smtp.EnableSsl = [bool]$SmtpUseSsl
        if ($SmtpCredential) {
            $smtp.Credentials = $SmtpCredential.GetNetworkCredential()
        }

        # Resolve $ReportFile / $CsvFile to absolute paths BEFORE handing
        # them to .NET.  System.Net.Mail.Attachment::new() resolves relative
        # paths against the .NET process CurrentDirectory (which is the
        # PowerShell launch directory, often C:\WINDOWS\system32 when
        # elevated) — not PowerShell's $PWD.  Send-MailMessage used to
        # handle this internally; SmtpClient does not.
        $reportFull = (Resolve-Path -LiteralPath $ReportFile).ProviderPath
        $csvFull    = (Resolve-Path -LiteralPath $CsvFile).ProviderPath

        $msg = [System.Net.Mail.MailMessage]::new()
        $msg.From = [System.Net.Mail.MailAddress]::new($From)
        foreach ($recipient in $To) { [void]$msg.To.Add($recipient) }
        # MailMessage defaults Body/Subject/Headers encoding to ASCII, which
        # mangles non-ASCII chars (en-dash, em-dash, arrows) in the HTML
        # report to '?'.  Pin everything to UTF-8 to match the report file
        # on disk and the <meta charset="utf-8"> in its <head>.
        $msg.SubjectEncoding = [System.Text.Encoding]::UTF8
        $msg.BodyEncoding    = [System.Text.Encoding]::UTF8
        $msg.HeadersEncoding = [System.Text.Encoding]::UTF8
        $msg.Subject     = $subject
        $msg.Body        = (Get-Content -LiteralPath $reportFull -Raw -Encoding UTF8)
        $msg.IsBodyHtml  = $true
        foreach ($a in @($reportFull, $csvFull)) {
            [void]$msg.Attachments.Add([System.Net.Mail.Attachment]::new($a))
        }

        $smtp.Send($msg)
        Write-Log 'Email notification sent successfully' 'SUCCESS'
    } catch {
        Write-Log "Email failed: $($_.Exception.Message)" 'ERROR'
    } finally {
        if ($msg)  { $msg.Dispose() }
        if ($smtp) { $smtp.Dispose() }
    }
}

# Explicit success exit so $LASTEXITCODE is reliably 0 for callers
# (scheduled tasks, CI). PowerShell scripts that end naturally without
# `exit` retain the previous $LASTEXITCODE, which leads to surprising
# results when a clean run follows a failed one in the same shell.
exit 0

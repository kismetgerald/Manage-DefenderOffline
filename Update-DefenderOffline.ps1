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

    # Endpoint classification
    [ValidateSet('AD','Pattern','Single')]
    [string]$ClassificationMethod,
    [string]$WorkstationPattern,
    [string]$DomainControllerPattern,

    # Path to configuration file. Defaults to .\conf\config.conf relative to the script.
    [string]$ConfigPath
)

# ===================================================================
# Constants
# ===================================================================
$ScriptVersion   = '0.0.6'
$ScriptStartTime = Get-Date
$ScriptDir       = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$HostsFile       = Join-Path $ScriptDir 'hosts.conf'
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
# Administrative Privilege Check
# ===================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'This script requires administrative privileges. Run PowerShell as Administrator.'
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
if (-not $PSBoundParameters.ContainsKey('LogPath')            -and $cfg['LogPath'])            { $LogPath            = $cfg['LogPath'] }
if (-not $PSBoundParameters.ContainsKey('ReportPath')         -and $cfg['ReportPath'])         { $ReportPath         = $cfg['ReportPath'] }
if (-not $PSBoundParameters.ContainsKey('TempFolderOnTarget') -and $cfg['TempFolderOnTarget']) { $TempFolderOnTarget = $cfg['TempFolderOnTarget'] }
if (-not $PSBoundParameters.ContainsKey('LogSharePath')       -and $cfg['LogSharePath'])       { $LogSharePath       = $cfg['LogSharePath'] }
if (-not $PSBoundParameters.ContainsKey('ParallelThreads')    -and $cfg['ParallelThreads'])    { try { $ParallelThreads = [int]$cfg['ParallelThreads'] } catch {} }
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

    if (-not $script:SuppressConsoleOutput -and
        [System.Threading.Thread]::CurrentThread.ManagedThreadId -eq 1) {
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

    # 2. hosts.conf in script directory
    if (Test-Path $HostsFile) {
        $list = Get-Content $HostsFile |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
            ForEach-Object { $_.Trim().ToUpper() }
        Write-Log "Loaded $($list.Count) computers from hosts.conf" 'SUCCESS'
        return $list
    }

    # 3. Active Directory auto-discovery
    Write-Log 'hosts.conf not found – querying Active Directory...' 'WARN'
    try {
        if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $computers = Get-ADComputer `
                -Filter 'OperatingSystem -like "*Windows*" -and Enabled -eq $true' `
                -Properties Name |
                Sort-Object Name |
                Select-Object -ExpandProperty Name
        } else {
            # ADSI fallback (no ActiveDirectory module required)
            $domain   = (Get-CimInstance Win32_ComputerSystem).Domain
            $searcher = [adsisearcher]'(&(objectCategory=computer)(operatingSystem=*Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
            $searcher.SearchRoot = "LDAP://$domain"
            $computers = $searcher.FindAll() |
                ForEach-Object { $_.Properties.name[0] } |
                Sort-Object
        }

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
        return $computers

    } catch {
        Write-Log "AD query failed: $($_.Exception.Message)" 'ERROR'
        throw 'Cannot proceed without a target list. Create hosts.conf manually or use -ComputerName.'
    }
}

# ===================================================================
# Source File Discovery
# Expects: <SourceSharePath>\<YYYYMMDD>\v#.###.###.#\mpam-fe.exe
# ===================================================================
function Get-LatestMpamFile {
    param([string]$Root)

    $files = Get-ChildItem -Path $Root -Recurse -Filter 'mpam-fe.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '(?i)[/\\]_?archive[/\\]' }

    if (-not $files) {
        throw "No mpam-fe.exe files found under '$Root'. " +
              "Expected folder structure: <base>\<YYYYMMDD>\v#.#.#.#\mpam-fe.exe"
    }

    $versioned = foreach ($f in $files) {
        if ($f.Directory.Name -match '^v(\d+\.\d+\.\d+\.\d+)$') {
            [pscustomobject]@{
                File    = $f.FullName
                Version = [version]$Matches[1]
            }
        }
    }

    if (-not $versioned) {
        throw "mpam-fe.exe files were found but none reside in a 'v#.#.#.#' versioned folder. " +
              "Rename the containing folder to match the pattern (e.g. v1.449.681.0)."
    }

    return $versioned | Sort-Object Version -Descending | Select-Object -First 1
}

# ===================================================================
# Endpoint Classification
# ===================================================================
function Get-EndpointClassification {
    param(
        [string[]]$Computers,
        [string]$Method,
        [string]$WsPattern,
        [string]$DcPattern
    )

    $tiers = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Computers) { $tiers[$c] = 'MemberServer' }

    if ($Method -eq 'Single') { return $tiers }

    if ($Method -eq 'AD') {
        try {
            $adMap = [System.Collections.Generic.Dictionary[string,pscustomobject]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
                Import-Module ActiveDirectory -ErrorAction Stop
                Get-ADComputer -Filter 'Enabled -eq $true' `
                    -Properties Name, OperatingSystem, userAccountControl `
                    -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $adMap[$_.Name] = [pscustomobject]@{
                        OS   = $_.OperatingSystem
                        IsDC = ($_.userAccountControl -band 0x2000) -ne 0
                    }
                }
            } else {
                $domain   = (Get-CimInstance Win32_ComputerSystem).Domain
                $searcher = [adsisearcher]'(objectCategory=computer)'
                $searcher.SearchRoot = "LDAP://$domain"
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
        [string]$SourceFile,
        [string]$TempFolderOnTarget,
        [string]$AvailableVersionStr,
        [bool]$WhatIfMode,
        [string]$LogSharePath,
        [System.Management.Automation.PSCredential]$WinRmCredential
    )

    $WarningPreference = 'SilentlyContinue'

    $result = [pscustomobject]@{
        ComputerName = $Computer
        Status       = 'Unknown'
        OldVersion   = ''
        NewVersion   = ''
        DurationSec  = 0
        Details      = ''
        Attempt      = 1
        Timeout      = $false
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
        if (-not (Test-NetConnection -ComputerName $Computer -Port 5985 `
                -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            throw $(if ($pingOk) { 'Online but WinRM (5985) not reachable — may be blocked or disabled' }
                    else          { 'Host offline (no ping response; WinRM 5985 not reachable)' })
        }

        $sessionParams = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
        if ($WinRmCredential) { $sessionParams.Credential = $WinRmCredential }
        $session = New-PSSession @sessionParams

        try {
            # --- Pre-update health check ---
            $svcStatus = Invoke-Command -Session $session -ScriptBlock {
                $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                if ($svc) { $svc.Status.ToString() } else { 'NotFound' }
            }
            if ($svcStatus -ne 'Running') {
                throw "Windows Defender service is not running (Status: $svcStatus)"
            }

            # --- Current version check (pre-transfer) ---
            $currentVerStr = Invoke-Command -Session $session -ScriptBlock {
                try { (Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureVersion }
                catch { $null }
            }
            $result.OldVersion = $currentVerStr

            if ($currentVerStr -and $AvailableVersionStr) {
                try {
                    if ([version]$currentVerStr -ge [version]$AvailableVersionStr) {
                        $result.Status     = 'No Update Needed'
                        $result.NewVersion = $currentVerStr
                        $result.Details    = "Already at v$currentVerStr (available: v$AvailableVersionStr)"
                        return $result
                    }
                } catch {
                    # Version parse failed – proceed with install and let it determine the outcome
                }
            }

            # --- File transfer ---
            $mpamFileName = Split-Path $SourceFile -Leaf
            Invoke-Command -Session $session -ScriptBlock {
                New-Item -Path $using:TempFolderOnTarget -ItemType Directory -Force | Out-Null
            }
            $remoteFile = Join-Path $TempFolderOnTarget $mpamFileName
            Copy-Item -Path $SourceFile -Destination $remoteFile -ToSession $session -Force

            # --- Silent install ---
            $install = Invoke-Command -Session $session -ScriptBlock {
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
            $newVerStr = Invoke-Command -Session $session -ScriptBlock {
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
            Invoke-Command -Session $session -ScriptBlock {
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
# Resolve Targets and Source
# ===================================================================
$TargetComputers = Resolve-TargetComputers
if (-not $TargetComputers -or $TargetComputers.Count -eq 0) {
    Write-Log 'No target computers found. Exiting.' 'ERROR'
    return
}
Write-Log "Will process $($TargetComputers.Count) computers" 'HEADER'

# ===================================================================
# Apply administrative exclusions
# ===================================================================
if ($ExcludeList.Count -gt 0) {
    foreach ($ex in $ExcludeList) {
        if ($TargetComputers -contains $ex) {
            Write-Log "EXCLUDED (administrative): $ex — listed in ExcludeComputers in config.conf" 'WARN'
            $Results.Add([pscustomobject]@{
                ComputerName = $ex
                Status       = 'Excluded'
                OldVersion   = ''
                NewVersion   = ''
                DurationSec  = 0
                Details      = 'Administrative exclusion (ExcludeComputers in config.conf)'
                Attempt      = 0
                Timeout      = $false
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
    -Computers  $TargetComputers `
    -Method     $ClassificationMethod `
    -WsPattern  $WorkstationPattern `
    -DcPattern  $DomainControllerPattern

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

$latest = Get-LatestMpamFile -Root $SourceSharePath
$SourceFile          = $latest.File
$AvailableVersionStr = $latest.Version.ToString()
Write-Log "Latest definition version: v$AvailableVersionStr" 'SUCCESS'
Write-Log "Source file              : $SourceFile" 'INFO'

if (-not (Test-Path $SourceFile)) {
    Write-Log "CRITICAL: Source file is not accessible: $SourceFile" 'ERROR'
    throw 'Source file missing or share not reachable.'
}

# ===================================================================
# Execution Engine
# ===================================================================
$Results = [System.Collections.Generic.List[pscustomobject]]::new()

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
    foreach ($comp in $TargetComputers) {
        $Queue.Enqueue([pscustomobject]@{ Computer = $comp; Attempt = 1; Credential = $HostCredentials[$comp] })
    }

    # Active jobs: keyed by Job.Id
    $ActiveJobs = [System.Collections.Generic.Dictionary[int, hashtable]]::new()

    Write-Log "Executing in PARALLEL mode ($MaxConcurrent concurrent threads)" 'HEADER'

    $script:SuppressConsoleOutput = $true
    $savedWarningPref = $WarningPreference
    $WarningPreference = 'SilentlyContinue'
    $DashTimer  = [System.Diagnostics.Stopwatch]::StartNew()
    $DashAnchor = $null

    while ($Queue.Count -gt 0 -or $ActiveJobs.Count -gt 0) {

        # Dashboard refresh every 5 seconds
        if (-not $DashAnchor) { $DashAnchor = $Host.UI.RawUI.CursorPosition }

        if ($DashTimer.Elapsed.TotalSeconds -ge 5) {
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
                $SourceFile,
                $TempFolderOnTarget,
                $AvailableVersionStr,
                [bool]$WhatIfMode,
                $LogSharePath,
                $item.Credential
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
                })
                Remove-Job $meta.Job -Force -ErrorAction SilentlyContinue
                [void]$ActiveJobs.Remove($id)
            }
        }

        Start-Sleep -Milliseconds 500
    }

    $script:SuppressConsoleOutput = $false
    $WarningPreference = $savedWarningPref
    Write-Host ''
    Write-Host '=== Final Results ===' -ForegroundColor Magenta
    $Results | Sort-Object ComputerName |
        Select-Object ComputerName, Status, OldVersion, NewVersion, DurationSec,
            @{n='Attempt#'; e={ $_.Attempt }},
            @{n='Timeout?'; e={ $_.Timeout }},
            Details |
        Format-Table -AutoSize -Wrap

} else {
    # -----------------------------------------------------------
    # SERIAL MODE  (PS 5.1)
    # -----------------------------------------------------------
    Write-Log 'Executing in SERIAL mode (PowerShell 5.1 detected; upgrade to PS 7+ for parallel)' 'WARN'
    $i = 0
    foreach ($comp in $TargetComputers) {
        $i++
        $pct = [math]::Round(($i / $TargetComputers.Count) * 100, 1)
        Write-Progress -Activity 'Updating Defender Definitions' `
            -Status "Processing $i of $($TargetComputers.Count): $comp" `
            -PercentComplete $pct

        $r = Invoke-DefenderUpdate `
            -Computer            $comp `
            -SourceFile          $SourceFile `
            -TempFolderOnTarget  $TempFolderOnTarget `
            -AvailableVersionStr $AvailableVersionStr `
            -WhatIfMode          ([bool]$WhatIfMode) `
            -LogSharePath        $LogSharePath `
            -WinRmCredential     $HostCredentials[$comp]
        $Results.Add($r)
    }
    Write-Progress -Activity 'Done' -Completed
}

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
  .stat-card     { display: inline-block; padding: 14px 28px; border-radius: 10px; margin: 6px 8px 6px 0;
                   font-size: 1.1em; font-weight: 700; color: #fff; min-width: 120px; text-align: center; }
  .sc-ok         { background: #107c10; }
  .sc-fail       { background: #d13438; }
  .sc-skip       { background: #9c5100; }
  .sc-info       { background: #0078d4; }
  .version-grid  { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin: 16px 0; }
  .vcard         { background: #fff; border-radius: 8px; padding: 16px 20px;
                   box-shadow: 0 2px 8px rgba(0,0,0,.08); }
  .vcard .label  { font-size: .85em; color: #666; margin-bottom: 4px; }
  .vcard .value  { font-size: 1.3em; font-weight: 700; color: #0078d4; }
  .footer        { margin-top: 48px; color: #888; font-size: .85em; text-align: center;
                   border-top: 1px solid #ddd; padding-top: 16px; }
  a              { color: #0078d4; }
</style>
'@

    # Build table rows and inject status badges
    $rows = $Data | Sort-Object ComputerName |
        ConvertTo-Html -Fragment -Property ComputerName, Status, OldVersion, NewVersion, DurationSec, Delta, Attempt, Timeout, Details

    foreach ($i in 0..($rows.Count - 1)) {
        $rows[$i] = $rows[$i] `
            -replace '<td>Success</td>',          '<td><span class="tag success">Success</span></td>' `
            -replace '<td>Failed</td>',           '<td><span class="tag failed">Failed</span></td>' `
            -replace '<td>No Update Needed</td>', '<td><span class="tag skipped">No Update Needed</span></td>' `
            -replace '<td>WhatIf</td>',           '<td><span class="tag whatif">WhatIf</span></td>' `
            -replace '<td>Excluded</td>',         '<td><span class="tag excluded">Excluded</span></td>' `
            -replace '<td>True</td>',             '<td><strong style="color:#d13438">Yes</strong></td>' `
            -replace '<td>False</td>',            '<td>No</td>'
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
    <strong>Available Version:</strong> v$AvailableVersionStr &nbsp;|&nbsp;
    <strong>Source File:</strong> $SourceFile &nbsp;|&nbsp;
    <strong>Total Duration:</strong> $($RunTime.ToString('hh\:mm\:ss'))
  </p>

  <div>
    <span class="stat-card sc-ok">&#x2714; Success<br>$successCount</span>
    <span class="stat-card sc-fail">&#x2718; Failed<br>$failCount</span>
    <span class="stat-card sc-skip">&#x25CB; Skipped<br>$skipCount</span>$(if ($whatifCount   -gt 0) { "`n    <span class='stat-card sc-info'>&#x25C6; WhatIf<br>$whatifCount</span>" })$(if ($excludedCount -gt 0) { "`n    <span class='stat-card' style='background:#6b7280'>&#x2205; Excluded<br>$excludedCount</span>" })
  </div>

  <h2>Fleet Version Summary</h2>
  <div class="version-grid">
    <div class="vcard"><div class="label">Oldest Version Found</div><div class="value">$OldestVersion</div></div>
    <div class="vcard"><div class="label">Newest Version Applied</div><div class="value">$NewestVersion</div></div>
    <div class="vcard"><div class="label">Hosts Updated</div><div class="value">$HostsUpdated</div></div>
  </div>

  <h2>Detailed Results ($($Data.Count) computers)</h2>
  $($rows -join "`n")

  <div class="footer">
    Generated by Update-DefenderOffline.ps1 v$ScriptVersion &nbsp;|&nbsp;
    <a href="file:///$([uri]::EscapeUriString($LogFile.Replace('\','/')))">View Full Log</a>
  </div>
</body>
</html>
"@
}

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

Write-Log "UPDATE COMPLETE in $($TotalDuration.ToString('hh\:mm\:ss'))" 'HEADER'
Write-Log "Success: $successCount  |  Failed: $failCount  |  Skipped: $skipCount  |  Excluded: $excludedCount  |  Total: $($Results.Count)" 'HEADER'

if ($successCount -gt 0) {
    Write-Log "Oldest version found   : $OldestVersion" 'INFO'
    Write-Log "Newest version applied : $NewestVersion" 'INFO'
    Write-Log "Hosts updated          : $HostsUpdated"  'INFO'
}

# ===================================================================
# Optional Email Notification
# ===================================================================
if ($SendEmail -and $To -and $SmtpServer -and -not $WhatIfMode) {
    $subject = "Defender Update $(Get-Date -f 'yyyy-MM-dd') – $successCount/$($Results.Count) OK | v$AvailableVersionStr"
    $mailParams = @{
        From        = $From
        To          = $To
        Subject     = $subject
        Body        = (Get-Content $ReportFile -Raw)
        BodyAsHtml  = $true
        SmtpServer  = $SmtpServer
        Port        = $SmtpPort
        UseSsl      = $SmtpUseSsl
        Attachments = @($ReportFile, $CsvFile)
    }
    if ($SmtpCredential) { $mailParams.Credential = $SmtpCredential }

    try {
        Send-MailMessage @mailParams -ErrorAction Stop
        Write-Log 'Email notification sent successfully' 'SUCCESS'
    } catch {
        Write-Log "Email failed: $($_.Exception.Message)" 'ERROR'
    }
}

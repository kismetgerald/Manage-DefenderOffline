<#
.SYNOPSIS
    Show-DefenderStatus.ps1 – Interactive Windows Forms fleet monitor for Microsoft Defender

.DESCRIPTION
    Opens a live Windows Forms dashboard showing the Microsoft Defender health status of all
    Windows endpoints discovered via hosts.conf, Active Directory, or a manual computer list.

    Queries endpoints in parallel (PS 7+) or serially (PS 5.1) over WinRM and displays
    results in a colour-coded data grid. Supports manual refresh, auto-refresh on a timer,
    and export to CSV or HTML.

    For a headless, service-based dashboard that runs continuously in the background,
    use Start-DefenderDashboard.ps1 (installed via Install-DefenderDashboard.ps1).

.PARAMETER ComputerName
    Manual list of computers to query. Bypasses hosts.conf and AD auto-discovery.

.PARAMETER SourceSharePath
    Base UNC path for the definitions share (same structure as Update-DefenderOffline.ps1).
    Used to determine whether each endpoint's version is current. Optional.
    Example: \\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender

.PARAMETER ParallelThreads
    Maximum concurrent WinRM queries in PS 7+ mode. Range: 1-32. Default: 16.

.PARAMETER TimeoutSeconds
    Per-host WinRM query timeout in seconds. Default: 30.

.EXAMPLE
    # Open GUI using hosts.conf or AD
    .\Show-DefenderStatus.ps1

.EXAMPLE
    # Open GUI with version comparison enabled
    .\Show-DefenderStatus.ps1 -SourceSharePath "\\NAS01\Share\_AVDefinitions\Microsoft_Defender"

.EXAMPLE
    # Open GUI for specific computers only
    .\Show-DefenderStatus.ps1 -ComputerName "WS01","WS02","SRV01"

.PARAMETER Credential
    Single PSCredential used for all WinRM connections. Fallback when no tier-specific
    credential is supplied. Auto-loaded from .\Config\WinRmCredential.xml if present.

.PARAMETER WorkstationCredential
    PSCredential for workstation-tier endpoints. Auto-loaded from .\Config\WorkstationCredential.xml.

.PARAMETER ServerCredential
    PSCredential for member-server-tier endpoints. Auto-loaded from .\Config\ServerCredential.xml.

.PARAMETER DomainControllerCredential
    PSCredential for domain controller endpoints. Auto-loaded from .\Config\DomainControllerCredential.xml.

.PARAMETER SaveCredential
    Interactive helper that saves WinRM credentials (DPAPI-encrypted) to .\Config\. Exits after saving.

.PARAMETER ClassificationMethod
    AD | Pattern | Single. Auto-detected if omitted (AD when domain-joined, Single otherwise).

.PARAMETER WorkstationPattern
    Regex for workstation name matching when ClassificationMethod = Pattern.
    IMPORTANT: Example only — customise for your environment.

.PARAMETER DomainControllerPattern
    Regex for DC name matching when ClassificationMethod = Pattern.
    IMPORTANT: Example only — customise for your environment.

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Requires       : PowerShell 5.1+ (7+ for parallel queries), WinRM on targets (TCP 5985)
    Version        : 0.0.6
    Last Updated   : 2026-05-19
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,

    [string]$SourceSharePath,

    [ValidateRange(1, 32)]
    [int]$ParallelThreads = 16,

    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 30,

    # WinRM credentials
    [pscredential]$Credential,
    [pscredential]$WorkstationCredential,
    [pscredential]$ServerCredential,
    [pscredential]$DomainControllerCredential,

    [switch]$SaveCredential,

    # AD discovery credential (used only for the LDAP bind that reads the
    # computer list; not used for WinRM connections)
    [pscredential]$ADCredential,
    [switch]$SaveADCredential,

    # Restrict AD auto-discovery to one or more OU subtrees. Distinguished-name
    # format; multiple DNs separated by semicolons. Empty = whole-domain search.
    [string]$ADSearchBase,

    [ValidateSet('AD','Pattern','Single')]
    [string]$ClassificationMethod,
    [string]$WorkstationPattern,
    [string]$DomainControllerPattern,

    [bool]$DisableIPv6 = $true,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.16'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$HostsFile     = Join-Path $ScriptDir 'hosts.conf'

# Shared discovery helper used by all three discovery-aware scripts.
$LibGetDefenderComputers = Join-Path $ScriptDir 'lib\Get-DefenderComputers.ps1'
if (Test-Path $LibGetDefenderComputers) { . $LibGetDefenderComputers }

# Single chokepoint for all WinRM execution. Path is also passed into thread
# runspaces (see Invoke-FleetRefresh) so the wrapper is available there too.
$LibInvokeDefenderRemote = Join-Path $ScriptDir 'lib\Invoke-DefenderRemote.ps1'
. $LibInvokeDefenderRemote

# Shared health classifier — same rules used by Update-DefenderOffline so
# the WinForms grid and the dashboard render the same labels for the same
# state.
$LibGetDefenderHealthProbe = Join-Path $ScriptDir 'lib\Get-DefenderHealthProbe.ps1'
. $LibGetDefenderHealthProbe

# ===================================================================
# Credential Helper Mode  (exits after completion)
# ===================================================================
if ($SaveCredential) {
    Write-Host "`n=== WinRM Credential Setup ===" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  [1] Single / management account  (WinRmCredential.xml)'
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
            } else { Write-Host "  Cancelled: $($slot.Label)" -ForegroundColor Yellow }
        } catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red }
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
    Write-Host '  hosts.conf is present and -ComputerName is not used.  Encrypted' -ForegroundColor Gray
    Write-Host '  per-user per-machine (DPAPI). Saved to conf\ADCredential.xml.' -ForegroundColor Gray
    Write-Host ''
    $cfgDir = Join-Path $ScriptDir 'conf'
    if (-not (Test-Path $cfgDir)) { New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null }
    try {
        $cred = Get-Credential -Message 'Enter AD credential (account with read on the domain naming context)'
        if ($cred) {
            $cred | Export-Clixml -Path (Join-Path $cfgDir 'ADCredential.xml') -Force
            Write-Host "  Saved: $(Join-Path $cfgDir 'ADCredential.xml')" -ForegroundColor Green
        } else { Write-Host '  Cancelled.' -ForegroundColor Yellow }
    } catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red }
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
if (-not $PSBoundParameters.ContainsKey('SourceSharePath')         -and $cfg['SourceSharePath'])         { $SourceSharePath         = $cfg['SourceSharePath'] }
if (-not $PSBoundParameters.ContainsKey('ADSearchBase')            -and $cfg['ADSearchBase'])            { $ADSearchBase            = $cfg['ADSearchBase'] }
if (-not $PSBoundParameters.ContainsKey('ParallelThreads')         -and $cfg['ParallelThreads'])         { try { $ParallelThreads = [int]$cfg['ParallelThreads'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('TimeoutSeconds')          -and $cfg['TimeoutSeconds'])          { try { $TimeoutSeconds  = [int]$cfg['TimeoutSeconds']  } catch {} }
if (-not $PSBoundParameters.ContainsKey('ClassificationMethod')    -and $cfg['ClassificationMethod'])    { $ClassificationMethod    = $cfg['ClassificationMethod'] }
if (-not $PSBoundParameters.ContainsKey('WorkstationPattern')      -and $cfg['WorkstationPattern'])      { $WorkstationPattern      = $cfg['WorkstationPattern'] }
if (-not $PSBoundParameters.ContainsKey('DomainControllerPattern') -and $cfg['DomainControllerPattern']) { $DomainControllerPattern = $cfg['DomainControllerPattern'] }
if (-not $PSBoundParameters.ContainsKey('DisableIPv6')              -and $cfg['DisableIPv6'])              { $DisableIPv6 = ($cfg['DisableIPv6'] -match '^(?i)true|1|yes$') }

$ExcludeList = @()
if ($cfg['ExcludeComputers']) {
    $ExcludeList = $cfg['ExcludeComputers'] -split ',' | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ }
}

# ===================================================================
# WinRM Credential Auto-Load
# ===================================================================
$configDir = Join-Path $ScriptDir 'conf'

function Import-SavedCredential ([string]$FileName) {
    $p = Join-Path $configDir $FileName
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        try { return Import-Clixml $p } catch { Write-Warning "Could not load credential from '$p': $($_.Exception.Message)" }
    }
    return $null
}

if (-not $PSBoundParameters.ContainsKey('Credential'))                 { $Credential                = Import-SavedCredential 'WinRmCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('WorkstationCredential'))      { $WorkstationCredential     = Import-SavedCredential 'WorkstationCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('ServerCredential'))           { $ServerCredential          = Import-SavedCredential 'ServerCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('DomainControllerCredential')) { $DomainControllerCredential = Import-SavedCredential 'DomainControllerCredential.xml' }
if (-not $PSBoundParameters.ContainsKey('ADCredential'))               { $ADCredential              = Import-SavedCredential 'ADCredential.xml' }

if (-not $ClassificationMethod) {
    $partOfDomain = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
    $ClassificationMethod = if ($partOfDomain) { 'AD' } else { 'Single' }
}

# ===================================================================
# Target Resolution
# ===================================================================
function Resolve-TargetComputers {
    if ($ComputerName) {
        return $ComputerName | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim().ToUpper() }
    }
    # hosts.conf is skipped when -ADSearchBase is set so a cached snapshot
    # from a previous (possibly differently-scoped) run does not override the
    # operator's explicit AD scope.
    $hostsExists = Test-Path $HostsFile
    if (-not $ADSearchBase -and $hostsExists) {
        return Get-Content $HostsFile |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
            ForEach-Object { $_.Trim().ToUpper() }
    }
    if ($ADSearchBase -and $hostsExists) {
        Write-Host 'Ignoring hosts.conf because ADSearchBase is set; querying AD with that scope.' -ForegroundColor DarkCyan
    }
    if (-not $hostsExists) {
        Write-Warning 'hosts.conf not found – attempting Active Directory auto-discovery...'
    }
    if ($ADCredential) {
        Write-Host "Using saved AD credential for LDAP bind: $($ADCredential.UserName)" -ForegroundColor DarkCyan
    }
    if ($ADSearchBase) {
        Write-Host "Restricting AD discovery to: $ADSearchBase" -ForegroundColor DarkCyan
    }
    try {
        $discovery = Get-DefenderComputers -SearchBase $ADSearchBase -ADCredential $ADCredential
        if (-not $discovery.UsedAdModule) {
            Write-Host 'ActiveDirectory PowerShell module is not installed; used ADSI fallback.' -ForegroundColor DarkCyan
        }
        if ($discovery.WasFiltered) {
            foreach ($s in $discovery.SearchBases) {
                if ($s.Resolved) {
                    Write-Host "  AD search base '$($s.DN)' -> $($s.Count) computer(s)" -ForegroundColor DarkGreen
                } else {
                    Write-Warning "  AD search base '$($s.DN)' could not be resolved: $($s.Error)"
                }
            }
            $resolved = @($discovery.SearchBases | Where-Object Resolved).Count
            if ($resolved -eq 0) {
                throw "All $($discovery.SearchBases.Count) AD search base(s) failed to resolve."
            }
        }
        if (-not $discovery.Computers -or $discovery.Computers.Count -eq 0) {
            throw 'AD discovery returned no computers.'
        }
        return $discovery.Computers
    } catch {
        $adErr = $_.Exception.Message
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

       .\Show-DefenderStatus.ps1 -SaveADCredential
       .\Show-DefenderStatus.ps1                # auto-loads it next run

  2. Create hosts.conf manually next to the script (one hostname per
     line, '#' lines are ignored):

       notepad "$HostsFile"

  3. Pass the targets explicitly on the command line:

       .\Show-DefenderStatus.ps1 -ComputerName SRV01,WS02

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
        # exit (not throw): see comment in Update-DefenderOffline's matching block.
        exit 1
    }
}

# ===================================================================
# Latest Available Version from Share
# ===================================================================
function Get-LatestAvailableVersion {
    param([string]$Root)
    # Returns $null for any failure. "No path configured" stays silent;
    # the caller checks $SourceSharePath separately. All other failures
    # log a distinguishing reason so the operator doesn't have to guess
    # between "path doesn't exist", "permission denied", and "share OK
    # but layout doesn't match".
    if (-not $Root) { return $null }

    try {
        if (-not (Test-Path -LiteralPath $Root -ErrorAction Stop)) {
            Write-Host "Note: SourceSharePath '$Root' is not reachable (path does not exist or current account lacks read access). Version currency check disabled." -ForegroundColor Yellow
            return $null
        }
    } catch {
        Write-Host "Error: accessing SourceSharePath '$Root' failed - $($_.Exception.Message). Version currency check disabled." -ForegroundColor Red
        return $null
    }

    # Supports two layouts (v0.0.8 introduced the per-arch subfolder layout):
    #   Flat (legacy)   : <version>\mpam-fe.exe                  -> parent matches ^v\d+...
    #   Per-arch (new)  : <version>\<arch>\mpam-fe.exe           -> parent is x64/x86/arm64; grandparent is ^v\d+...
    try {
        $versions = Get-ChildItem -LiteralPath $Root -Recurse -Filter 'mpam-fe.exe' -ErrorAction Stop |
            Where-Object { $_.FullName -notmatch '(?i)[/\\]_?archive[/\\]' } |
            ForEach-Object {
                $parent      = $_.Directory.Name
                $grandparent = if ($_.Directory.Parent) { $_.Directory.Parent.Name } else { '' }
                if ($parent -match '^(?i)(x64|x86|arm64)$' -and $grandparent -match '^v(\d+\.\d+\.\d+\.\d+)$') {
                    [version]$Matches[1]
                } elseif ($parent -match '^v(\d+\.\d+\.\d+\.\d+)$') {
                    [version]$Matches[1]
                }
            }
    } catch {
        Write-Host "Error: enumerating SourceSharePath '$Root' failed - $($_.Exception.Message). Version currency check disabled." -ForegroundColor Red
        return $null
    }

    $latest = $versions | Sort-Object -Descending | Select-Object -First 1
    if (-not $latest) {
        Write-Host "Note: SourceSharePath '$Root' contains no 'mpam-fe.exe' matching the expected '<YYYYMMDD>\v#.#.#.#\[arch\]\mpam-fe.exe' structure. Version currency check disabled." -ForegroundColor Yellow
    }
    return $latest
}

# ===================================================================
# Endpoint Classification
# ===================================================================
function Get-EndpointClassification {
    param(
        [string[]]$Computers, [string]$Method, [string]$WsPattern, [string]$DcPattern,
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
                $adParams = @{ Filter = 'Enabled -eq $true'; Properties = 'Name','OperatingSystem','userAccountControl'; ErrorAction = 'SilentlyContinue' }
                if ($ADCredential) { $adParams.Credential = $ADCredential }
                Get-ADComputer @adParams |
                    ForEach-Object { $adMap[$_.Name] = [pscustomobject]@{ OS = $_.OperatingSystem; IsDC = ($_.userAccountControl -band 0x2000) -ne 0 } }
            } else {
                $domain = (Get-CimInstance Win32_ComputerSystem).Domain
                if ($ADCredential) {
                    $de = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$domain", $ADCredential.UserName, $ADCredential.GetNetworkCredential().Password)
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new($de)
                    $searcher.Filter = '(objectCategory=computer)'
                } else {
                    $searcher = [adsisearcher]'(objectCategory=computer)'
                    $searcher.SearchRoot = "LDAP://$domain"
                }
                $searcher.PropertiesToLoad.AddRange(@('name','operatingsystem','userAccountControl'))
                $searcher.PageSize = 1000
                $searcher.FindAll() | ForEach-Object {
                    $n = $_.Properties['name'][0]
                    if ($n) { $adMap[$n] = [pscustomobject]@{ OS = $_.Properties['operatingsystem'][0]; IsDC = ([int]$_.Properties['useraccountcontrol'][0] -band 0x2000) -ne 0 } }
                }
                if ($ADCredential) { $de.Dispose() }
            }
            foreach ($c in $Computers) {
                if ($adMap.ContainsKey($c)) {
                    if ($adMap[$c].IsDC) { $tiers[$c] = 'DomainController' }
                    elseif ($adMap[$c].OS -match 'Windows (10|11|7|8|Vista|XP)') { $tiers[$c] = 'Workstation' }
                }
            }
        } catch { Write-Warning "AD classification failed: $($_.Exception.Message)" }
        return $tiers
    }
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
    return $Credential
}

# ===================================================================
# Per-Host Defender Query
# ===================================================================
function Get-DefenderStatus {
    param(
        [string]$Computer,
        [int]$TimeoutSeconds,
        [string]$AvailableVersionStr,
        [System.Management.Automation.PSCredential]$WinRmCredential,
        [bool]$DisableIPv6 = $true
    )

    $result = [pscustomobject]@{
        ComputerName              = $Computer
        IPv4Address               = ''
        Online                    = $false
        DefenderService           = 'Unknown'
        SignatureVersion          = ''
        AvailableVersion          = $AvailableVersionStr
        VersionStatus             = 'Unknown'
        RealTimeProtection        = 'Unknown'
        AntivirusEnabled          = 'Unknown'
        # Full toggle set surfaced in the Host Details dialog (v0.0.10).
        AmServiceEnabled          = 'Unknown'
        BehaviorMonitorEnabled    = 'Unknown'
        IoavProtectionEnabled     = 'Unknown'
        OnAccessProtectionEnabled = 'Unknown'
        LastQuickScan             = ''
        LastFullScan              = ''
        ThreatCount               = ''
        ThreatList                = @()
        HealthStatus              = ''
        HealthReason              = ''
        QueryDuration             = 0
        Error                     = ''
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Resolve IPv4 once, up front, regardless of reachability strategy —
        # the address surfaces in the grid whether the host is online,
        # offline, or DNS-known-but-unreachable. The DisableIPv6 reachability
        # path reuses this lookup to avoid a duplicate DNS hit.
        $ipv4 = $null
        try {
            $ipv4 = [System.Net.Dns]::GetHostAddresses($Computer) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                Select-Object -First 1
            if ($ipv4) { $result.IPv4Address = $ipv4.IPAddressToString }
        } catch {}

        # Reachability check.  When DisableIPv6 is set (LAN default), connect
        # directly to the IPv4 we already resolved — avoids the ~21s TCP
        # timeout that Test-NetConnection eats on IPv6 ULA addresses
        # advertised in DNS but not actually routed.
        $reachable = $false
        if ($DisableIPv6) {
            if ($ipv4) {
                try {
                    $client = [System.Net.Sockets.TcpClient]::new()
                    $task   = $client.ConnectAsync($ipv4, 5985)
                    $reachable = $task.Wait(3000) -and -not $task.IsFaulted -and $client.Connected
                    try { $client.Close() } catch {}
                } catch { $reachable = $false }
            }
        } else {
            $reachable = [bool](Test-NetConnection -ComputerName $Computer -Port 5985 `
                -InformationLevel Quiet -WarningAction SilentlyContinue)
        }
        if (-not $reachable) {
            $result.Error = 'WinRM not reachable'
            return $result
        }

        $sessionParams = @{ ComputerName = $Computer }
        if ($WinRmCredential) { $sessionParams.Credential = $WinRmCredential }
        $session = New-DefenderRemoteSession @sessionParams
        try {
            $data = Invoke-DefenderRemote -Session $session -ScriptBlock {
                $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                $mp  = $null
                try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
                # Per-threat detail for the Host Details dialog. Get-MpThreat
                # is the catalog of threat types ever seen — it doesn't reliably
                # populate InitialDetectionTime / Resources for long-quarantined
                # PUA items. Get-MpThreatDetection has the per-event timestamps
                # and resource paths, so we cross-reference both: ThreatID -> Name
                # from the catalog, plus the most recent detection event's time
                # and resources from MpThreatDetection. One row per distinct
                # ThreatID so ThreatCount matches the rendered grid.
                $threats = @()
                if ($mp) {
                    $catalog = @{}
                    foreach ($t in (Get-MpThreat -ErrorAction SilentlyContinue)) {
                        $catalog[[int64]$t.ThreatID] = [string]$t.ThreatName
                    }
                    $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
                    $threats = @($detections | Group-Object ThreatID | ForEach-Object {
                        $latest = $_.Group | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
                        $id     = [int64]$_.Name
                        [pscustomobject]@{
                            ThreatName           = if ($catalog.ContainsKey($id)) { $catalog[$id] } else { "ThreatID $id" }
                            ThreatID             = $id
                            InitialDetectionTime = $latest.InitialDetectionTime
                            Resources            = if ($latest.Resources) { [string]($latest.Resources -join '; ') } else { '' }
                        }
                    } | Sort-Object InitialDetectionTime -Descending)
                }
                [pscustomobject]@{
                    # Stringify the ServiceController.Status enum so consumers
                    # render 'Running' rather than the deserialized object form.
                    SvcStatus            = if ($svc) { [string]$svc.Status } else { 'NotFound' }
                    SignatureVersion     = if ($mp) { $mp.AntivirusSignatureVersion }   else { $null }
                    RealTimeProtection   = if ($mp) { $mp.RealTimeProtectionEnabled }  else { $null }
                    AMServiceEnabled     = if ($mp) { $mp.AMServiceEnabled }            else { $null }
                    AntivirusEnabled     = if ($mp) { $mp.AntivirusEnabled }            else { $null }
                    BehaviorMonitor      = if ($mp) { $mp.BehaviorMonitorEnabled }      else { $null }
                    IoavProtection       = if ($mp) { $mp.IoavProtectionEnabled }       else { $null }
                    OnAccessProtection   = if ($mp) { $mp.OnAccessProtectionEnabled }   else { $null }
                    LastQuickScan        = if ($mp) { $mp.QuickScanStartTime }          else { $null }
                    LastFullScan         = if ($mp) { $mp.FullScanStartTime }           else { $null }
                    ThreatCount          = $threats.Count
                    ThreatList           = $threats
                }
            }

            $result.Online                    = $true
            $result.DefenderService           = $data.SvcStatus
            $result.SignatureVersion          = $data.SignatureVersion
            $result.RealTimeProtection        = if ($null -ne $data.RealTimeProtection) { $data.RealTimeProtection.ToString() } else { 'Unknown' }
            $result.AntivirusEnabled          = if ($null -ne $data.AntivirusEnabled)   { $data.AntivirusEnabled.ToString() }   else { 'Unknown' }
            $result.AmServiceEnabled          = if ($null -ne $data.AMServiceEnabled)   { $data.AMServiceEnabled.ToString() }   else { 'Unknown' }
            $result.BehaviorMonitorEnabled    = if ($null -ne $data.BehaviorMonitor)    { $data.BehaviorMonitor.ToString() }    else { 'Unknown' }
            $result.IoavProtectionEnabled     = if ($null -ne $data.IoavProtection)     { $data.IoavProtection.ToString() }     else { 'Unknown' }
            $result.OnAccessProtectionEnabled = if ($null -ne $data.OnAccessProtection) { $data.OnAccessProtection.ToString() } else { 'Unknown' }
            $result.LastQuickScan             = if ($data.LastQuickScan) { $data.LastQuickScan.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
            $result.LastFullScan              = if ($data.LastFullScan)  { $data.LastFullScan.ToString('yyyy-MM-dd HH:mm') }  else { 'Never' }
            $result.ThreatCount               = if ($null -ne $data.ThreatCount) { $data.ThreatCount.ToString() } else { 'Unknown' }
            $result.ThreatList                = @($data.ThreatList)

            # Classify via the shared helper if Get-MpComputerStatus returned
            # the full toggle set. If any toggle is $null (Defender service
            # stopped or service errored), HealthStatus stays empty and the
            # operator sees the legacy fields instead.
            if ($null -ne $data.RealTimeProtection -and
                $null -ne $data.AMServiceEnabled  -and
                $null -ne $data.AntivirusEnabled  -and
                $null -ne $data.BehaviorMonitor   -and
                $null -ne $data.IoavProtection    -and
                $null -ne $data.OnAccessProtection) {
                $cls = Get-DefenderHealthClassification `
                    -RealTimeProtectionEnabled  ([bool]$data.RealTimeProtection) `
                    -AntimalwareServiceEnabled  ([bool]$data.AMServiceEnabled)   `
                    -AntivirusEnabled           ([bool]$data.AntivirusEnabled)   `
                    -BehaviorMonitorEnabled     ([bool]$data.BehaviorMonitor)    `
                    -IoavProtectionEnabled      ([bool]$data.IoavProtection)     `
                    -OnAccessProtectionEnabled  ([bool]$data.OnAccessProtection) `
                    -RecentThreatCount          ([int]($data.ThreatCount ?? 0))
                $result.HealthStatus = $cls.OverallStatus
                $result.HealthReason = if ($cls.StatusReason) { $cls.StatusReason } else { '' }
            }

            if ($result.SignatureVersion -and $AvailableVersionStr) {
                try {
                    # Three-way compare so hosts that received defs from
                    # another channel (cloud, manual, lingering MECM) — or
                    # a stale share — surface as 'Ahead' instead of being
                    # silently bucketed with 'Current'. Ahead is informational,
                    # not an error; the detail string is written to .Error so
                    # it shows in the GUI's Error/Detail column and the Host
                    # Details modal's Error/Detail section.
                    $cmp = ([version]$result.SignatureVersion).CompareTo([version]$AvailableVersionStr)
                    if     ($cmp -lt 0) { $result.VersionStatus = 'Outdated' }
                    elseif ($cmp -gt 0) {
                        $result.VersionStatus = 'Ahead'
                        $result.Error         = "Newer than share (available: v$AvailableVersionStr)"
                    }
                    else { $result.VersionStatus = 'Current' }
                } catch { $result.VersionStatus = 'Unknown' }
            } elseif ($result.SignatureVersion) {
                $result.VersionStatus = 'Unknown'
            }

        } finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
    } catch {
        $result.Error = ($_.Exception.Message -replace "`r`n", ' ').Trim()
    } finally {
        $sw.Stop()
        $result.QueryDuration = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
    return $result
}

# ===================================================================
# HTML Builder  (used by the Export HTML button)
# ===================================================================
function ConvertTo-StatusHtml {
    param(
        [object[]]$Data,
        [string]$AvailableVersionStr,
        [datetime]$AsOf
    )

    $onlineCount  = @($Data | Where-Object Online).Count
    $offlineCount = $Data.Count - $onlineCount
    $outdated     = @($Data | Where-Object VersionStatus -eq 'Outdated').Count
    $rtOff        = @($Data | Where-Object { $_.RealTimeProtection -eq 'False' -and $_.Online }).Count

    $rows = foreach ($r in $Data | Sort-Object ComputerName) {
        # Mirror the grid's pill logic: prefer the shared health classifier
        # when present, fall back to the legacy RT/AV check otherwise.
        $status = if (-not $r.Online) { 'Offline' }
                  elseif ($r.VersionStatus -eq 'Outdated') { 'Outdated' }
                  elseif ($r.HealthStatus) { $r.HealthStatus }
                  elseif ($r.RealTimeProtection -eq 'False' -or $r.AntivirusEnabled -eq 'False') { 'Degraded' }
                  else { 'Healthy' }
        $cls = switch ($status) {
            'Offline'         { 'offline' }
            'Outdated'        { 'skipped' }
            'Degraded'        { 'warn'    }
            'ThreatsDetected' { 'failed'  }
            default           { 'success' }
        }
        $tip = if ($r.Error) {
            " title=`"$($r.Error -replace '"','&quot;' -replace '<','&lt;' -replace '>','&gt;')`""
        } else { '' }

        "<tr>
          <td$tip>$($r.ComputerName)</td>
          <td>$($r.IPv4Address)</td>
          <td><span class='tag $cls'>$status</span></td>
          <td>$($r.SignatureVersion)</td>
          <td>$($r.AvailableVersion)</td>
          <td>$($r.VersionStatus)</td>
          <td>$($r.RealTimeProtection)</td>
          <td>$($r.AntivirusEnabled)</td>
          <td>$($r.LastQuickScan)</td>
          <td>$($r.ThreatCount)</td>
          <td>$($r.QueryDuration)s</td>
        </tr>"
    }

    $css = @'
<style>
* { box-sizing: border-box; }
body { font-family: "Segoe UI", Arial, sans-serif; margin: 40px; background: #f5f7fa; color: #333; }
h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
p  { line-height: 1.6; }
.stats { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin: 20px 0; }
.stat { padding: 14px 20px; border-radius: 8px; text-align: center; font-weight: 700; font-size: 1.1em; color: #fff; }
.s1 { background: #107c10; } .s2 { background: #d13438; } .s3 { background: #fab387; } .s4 { background: #f9e2af; color: #333; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden;
        box-shadow: 0 4px 12px rgba(0,0,0,.1); margin-top: 20px; }
th { background: #0078d4; color: #fff; padding: 13px 12px; text-align: left; font-weight: 600; }
td { padding: 11px 12px; border-bottom: 1px solid #e8e8e8; }
tr:last-child td { border-bottom: none; }
tr:nth-child(even) td { background: #f9f9f9; }
.tag { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: .82em; font-weight: 700; color: #fff; }
.success { background: #107c10; } .failed { background: #d13438; }
.skipped { background: #9c5100; } .warn { background: #b8860b; }
.offline { background: #4b5563; }
.footer { margin-top: 40px; color: #888; font-size: .85em; text-align: center; border-top: 1px solid #ddd; padding-top: 16px; }
</style>
'@

    @"
<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8">
<title>Microsoft Defender Antivirus – Fleet Status – $(Get-Date -f 'yyyy-MM-dd')</title>$css</head>
<body>
<h1>Microsoft Defender Antivirus – Fleet Status</h1>
<p><strong>Generated:</strong> $($AsOf.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;|&nbsp;
<strong>Available Version:</strong> $(if ($AvailableVersionStr) { "v$AvailableVersionStr" } else { 'N/A' }) &nbsp;|&nbsp;
<strong>Total Systems:</strong> $($Data.Count)</p>
<div class="stats">
  <div class="stat s1">Online<br>$onlineCount</div>
  <div class="stat s2">Offline<br>$offlineCount</div>
  <div class="stat s3">Outdated<br>$outdated</div>
  <div class="stat s4">RT Off<br>$rtOff</div>
</div>
<table>
<thead><tr>
  <th>Computer</th><th>IPv4</th><th>Status</th><th>Installed Version</th><th>Available Version</th>
  <th>Currency</th><th>RT Protection</th><th>AV Enabled</th><th>Last Quick Scan</th>
  <th>Threats</th><th>Query Time</th>
</tr></thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>
<div class="footer">Show-DefenderStatus.ps1 v$ScriptVersion</div>
</body></html>
"@
}

# ===================================================================
# Main-flow guard
#
# When this script is dot-sourced (Pester or interactive testing of
# individual functions), return here so the setup and Forms GUI below
# do not run.  Direct invocation continues normally.
# ===================================================================
if ($MyInvocation.InvocationName -eq '.') { return }

# ===================================================================
# Setup
# ===================================================================
$TargetComputers = @(Resolve-TargetComputers)
if ($ExcludeList.Count -gt 0) {
    $excluded = @($TargetComputers | Where-Object { $ExcludeList -contains $_ })
    if ($excluded.Count -gt 0) {
        Write-Host "Excluding $($excluded.Count) computer(s) per config.conf ExcludeComputers: $($excluded -join ', ')" -ForegroundColor Yellow
    }
    $TargetComputers = @($TargetComputers | Where-Object { $ExcludeList -notcontains $_ })
}
if ($TargetComputers.Count -eq 0) { throw 'No target computers found.' }

$EndpointTiers = Get-EndpointClassification `
    -Computers    $TargetComputers `
    -Method       $ClassificationMethod `
    -WsPattern    $WorkstationPattern `
    -DcPattern    $DomainControllerPattern `
    -ADCredential $ADCredential

$HostCredentials = [System.Collections.Generic.Dictionary[string,System.Management.Automation.PSCredential]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($c in $TargetComputers) {
    $HostCredentials[$c] = Resolve-WinRmCredential -Tier ($EndpointTiers.ContainsKey($c) ? $EndpointTiers[$c] : 'MemberServer')
}

$AvailableVersion    = Get-LatestAvailableVersion -Root $SourceSharePath
$AvailableVersionStr = if ($AvailableVersion) { $AvailableVersion.ToString() } else { '' }

if ($AvailableVersionStr) {
    Write-Host "Latest available version: v$AvailableVersionStr" -ForegroundColor Cyan
} elseif (-not $SourceSharePath) {
    # Only log the "no path configured" branch here. All other failure
    # branches (path unreachable, permission denied, layout mismatch)
    # log their distinct reason from inside Get-LatestAvailableVersion.
    Write-Host 'Note: No -SourceSharePath provided; version currency check disabled.' -ForegroundColor Yellow
}

# ===================================================================
# Windows Forms GUI
# ===================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Win32 EM_SETCUEBANNER for placeholder ("hint") text on the filter
# TextBox — Windows Forms doesn't expose a managed equivalent on the
# .NET Framework runtime PowerShell uses. The cue draws when the
# control is empty and unfocused; passes through normally on focus.
if (-not ('CueBannerHelper' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CueBannerHelper {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, string lParam);
    private const int EM_SETCUEBANNER = 0x1501;
    public static void SetCue(IntPtr hWnd, string text) {
        SendMessage(hWnd, EM_SETCUEBANNER, 0, text);
    }
}
'@
}

#region Colour palette  (mirrors the HTML report exported by Export HTML)
$clrPrimary       = [System.Drawing.Color]::FromArgb(0,   120, 212)  # #0078d4 Fluent blue
$clrBackground    = [System.Drawing.Color]::FromArgb(245, 247, 250)  # #f5f7fa page bg
$clrCardBg        = [System.Drawing.Color]::White                    # #ffffff
$clrToolbarBg     = [System.Drawing.Color]::FromArgb(248, 250, 252)  # very light gray
$clrTextDark      = [System.Drawing.Color]::FromArgb(51,  51,  51)   # #333333
$clrTextMuted     = [System.Drawing.Color]::FromArgb(136, 136, 136)  # #888888
$clrBorder        = [System.Drawing.Color]::FromArgb(232, 232, 232)  # #e8e8e8
$clrRowAlt        = [System.Drawing.Color]::FromArgb(249, 249, 249)  # #f9f9f9
$clrSelection     = [System.Drawing.Color]::FromArgb(220, 233, 248)  # selection tint
# Status colours (match HTML .tag classes and stat cards)
$clrSuccess       = [System.Drawing.Color]::FromArgb(16,  124, 16)   # #107c10 - Healthy/Online
$clrError         = [System.Drawing.Color]::FromArgb(209, 52,  56)   # #d13438 - ThreatsDetected (critical — Defender flagged threats on this host)
$clrOutdatedPill  = [System.Drawing.Color]::FromArgb(156, 81,  0)    # #9c5100 - Outdated pill (HTML .skipped)
$clrWarn          = [System.Drawing.Color]::FromArgb(184, 134, 11)   # #b8860b - Degraded pill (HTML .warn)
$clrOffline       = [System.Drawing.Color]::FromArgb(75,  85,  99)   # #4b5563 - Offline (no comms — informational, not a critical signal)
$clrOutdatedCard  = [System.Drawing.Color]::FromArgb(245, 158, 11)   # #f59e0b - Outdated stat card (amber per ISSM round-1 feedback)
$clrRtOffCard     = [System.Drawing.Color]::FromArgb(249, 226, 175)  # #f9e2af - RT Off stat card (HTML .s4)
$clrWhite         = [System.Drawing.Color]::White
#endregion

# Defender shield-with-checkmark icon, rendered via GDI+ so we don't ship
# a binary PNG/ICO file in the bundle. Shape mirrors the inline SVG used
# by the dashboard's /favicon.svg endpoint; curves are approximated as
# straight segments at icon size where the difference is invisible. Used
# for both the in-form header PictureBox and the Windows title-bar Icon.
function script:New-DefenderShieldBitmap {
    param([int]$Size = 24)
    $bmp = [System.Drawing.Bitmap]::new($Size, $Size)
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = $Size / 24.0
    $shieldPts = [System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new(12 * $s,  2 * $s),
        [System.Drawing.PointF]::new( 4 * $s,  5 * $s),
        [System.Drawing.PointF]::new( 4 * $s, 11 * $s),
        [System.Drawing.PointF]::new( 6 * $s, 17 * $s),
        [System.Drawing.PointF]::new(12 * $s, 22 * $s),
        [System.Drawing.PointF]::new(18 * $s, 17 * $s),
        [System.Drawing.PointF]::new(20 * $s, 11 * $s),
        [System.Drawing.PointF]::new(20 * $s,  5 * $s)
    )
    $shieldBrush = [System.Drawing.SolidBrush]::new($clrPrimary)
    $g.FillPolygon($shieldBrush, $shieldPts)
    $shieldBrush.Dispose()

    $checkPen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, [single](2.2 * $s))
    $checkPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $checkPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $checkPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $checkPts = [System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new( 8.5 * $s, 12.0 * $s),
        [System.Drawing.PointF]::new(11.0 * $s, 14.5 * $s),
        [System.Drawing.PointF]::new(15.5 * $s,  9.5 * $s)
    )
    $g.DrawLines($checkPen, $checkPts)
    $checkPen.Dispose()
    $g.Dispose()
    return $bmp
}

#region Form
$form               = [System.Windows.Forms.Form]::new()
$form.Text          = "Microsoft Defender Fleet Monitor v$ScriptVersion"
$form.Size          = [System.Drawing.Size]::new(1440, 860)
$form.MinimumSize   = [System.Drawing.Size]::new(960, 540)
$form.StartPosition = 'CenterScreen'
$form.BackColor     = $clrBackground
$form.ForeColor     = $clrTextDark
$form.Font          = [System.Drawing.Font]::new('Segoe UI', 9)

# Windows title-bar icon. Render at 32x32 then convert via GetHicon —
# Windows scales the result for taskbar / alt-tab / title bar as needed.
try {
    $iconBmp = New-DefenderShieldBitmap -Size 32
    $hIcon   = $iconBmp.GetHicon()
    $form.Icon = [System.Drawing.Icon]::FromHandle($hIcon)
    $iconBmp.Dispose()
} catch {}
#endregion

#region Header  (matches HTML <h1> with blue underline + status subline)
$pnlHeader           = [System.Windows.Forms.Panel]::new()
$pnlHeader.Dock      = 'Top'
$pnlHeader.Height    = 84
$pnlHeader.BackColor = $clrCardBg

# Shield icon to the left of the title. Same shape as the dashboard's
# /favicon.svg so the two UIs look like siblings rather than cousins.
$picTitleIcon            = [System.Windows.Forms.PictureBox]::new()
$picTitleIcon.Image      = New-DefenderShieldBitmap -Size 32
$picTitleIcon.SizeMode   = 'Zoom'
$picTitleIcon.Size       = [System.Drawing.Size]::new(32, 32)
$picTitleIcon.Location   = [System.Drawing.Point]::new(20, 12)
$picTitleIcon.BackColor  = $clrCardBg

$lblTitle            = [System.Windows.Forms.Label]::new()
$lblTitle.Text       = 'Microsoft Defender Antivirus – Fleet Status'
$lblTitle.Font       = [System.Drawing.Font]::new('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor  = $clrPrimary
$lblTitle.AutoSize   = $true
$lblTitle.Location   = [System.Drawing.Point]::new(60, 14)

$lblInfo             = [System.Windows.Forms.Label]::new()
$lblInfo.Text        = if ($AvailableVersionStr) {
    "Available Version: v$AvailableVersionStr     Total Systems: $($TargetComputers.Count)"
} else {
    "Available Version: N/A (no share specified)     Total Systems: $($TargetComputers.Count)"
}
$lblInfo.Font        = [System.Drawing.Font]::new('Segoe UI', 9)
$lblInfo.ForeColor   = $clrTextMuted
$lblInfo.AutoSize    = $true
$lblInfo.Location    = [System.Drawing.Point]::new(60, 50)

# 3px blue accent line at the bottom (matches HTML h1 border-bottom)
$pnlHeaderAccent           = [System.Windows.Forms.Panel]::new()
$pnlHeaderAccent.Dock      = 'Bottom'
$pnlHeaderAccent.Height    = 3
$pnlHeaderAccent.BackColor = $clrPrimary

$pnlHeader.Controls.AddRange(@($picTitleIcon, $lblTitle, $lblInfo, $pnlHeaderAccent))
#endregion

#region Stat cards  (4 cards mirroring the HTML stats grid)
$pnlStats              = [System.Windows.Forms.TableLayoutPanel]::new()
$pnlStats.Dock         = 'Top'
$pnlStats.Height       = 96
$pnlStats.ColumnCount  = 4
$pnlStats.RowCount     = 1
$pnlStats.BackColor    = $clrBackground
$pnlStats.Padding      = [System.Windows.Forms.Padding]::new(16, 10, 16, 8)
for ($c = 0; $c -lt 4; $c++) {
    $pnlStats.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 25)) | Out-Null
}

function New-StatCard ([string]$Label, [System.Drawing.Color]$Bg, [System.Drawing.Color]$Fg) {
    # TableLayoutPanel with two rows gives deterministic row heights — using
    # Dock=Fill + Dock=Bottom on plain Panel was clipping the label.
    $card             = [System.Windows.Forms.TableLayoutPanel]::new()
    $card.Dock        = 'Fill'
    $card.Margin      = [System.Windows.Forms.Padding]::new(6, 0, 6, 0)
    $card.BackColor   = $Bg
    $card.RowCount    = 2
    $card.ColumnCount = 1
    [void]$card.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 100))
    [void]$card.RowStyles.Add([System.Windows.Forms.RowStyle]::new('Percent', 65))
    [void]$card.RowStyles.Add([System.Windows.Forms.RowStyle]::new('Percent', 35))

    # Non-zero top/bottom margins leave a small strip of the card's
    # BackColor visible at the top + bottom edges — needed so the
    # selection paint (inset border) has somewhere to render.
    $lblNumber           = [System.Windows.Forms.Label]::new()
    $lblNumber.Text      = '—'
    $lblNumber.Dock      = 'Fill'
    $lblNumber.TextAlign = 'BottomCenter'
    $lblNumber.Font      = [System.Drawing.Font]::new('Segoe UI', 22, [System.Drawing.FontStyle]::Bold)
    $lblNumber.ForeColor = $Fg
    $lblNumber.Margin    = [System.Windows.Forms.Padding]::new(3, 4, 3, 0)

    $lblLabel            = [System.Windows.Forms.Label]::new()
    $lblLabel.Text       = $Label
    $lblLabel.Dock       = 'Fill'
    $lblLabel.TextAlign  = 'TopCenter'
    $lblLabel.Font       = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblLabel.ForeColor  = $Fg
    $lblLabel.Margin     = [System.Windows.Forms.Padding]::new(3, 0, 3, 4)

    $card.Controls.Add($lblNumber, 0, 0)
    $card.Controls.Add($lblLabel,  0, 1)
    return @{ Panel = $card; Number = $lblNumber }
}

$statOnline   = New-StatCard 'ONLINE'   $clrSuccess      $clrWhite
$statOffline  = New-StatCard 'OFFLINE'  $clrOffline      $clrWhite
$statOutdated = New-StatCard 'OUTDATED' $clrOutdatedCard $clrTextDark
$statRtOff    = New-StatCard 'RT OFF'   $clrRtOffCard    $clrTextDark

# Make each card clickable so it acts as a quick filter (matches the
# HTML report's clickable stat badges).  The card's Tag stores the
# filter key ('Online' / 'Offline' / 'Outdated' / 'RTOff').  A Paint
# handler draws a 3px primary-blue outline when the card is the
# currently-selected filter.
#
# [ordered] is significant: the GUI paints the cards in the order this
# dictionary enumerates its keys (see foreach below). An unordered
# Hashtable would scramble the visual order, producing inconsistency
# with the dashboard's stat-card layout.
$cardMap = [ordered]@{
    'Online'   = $statOnline
    'Offline'  = $statOffline
    'Outdated' = $statOutdated
    'RTOff'    = $statRtOff
}
$script:CardFilter = $null   # null | 'Online' | 'Offline' | 'Outdated' | 'RTOff'

# Capture each card's resting BackColor so we can swap to a darker shade
# when the card is the active filter, and restore it when deselected.
$script:CardOriginalColors = @{}
foreach ($k in $cardMap.Keys) { $script:CardOriginalColors[$k] = $cardMap[$k].Panel.BackColor }

function script:Get-DarkerShade {
    param([System.Drawing.Color]$c, [double]$f = 0.72)
    [System.Drawing.Color]::FromArgb($c.A,
        [int]([Math]::Max(0, $c.R * $f)),
        [int]([Math]::Max(0, $c.G * $f)),
        [int]([Math]::Max(0, $c.B * $f)))
}

$cardClickHandler = {
    $key = $this.Tag
    if (-not $key) { return }
    $script:CardFilter = if ($script:CardFilter -eq $key) { $null } else { $key }
    foreach ($k in $cardMap.Keys) {
        $card = $cardMap[$k].Panel
        $orig = $script:CardOriginalColors[$k]
        $card.BackColor = if ($script:CardFilter -eq $k) { Get-DarkerShade $orig } else { $orig }
        $card.Invalidate()
    }
    if ($script:AllResults) { Update-Grid }
}

# Sunken-edge effect: a semi-transparent dark inset border on the
# selected card, drawn into the small strips left by the label margins.
$cardPaintHandler = {
    param($src, $e)
    if ($script:CardFilter -and $src.Tag -eq $script:CardFilter) {
        $darkPen = [System.Drawing.Pen]::new(
            [System.Drawing.Color]::FromArgb(140, 0, 0, 0), 2)
        $e.Graphics.DrawRectangle($darkPen, 0, 0, $src.Width - 1, $src.Height - 1)
        $darkPen.Dispose()
    }
}

foreach ($key in $cardMap.Keys) {
    $cardPanel = $cardMap[$key].Panel
    $cardPanel.Tag    = $key
    $cardPanel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $cardPanel.add_Click($cardClickHandler)
    $cardPanel.add_Paint($cardPaintHandler)
    # Child labels intercept the click; route them to the same handler
    foreach ($child in $cardPanel.Controls) {
        $child.Cursor = [System.Windows.Forms.Cursors]::Hand
        $child.Tag    = $key
        $child.add_Click($cardClickHandler)
    }
    $pnlStats.Controls.Add($cardPanel)
}
#endregion

#region Toolbar
# Status color legend — a small row of colored chips below the stat cards
# matching the dashboard's legend. Reuses the existing palette so the
# colors track any future palette change without a second source of truth.
$pnlLegend                = [System.Windows.Forms.FlowLayoutPanel]::new()
$pnlLegend.Dock           = 'Top'
$pnlLegend.AutoSize       = $true
$pnlLegend.FlowDirection  = 'LeftToRight'
$pnlLegend.WrapContents   = $false
$pnlLegend.BackColor      = $clrBackground
$pnlLegend.Padding        = [System.Windows.Forms.Padding]::new(20, 4, 16, 4)

function script:Add-LegendChip {
    param(
        [System.Windows.Forms.FlowLayoutPanel]$Parent,
        [string]$Label,
        [System.Drawing.Color]$Color
    )
    $chip               = [System.Windows.Forms.FlowLayoutPanel]::new()
    $chip.AutoSize      = $true
    $chip.FlowDirection = 'LeftToRight'
    $chip.WrapContents  = $false
    $chip.Margin        = [System.Windows.Forms.Padding]::new(0, 0, 14, 0)
    $chip.Padding       = [System.Windows.Forms.Padding]::new(0)

    $dot               = [System.Windows.Forms.Panel]::new()
    $dot.Size          = [System.Drawing.Size]::new(10, 10)
    $dot.BackColor     = $Color
    $dot.Margin        = [System.Windows.Forms.Padding]::new(0, 5, 6, 0)
    [void]$chip.Controls.Add($dot)

    $txt               = [System.Windows.Forms.Label]::new()
    $txt.Text          = $Label
    $txt.AutoSize      = $true
    $txt.ForeColor     = $clrTextMuted
    $txt.Margin        = [System.Windows.Forms.Padding]::new(0, 1, 0, 0)
    [void]$chip.Controls.Add($txt)

    [void]$Parent.Controls.Add($chip)
}

$lblLegendTitle           = [System.Windows.Forms.Label]::new()
$lblLegendTitle.Text      = 'Status:'
$lblLegendTitle.AutoSize  = $true
$lblLegendTitle.ForeColor = $clrTextDark
$lblLegendTitle.Font      = [System.Drawing.Font]::new(
    $lblLegendTitle.Font.FontFamily, $lblLegendTitle.Font.Size, [System.Drawing.FontStyle]::Bold)
$lblLegendTitle.Margin    = [System.Windows.Forms.Padding]::new(0, 1, 12, 0)
[void]$pnlLegend.Controls.Add($lblLegendTitle)

Add-LegendChip -Parent $pnlLegend -Label 'Healthy'         -Color $clrSuccess
Add-LegendChip -Parent $pnlLegend -Label 'Outdated'        -Color $clrOutdatedPill
Add-LegendChip -Parent $pnlLegend -Label 'ThreatsDetected' -Color $clrError
Add-LegendChip -Parent $pnlLegend -Label 'Degraded'        -Color $clrWarn
Add-LegendChip -Parent $pnlLegend -Label 'Offline'         -Color $clrOffline

$pnlToolbar           = [System.Windows.Forms.FlowLayoutPanel]::new()
$pnlToolbar.Dock      = 'Top'
$pnlToolbar.Height    = 46
$pnlToolbar.Padding   = [System.Windows.Forms.Padding]::new(20, 9, 20, 0)
$pnlToolbar.BackColor = $clrToolbarBg

function New-ToolButton ([string]$Text) {
    $b             = [System.Windows.Forms.Button]::new()
    $b.Text        = $Text
    $b.AutoSize    = $true
    $b.Height      = 28
    $b.Padding     = [System.Windows.Forms.Padding]::new(12, 0, 12, 0)
    $b.FlatStyle   = 'Flat'
    $b.BackColor   = $clrPrimary
    $b.ForeColor   = $clrWhite
    $b.Font        = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $b.FlatAppearance.BorderSize = 0
    $b.Cursor      = [System.Windows.Forms.Cursors]::Hand
    $b.Margin      = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)
    return $b
}

$btnRefresh     = New-ToolButton '⟳  Refresh Now'
$btnExportCsv   = New-ToolButton '⬇  Export CSV'
$btnExportHtml  = New-ToolButton '⬇  Export HTML'

$sep            = [System.Windows.Forms.Label]::new()
$sep.Width      = 24

$lblFilter      = [System.Windows.Forms.Label]::new()
$lblFilter.Text = 'Filter:'
$lblFilter.AutoSize  = $true
$lblFilter.ForeColor = $clrTextDark
$lblFilter.Padding   = [System.Windows.Forms.Padding]::new(0, 7, 4, 0)

$txtFilter             = [System.Windows.Forms.TextBox]::new()
$txtFilter.Width       = 220
$txtFilter.Height      = 24
$txtFilter.Margin      = [System.Windows.Forms.Padding]::new(2, 5, 0, 0)
$txtFilter.BorderStyle = 'FixedSingle'

# Set the placeholder ("hint") text once the Win32 handle exists. Wires
# via HandleCreated rather than after-the-fact so the cue is in place
# the first time the textbox renders, matching the dashboard's HTML
# placeholder behaviour.
$txtFilter.add_HandleCreated({
    [CueBannerHelper]::SetCue($txtFilter.Handle, 'Filter by computer name…')
})

$chkAuto             = [System.Windows.Forms.CheckBox]::new()
$chkAuto.Text        = 'Auto-refresh (5 min)'
$chkAuto.AutoSize    = $true
$chkAuto.ForeColor   = $clrTextDark
$chkAuto.Padding     = [System.Windows.Forms.Padding]::new(12, 7, 0, 0)

$lblCountdown            = [System.Windows.Forms.Label]::new()
$lblCountdown.Text       = ''
$lblCountdown.AutoSize   = $true
$lblCountdown.ForeColor  = $clrTextMuted
# Top padding tuned to match the checkbox text baseline (the checkbox
# glyph centers its text a few px higher than a bare Label would).
$lblCountdown.Padding    = [System.Windows.Forms.Padding]::new(6, 9, 0, 0)
$lblCountdown.Font       = [System.Drawing.Font]::new('Segoe UI', 9)

$pnlToolbar.Controls.AddRange(@($btnRefresh, $btnExportCsv, $btnExportHtml, $sep, $lblFilter, $txtFilter, $chkAuto, $lblCountdown))
#endregion

#region Status bar
$statusStrip            = [System.Windows.Forms.StatusStrip]::new()
$statusStrip.BackColor  = $clrToolbarBg
$statusStrip.SizingGrip = $false
$statusLabel            = [System.Windows.Forms.ToolStripStatusLabel]::new()
$statusLabel.Text       = "Ready – $($TargetComputers.Count) computers loaded"
$statusLabel.ForeColor  = $clrTextDark
$statusStrip.Items.Add($statusLabel) | Out-Null

# Right-aligned discoverability hint for the Host Details modal. The
# modal is reachable via double-click or right-click → View Details,
# but neither surface is visible without the user trying. Status-strip
# hint is always on screen, costs no toolbar real estate, and matches
# the precedent set by file-explorer-style "Tip:" affordances.
$statusHint            = [System.Windows.Forms.ToolStripStatusLabel]::new()
$statusHint.Text       = 'Tip: Double-click a row (or right-click → View Details) to see full host detail'
$statusHint.ForeColor  = $clrTextMuted
$statusHint.Alignment  = [System.Windows.Forms.ToolStripItemAlignment]::Right
$statusStrip.Items.Add($statusHint) | Out-Null
#endregion

#region Host Details dialog  (right-click / double-click drill-in)
# Modal dialog showing the full Defender state for one host. Surfaces fields
# that aren't in the grid (HealthReason, all 6 protection toggles, last full
# scan, full Error text) plus the per-threat list collected by Get-MpThreat.

function Show-HostDetailsDialog {
    param([Parameter(Mandatory)][pscustomobject]$HostData)

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text          = "Host Details – $($HostData.ComputerName)"
    $dlg.Size          = [System.Drawing.Size]::new(760, 720)
    $dlg.StartPosition = 'CenterParent'
    $dlg.MinimumSize   = [System.Drawing.Size]::new(640, 480)
    $dlg.BackColor     = $clrBackground
    $dlg.Font          = [System.Drawing.Font]::new('Segoe UI', 9)
    $dlg.ShowIcon      = $false

    # Recompute the same Status pill text the grid uses so the dialog matches
    # what the operator just clicked on.
    $pillStatus = if (-not $HostData.Online) { 'Offline' }
                  elseif ($HostData.VersionStatus -eq 'Outdated') { 'Outdated' }
                  elseif ($HostData.HealthStatus) { $HostData.HealthStatus }
                  elseif ($HostData.RealTimeProtection -eq 'False' -or $HostData.AntivirusEnabled -eq 'False') { 'Degraded' }
                  else { 'Healthy' }
    $pillBg = switch ($pillStatus) {
        'Healthy'         { $clrSuccess }
        'Offline'         { $clrOffline }
        'Outdated'        { $clrOutdatedPill }
        'Degraded'        { $clrWarn }
        'ThreatsDetected' { $clrError }
        default           { [System.Drawing.Color]::Gray }
    }

    # Root scroll container so longer error text or threat lists don't get
    # clipped on small dialog sizes.
    $scroll = [System.Windows.Forms.Panel]::new()
    $scroll.Dock       = 'Fill'
    $scroll.AutoScroll = $true
    $scroll.Padding    = [System.Windows.Forms.Padding]::new(16)

    $stack = [System.Windows.Forms.FlowLayoutPanel]::new()
    $stack.Dock          = 'Top'
    $stack.AutoSize      = $true
    $stack.FlowDirection = 'TopDown'
    $stack.WrapContents  = $false
    $stack.Width         = 700

    # ---- Helpers ---------------------------------------------------------
    $addSectionHeader = {
        param([string]$Text)
        $lbl = [System.Windows.Forms.Label]::new()
        $lbl.Text      = $Text.ToUpper()
        $lbl.Font      = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $lbl.ForeColor = $clrPrimary
        $lbl.AutoSize  = $true
        $lbl.Margin    = [System.Windows.Forms.Padding]::new(0, 14, 0, 4)
        $stack.Controls.Add($lbl)
    }
    $addKeyValue = {
        param([string]$Key, [string]$Value, [System.Drawing.Color]$ValueColor = $clrTextDark)
        $row = [System.Windows.Forms.TableLayoutPanel]::new()
        $row.ColumnCount = 2
        $row.RowCount    = 1
        $row.AutoSize    = $true
        $row.Width       = 680
        $row.Margin      = [System.Windows.Forms.Padding]::new(8, 1, 0, 1)
        [void]$row.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Absolute', 200))
        [void]$row.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 100))

        $lblK = [System.Windows.Forms.Label]::new()
        $lblK.Text      = "$Key :"
        $lblK.AutoSize  = $true
        $lblK.ForeColor = $clrTextMuted
        $row.Controls.Add($lblK, 0, 0)

        $lblV = [System.Windows.Forms.Label]::new()
        $lblV.Text      = if ([string]::IsNullOrWhiteSpace($Value)) { '—' } else { $Value }
        $lblV.AutoSize  = $true
        $lblV.ForeColor = $ValueColor
        $row.Controls.Add($lblV, 1, 0)

        $stack.Controls.Add($row)
    }
    $boolColor = {
        param($Value)
        if ($Value -eq 'True')  { return $clrSuccess }
        if ($Value -eq 'False') { return $clrError }
        return $clrTextDark
    }

    # ---- Identity --------------------------------------------------------
    & $addSectionHeader 'Identity'
    & $addKeyValue 'Computer'        $HostData.ComputerName
    & $addKeyValue 'IPv4 address'    $(if ($HostData.IPv4Address) { $HostData.IPv4Address } else { '-' })
    & $addKeyValue 'Online'          $(if ($HostData.Online) { 'Yes' } else { 'No' }) (& $boolColor ($HostData.Online.ToString()))
    & $addKeyValue 'Query duration'  ("{0}s" -f $HostData.QueryDuration)

    # ---- Health classification (with pill) -------------------------------
    & $addSectionHeader 'Health Classification'
    $pillRow = [System.Windows.Forms.TableLayoutPanel]::new()
    $pillRow.ColumnCount = 2
    $pillRow.RowCount    = 1
    $pillRow.AutoSize    = $true
    $pillRow.Width       = 680
    $pillRow.Margin      = [System.Windows.Forms.Padding]::new(8, 1, 0, 1)
    [void]$pillRow.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Absolute', 200))
    [void]$pillRow.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 100))
    $lblPillKey = [System.Windows.Forms.Label]::new()
    $lblPillKey.Text = 'Status :'; $lblPillKey.AutoSize = $true; $lblPillKey.ForeColor = $clrTextMuted
    $pillRow.Controls.Add($lblPillKey, 0, 0)
    $pill = [System.Windows.Forms.Label]::new()
    $pill.Text      = $pillStatus
    $pill.AutoSize  = $true
    $pill.BackColor = $pillBg
    $pill.ForeColor = $clrWhite
    $pill.Font      = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $pill.Padding   = [System.Windows.Forms.Padding]::new(10, 3, 10, 3)
    $pillRow.Controls.Add($pill, 1, 0)
    $stack.Controls.Add($pillRow)
    & $addKeyValue 'Reason' $(if ($HostData.HealthReason) { $HostData.HealthReason } else { '—' })

    # ---- Defender state --------------------------------------------------
    & $addSectionHeader 'Defender State'
    & $addKeyValue 'WinDefend service' $HostData.DefenderService
    $verLabel = $HostData.SignatureVersion
    if ($HostData.VersionStatus) { $verLabel = "$($HostData.SignatureVersion) ($($HostData.VersionStatus))" }
    & $addKeyValue 'Signature version' $verLabel
    & $addKeyValue 'Available version' $HostData.AvailableVersion
    & $addKeyValue 'Real-time protection'  $HostData.RealTimeProtection         (& $boolColor $HostData.RealTimeProtection)
    & $addKeyValue 'Antimalware service'   $HostData.AmServiceEnabled           (& $boolColor $HostData.AmServiceEnabled)
    & $addKeyValue 'Antivirus engine'      $HostData.AntivirusEnabled           (& $boolColor $HostData.AntivirusEnabled)
    & $addKeyValue 'Behavior monitor'      $HostData.BehaviorMonitorEnabled     (& $boolColor $HostData.BehaviorMonitorEnabled)
    & $addKeyValue 'IOAV protection'       $HostData.IoavProtectionEnabled      (& $boolColor $HostData.IoavProtectionEnabled)
    & $addKeyValue 'On-access protection'  $HostData.OnAccessProtectionEnabled  (& $boolColor $HostData.OnAccessProtectionEnabled)

    # ---- Scans -----------------------------------------------------------
    & $addSectionHeader 'Scans'
    & $addKeyValue 'Last quick scan' $HostData.LastQuickScan
    & $addKeyValue 'Last full scan'  $HostData.LastFullScan

    # ---- Threats ---------------------------------------------------------
    $threatList = @($HostData.ThreatList)
    & $addSectionHeader ("Threats ({0})" -f $threatList.Count)
    if ($threatList.Count -gt 0) {
        $threatGrid = [System.Windows.Forms.DataGridView]::new()
        $threatGrid.Width                 = 680
        $threatGrid.Height                = [Math]::Min(40 + 24 * $threatList.Count, 240)
        $threatGrid.Margin                = [System.Windows.Forms.Padding]::new(8, 4, 0, 4)
        $threatGrid.ReadOnly              = $true
        $threatGrid.AllowUserToAddRows    = $false
        $threatGrid.AllowUserToResizeRows = $false
        $threatGrid.RowHeadersVisible     = $false
        $threatGrid.BackgroundColor       = $clrCardBg
        $threatGrid.BorderStyle           = 'FixedSingle'
        $threatGrid.AutoSizeColumnsMode   = 'Fill'
        $threatGrid.SelectionMode         = 'FullRowSelect'
        $threatGrid.EnableHeadersVisualStyles = $false
        $threatGrid.ColumnHeadersDefaultCellStyle.BackColor = $clrPrimary
        $threatGrid.ColumnHeadersDefaultCellStyle.ForeColor = $clrWhite
        $threatGrid.ColumnHeadersDefaultCellStyle.Font      = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $threatGrid.RowTemplate.Height                      = 22

        foreach ($c in @(
            @{ Name='Threat';    Weight=22 },
            @{ Name='Detected';  Weight=18 },
            @{ Name='Resource';  Weight=60 }
        )) {
            $col = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
            $col.HeaderText = $c.Name
            $col.FillWeight = $c.Weight
            $col.ReadOnly   = $true
            [void]$threatGrid.Columns.Add($col)
        }

        foreach ($t in $threatList) {
            $detected = if ($t.InitialDetectionTime) { $t.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm') } else { '—' }
            [void]$threatGrid.Rows.Add($t.ThreatName, $detected, $t.Resources)
        }
        $stack.Controls.Add($threatGrid)
    } else {
        & $addKeyValue 'No threats reported' ''
    }

    # ---- Error / Detail --------------------------------------------------
    if ($HostData.Error) {
        & $addSectionHeader 'Error / Detail'
        $errLbl = [System.Windows.Forms.Label]::new()
        $errLbl.Text      = $HostData.Error
        $errLbl.AutoSize  = $true
        $errLbl.MaximumSize = [System.Drawing.Size]::new(680, 0)
        $errLbl.ForeColor = $clrError
        $errLbl.Margin    = [System.Windows.Forms.Padding]::new(8, 1, 0, 1)
        $stack.Controls.Add($errLbl)
    }

    $scroll.Controls.Add($stack)

    # ---- Bottom button bar ----------------------------------------------
    $btnPanel = [System.Windows.Forms.Panel]::new()
    $btnPanel.Dock      = 'Bottom'
    $btnPanel.Height    = 48
    $btnPanel.BackColor = $clrToolbarBg
    $btnClose = [System.Windows.Forms.Button]::new()
    $btnClose.Text         = 'Close'
    $btnClose.Width        = 100
    $btnClose.Height       = 30
    $btnClose.Top          = 9
    $btnClose.Left         = $dlg.ClientSize.Width - $btnClose.Width - 16
    $btnClose.Anchor       = 'Top,Right'
    $btnClose.DialogResult = 'OK'
    $btnPanel.Controls.Add($btnClose)
    $dlg.AcceptButton = $btnClose
    $dlg.CancelButton = $btnClose

    $dlg.Controls.Add($scroll)
    $dlg.Controls.Add($btnPanel)
    [void]$dlg.ShowDialog()
    $dlg.Dispose()
}
#endregion

#region DataGridView
$grid                       = [System.Windows.Forms.DataGridView]::new()
$grid.Dock                  = 'Fill'
$grid.ReadOnly              = $true
$grid.AllowUserToAddRows    = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.MultiSelect           = $false
$grid.SelectionMode         = 'FullRowSelect'
$grid.RowHeadersVisible     = $false
$grid.AutoSizeColumnsMode   = 'None'
$grid.BackgroundColor       = $clrCardBg
$grid.BorderStyle           = 'None'
$grid.CellBorderStyle       = 'SingleHorizontal'
$grid.GridColor             = $clrBorder
$grid.EnableHeadersVisualStyles               = $false
$grid.ColumnHeadersDefaultCellStyle.BackColor = $clrPrimary
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $clrWhite
$grid.ColumnHeadersDefaultCellStyle.Font      = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$grid.ColumnHeadersDefaultCellStyle.Alignment = 'MiddleLeft'
$grid.ColumnHeadersDefaultCellStyle.Padding   = [System.Windows.Forms.Padding]::new(10, 0, 0, 0)
$grid.ColumnHeadersHeightSizeMode             = 'DisableResizing'
$grid.ColumnHeadersHeight                     = 38
$grid.DefaultCellStyle.BackColor              = $clrCardBg
$grid.DefaultCellStyle.ForeColor              = $clrTextDark
$grid.DefaultCellStyle.SelectionBackColor     = $clrSelection
$grid.DefaultCellStyle.SelectionForeColor     = $clrTextDark
$grid.DefaultCellStyle.Padding                = [System.Windows.Forms.Padding]::new(8, 0, 4, 0)
$grid.AlternatingRowsDefaultCellStyle.BackColor = $clrRowAlt
$grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = $clrSelection
$grid.RowTemplate.Height                      = 32

# 12 columns matching the HTML report (Online dropped — Status pill covers it; Error / Detail kept as GUI extra).
# IPv4 sits between Computer and Status per ISSM feedback so operators can
# triage by hostname or address without drilling into Host Details.
# AutoSizeColumnsMode = Fill on the grid + per-column FillWeight makes every
# column resize proportionally with the form, and MinimumWidth keeps content
# legible when the window is narrowed.
$grid.AutoSizeColumnsMode = 'Fill'
$colDefs = @(
    @{ Name = 'Computer';          Weight = 14; Min = 110 }
    @{ Name = 'IPv4';              Weight =  9; Min =  95 }
    @{ Name = 'Status';            Weight = 11; Min = 110 }
    @{ Name = 'Installed Version'; Weight = 12; Min = 110 }
    @{ Name = 'Available Version'; Weight = 12; Min = 110 }
    @{ Name = 'Currency';          Weight =  9; Min =  85 }
    @{ Name = 'RT Protection';     Weight = 10; Min =  90 }
    @{ Name = 'AV Enabled';        Weight =  9; Min =  85 }
    @{ Name = 'Last Quick Scan';   Weight = 14; Min = 130 }
    @{ Name = 'Threats';           Weight =  6; Min =  60 }
    @{ Name = 'Query Time';        Weight =  8; Min =  75 }
    @{ Name = 'Error / Detail';    Weight = 22; Min = 180 }
)
foreach ($cd in $colDefs) {
    $col              = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $col.HeaderText   = $cd.Name
    $col.SortMode     = 'Automatic'
    $col.AutoSizeMode = 'Fill'
    $col.FillWeight   = $cd.Weight
    $col.MinimumWidth = $cd.Min
    [void]$grid.Columns.Add($col)
}

# Custom-paint the Status column as a rounded pill, matching the HTML report's .tag styling.
$grid.add_CellPainting({
    param($src, $e)
    # Status pill custom-paint lives in column index 2 (was 1 before the
    # IPv4 column inserted itself between Computer and Status in v0.0.16).
    if ($e.RowIndex -lt 0 -or $e.ColumnIndex -ne 2) { return }
    $statusText = "$($e.Value)"
    if (-not $statusText) { return }

    $pillBg = switch ($statusText) {
        'Healthy'         { $clrSuccess }
        'Offline'         { $clrOffline }
        'Outdated'        { $clrOutdatedPill }
        'Degraded'        { $clrWarn }
        'ThreatsDetected' { $clrError }
        default           { [System.Drawing.Color]::Gray }
    }
    $pillFg = $clrWhite

    # Cell background — respect alternating row tint and selection
    $isSelected = ($e.State -band [System.Windows.Forms.DataGridViewElementStates]::Selected) -ne 0
    $cellBg = if ($isSelected) { $clrSelection }
              elseif ($e.RowIndex % 2 -eq 1) { $clrRowAlt }
              else { $clrCardBg }
    $bgBrush = [System.Drawing.SolidBrush]::new($cellBg)
    $e.Graphics.FillRectangle($bgBrush, $e.CellBounds)
    $bgBrush.Dispose()

    # Bottom cell border to match the rest of the grid
    $borderPen = [System.Drawing.Pen]::new($clrBorder)
    $e.Graphics.DrawLine($borderPen,
        $e.CellBounds.Left, $e.CellBounds.Bottom - 1,
        $e.CellBounds.Right, $e.CellBounds.Bottom - 1)
    $borderPen.Dispose()

    # Rounded pill
    $padX = 14; $padY = 6
    $pill = [System.Drawing.Rectangle]::new(
        $e.CellBounds.X + $padX,
        $e.CellBounds.Y + $padY,
        $e.CellBounds.Width - 2 * $padX,
        $e.CellBounds.Height - 2 * $padY)
    $r    = [Math]::Min([int]($pill.Height / 2), 12)
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $path.AddArc($pill.X,            $pill.Y,            $r * 2, $r * 2, 180, 90)
    $path.AddArc($pill.Right - $r*2, $pill.Y,            $r * 2, $r * 2, 270, 90)
    $path.AddArc($pill.Right - $r*2, $pill.Bottom - $r*2,$r * 2, $r * 2,   0, 90)
    $path.AddArc($pill.X,            $pill.Bottom - $r*2,$r * 2, $r * 2,  90, 90)
    $path.CloseFigure()

    $prevSmoothing = $e.Graphics.SmoothingMode
    $e.Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $fillBrush = [System.Drawing.SolidBrush]::new($pillBg)
    $e.Graphics.FillPath($fillBrush, $path)
    $fillBrush.Dispose()

    $sf            = [System.Drawing.StringFormat]::new()
    $sf.Alignment  = 'Center'
    $sf.LineAlignment = 'Center'
    $pillFont      = [System.Drawing.Font]::new('Segoe UI', 8, [System.Drawing.FontStyle]::Bold)
    $textBrush     = [System.Drawing.SolidBrush]::new($pillFg)
    $e.Graphics.DrawString($statusText, $pillFont, $textBrush, [System.Drawing.RectangleF]$pill, $sf)
    $textBrush.Dispose()
    $pillFont.Dispose()
    $sf.Dispose()
    $path.Dispose()

    $e.Graphics.SmoothingMode = $prevSmoothing
    $e.Handled = $true
})

# Right-click + double-click → Host Details drill-in dialog.
# Grid filtering is non-destructive (only changes which rows are displayed),
# so we look up the per-host record from $script:AllResults by ComputerName
# rather than relying on the visible row index.
$ctxMenu  = [System.Windows.Forms.ContextMenuStrip]::new()
$ctxView  = $ctxMenu.Items.Add('View Details…')
$grid.ContextMenuStrip = $ctxMenu

$openDetails = {
    param([int]$RowIndex)
    if ($RowIndex -lt 0 -or $RowIndex -ge $grid.Rows.Count) { return }
    $comp = $grid.Rows[$RowIndex].Cells[0].Value
    if (-not $comp) { return }
    $rec = $script:AllResults | Where-Object { $_.ComputerName -eq $comp } | Select-Object -First 1
    if ($rec) { Show-HostDetailsDialog -HostData $rec }
}

# Right-click on a row should select it before the context menu fires so the
# menu acts on the row under the cursor (matches standard Explorer behaviour).
$grid.add_CellMouseDown({
    param($src, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0) {
        $grid.ClearSelection()
        $grid.Rows[$e.RowIndex].Selected = $true
    }
})

$ctxView.add_Click({
    if ($grid.SelectedRows.Count -gt 0) { & $openDetails $grid.SelectedRows[0].Index }
})

$grid.add_CellDoubleClick({
    param($src, $e)
    & $openDetails $e.RowIndex
})
#endregion

#region Refresh overlay  (covers the grid area during a query with a marquee)
$pnlOverlay              = [System.Windows.Forms.TableLayoutPanel]::new()
$pnlOverlay.Dock         = 'Fill'
$pnlOverlay.BackColor    = $clrCardBg
$pnlOverlay.Visible      = $false
$pnlOverlay.RowCount     = 3
$pnlOverlay.ColumnCount  = 3
[void]$pnlOverlay.RowStyles.Add([System.Windows.Forms.RowStyle]::new('Percent', 50))
[void]$pnlOverlay.RowStyles.Add([System.Windows.Forms.RowStyle]::new('AutoSize'))
[void]$pnlOverlay.RowStyles.Add([System.Windows.Forms.RowStyle]::new('Percent', 50))
[void]$pnlOverlay.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 50))
[void]$pnlOverlay.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('AutoSize'))
[void]$pnlOverlay.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 50))

$pnlOverlayContent              = [System.Windows.Forms.FlowLayoutPanel]::new()
$pnlOverlayContent.FlowDirection = 'TopDown'
$pnlOverlayContent.AutoSize     = $true
$pnlOverlayContent.AutoSizeMode = 'GrowAndShrink'
$pnlOverlayContent.WrapContents = $false
$pnlOverlayContent.BackColor    = $clrCardBg

$lblOverlayTitle           = [System.Windows.Forms.Label]::new()
$lblOverlayTitle.Text      = 'Querying endpoints…'
$lblOverlayTitle.Font      = [System.Drawing.Font]::new('Segoe UI', 16, [System.Drawing.FontStyle]::Regular)
$lblOverlayTitle.ForeColor = $clrPrimary
$lblOverlayTitle.AutoSize  = $true
$lblOverlayTitle.Anchor    = 'None'
$lblOverlayTitle.Margin    = [System.Windows.Forms.Padding]::new(0, 0, 0, 14)
$lblOverlayTitle.TextAlign = 'MiddleCenter'

$lblOverlaySub             = [System.Windows.Forms.Label]::new()
$lblOverlaySub.Text        = ''
$lblOverlaySub.Font        = [System.Drawing.Font]::new('Segoe UI', 9)
$lblOverlaySub.ForeColor   = $clrTextMuted
$lblOverlaySub.AutoSize    = $true
$lblOverlaySub.Anchor      = 'None'
$lblOverlaySub.Margin      = [System.Windows.Forms.Padding]::new(0, 0, 0, 10)
$lblOverlaySub.TextAlign   = 'MiddleCenter'

$pgOverlay                       = [System.Windows.Forms.ProgressBar]::new()
$pgOverlay.Style                 = 'Marquee'
$pgOverlay.MarqueeAnimationSpeed = 30
$pgOverlay.Width                 = 360
$pgOverlay.Height                = 8
$pgOverlay.Anchor                = 'None'

$pnlOverlayContent.Controls.Add($lblOverlayTitle)
$pnlOverlayContent.Controls.Add($lblOverlaySub)
$pnlOverlayContent.Controls.Add($pgOverlay)
$pnlOverlay.Controls.Add($pnlOverlayContent, 1, 1)
#endregion

# Add controls in the order that yields the visual top→bottom layout
# (Header → Stats → Toolbar → Grid → StatusBar).  WinForms stacks the
# LAST-added Dock=Top control closest to the edge, so add top-docked
# panels in reverse visual order.  The overlay is added AFTER the grid
# so it sits in front of the grid in z-order when made visible.
$form.Controls.Add($grid)         # Dock=Fill (added first, behind the overlay)
$form.Controls.Add($pnlOverlay)   # Dock=Fill (front of grid; hidden by default)
$form.Controls.Add($pnlToolbar)   # Dock=Top — lowest of the top-docked
$form.Controls.Add($pnlLegend)    # Dock=Top — above the toolbar
$form.Controls.Add($pnlStats)     # Dock=Top — above the legend
$form.Controls.Add($pnlHeader)    # Dock=Top — very top
$form.Controls.Add($statusStrip)  # Dock=Bottom

$script:AllResults = $null
$script:FilterText = ''

function Update-Grid {
    $data = $script:AllResults
    if (-not $data) { return }

    $filter = $script:FilterText.Trim()
    if ($filter) { $data = @($data | Where-Object { $_.ComputerName -like "*$filter*" }) }

    if ($script:CardFilter) {
        # Capture $_ in $item BEFORE switch — inside switch, $_ rebinds
        # to the switch's matched value, not the pipeline item.
        $data = @($data | Where-Object {
            $item = $_
            switch ($script:CardFilter) {
                'Online'   { $item.Online -eq $true }
                'Offline'  { $item.Online -eq $false }
                'Outdated' { $item.VersionStatus -eq 'Outdated' }
                'RTOff'    { $item.RealTimeProtection -eq 'False' -and $item.Online -eq $true }
            }
        })
    }

    $grid.SuspendLayout()
    $grid.Rows.Clear()

    foreach ($r in $data | Sort-Object ComputerName) {
        # Status pill priority:
        #   Offline   - no WinRM, nothing else matters
        #   Outdated  - reachable but signature is behind the available version
        #   else      - defer to the shared health classifier (Healthy /
        #               Degraded / ThreatsDetected). Falls back to the legacy
        #               RT/AV check if HealthStatus is empty (Defender service
        #               down, or older script versions in mixed-test scenarios).
        $status = if (-not $r.Online) { 'Offline' }
                  elseif ($r.VersionStatus -eq 'Outdated') { 'Outdated' }
                  elseif ($r.HealthStatus) { $r.HealthStatus }
                  elseif ($r.RealTimeProtection -eq 'False' -or $r.AntivirusEnabled -eq 'False') { 'Degraded' }
                  else { 'Healthy' }

        $idx = $grid.Rows.Add(
            $r.ComputerName,
            $r.IPv4Address,
            $status,
            $r.SignatureVersion,
            $r.AvailableVersion,
            $r.VersionStatus,
            $r.RealTimeProtection,
            $r.AntivirusEnabled,
            $r.LastQuickScan,
            $r.ThreatCount,
            "$($r.QueryDuration)s",
            $r.Error
        )
        # Pill badge in the Status column carries the visual indicator;
        # mute the text on offline rows so they read as deactivated.
        if ($status -eq 'Offline') {
            $grid.Rows[$idx].DefaultCellStyle.ForeColor = $clrTextMuted
        }
    }
    $grid.ResumeLayout()

    $all      = $script:AllResults
    $online   = @($all | Where-Object Online).Count
    $offline  = $all.Count - $online
    $outdated = @($all | Where-Object VersionStatus -eq 'Outdated').Count
    $rtOff    = @($all | Where-Object { $_.RealTimeProtection -eq 'False' -and $_.Online }).Count

    $statOnline.Number.Text   = "$online"
    $statOffline.Number.Text  = "$offline"
    $statOutdated.Number.Text = "$outdated"
    $statRtOff.Number.Text    = "$rtOff"

    # Refresh the info subline with the latest total
    $lblInfo.Text = if ($AvailableVersionStr) {
        "Available Version: v$AvailableVersionStr     Total Systems: $($all.Count)"
    } else {
        "Available Version: N/A (no share specified)     Total Systems: $($all.Count)"
    }
}

#region Query engine  (Start-ThreadJob + polling Timer — avoids BackgroundWorker runspace issue)
$script:QueryJob       = $null
$script:QueryStartTime = [datetime]::MinValue

$pollTimer          = [System.Windows.Forms.Timer]::new()
$pollTimer.Interval = 250   # fires on UI thread — safe for Forms controls

$pollTimer.add_Tick({
    if (-not $script:QueryJob) { $pollTimer.Stop(); return }

    if ($script:QueryJob.State -in 'Running','NotStarted') {
        $secs  = [math]::Round(([datetime]::UtcNow - $script:QueryStartTime).TotalSeconds)
        $done  = if ($script:CompletedHosts) { $script:CompletedHosts.Count } else { 0 }
        $total = $TargetComputers.Count
        $statusLabel.Text   = "Querying endpoints… $done of $total  (${secs}s elapsed)"
        $lblOverlaySub.Text = "Completed $done of $total     Elapsed: ${secs}s"
        return
    }

    $pollTimer.Stop()
    $jobState = $script:QueryJob.State
    $newData  = Receive-Job $script:QueryJob -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Remove-Job $script:QueryJob -Force -ErrorAction SilentlyContinue
    $script:QueryJob = $null

    if ($jobState -eq 'Failed') {
        $statusLabel.Text = 'Query failed — check WinRM connectivity and credentials'
    } elseif ($newData) {
        # Reconstruct as List regardless of whether return value was unrolled
        $data = if ($newData -is [System.Collections.Generic.List[pscustomobject]]) {
            $newData
        } elseif ($newData -is [array]) {
            [System.Collections.Generic.List[pscustomobject]]$newData
        } else {
            [System.Collections.Generic.List[pscustomobject]]@($newData)
        }
        $script:AllResults = $data
        Update-Grid
        $statusLabel.Text = "Last refreshed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  $($data.Count) computers"
    } else {
        $statusLabel.Text = 'Query returned no data'
    }

    # Hide the overlay; bring the grid back to the front
    $pnlOverlay.Visible = $false
    $btnRefresh.Enabled = $true

    # Re-anchor the auto-refresh countdown to "now" so it always reads
    # full-interval remaining after any refresh (manual or automatic).
    if ($chkAuto.Checked) { Reset-AutoRefreshCountdown }
})
#endregion

#region Auto-refresh timer + countdown
$script:NextAutoRefreshAt = [datetime]::MaxValue

$autoTimer          = [System.Windows.Forms.Timer]::new()
$autoTimer.Interval = 300000   # 5 minutes
$autoTimer.add_Tick({ if ($chkAuto.Checked -and -not $script:QueryJob) { $btnRefresh.PerformClick() } })

$countdownTimer          = [System.Windows.Forms.Timer]::new()
$countdownTimer.Interval = 1000

$countdownTimer.add_Tick({
    if (-not $chkAuto.Checked) { $countdownTimer.Stop(); $lblCountdown.Text = ''; return }
    $remaining = $script:NextAutoRefreshAt - [datetime]::UtcNow
    if ($remaining.TotalSeconds -le 0) {
        $lblCountdown.Text = '  Refreshing…'
    } else {
        $lblCountdown.Text = '  Next refresh in {0:m\:ss}' -f $remaining
    }
})

function Reset-AutoRefreshCountdown {
    $script:NextAutoRefreshAt = [datetime]::UtcNow.AddMilliseconds($autoTimer.Interval)
    # Stop+Start makes the underlying Win32 timer requeue from "now",
    # so the auto-refresh actually fires 5 min after the last refresh
    # rather than at an arbitrary point in the original 5-min cycle.
    $autoTimer.Stop(); $autoTimer.Start()
}
#endregion

#region Wire-up
$btnRefresh.add_Click({
    if ($script:QueryJob) { return }
    $btnRefresh.Enabled    = $false
    $statusLabel.Text      = 'Querying endpoints…'
    $script:QueryStartTime = [datetime]::UtcNow

    # Fresh thread-safe "completed" tracker for this run.  The parallel
    # workers Add() to it as each host finishes; the poll timer reads
    # .Count to display live "X/N" progress.
    $script:CompletedHosts = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

    # Show the marquee overlay over the grid area
    $lblOverlaySub.Text  = "Completed 0 of $($TargetComputers.Count)     Elapsed: 0s"
    $pnlOverlay.Visible  = $true
    $pnlOverlay.BringToFront()

    # Bundle everything in a hashtable to pass as a single -ArgumentList
    # value (avoids the array-flattening trap with multi-arg lists).
    # LibPaths are dot-sourced inside each parallel runspace so Get-DefenderStatus
    # (which calls New-DefenderRemoteSession / Invoke-DefenderRemote and the
    # shared health classifier) has the helper functions available — they
    # don't propagate across runspace boundaries automatically.
    $ctx = @{
        Computers           = $TargetComputers
        AvailableVersionStr = $AvailableVersionStr
        Threads             = $ParallelThreads
        Ts                  = $TimeoutSeconds
        FuncDef             = ${function:Get-DefenderStatus}.ToString()
        LibPaths            = @($LibInvokeDefenderRemote, $LibGetDefenderHealthProbe)
        CompletedHosts      = $script:CompletedHosts
        Credentials         = $HostCredentials
        DisableIPv6         = $DisableIPv6
    }

    $script:QueryJob = Start-ThreadJob -ScriptBlock {
        param([hashtable]$Ctx)

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $Ctx.Computers | ForEach-Object -Parallel {
                $c    = $using:Ctx
                $comp = [string]$_
                # Make wrapper functions available in this runspace
                foreach ($lib in $c.LibPaths) { . $lib }
                # Assigning to ${function:Name} actually DEFINES the function
                # in this runspace; dot-sourcing the body alone does not.
                ${function:Get-DefenderStatus} = [scriptblock]::Create($c.FuncDef)
                $cred = if ($c.Credentials -and $c.Credentials.ContainsKey($comp)) {
                    $c.Credentials[$comp]
                } else { $null }
                $r = Get-DefenderStatus -Computer $comp `
                    -TimeoutSeconds      $c.Ts `
                    -AvailableVersionStr $c.AvailableVersionStr `
                    -WinRmCredential     $cred `
                    -DisableIPv6         $c.DisableIPv6
                $c.CompletedHosts.Add($comp)   # thread-safe; live progress counter
                $r
            } -ThrottleLimit $Ctx.Threads
        } else {
            foreach ($lib in $Ctx.LibPaths) { . $lib }
            ${function:Get-DefenderStatus} = [scriptblock]::Create($Ctx.FuncDef)
            foreach ($comp in $Ctx.Computers) {
                $compStr = [string]$comp
                $cred = if ($Ctx.Credentials -and $Ctx.Credentials.ContainsKey($compStr)) {
                    $Ctx.Credentials[$compStr]
                } else { $null }
                $r = Get-DefenderStatus -Computer $compStr `
                    -TimeoutSeconds      $Ctx.Ts `
                    -AvailableVersionStr $Ctx.AvailableVersionStr `
                    -WinRmCredential     $cred `
                    -DisableIPv6         $Ctx.DisableIPv6
                $Ctx.CompletedHosts.Add($compStr)
                $r
            }
        }
    } -ArgumentList $ctx

    $pollTimer.Start()
})

$txtFilter.add_TextChanged({
    $script:FilterText = $txtFilter.Text
    if ($script:AllResults) { Update-Grid }
})

$chkAuto.add_CheckedChanged({
    if ($chkAuto.Checked) {
        Reset-AutoRefreshCountdown
        $countdownTimer.Start()
    } else {
        $countdownTimer.Stop()
        $lblCountdown.Text = ''
        $autoTimer.Stop()
    }
})

$btnExportCsv.add_Click({
    if (-not $script:AllResults) { return }
    $dlg = [System.Windows.Forms.SaveFileDialog]::new()
    $dlg.Filter   = 'CSV files (*.csv)|*.csv'
    $dlg.FileName = "DefenderStatus_$(Get-Date -f 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -eq 'OK') {
        $script:AllResults | Export-Csv -Path $dlg.FileName -NoTypeInformation
        $statusLabel.Text = "Saved: $($dlg.FileName)"
    }
})

$btnExportHtml.add_Click({
    if (-not $script:AllResults) { return }
    $dlg = [System.Windows.Forms.SaveFileDialog]::new()
    $dlg.Filter   = 'HTML files (*.html)|*.html'
    $dlg.FileName = "DefenderStatus_$(Get-Date -f 'yyyyMMdd_HHmmss').html"
    if ($dlg.ShowDialog() -eq 'OK') {
        (ConvertTo-StatusHtml -Data $script:AllResults -AvailableVersionStr $AvailableVersionStr -AsOf (Get-Date)) |
            Out-File -FilePath $dlg.FileName -Encoding utf8
        Start-Process $dlg.FileName
        $statusLabel.Text = "Saved: $($dlg.FileName)"
    }
})

$form.add_Load({ $btnRefresh.PerformClick() })
$form.add_FormClosing({
    $autoTimer.Stop()
    $pollTimer.Stop()
    $countdownTimer.Stop()
    if ($script:QueryJob) {
        Stop-Job  $script:QueryJob -Force -ErrorAction SilentlyContinue
        Remove-Job $script:QueryJob -Force -ErrorAction SilentlyContinue
    }
})
#endregion

# Suppress SafeWaitHandle ObjectDisposedException that WinForms/.NET 10 can
# raise as an unhandled thread exception during timer teardown.
[System.Windows.Forms.Application]::add_ThreadException(
    [System.Threading.ThreadExceptionEventHandler]{
        param($s, $e)
        if ($e.Exception -is [System.ObjectDisposedException] -and
            $e.Exception.ObjectName -like '*SafeWaitHandle*') { return }
        [System.Windows.Forms.MessageBox]::Show(
            $e.Exception.ToString(), 'Unhandled Error',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
    })

[System.Windows.Forms.Application]::Run($form)

# Explicit success exit so $LASTEXITCODE is reliably 0 after the form closes.
exit 0

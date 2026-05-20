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

    [ValidateSet('AD','Pattern','Single')]
    [string]$ClassificationMethod,
    [string]$WorkstationPattern,
    [string]$DomainControllerPattern,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.6'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$HostsFile     = Join-Path $ScriptDir 'hosts.conf'

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
    $cfgDir = Join-Path $ScriptDir 'Config'
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
if (-not $PSBoundParameters.ContainsKey('ParallelThreads')         -and $cfg['ParallelThreads'])         { try { $ParallelThreads = [int]$cfg['ParallelThreads'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('TimeoutSeconds')          -and $cfg['TimeoutSeconds'])          { try { $TimeoutSeconds  = [int]$cfg['TimeoutSeconds']  } catch {} }
if (-not $PSBoundParameters.ContainsKey('ClassificationMethod')    -and $cfg['ClassificationMethod'])    { $ClassificationMethod    = $cfg['ClassificationMethod'] }
if (-not $PSBoundParameters.ContainsKey('WorkstationPattern')      -and $cfg['WorkstationPattern'])      { $WorkstationPattern      = $cfg['WorkstationPattern'] }
if (-not $PSBoundParameters.ContainsKey('DomainControllerPattern') -and $cfg['DomainControllerPattern']) { $DomainControllerPattern = $cfg['DomainControllerPattern'] }

# ===================================================================
# WinRM Credential Auto-Load
# ===================================================================
$configDir = Join-Path $ScriptDir 'Config'

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
    if (Test-Path $HostsFile) {
        return Get-Content $HostsFile |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
            ForEach-Object { $_.Trim().ToUpper() }
    }
    Write-Warning 'hosts.conf not found – querying Active Directory...'
    try {
        if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
            Import-Module ActiveDirectory -ErrorAction Stop
            return Get-ADComputer `
                -Filter 'OperatingSystem -like "*Windows*" -and Enabled -eq $true' `
                -Properties Name | Sort-Object Name | Select-Object -ExpandProperty Name
        } else {
            $domain   = (Get-CimInstance Win32_ComputerSystem).Domain
            $searcher = [adsisearcher]'(&(objectCategory=computer)(operatingSystem=*Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
            $searcher.SearchRoot = "LDAP://$domain"
            return $searcher.FindAll() | ForEach-Object { $_.Properties.name[0] } | Sort-Object
        }
    } catch {
        throw "Cannot resolve target list: $($_.Exception.Message)"
    }
}

# ===================================================================
# Latest Available Version from Share
# ===================================================================
function Get-LatestAvailableVersion {
    param([string]$Root)
    if (-not $Root -or -not (Test-Path $Root -ErrorAction SilentlyContinue)) { return $null }
    $versioned = Get-ChildItem -Path $Root -Recurse -Filter 'mpam-fe.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '(?i)[/\\]_?archive[/\\]' } |
        Where-Object { $_.Directory.Name -match '^v(\d+\.\d+\.\d+\.\d+)$' } |
        ForEach-Object { [version]$_.Directory.Name.TrimStart('v') }
    return $versioned | Sort-Object -Descending | Select-Object -First 1
}

# ===================================================================
# Endpoint Classification
# ===================================================================
function Get-EndpointClassification {
    param([string[]]$Computers, [string]$Method, [string]$WsPattern, [string]$DcPattern)
    $tiers = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Computers) { $tiers[$c] = 'MemberServer' }
    if ($Method -eq 'Single') { return $tiers }
    if ($Method -eq 'AD') {
        try {
            $adMap = [System.Collections.Generic.Dictionary[string,pscustomobject]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
                Import-Module ActiveDirectory -ErrorAction Stop
                Get-ADComputer -Filter 'Enabled -eq $true' -Properties Name,OperatingSystem,userAccountControl -ErrorAction SilentlyContinue |
                    ForEach-Object { $adMap[$_.Name] = [pscustomobject]@{ OS = $_.OperatingSystem; IsDC = ($_.userAccountControl -band 0x2000) -ne 0 } }
            } else {
                $searcher = [adsisearcher]'(objectCategory=computer)'
                $searcher.SearchRoot = "LDAP://$((Get-CimInstance Win32_ComputerSystem).Domain)"
                $searcher.PropertiesToLoad.AddRange(@('name','operatingsystem','useraccountcontrol'))
                $searcher.PageSize = 1000
                $searcher.FindAll() | ForEach-Object {
                    $n = $_.Properties['name'][0]
                    if ($n) { $adMap[$n] = [pscustomobject]@{ OS = $_.Properties['operatingsystem'][0]; IsDC = ([int]$_.Properties['useraccountcontrol'][0] -band 0x2000) -ne 0 } }
                }
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
        [System.Management.Automation.PSCredential]$WinRmCredential
    )

    $result = [pscustomobject]@{
        ComputerName       = $Computer
        Online             = $false
        DefenderService    = 'Unknown'
        SignatureVersion   = ''
        AvailableVersion   = $AvailableVersionStr
        VersionStatus      = 'Unknown'
        RealTimeProtection = 'Unknown'
        AntivirusEnabled   = 'Unknown'
        LastQuickScan      = ''
        LastFullScan       = ''
        ThreatCount        = ''
        QueryDuration      = 0
        Error              = ''
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not (Test-NetConnection -ComputerName $Computer -Port 5985 `
                -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            $result.Error = 'WinRM not reachable'
            return $result
        }

        $sessionParams = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
        if ($WinRmCredential) { $sessionParams.Credential = $WinRmCredential }
        $session = New-PSSession @sessionParams
        try {
            $data = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                $mp  = $null
                try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
                [pscustomobject]@{
                    SvcStatus          = $svc.Status
                    SignatureVersion   = if ($mp) { $mp.AntivirusSignatureVersion }   else { $null }
                    RealTimeProtection = if ($mp) { $mp.RealTimeProtectionEnabled }  else { $null }
                    AntivirusEnabled   = if ($mp) { $mp.AntivirusEnabled }           else { $null }
                    LastQuickScan      = if ($mp) { $mp.QuickScanStartTime }         else { $null }
                    LastFullScan       = if ($mp) { $mp.FullScanStartTime }          else { $null }
                    ThreatCount        = if ($mp) {
                        (Get-MpThreat -ErrorAction SilentlyContinue | Measure-Object).Count
                    } else { $null }
                }
            }

            $result.Online             = $true
            $result.DefenderService    = $data.SvcStatus
            $result.SignatureVersion   = $data.SignatureVersion
            $result.RealTimeProtection = if ($null -ne $data.RealTimeProtection) { $data.RealTimeProtection.ToString() } else { 'Unknown' }
            $result.AntivirusEnabled   = if ($null -ne $data.AntivirusEnabled)   { $data.AntivirusEnabled.ToString() }   else { 'Unknown' }
            $result.LastQuickScan      = if ($data.LastQuickScan) { $data.LastQuickScan.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
            $result.LastFullScan       = if ($data.LastFullScan)  { $data.LastFullScan.ToString('yyyy-MM-dd HH:mm') }  else { 'Never' }
            $result.ThreatCount        = if ($null -ne $data.ThreatCount) { $data.ThreatCount.ToString() } else { 'Unknown' }

            if ($result.SignatureVersion -and $AvailableVersionStr) {
                try {
                    $result.VersionStatus = if ([version]$result.SignatureVersion -ge [version]$AvailableVersionStr) {
                        'Current'
                    } else { 'Outdated' }
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
        $status = if (-not $r.Online) { 'Offline' }
                  elseif ($r.VersionStatus -eq 'Outdated') { 'Outdated' }
                  elseif ($r.RealTimeProtection -eq 'False' -or $r.AntivirusEnabled -eq 'False') { 'Degraded' }
                  else { 'Healthy' }
        $cls = switch ($status) {
            'Offline'  { 'failed'  }
            'Outdated' { 'skipped' }
            'Degraded' { 'warn'    }
            default    { 'success' }
        }
        $tip = if ($r.Error) {
            " title=`"$($r.Error -replace '"','&quot;' -replace '<','&lt;' -replace '>','&gt;')`""
        } else { '' }

        "<tr>
          <td$tip>$($r.ComputerName)</td>
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
.footer { margin-top: 40px; color: #888; font-size: .85em; text-align: center; border-top: 1px solid #ddd; padding-top: 16px; }
</style>
'@

    @"
<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8">
<title>Defender Status – $(Get-Date -f 'yyyy-MM-dd')</title>$css</head>
<body>
<h1>Microsoft Defender Fleet Status</h1>
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
  <th>Computer</th><th>Status</th><th>Installed Version</th><th>Available Version</th>
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
# Setup
# ===================================================================
$TargetComputers = @(Resolve-TargetComputers)
if ($TargetComputers.Count -eq 0) { throw 'No target computers found.' }

$EndpointTiers = Get-EndpointClassification `
    -Computers  $TargetComputers `
    -Method     $ClassificationMethod `
    -WsPattern  $WorkstationPattern `
    -DcPattern  $DomainControllerPattern

$HostCredentials = [System.Collections.Generic.Dictionary[string,System.Management.Automation.PSCredential]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($c in $TargetComputers) {
    $HostCredentials[$c] = Resolve-WinRmCredential -Tier ($EndpointTiers.ContainsKey($c) ? $EndpointTiers[$c] : 'MemberServer')
}

$AvailableVersion    = Get-LatestAvailableVersion -Root $SourceSharePath
$AvailableVersionStr = if ($AvailableVersion) { $AvailableVersion.ToString() } else { '' }

if ($AvailableVersionStr) {
    Write-Host "Latest available version: v$AvailableVersionStr" -ForegroundColor Cyan
} else {
    Write-Host 'Note: No -SourceSharePath provided; version currency check disabled.' -ForegroundColor Yellow
}

# ===================================================================
# Windows Forms GUI
# ===================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

#region Colour palette
$clrBlue         = [System.Drawing.Color]::FromArgb(0, 120, 212)
$clrBackground   = [System.Drawing.Color]::FromArgb(240, 242, 246)
$clrToolbar      = [System.Drawing.Color]::FromArgb(220, 225, 235)
$clrStats        = [System.Drawing.Color]::FromArgb(228, 232, 240)
$clrOkBg         = [System.Drawing.Color]::FromArgb(198, 239, 206)
$clrOkFg         = [System.Drawing.Color]::FromArgb(0, 97, 0)
$clrWarnBg       = [System.Drawing.Color]::FromArgb(255, 235, 156)
$clrWarnFg       = [System.Drawing.Color]::FromArgb(120, 72, 0)
$clrBadBg        = [System.Drawing.Color]::FromArgb(255, 199, 206)
$clrBadFg        = [System.Drawing.Color]::FromArgb(156, 0, 6)
$clrGridHeader   = [System.Drawing.Color]::FromArgb(20, 20, 60)
#endregion

#region Form
$form              = [System.Windows.Forms.Form]::new()
$form.Text         = "Defender Fleet Monitor v$ScriptVersion"
$form.Size         = [System.Drawing.Size]::new(1420, 840)
$form.MinimumSize  = [System.Drawing.Size]::new(900, 500)
$form.StartPosition = 'CenterScreen'
$form.BackColor    = $clrBackground
$form.Font         = [System.Drawing.Font]::new('Segoe UI', 9)
#endregion

#region Header strip
$pnlHeader           = [System.Windows.Forms.Panel]::new()
$pnlHeader.Dock      = 'Top'
$pnlHeader.Height    = 56
$pnlHeader.BackColor = $clrBlue

$lblTitle            = [System.Windows.Forms.Label]::new()
$lblTitle.Text       = '  Defender Fleet Monitor'
$lblTitle.Font       = [System.Drawing.Font]::new('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor  = [System.Drawing.Color]::White
$lblTitle.AutoSize   = $true
$lblTitle.Location   = [System.Drawing.Point]::new(8, 10)

$lblAvail            = [System.Windows.Forms.Label]::new()
$lblAvail.Text       = if ($AvailableVersionStr) { "  Available: v$AvailableVersionStr" } else { '  Available: N/A (no share specified)' }
$lblAvail.ForeColor  = [System.Drawing.Color]::FromArgb(200, 230, 255)
$lblAvail.AutoSize   = $true
$lblAvail.Location   = [System.Drawing.Point]::new(8, 36)

$pnlHeader.Controls.AddRange(@($lblTitle, $lblAvail))
$form.Controls.Add($pnlHeader)
#endregion

#region Toolbar
$pnlToolbar           = [System.Windows.Forms.FlowLayoutPanel]::new()
$pnlToolbar.Dock      = 'Top'
$pnlToolbar.Height    = 44
$pnlToolbar.Padding   = [System.Windows.Forms.Padding]::new(8, 7, 0, 0)
$pnlToolbar.BackColor = $clrToolbar

function New-ToolButton ([string]$Text) {
    $b             = [System.Windows.Forms.Button]::new()
    $b.Text        = $Text
    $b.AutoSize    = $true
    $b.Height      = 28
    $b.Padding     = [System.Windows.Forms.Padding]::new(10, 0, 10, 0)
    $b.FlatStyle   = 'Flat'
    $b.BackColor   = $clrBlue
    $b.ForeColor   = [System.Drawing.Color]::White
    $b.Font        = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $b.FlatAppearance.BorderSize = 0
    $b.Cursor      = [System.Windows.Forms.Cursors]::Hand
    return $b
}

$btnRefresh     = New-ToolButton '⟳  Refresh Now'
$btnExportCsv   = New-ToolButton '⬇  Export CSV'
$btnExportHtml  = New-ToolButton '⬇  Export HTML'

$sep = [System.Windows.Forms.Label]::new()
$sep.Width = 16

$lblFilter      = [System.Windows.Forms.Label]::new()
$lblFilter.Text = 'Filter:'
$lblFilter.AutoSize = $true
$lblFilter.Padding  = [System.Windows.Forms.Padding]::new(0, 6, 4, 0)

$txtFilter      = [System.Windows.Forms.TextBox]::new()
$txtFilter.Width  = 200
$txtFilter.Height = 24
$txtFilter.Margin = [System.Windows.Forms.Padding]::new(2, 4, 0, 0)

$chkAuto        = [System.Windows.Forms.CheckBox]::new()
$chkAuto.Text   = 'Auto-refresh (5 min)'
$chkAuto.AutoSize = $true
$chkAuto.Padding  = [System.Windows.Forms.Padding]::new(12, 6, 0, 0)

$pnlToolbar.Controls.AddRange(@($btnRefresh, $btnExportCsv, $btnExportHtml, $sep, $lblFilter, $txtFilter, $chkAuto))
$form.Controls.Add($pnlToolbar)
#endregion

#region Stat cards
$pnlStats              = [System.Windows.Forms.TableLayoutPanel]::new()
$pnlStats.Dock         = 'Top'
$pnlStats.Height       = 72
$pnlStats.ColumnCount  = 5
$pnlStats.RowCount     = 1
$pnlStats.BackColor    = $clrStats
$pnlStats.Padding      = [System.Windows.Forms.Padding]::new(8, 8, 8, 0)
for ($c = 0; $c -lt 5; $c++) {
    $pnlStats.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 20)) | Out-Null
}
$form.Controls.Add($pnlStats)

function New-StatCard ([string]$InitText, [System.Drawing.Color]$Bg, [System.Drawing.Color]$Fg) {
    $p           = [System.Windows.Forms.Panel]::new()
    $p.Dock      = 'Fill'
    $p.Margin    = [System.Windows.Forms.Padding]::new(4)
    $p.BackColor = $Bg
    $lbl         = [System.Windows.Forms.Label]::new()
    $lbl.Dock    = 'Fill'
    $lbl.Text    = $InitText
    $lbl.TextAlign = 'MiddleCenter'
    $lbl.Font    = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lbl.ForeColor = $Fg
    $p.Controls.Add($lbl)
    return @{ Panel = $p; Label = $lbl }
}

$statTotal    = New-StatCard "Total`r`n—"    ([System.Drawing.Color]::FromArgb(210,220,240)) ([System.Drawing.Color]::FromArgb(20,20,80))
$statOnline   = New-StatCard "Online`r`n—"  $clrOkBg  $clrOkFg
$statOffline  = New-StatCard "Offline`r`n—" $clrBadBg $clrBadFg
$statCurrent  = New-StatCard "Current`r`n—" $clrOkBg  $clrOkFg
$statOutdated = New-StatCard "Outdated`r`n—" $clrWarnBg $clrWarnFg

foreach ($s in $statTotal, $statOnline, $statOffline, $statCurrent, $statOutdated) {
    $pnlStats.Controls.Add($s.Panel)
}
#endregion

#region Status bar
$statusStrip  = [System.Windows.Forms.StatusStrip]::new()
$statusLabel  = [System.Windows.Forms.ToolStripStatusLabel]::new()
$statusLabel.Text = "Ready – $($TargetComputers.Count) computers loaded"
$statusStrip.Items.Add($statusLabel) | Out-Null
$form.Controls.Add($statusStrip)
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
$grid.BackgroundColor       = $clrBackground
$grid.BorderStyle           = 'None'
$grid.CellBorderStyle       = 'SingleHorizontal'
$grid.GridColor             = [System.Drawing.Color]::FromArgb(210, 215, 225)
$grid.ColumnHeadersDefaultCellStyle.BackColor = $clrGridHeader
$grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$grid.ColumnHeadersDefaultCellStyle.Font      = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$grid.ColumnHeadersHeightSizeMode             = 'DisableResizing'
$grid.ColumnHeadersHeight                     = 32
$grid.EnableHeadersVisualStyles               = $false
$grid.DefaultCellStyle.Padding                = [System.Windows.Forms.Padding]::new(4, 0, 4, 0)
$grid.RowTemplate.Height                      = 26

$colDefs = @(
    'Computer Name',150
    'Online',70
    'Status',90
    'Installed Version',130
    'Available Version',130
    'Currency',90
    'RT Protection',100
    'AV Enabled',90
    'Last Quick Scan',140
    'Threats',65
    'Query Time',80
    'Error / Detail',0   # 0 = Fill
)
for ($i = 0; $i -lt $colDefs.Count; $i += 2) {
    $col            = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $col.HeaderText = $colDefs[$i]
    $col.SortMode   = 'Automatic'
    if ($colDefs[$i+1] -eq 0) {
        $col.AutoSizeMode = 'Fill'
    } else {
        $col.Width = $colDefs[$i+1]
    }
    $grid.Columns.Add($col) | Out-Null
}

$form.Controls.Add($grid)
#endregion

$script:AllResults = $null
$script:FilterText = ''

function Update-Grid {
    $data = $script:AllResults
    if (-not $data) { return }

    $filter = $script:FilterText.Trim()
    if ($filter) { $data = @($data | Where-Object { $_.ComputerName -like "*$filter*" }) }

    $grid.SuspendLayout()
    $grid.Rows.Clear()

    foreach ($r in $data | Sort-Object ComputerName) {
        $status = if (-not $r.Online) { 'Offline' }
                  elseif ($r.VersionStatus -eq 'Outdated') { 'Outdated' }
                  elseif ($r.RealTimeProtection -eq 'False' -or $r.AntivirusEnabled -eq 'False') { 'Degraded' }
                  else { 'Healthy' }

        $idx = $grid.Rows.Add(
            $r.ComputerName,
            $(if ($r.Online) { 'Yes' } else { 'No' }),
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
        $row = $grid.Rows[$idx]
        switch ($status) {
            'Offline'  { $row.DefaultCellStyle.BackColor = $clrBadBg;  $row.DefaultCellStyle.ForeColor = $clrBadFg }
            'Outdated' { $row.DefaultCellStyle.BackColor = $clrWarnBg; $row.DefaultCellStyle.ForeColor = $clrWarnFg }
            'Degraded' { $row.DefaultCellStyle.BackColor = $clrWarnBg; $row.DefaultCellStyle.ForeColor = $clrWarnFg }
            default    { $row.DefaultCellStyle.BackColor = $clrOkBg;   $row.DefaultCellStyle.ForeColor = $clrOkFg }
        }
    }
    $grid.ResumeLayout()

    $all      = $script:AllResults
    $online   = @($all | Where-Object Online).Count
    $offline  = $all.Count - $online
    $current  = @($all | Where-Object VersionStatus -eq 'Current').Count
    $outdated = @($all | Where-Object VersionStatus -eq 'Outdated').Count

    $statTotal.Label.Text    = "Total`r`n$($all.Count)"
    $statOnline.Label.Text   = "Online`r`n$online"
    $statOffline.Label.Text  = "Offline`r`n$offline"
    $statCurrent.Label.Text  = "Current`r`n$current"
    $statOutdated.Label.Text = "Outdated`r`n$outdated"
}

#region BackgroundWorker
$worker                             = [System.ComponentModel.BackgroundWorker]::new()
$worker.WorkerReportsProgress       = $true
$worker.WorkerSupportsCancellation  = $true

$worker.add_DoWork({
    param($s, $e)
    $tc        = $e.Argument[0]
    $avs       = $e.Argument[1]
    $pt        = $e.Argument[2]
    $ts        = $e.Argument[3]
    $fDef      = $e.Argument[4]
    $hostCreds = $e.Argument[5]

    . ([scriptblock]::Create($fDef))

    $done  = [System.Collections.Generic.List[pscustomobject]]::new()
    $total = $tc.Count

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $queue  = [System.Collections.Generic.Queue[string]]::new($tc)
        $active = [System.Collections.Generic.Dictionary[int, hashtable]]::new()

        while ($queue.Count -gt 0 -or $active.Count -gt 0) {
            while ($active.Count -lt $pt -and $queue.Count -gt 0) {
                $comp = $queue.Dequeue()
                $cred = if ($hostCreds -and $hostCreds.ContainsKey($comp)) { $hostCreds[$comp] } else { $null }
                $job  = Start-ThreadJob -ScriptBlock $using:funcSB -ArgumentList @($comp, $ts, $avs, $cred)
                $active[$job.Id] = @{ Job = $job; Start = [datetime]::UtcNow }
            }
            foreach ($id in @($active.Keys)) {
                $m = $active[$id]
                if ($m.Job.State -notin 'Running','NotStarted') {
                    $r = Receive-Job $m.Job -ErrorAction SilentlyContinue
                    if (-not $r) { $r = [pscustomobject]@{ ComputerName='?'; Online=$false; Error='No output' } }
                    elseif ($r -is [array]) { $r = $r[-1] }
                    $done.Add($r)
                    Remove-Job $m.Job -Force
                    [void]$active.Remove($id)
                    $s.ReportProgress([int]($done.Count * 100 / $total), $r.ComputerName)
                }
            }
            foreach ($id in @($active.Keys)) {
                $m = $active[$id]
                if (([datetime]::UtcNow - $m.Start).TotalSeconds -gt $ts + 5) {
                    Stop-Job $m.Job -Force
                    $done.Add([pscustomobject]@{ ComputerName='?'; Online=$false; Error='Timeout' })
                    Remove-Job $m.Job -Force
                    [void]$active.Remove($id)
                    $s.ReportProgress([int]($done.Count * 100 / $total), 'timeout')
                }
            }
            Start-Sleep -Milliseconds 150
        }
    } else {
        $i = 0
        foreach ($comp in $tc) {
            $cred = if ($hostCreds -and $hostCreds.ContainsKey($comp)) { $hostCreds[$comp] } else { $null }
            $r = Get-DefenderStatus -Computer $comp -TimeoutSeconds $ts -AvailableVersionStr $avs -WinRmCredential $cred
            $done.Add($r)
            $i++
            $s.ReportProgress([int]($i * 100 / $total), $comp)
        }
    }
    $e.Result = $done
})

$worker.add_ProgressChanged({
    param($s, $e)
    $statusLabel.Text = "Querying… $($e.ProgressPercentage)%  –  last: $($e.UserState)"
})

$worker.add_RunWorkerCompleted({
    param($s, $e)
    if ($e.Error) {
        $statusLabel.Text = "Query error: $($e.Error.Message)"
    } elseif ($e.Result) {
        $script:AllResults = $e.Result
        Update-Grid
        $statusLabel.Text = "Last refreshed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  $($e.Result.Count) computers"
    }
    $btnRefresh.Enabled = $true
})
#endregion

#region Auto-refresh timer
$autoTimer          = [System.Windows.Forms.Timer]::new()
$autoTimer.Interval = 300000   # 5 minutes
$autoTimer.add_Tick({ if ($chkAuto.Checked -and -not $worker.IsBusy) { $btnRefresh.PerformClick() } })
$autoTimer.Start()
#endregion

#region Wire-up
$funcSB = ${function:Get-DefenderStatus}

$btnRefresh.add_Click({
    if ($worker.IsBusy) { return }
    $btnRefresh.Enabled = $false
    $statusLabel.Text   = 'Querying endpoints…'
    $worker.RunWorkerAsync(@($TargetComputers, $AvailableVersionStr, $ParallelThreads, $TimeoutSeconds, ${function:Get-DefenderStatus}.ToString(), $HostCredentials))
})

$txtFilter.add_TextChanged({
    $script:FilterText = $txtFilter.Text
    if ($script:AllResults) { Update-Grid }
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
$form.add_FormClosed({ $autoTimer.Stop(); $autoTimer.Dispose(); $worker.Dispose() })
#endregion

[System.Windows.Forms.Application]::Run($form)

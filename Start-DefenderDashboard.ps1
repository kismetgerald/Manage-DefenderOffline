<#
.SYNOPSIS
    Start-DefenderDashboard.ps1 – Headless Microsoft Defender fleet status HTTP dashboard

.DESCRIPTION
    Runs a lightweight HTTP listener that serves a self-refreshing browser dashboard
    showing the Microsoft Defender health status of all Windows endpoints in scope.

    Designed to run continuously as a Windows Scheduled Task under a service account
    or Group Managed Service Account (gMSA). All output is written to a log file;
    no interactive console required.

    Two endpoints are served:
      /defender   – HTML dashboard (auto-refreshes in the browser)
      /status     – JSON snapshot of the current data (for scripting / monitoring tools)
      /health     – Plain-text "OK" liveness probe (for uptime monitors)
      /refresh    – Forces an immediate background data refresh (GET or POST)

    Data is cached and refreshed on a background thread every -RefreshInterval seconds.
    Visitors always receive the most recently cached data; they are never blocked waiting
    for a live query.

    Use Install-DefenderDashboard.ps1 to register this script as a scheduled task.

.PARAMETER Port
    TCP port the HTTP listener binds to. Default: 8080.

.PARAMETER RefreshInterval
    How often (in seconds) background data is refreshed. Default: 300 (5 minutes).

.PARAMETER ComputerName
    Manual list of computers to query. Bypasses hosts.conf and AD auto-discovery.

.PARAMETER SourceSharePath
    Base UNC path for the definitions share. Used to determine version currency.
    Example: \\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender

.PARAMETER LogPath
    Directory for dashboard log files. Default: C:\Logs\DefenderDashboard

.PARAMETER ParallelThreads
    Maximum concurrent WinRM queries per refresh cycle. Range: 1-32. Default: 16.

.PARAMETER TimeoutSeconds
    Per-host WinRM query timeout in seconds. Default: 30.

.EXAMPLE
    # Run interactively for testing
    .\Start-DefenderDashboard.ps1 -Port 8080 -SourceSharePath "\\NAS01\Share\_AVDefinitions\Microsoft_Defender"

.EXAMPLE
    # Run on a non-default port with a shorter refresh
    .\Start-DefenderDashboard.ps1 -Port 9090 -RefreshInterval 120

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Requires       : PowerShell 7+ (recommended), WinRM on targets (TCP 5985)
                     Administrator privileges or delegated WinRM access on targets
    Version        : 0.0.6
    Last Updated   : 2026-05-19
#>

[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [ValidateRange(1024, 65535)]
    [int]$FallbackPort = 8443,

    [ValidateRange(30, 86400)]
    [int]$RefreshInterval = 300,

    [string[]]$ComputerName,

    [string]$SourceSharePath,

    [string]$LogPath = 'C:\Logs\DefenderDashboard',

    [ValidateRange(1, 32)]
    [int]$ParallelThreads = 16,

    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 30,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.6'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$HostsFile     = Join-Path $ScriptDir 'hosts.conf'

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
        if ($t -match '^([^=]+?)\s*=\s*(.+)$') { $cfg[$Matches[1].Trim()] = $Matches[2].Trim() }
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

# ===================================================================
# Port Availability
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
# Logging  (file-only; no console assumed when running as a task)
# ===================================================================
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "DefenderDashboard_$(Get-Date -Format 'yyyyMMdd').log"

function Write-DashLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    # Mirror to console for interactive/debug runs
    $color = switch ($Level) {
        'INFO'    { 'Cyan'    }
        'WARN'    { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
    }
    Write-Host $line -ForegroundColor $color
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
    Write-DashLog 'hosts.conf not found – querying Active Directory...' 'WARN'
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
# Latest Available Version
# ===================================================================
function Get-LatestAvailableVersion {
    param([string]$Root)
    if (-not $Root -or -not (Test-Path $Root -ErrorAction SilentlyContinue)) { return $null }
    $versioned = Get-ChildItem -Path $Root -Recurse -Filter 'mpam-fe.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -match '^v(\d+\.\d+\.\d+\.\d+)$' } |
        ForEach-Object { [version]$_.Directory.Name.TrimStart('v') }
    return $versioned | Sort-Object -Descending | Select-Object -First 1
}

# ===================================================================
# Per-Host Defender Query
# (defined at script scope so it can be captured for thread jobs)
# ===================================================================
function Get-DefenderStatus {
    param(
        [string]$Computer,
        [int]$TimeoutSeconds,
        [string]$AvailableVersionStr
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

        $session = New-PSSession -ComputerName $Computer -ErrorAction Stop
        try {
            $data = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                $mp  = $null
                try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
                [pscustomobject]@{
                    SvcStatus          = $svc.Status
                    SignatureVersion   = if ($mp) { $mp.AntivirusSignatureVersion }  else { $null }
                    RealTimeProtection = if ($mp) { $mp.RealTimeProtectionEnabled } else { $null }
                    AntivirusEnabled   = if ($mp) { $mp.AntivirusEnabled }          else { $null }
                    LastQuickScan      = if ($mp) { $mp.QuickScanStartTime }        else { $null }
                    LastFullScan       = if ($mp) { $mp.FullScanStartTime }         else { $null }
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
# Parallel Refresh
# Returns a List of results; runs in background via Start-ThreadJob
# ===================================================================
function Invoke-FleetRefresh {
    param(
        [string[]]$Computers,
        [string]$AvailableVersionStr,
        [int]$Threads,
        [int]$TSeconds,
        [string]$FunctionDef     # Get-DefenderStatus serialised as a string
    )

    . ([scriptblock]::Create($FunctionDef))

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    $total   = $Computers.Count

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $queue  = [System.Collections.Generic.Queue[string]]::new($Computers)
        $active = [System.Collections.Generic.Dictionary[int, hashtable]]::new()

        while ($queue.Count -gt 0 -or $active.Count -gt 0) {
            while ($active.Count -lt $Threads -and $queue.Count -gt 0) {
                $comp = $queue.Dequeue()
                $job  = Start-ThreadJob -ScriptBlock {
                    param($c, $ts, $avs, $fdef)
                    . ([scriptblock]::Create($fdef))
                    Get-DefenderStatus -Computer $c -TimeoutSeconds $ts -AvailableVersionStr $avs
                } -ArgumentList $comp, $TSeconds, $AvailableVersionStr, $FunctionDef
                $active[$job.Id] = @{ Job = $job; Start = [datetime]::UtcNow }
            }

            foreach ($id in @($active.Keys)) {
                $m = $active[$id]
                if ($m.Job.State -notin 'Running','NotStarted') {
                    $r = Receive-Job $m.Job -ErrorAction SilentlyContinue
                    if (-not $r) { $r = [pscustomobject]@{ ComputerName = '?'; Online = $false; Error = 'No output' } }
                    elseif ($r -is [array]) { $r = $r[-1] }
                    $results.Add($r)
                    Remove-Job $m.Job -Force
                    $active.Remove($id)
                }
            }

            # Per-job timeout guard
            foreach ($id in @($active.Keys)) {
                $m = $active[$id]
                if (([datetime]::UtcNow - $m.Start).TotalSeconds -gt $TSeconds + 10) {
                    Stop-Job $m.Job -Force
                    $results.Add([pscustomobject]@{ ComputerName = '?'; Online = $false; Error = 'Timeout' })
                    Remove-Job $m.Job -Force
                    $active.Remove($id)
                }
            }

            Start-Sleep -Milliseconds 200
        }
    } else {
        # PS 5.1 serial fallback
        foreach ($comp in $Computers) {
            $results.Add((Get-DefenderStatus -Computer $comp -TimeoutSeconds $TSeconds -AvailableVersionStr $AvailableVersionStr))
        }
    }

    return $results
}

# ===================================================================
# HTML Page Builder
# ===================================================================
function Build-DashboardHtml {
    param(
        [object[]]$Data,
        [string]$AvailableVersionStr,
        [datetime]$AsOf,
        [bool]$IsRefreshing
    )

    $onlineCount  = @($Data | Where-Object Online).Count
    $offlineCount = $Data.Count - $onlineCount
    $outdated     = @($Data | Where-Object VersionStatus -eq 'Outdated').Count
    $rtOff        = @($Data | Where-Object { $_.RealTimeProtection -eq 'False' -and $_.Online }).Count

    $nextRefresh  = $AsOf.AddSeconds($RefreshInterval)
    $secsUntil    = [math]::Max(0, [int]($nextRefresh - (Get-Date)).TotalSeconds)

    $rows = foreach ($r in $Data | Sort-Object ComputerName) {
        $status = if (-not $r.Online) { 'Offline' }
                  elseif ($r.VersionStatus -eq 'Outdated') { 'Outdated' }
                  elseif ($r.RealTimeProtection -eq 'False' -or $r.AntivirusEnabled -eq 'False') { 'Degraded' }
                  else { 'Healthy' }
        $badge  = switch ($status) {
            'Offline'  { '<span class="badge b-off">Offline</span>' }
            'Outdated' { '<span class="badge b-out">Outdated</span>' }
            'Degraded' { '<span class="badge b-deg">Degraded</span>' }
            default    { '<span class="badge b-ok">Healthy</span>' }
        }
        $tip = if ($r.Error) {
            " title=`"$($r.Error -replace '"','&quot;' -replace '<','&lt;' -replace '>','&gt;')`""
        } else { '' }

        "<tr>
          <td$tip>$($r.ComputerName)</td>
          <td>$badge</td>
          <td>$($r.SignatureVersion)</td>
          <td>$($r.VersionStatus)</td>
          <td>$($r.RealTimeProtection)</td>
          <td>$($r.AntivirusEnabled)</td>
          <td>$($r.LastQuickScan)</td>
          <td>$($r.ThreatCount)</td>
          <td>$($r.QueryDuration)s</td>
        </tr>"
    }

    $refreshingBanner = if ($IsRefreshing) {
        '<div class="banner">&#x21BB; Refresh in progress…</div>'
    } else { '' }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="$RefreshInterval">
  <title>Defender Fleet Monitor</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: "Segoe UI", Arial, sans-serif; background: #1e1e2e; color: #cdd6f4; min-height: 100vh; }

    .topbar { background: #313244; padding: 14px 28px; display: flex; align-items: center;
              justify-content: space-between; border-bottom: 2px solid #45475a; }
    .topbar h1 { font-size: 1.25em; color: #cba6f7; font-weight: 700; }
    .topbar .meta { font-size: .82em; color: #a6adc8; text-align: right; line-height: 1.6; }
    .topbar .meta a { color: #89b4fa; text-decoration: none; }
    .topbar .meta a:hover { text-decoration: underline; }

    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px;
             padding: 20px 28px 8px; }
    .stat { background: #313244; border-radius: 10px; padding: 14px 18px; border-left: 4px solid transparent; }
    .stat .lbl { font-size: .78em; color: #a6adc8; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .05em; }
    .stat .val { font-size: 2em; font-weight: 800; line-height: 1; }
    .st-online  { border-color: #a6e3a1; } .st-online  .val { color: #a6e3a1; }
    .st-offline { border-color: #f38ba8; } .st-offline .val { color: #f38ba8; }
    .st-out     { border-color: #fab387; } .st-out     .val { color: #fab387; }
    .st-rt      { border-color: #f9e2af; } .st-rt      .val { color: #f9e2af; }

    .toolbar { padding: 10px 28px; display: flex; align-items: center; gap: 10px; }
    .toolbar input { background: #45475a; border: 1px solid #585b70; color: #cdd6f4;
                     padding: 7px 12px; border-radius: 6px; font-size: .88em; width: 240px; }
    .toolbar a.btn { background: #45475a; color: #cdd6f4; padding: 7px 16px; border-radius: 6px;
                     text-decoration: none; font-size: .85em; border: 1px solid #585b70; }
    .toolbar a.btn:hover { background: #585b70; }

    .banner { background: #45475a; color: #f9e2af; text-align: center; padding: 6px;
              font-size: .85em; margin: 0 28px 8px; border-radius: 6px; }

    .wrap { padding: 0 28px 32px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; background: #313244; border-radius: 10px; overflow: hidden; }
    th { background: #45475a; color: #cba6f7; padding: 11px 14px; text-align: left;
         font-size: .82em; font-weight: 700; cursor: pointer; user-select: none;
         white-space: nowrap; }
    th:hover { background: #585b70; }
    td { padding: 10px 14px; border-bottom: 1px solid #45475a; font-size: .88em; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,.04); }

    .badge { display: inline-block; padding: 2px 10px; border-radius: 10px;
             font-size: .78em; font-weight: 700; }
    .b-ok  { background: #a6e3a1; color: #1e3a1e; }
    .b-off { background: #f38ba8; color: #1e1e2e; }
    .b-out { background: #fab387; color: #1e1e2e; }
    .b-deg { background: #f9e2af; color: #1e1e2e; }

    .footer { text-align: center; padding: 16px 28px; font-size: .78em; color: #6c7086;
              border-top: 1px solid #313244; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>&#x1F6E1; Defender Fleet Monitor</h1>
    <div class="meta">
      Available: <strong>$(if ($AvailableVersionStr) { "v$AvailableVersionStr" } else { 'N/A' })</strong><br>
      Last data: <strong>$($AsOf.ToString('yyyy-MM-dd HH:mm:ss'))</strong> &nbsp;|&nbsp;
      Next refresh in: <strong id="countdown">$secsUntil</strong>s &nbsp;|&nbsp;
      <a href="/refresh">Force Refresh</a> &nbsp;|&nbsp;
      <a href="/status" target="_blank">JSON</a>
    </div>
  </div>

  <div class="stats">
    <div class="stat st-online">  <div class="lbl">Online</div>  <div class="val">$onlineCount</div></div>
    <div class="stat st-offline"> <div class="lbl">Offline</div> <div class="val">$offlineCount</div></div>
    <div class="stat st-out">     <div class="lbl">Outdated</div><div class="val">$outdated</div></div>
    <div class="stat st-rt">      <div class="lbl">RT Prot Off</div><div class="val">$rtOff</div></div>
  </div>

  <div class="toolbar">
    <input type="text" id="filter" placeholder="Filter by computer name…" oninput="applyFilter()">
    <a href="/refresh" class="btn">&#x21BB; Refresh Now</a>
  </div>

  $refreshingBanner

  <div class="wrap">
    <table id="tbl">
      <thead><tr>
        <th onclick="sort(0)">Computer &#9651;</th>
        <th onclick="sort(1)">Status</th>
        <th onclick="sort(2)">Installed Version</th>
        <th onclick="sort(3)">Currency</th>
        <th onclick="sort(4)">RT Protection</th>
        <th onclick="sort(5)">AV Enabled</th>
        <th onclick="sort(6)">Last Quick Scan</th>
        <th onclick="sort(7)">Threats</th>
        <th onclick="sort(8)">Query Time</th>
      </tr></thead>
      <tbody>
        $($rows -join "`n        ")
      </tbody>
    </table>
  </div>

  <div class="footer">
    Start-DefenderDashboard.ps1 v$ScriptVersion &nbsp;|&nbsp;
    $($Data.Count) computers &nbsp;|&nbsp; $onlineCount online &nbsp;|&nbsp; $offlineCount offline
  </div>

  <script>
    // Countdown timer
    var secs = $secsUntil;
    setInterval(function() {
      if (secs > 0) secs--;
      var el = document.getElementById('countdown');
      if (el) el.textContent = secs;
    }, 1000);

    // Filter
    function applyFilter() {
      var q = document.getElementById('filter').value.toLowerCase();
      var rows = document.getElementById('tbl').tBodies[0].rows;
      for (var i = 0; i < rows.length; i++) {
        var name = rows[i].cells[0] ? rows[i].cells[0].innerText.toLowerCase() : '';
        rows[i].style.display = name.includes(q) ? '' : 'none';
      }
    }

    // Sort
    var sortDir = {};
    function sort(col) {
      var tb   = document.getElementById('tbl').tBodies[0];
      var rows = Array.from(tb.rows);
      var asc  = sortDir[col] = !sortDir[col];
      rows.sort(function(a, b) {
        var av = a.cells[col] ? a.cells[col].innerText : '';
        var bv = b.cells[col] ? b.cells[col].innerText : '';
        return asc ? av.localeCompare(bv, undefined, {numeric:true})
                   : bv.localeCompare(av, undefined, {numeric:true});
      });
      rows.forEach(function(r) { tb.appendChild(r); });
    }
  </script>
</body>
</html>
"@
}

# ===================================================================
# JSON Serialiser  (for /status endpoint)
# ===================================================================
function ConvertTo-DashboardJson {
    param([object[]]$Data, [datetime]$AsOf, [string]$AvailableVersionStr)
    $payload = [ordered]@{
        generated        = $AsOf.ToString('o')
        availableVersion = $AvailableVersionStr
        totalComputers   = $Data.Count
        onlineCount      = @($Data | Where-Object Online).Count
        offlineCount     = @($Data | Where-Object { -not $_.Online }).Count
        outdatedCount    = @($Data | Where-Object VersionStatus -eq 'Outdated').Count
        computers        = @($Data | Sort-Object ComputerName | ForEach-Object {
            [ordered]@{
                computerName       = $_.ComputerName
                online             = $_.Online
                defenderService    = $_.DefenderService
                signatureVersion   = $_.SignatureVersion
                availableVersion   = $_.AvailableVersion
                versionStatus      = $_.VersionStatus
                realTimeProtection = $_.RealTimeProtection
                antivirusEnabled   = $_.AntivirusEnabled
                lastQuickScan      = $_.LastQuickScan
                lastFullScan       = $_.LastFullScan
                threatCount        = $_.ThreatCount
                queryDurationSec   = $_.QueryDuration
                error              = $_.Error
            }
        })
    }
    return $payload | ConvertTo-Json -Depth 5
}

# ===================================================================
# HTTP Response Helper
# ===================================================================
function Send-HttpResponse {
    param(
        [System.Net.HttpListenerContext]$Context,
        [string]$Body,
        [string]$ContentType = 'text/html; charset=utf-8',
        [int]$StatusCode = 200
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Context.Response.StatusCode      = $StatusCode
    $Context.Response.ContentType     = $ContentType
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.AddHeader('X-Powered-By', "DefenderDashboard/$ScriptVersion")
    try {
        $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } finally {
        $Context.Response.OutputStream.Close()
    }
}

# ===================================================================
# Startup
# ===================================================================
Write-DashLog "=== Defender Dashboard v$ScriptVersion starting ===" 'SUCCESS'
Write-DashLog "Port            : $Port"
Write-DashLog "Refresh interval: ${RefreshInterval}s"
Write-DashLog "Parallel threads: $ParallelThreads"
Write-DashLog "Log file        : $LogFile"

$TargetComputers = @(Resolve-TargetComputers)
if ($TargetComputers.Count -eq 0) {
    Write-DashLog 'No target computers found. Exiting.' 'ERROR'
    exit 1
}
Write-DashLog "Target computers: $($TargetComputers.Count)" 'SUCCESS'

$AvailableVersion    = Get-LatestAvailableVersion -Root $SourceSharePath
$AvailableVersionStr = if ($AvailableVersion) { $AvailableVersion.ToString() } else { '' }
if ($AvailableVersionStr) {
    Write-DashLog "Available version: v$AvailableVersionStr" 'SUCCESS'
} else {
    Write-DashLog 'No SourceSharePath provided; version currency check disabled.' 'WARN'
}

# Resolve port (check availability, fall back if needed)
$portResult = Find-AvailablePort -Primary $Port -Fallback $FallbackPort
if ($portResult.IsFallback) {
    Write-DashLog "Port $($portResult.PrimaryPort) is in use. Binding to fallback port $($portResult.Port) instead." 'WARN'
}
$Port = $portResult.Port

# Start HTTP listener
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://+:$Port/")
try {
    $listener.Start()
} catch {
    Write-DashLog "Failed to bind to port $Port : $($_.Exception.Message)" 'ERROR'
    Write-DashLog 'Ensure no other process owns this port and that the account has permission to register HTTP prefixes.' 'ERROR'
    exit 1
}
Write-DashLog "HTTP listener started on http://+:$Port/" 'SUCCESS'
Write-DashLog "Browse to: http://localhost:$Port/defender" 'INFO'

# ===================================================================
# State
# ===================================================================
$script:CachedResults  = [System.Collections.Generic.List[pscustomobject]]::new()
$script:CachedAt       = [datetime]::MinValue
$script:IsRefreshing   = $false
$script:RefreshJob     = $null
$FunctionDef           = ${function:Get-DefenderStatus}.ToString()

function Start-BackgroundRefresh {
    if ($script:IsRefreshing) { return }
    $script:IsRefreshing = $true
    Write-DashLog "Starting background refresh ($($TargetComputers.Count) computers)…" 'INFO'

    $script:RefreshJob = Start-ThreadJob -ScriptBlock ${function:Invoke-FleetRefresh} -ArgumentList @(
        $TargetComputers,
        $AvailableVersionStr,
        $ParallelThreads,
        $TimeoutSeconds,
        $FunctionDef
    )
}

function Receive-RefreshIfDone {
    if (-not $script:RefreshJob) { return }
    if ($script:RefreshJob.State -notin 'Running','NotStarted') {
        $newData = Receive-Job $script:RefreshJob -ErrorAction SilentlyContinue
        Remove-Job $script:RefreshJob -Force
        $script:RefreshJob   = $null
        $script:IsRefreshing = $false

        if ($newData) {
            $script:CachedResults = if ($newData -is [array]) { [System.Collections.Generic.List[pscustomobject]]$newData } else { $newData }
            $script:CachedAt      = Get-Date
            $onlineCount  = @($script:CachedResults | Where-Object Online).Count
            $outdatedCount = @($script:CachedResults | Where-Object VersionStatus -eq 'Outdated').Count
            Write-DashLog "Refresh complete: $($script:CachedResults.Count) computers | $onlineCount online | $outdatedCount outdated" 'SUCCESS'
        } else {
            Write-DashLog 'Refresh job returned no data.' 'WARN'
        }
    }
}

# Do an initial synchronous refresh so the first visitor sees real data
Write-DashLog 'Performing initial data collection…' 'INFO'
$initResults = Invoke-FleetRefresh `
    -Computers           $TargetComputers `
    -AvailableVersionStr $AvailableVersionStr `
    -Threads             $ParallelThreads `
    -TSeconds            $TimeoutSeconds `
    -FunctionDef         $FunctionDef

$script:CachedResults = $initResults
$script:CachedAt      = Get-Date
Write-DashLog "Initial collection complete: $($script:CachedResults.Count) computers" 'SUCCESS'

# ===================================================================
# Main Loop
# ===================================================================
Write-DashLog 'Entering main request loop. Press Ctrl+C to stop.' 'INFO'

try {
    while ($listener.IsListening) {

        # Check if background refresh has completed
        Receive-RefreshIfDone

        # Kick off a new refresh if the interval has elapsed and we're not already refreshing
        if (-not $script:IsRefreshing -and
            ($script:CachedAt -eq [datetime]::MinValue -or
             ([datetime]::Now - $script:CachedAt).TotalSeconds -ge $RefreshInterval)) {
            Start-BackgroundRefresh
        }

        # Non-blocking HTTP request check
        if (-not $listener.Pending()) {
            Start-Sleep -Milliseconds 500
            continue
        }

        $context = $listener.GetContext()
        $path    = $context.Request.Url.AbsolutePath.TrimEnd('/')

        switch ($path) {
            '/defender' {
                $html = Build-DashboardHtml `
                    -Data               $script:CachedResults `
                    -AvailableVersionStr $AvailableVersionStr `
                    -AsOf               $script:CachedAt `
                    -IsRefreshing       $script:IsRefreshing
                Send-HttpResponse -Context $context -Body $html
            }

            '/status' {
                $json = ConvertTo-DashboardJson `
                    -Data               $script:CachedResults `
                    -AsOf               $script:CachedAt `
                    -AvailableVersionStr $AvailableVersionStr
                Send-HttpResponse -Context $context -Body $json -ContentType 'application/json; charset=utf-8'
            }

            '/health' {
                Send-HttpResponse -Context $context -Body 'OK' -ContentType 'text/plain; charset=utf-8'
            }

            '/refresh' {
                # Force an immediate refresh; redirect back to dashboard
                if (-not $script:IsRefreshing) { Start-BackgroundRefresh }
                $context.Response.Redirect("http://$($context.Request.UserHostName)/defender")
                $context.Response.OutputStream.Close()
            }

            '/' {
                $context.Response.Redirect("http://$($context.Request.UserHostName)/defender")
                $context.Response.OutputStream.Close()
            }

            default {
                Send-HttpResponse -Context $context -Body '<html><body>404 Not Found</body></html>' -StatusCode 404
                Write-DashLog "404: $path" 'WARN'
            }
        }
    }
} finally {
    Write-DashLog 'Stopping listener…' 'WARN'
    $listener.Stop()
    $listener.Close()
    if ($script:RefreshJob) {
        Stop-Job $script:RefreshJob -Force -ErrorAction SilentlyContinue
        Remove-Job $script:RefreshJob -Force -ErrorAction SilentlyContinue
    }
    Write-DashLog 'Dashboard stopped.' 'WARN'
}

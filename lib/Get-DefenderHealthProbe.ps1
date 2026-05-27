<#
.SYNOPSIS
    Defender health probe — gathers Get-MpComputerStatus + Get-MpThreat from a
    remote endpoint and classifies the result.

.DESCRIPTION
    Called by Update-DefenderOffline post-install, by Show-DefenderStatus as
    part of fleet monitoring, and by Start-DefenderDashboard for the live
    web view. Single source of truth for what "healthy" means in this toolkit:
    every consumer sees the same classification labels and field names.

    The probe runs Get-MpComputerStatus to read the protection state and
    Get-MpThreat to surface recent threats. Both are executed in one WinRM
    round-trip via Invoke-DefenderRemote.

    The classification:
      Healthy         - real-time + AM service + behavior monitor + IOAV +
                        on-access protections all enabled, no recent threats
      Degraded        - any of the protection toggles disabled
      ThreatsDetected - protections OK but Get-MpThreat returned >= the
                        configured threshold within the window
      ProbeFailed     - the WinRM call itself errored (host unreachable,
                        Defender service stopped, etc.)

    Degraded wins over ThreatsDetected when both apply.

.NOTES
    Dot-source from each script that needs it. Requires Invoke-DefenderRemote
    to be in scope as well.

        . (Join-Path $PSScriptRoot 'lib\Invoke-DefenderRemote.ps1')
        . (Join-Path $PSScriptRoot 'lib\Get-DefenderHealthProbe.ps1')
#>


<#
.SYNOPSIS
    Run a Defender health probe against a remote endpoint.

.PARAMETER ComputerName
    Target endpoint. Mutually exclusive with -Session.

.PARAMETER Session
    Existing PSSession to reuse. Mutually exclusive with -ComputerName.

.PARAMETER Credential
    Only honored with -ComputerName.

.PARAMETER TimeoutSeconds
    Only honored with -ComputerName.

.PARAMETER ThreatWindowHours
    How far back to look for threats. Default 24.

.PARAMETER ThreatSpikeThreshold
    Number of threats within the window that trips the ThreatsDetected
    classification. Default 1 (any threat surfaces).

.OUTPUTS
    [pscustomobject] with fields:
      OverallStatus               'Healthy' | 'Degraded' | 'ThreatsDetected' | 'ProbeFailed'
      StatusReason                Short human-readable explanation for non-Healthy states
      RealTimeProtectionEnabled   [bool]
      AntimalwareServiceEnabled   [bool]
      AntivirusEnabled            [bool]
      BehaviorMonitorEnabled      [bool]
      IoavProtectionEnabled       [bool]
      OnAccessProtectionEnabled   [bool]
      AntivirusSignatureVersion   [string]
      RecentThreatCount           [int]
      RecentThreats               [object[]] — ThreatName, ThreatID, InitialDetectionTime, Resources
      ProbedAt                    [datetime]
      ProbeError                  [string] — populated only when OverallStatus = ProbeFailed
#>
function Get-DefenderHealthProbe {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ComputerName')]
        [string]$ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [pscredential]$Credential,

        [ValidateRange(5, 600)]
        [int]$TimeoutSeconds,

        [ValidateRange(1, 720)]
        [int]$ThreatWindowHours = 24,

        [ValidateRange(1, 10000)]
        [int]$ThreatSpikeThreshold = 1
    )

    $probeScript = {
        param([int]$WindowHours)
        $err = $null
        $status = $null
        $threats = @()
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
        } catch {
            $err = "Get-MpComputerStatus failed: $($_.Exception.Message)"
        }
        if (-not $err) {
            try {
                $cutoff = (Get-Date).AddHours(-$WindowHours)
                $allThreats = @(Get-MpThreat -ErrorAction SilentlyContinue)
                $threats = @($allThreats | Where-Object { $_.InitialDetectionTime -gt $cutoff } |
                    Select-Object ThreatName, ThreatID, InitialDetectionTime,
                                  @{ N = 'Resources'; E = { ($_.Resources -join '; ') } })
            } catch {
                # Threat enumeration failing isn't fatal; we still have the status.
                $threats = @()
            }
        }
        [pscustomobject]@{
            Status     = $status
            Threats    = $threats
            ProbeError = $err
            ProbedAt   = Get-Date
        }
    }

    $invokeArgs = @{
        ScriptBlock  = $probeScript
        ArgumentList = @($ThreatWindowHours)
    }
    if ($PSCmdlet.ParameterSetName -eq 'Session') {
        $invokeArgs.Session = $Session
    } else {
        $invokeArgs.ComputerName = $ComputerName
        if ($Credential)                                       { $invokeArgs.Credential     = $Credential }
        if ($PSBoundParameters.ContainsKey('TimeoutSeconds'))  { $invokeArgs.TimeoutSeconds = $TimeoutSeconds }
    }

    try {
        $raw = Invoke-DefenderRemote @invokeArgs
    } catch {
        return [pscustomobject]@{
            OverallStatus              = 'ProbeFailed'
            StatusReason               = "WinRM probe error: $($_.Exception.Message)"
            RealTimeProtectionEnabled  = $null
            AntimalwareServiceEnabled  = $null
            AntivirusEnabled           = $null
            BehaviorMonitorEnabled     = $null
            IoavProtectionEnabled      = $null
            OnAccessProtectionEnabled  = $null
            AntivirusSignatureVersion  = $null
            RecentThreatCount          = 0
            RecentThreats              = @()
            ProbedAt                   = Get-Date
            ProbeError                 = $_.Exception.Message
        }
    }

    if ($raw.ProbeError) {
        return [pscustomobject]@{
            OverallStatus              = 'ProbeFailed'
            StatusReason               = $raw.ProbeError
            RealTimeProtectionEnabled  = $null
            AntimalwareServiceEnabled  = $null
            AntivirusEnabled           = $null
            BehaviorMonitorEnabled     = $null
            IoavProtectionEnabled      = $null
            OnAccessProtectionEnabled  = $null
            AntivirusSignatureVersion  = $null
            RecentThreatCount          = 0
            RecentThreats              = @()
            ProbedAt                   = $raw.ProbedAt
            ProbeError                 = $raw.ProbeError
        }
    }

    $s = $raw.Status
    $threats = @($raw.Threats)

    # Build the disabled-protection list (Degraded reasons).
    $disabled = New-Object System.Collections.Generic.List[string]
    if (-not $s.RealTimeProtectionEnabled) { [void]$disabled.Add('real-time protection') }
    if (-not $s.AMServiceEnabled)          { [void]$disabled.Add('antimalware service') }
    if (-not $s.AntivirusEnabled)          { [void]$disabled.Add('antivirus engine') }
    if (-not $s.BehaviorMonitorEnabled)    { [void]$disabled.Add('behavior monitor') }
    if (-not $s.IoavProtectionEnabled)     { [void]$disabled.Add('IOAV protection') }
    if (-not $s.OnAccessProtectionEnabled) { [void]$disabled.Add('on-access protection') }

    if ($disabled.Count -gt 0) {
        $overall = 'Degraded'
        $reason  = "Disabled: $($disabled -join ', ')"
    } elseif ($threats.Count -ge $ThreatSpikeThreshold) {
        $overall = 'ThreatsDetected'
        $reason  = "$($threats.Count) threat(s) in last ${ThreatWindowHours}h (threshold: ${ThreatSpikeThreshold})"
    } else {
        $overall = 'Healthy'
        $reason  = $null
    }

    [pscustomobject]@{
        OverallStatus              = $overall
        StatusReason               = $reason
        RealTimeProtectionEnabled  = [bool]$s.RealTimeProtectionEnabled
        AntimalwareServiceEnabled  = [bool]$s.AMServiceEnabled
        AntivirusEnabled           = [bool]$s.AntivirusEnabled
        BehaviorMonitorEnabled     = [bool]$s.BehaviorMonitorEnabled
        IoavProtectionEnabled      = [bool]$s.IoavProtectionEnabled
        OnAccessProtectionEnabled  = [bool]$s.OnAccessProtectionEnabled
        AntivirusSignatureVersion  = [string]$s.AntivirusSignatureVersion
        RecentThreatCount          = $threats.Count
        RecentThreats              = $threats
        ProbedAt                   = $raw.ProbedAt
        ProbeError                 = $null
    }
}

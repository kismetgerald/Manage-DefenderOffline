<#
.SYNOPSIS
    Test-CanaryGate.ps1 - Staged-rollout health gate evaluator.

.DESCRIPTION
    Pure helper. Takes the result rows from the canary wave of an
    Update-DefenderOffline run and decides whether the production wave
    should proceed. Failure is counted only against HealthStatus
    Degraded/ProbeFailed; install failures, ThreatsDetected, and Excluded
    rows are excluded from the gate count.
#>

function Test-CanaryGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$WaveResults,

        [ValidateRange(0, 10000)]
        [int]$MaxFailures = 0
    )

    $rows = @($WaveResults | Where-Object { $_ })

    $degraded    = @($rows | Where-Object { $_.HealthStatus -eq 'Degraded'    })
    $probeFail   = @($rows | Where-Object { $_.HealthStatus -eq 'ProbeFailed' })
    $threats     = @($rows | Where-Object { $_.HealthStatus -eq 'ThreatsDetected' })
    $healthy     = @($rows | Where-Object { $_.HealthStatus -eq 'Healthy' })
    $installFail = @($rows | Where-Object { $_.Status -eq 'Failed' })

    $failureCount = $degraded.Count + $probeFail.Count

    [pscustomobject]@{
        Pass               = ($failureCount -le $MaxFailures)
        FailureCount       = $failureCount
        Threshold          = $MaxFailures
        DegradedCount      = $degraded.Count
        ProbeFailedCount   = $probeFail.Count
        ThreatsCount       = $threats.Count
        HealthyCount       = $healthy.Count
        InstallFailedCount = $installFail.Count
        Total              = $rows.Count
        DegradedHosts      = [string[]]@($degraded    | ForEach-Object { $_.ComputerName })
        ProbeFailedHosts   = [string[]]@($probeFail   | ForEach-Object { $_.ComputerName })
    }
}

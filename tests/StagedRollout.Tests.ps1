#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester test scopes share state via $script:')]
param()
<#
Tests for lib/Test-CanaryGate.ps1 — the staged-rollout health gate added in
v0.0.10. The gate counts only HealthStatus = Degraded or ProbeFailed against
MaxFailures. Install failures, ThreatsDetected, and Healthy rows do not count.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Test-CanaryGate.ps1')

    function script:Row {
        param(
            [string]$Name = 'HOST',
            [string]$Status = 'Success',
            [string]$HealthStatus = 'Healthy'
        )
        [pscustomobject]@{
            ComputerName      = $Name
            Status            = $Status
            HealthStatus      = $HealthStatus
            HealthReason      = ''
            RecentThreatCount = 0
        }
    }
}

Describe 'Test-CanaryGate' {

    Context 'Pass / fail decision' {

        It 'passes with all-healthy canary and threshold 0' {
            $rows = @(
                (Row 'H1' 'Success' 'Healthy'),
                (Row 'H2' 'Success' 'Healthy'),
                (Row 'H3' 'No Update Needed' 'Healthy')
            )
            $r = Test-CanaryGate -WaveResults $rows -MaxFailures 0
            $r.Pass         | Should -BeTrue
            $r.FailureCount | Should -Be 0
            $r.HealthyCount | Should -Be 3
        }

        It 'fails when one Degraded host exceeds threshold 0' {
            $rows = @(
                (Row 'H1' 'Success' 'Healthy'),
                (Row 'H2' 'Success' 'Degraded')
            )
            $r = Test-CanaryGate -WaveResults $rows -MaxFailures 0
            $r.Pass          | Should -BeFalse
            $r.FailureCount  | Should -Be 1
            $r.DegradedCount | Should -Be 1
            $r.DegradedHosts | Should -Be @('H2')
        }

        It 'passes when one Degraded host is at threshold 1' {
            $rows = @(
                (Row 'H1' 'Success' 'Healthy'),
                (Row 'H2' 'Success' 'Degraded')
            )
            $r = Test-CanaryGate -WaveResults $rows -MaxFailures 1
            $r.Pass         | Should -BeTrue
            $r.FailureCount | Should -Be 1
        }

        It 'fails when Degraded + ProbeFailed combined exceed threshold' {
            $rows = @(
                (Row 'H1' 'Success' 'Degraded'),
                (Row 'H2' 'Failed'  'ProbeFailed')
            )
            $r = Test-CanaryGate -WaveResults $rows -MaxFailures 1
            $r.Pass             | Should -BeFalse
            $r.FailureCount     | Should -Be 2
            $r.DegradedCount    | Should -Be 1
            $r.ProbeFailedCount | Should -Be 1
        }
    }

    Context 'What does NOT count against the gate' {

        It 'ignores install Failed rows when health is good' {
            # A row can have Status=Failed yet HealthStatus='' (probe didn't run)
            # or Healthy (probe ran on a recovered host). Either way the gate
            # is health-only by design.
            $rows = @(
                (Row 'H1' 'Failed'  ''),
                (Row 'H2' 'Success' 'Healthy')
            )
            $r = Test-CanaryGate -WaveResults $rows -MaxFailures 0
            $r.Pass               | Should -BeTrue
            $r.FailureCount       | Should -Be 0
            $r.InstallFailedCount | Should -Be 1
        }

        It 'does not halt on ThreatsDetected (pre-existing, not caused by the update)' {
            $rows = @(
                (Row 'H1' 'Success' 'ThreatsDetected'),
                (Row 'H2' 'Success' 'Healthy')
            )
            $r = Test-CanaryGate -WaveResults $rows -MaxFailures 0
            $r.Pass         | Should -BeTrue
            $r.FailureCount | Should -Be 0
            $r.ThreatsCount | Should -Be 1
        }
    }

    Context 'Edge cases' {

        It 'passes on an empty wave (no canary results)' {
            $r = Test-CanaryGate -WaveResults @() -MaxFailures 0
            $r.Pass         | Should -BeTrue
            $r.FailureCount | Should -Be 0
            $r.Total        | Should -Be 0
        }

        It 'returns a stable object shape for empty input' {
            $r = Test-CanaryGate -WaveResults @() -MaxFailures 0
            $r.PSObject.Properties.Name | Should -Contain 'DegradedHosts'
            $r.PSObject.Properties.Name | Should -Contain 'ProbeFailedHosts'
            ,$r.DegradedHosts    | Should -BeOfType [string[]]
            ,$r.ProbeFailedHosts | Should -BeOfType [string[]]
            $r.DegradedHosts.Count    | Should -Be 0
            $r.ProbeFailedHosts.Count | Should -Be 0
        }
    }
}

#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester test scopes share state via $script:')]
param()
<#
Tests for lib/Get-DefenderHealthProbe.ps1 — the post-update Defender health
probe added in v0.0.10.

The probe runs a scriptblock via Invoke-DefenderRemote that returns
Get-MpComputerStatus + a recent-threat list, then classifies the result as
Healthy / Degraded / ThreatsDetected / ProbeFailed.

We mock Invoke-DefenderRemote to return synthetic data so the classification
logic is exercised without a real WinRM call.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Invoke-DefenderRemote.ps1')
    . (Join-Path $script:RepoRoot 'lib\Get-DefenderHealthProbe.ps1')

    # All-on baseline used by the Healthy/ThreatsDetected tests
    function script:New-HealthyStatus {
        [pscustomobject]@{
            RealTimeProtectionEnabled  = $true
            AMServiceEnabled           = $true
            AntivirusEnabled           = $true
            BehaviorMonitorEnabled     = $true
            IoavProtectionEnabled      = $true
            OnAccessProtectionEnabled  = $true
            AntivirusSignatureVersion  = '1.451.122.0'
        }
    }
}

Describe 'Get-DefenderHealthProbe — classification' {

    Context 'Healthy path' {
        It 'returns Healthy when all protections are on and no threats' {
            Mock Invoke-DefenderRemote {
                [pscustomobject]@{
                    Status     = New-HealthyStatus
                    Threats    = @()
                    ProbeError = $null
                    ProbedAt   = Get-Date
                }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01'
            $r.OverallStatus              | Should -Be 'Healthy'
            $r.StatusReason               | Should -BeNullOrEmpty
            $r.AntivirusSignatureVersion  | Should -Be '1.451.122.0'
            $r.RecentThreatCount          | Should -Be 0
            $r.RealTimeProtectionEnabled  | Should -BeTrue
            $r.ProbeError                 | Should -BeNullOrEmpty
        }
    }

    Context 'Degraded path — protection toggle off' {
        It 'returns Degraded with reason when real-time protection is off' {
            Mock Invoke-DefenderRemote {
                $s = New-HealthyStatus
                $s.RealTimeProtectionEnabled = $false
                [pscustomobject]@{ Status = $s; Threats = @(); ProbeError = $null; ProbedAt = Get-Date }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01'
            $r.OverallStatus | Should -Be 'Degraded'
            $r.StatusReason  | Should -Match 'real-time protection'
        }

        It 'returns Degraded when antimalware service is stopped' {
            Mock Invoke-DefenderRemote {
                $s = New-HealthyStatus
                $s.AMServiceEnabled = $false
                [pscustomobject]@{ Status = $s; Threats = @(); ProbeError = $null; ProbedAt = Get-Date }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01'
            $r.OverallStatus | Should -Be 'Degraded'
            $r.StatusReason  | Should -Match 'antimalware service'
        }

        It 'lists every disabled protection in the reason' {
            Mock Invoke-DefenderRemote {
                $s = New-HealthyStatus
                $s.BehaviorMonitorEnabled    = $false
                $s.IoavProtectionEnabled     = $false
                $s.OnAccessProtectionEnabled = $false
                [pscustomobject]@{ Status = $s; Threats = @(); ProbeError = $null; ProbedAt = Get-Date }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01'
            $r.OverallStatus | Should -Be 'Degraded'
            $r.StatusReason  | Should -Match 'behavior monitor'
            $r.StatusReason  | Should -Match 'IOAV'
            $r.StatusReason  | Should -Match 'on-access'
        }
    }

    Context 'ThreatsDetected path' {
        It 'returns ThreatsDetected when threats meet the threshold' {
            Mock Invoke-DefenderRemote {
                [pscustomobject]@{
                    Status     = New-HealthyStatus
                    Threats    = @(
                        [pscustomobject]@{ ThreatName = 'EICAR_Test_File'; ThreatID = 2147519003; InitialDetectionTime = (Get-Date).AddHours(-2); Resources = 'C:\eicar.txt' }
                    )
                    ProbeError = $null
                    ProbedAt   = Get-Date
                }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01' -ThreatSpikeThreshold 1
            $r.OverallStatus      | Should -Be 'ThreatsDetected'
            $r.RecentThreatCount  | Should -Be 1
            $r.StatusReason       | Should -Match '1 threat'
        }

        It 'returns Healthy when threats are below the threshold' {
            Mock Invoke-DefenderRemote {
                [pscustomobject]@{
                    Status     = New-HealthyStatus
                    Threats    = @(
                        [pscustomobject]@{ ThreatName = 'EICAR_Test_File'; ThreatID = 1; InitialDetectionTime = (Get-Date).AddHours(-1); Resources = 'C:\a.txt' },
                        [pscustomobject]@{ ThreatName = 'EICAR_Test_File'; ThreatID = 2; InitialDetectionTime = (Get-Date).AddHours(-1); Resources = 'C:\b.txt' }
                    )
                    ProbeError = $null
                    ProbedAt   = Get-Date
                }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01' -ThreatSpikeThreshold 5
            $r.OverallStatus      | Should -Be 'Healthy'
            $r.RecentThreatCount  | Should -Be 2
        }
    }

    Context 'Degraded wins over ThreatsDetected when both apply' {
        It 'returns Degraded even when threats are above threshold' {
            Mock Invoke-DefenderRemote {
                $s = New-HealthyStatus
                $s.RealTimeProtectionEnabled = $false
                [pscustomobject]@{
                    Status     = $s
                    Threats    = @(1..10 | ForEach-Object {
                        [pscustomobject]@{ ThreatName = "T$_"; ThreatID = $_; InitialDetectionTime = (Get-Date).AddMinutes(-$_); Resources = "C:\$_.txt" }
                    })
                    ProbeError = $null
                    ProbedAt   = Get-Date
                }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01' -ThreatSpikeThreshold 1
            $r.OverallStatus      | Should -Be 'Degraded'
            $r.RecentThreatCount  | Should -Be 10
            $r.StatusReason       | Should -Match 'real-time protection'
        }
    }

    Context 'ProbeFailed path' {
        It 'returns ProbeFailed when Invoke-DefenderRemote throws' {
            Mock Invoke-DefenderRemote {
                throw 'WinRM connection refused'
            }
            $r = Get-DefenderHealthProbe -ComputerName 'OFFLINE01'
            $r.OverallStatus | Should -Be 'ProbeFailed'
            $r.StatusReason  | Should -Match 'WinRM connection refused'
            $r.ProbeError    | Should -Match 'WinRM connection refused'
            $r.RealTimeProtectionEnabled | Should -BeNullOrEmpty
        }

        It 'returns ProbeFailed when the remote scriptblock reports ProbeError' {
            Mock Invoke-DefenderRemote {
                [pscustomobject]@{
                    Status     = $null
                    Threats    = @()
                    ProbeError = 'Get-MpComputerStatus failed: service stopped'
                    ProbedAt   = Get-Date
                }
            }
            $r = Get-DefenderHealthProbe -ComputerName 'TEST01'
            $r.OverallStatus | Should -Be 'ProbeFailed'
            $r.StatusReason  | Should -Match 'service stopped'
        }
    }
}

Describe 'Get-DefenderHealthClassification — pure classifier' {
    # Direct tests on the extracted classifier. Get-DefenderHealthProbe
    # delegates here; Show-DefenderStatus calls it on its own inline-collected
    # data. Single source of truth — these tests are the contract.

    It 'returns Healthy when all six toggles are on and no threats' {
        $r = Get-DefenderHealthClassification `
            -RealTimeProtectionEnabled  $true  -AntimalwareServiceEnabled  $true `
            -AntivirusEnabled           $true  -BehaviorMonitorEnabled     $true `
            -IoavProtectionEnabled      $true  -OnAccessProtectionEnabled  $true `
            -RecentThreatCount          0
        $r.OverallStatus | Should -Be 'Healthy'
        $r.StatusReason  | Should -BeNullOrEmpty
    }

    It 'returns Degraded with a list of disabled protections' {
        $r = Get-DefenderHealthClassification `
            -RealTimeProtectionEnabled  $false -AntimalwareServiceEnabled  $true `
            -AntivirusEnabled           $true  -BehaviorMonitorEnabled     $false `
            -IoavProtectionEnabled      $true  -OnAccessProtectionEnabled  $true `
            -RecentThreatCount          0
        $r.OverallStatus | Should -Be 'Degraded'
        $r.StatusReason  | Should -Match 'real-time protection'
        $r.StatusReason  | Should -Match 'behavior monitor'
    }

    It 'returns ThreatsDetected when threat count meets threshold' {
        $r = Get-DefenderHealthClassification `
            -RealTimeProtectionEnabled  $true  -AntimalwareServiceEnabled  $true `
            -AntivirusEnabled           $true  -BehaviorMonitorEnabled     $true `
            -IoavProtectionEnabled      $true  -OnAccessProtectionEnabled  $true `
            -RecentThreatCount          3      -ThreatSpikeThreshold       3
        $r.OverallStatus | Should -Be 'ThreatsDetected'
        $r.StatusReason  | Should -Match '3 threat'
    }

    It 'prefers Degraded over ThreatsDetected when both apply' {
        $r = Get-DefenderHealthClassification `
            -RealTimeProtectionEnabled  $false -AntimalwareServiceEnabled  $true `
            -AntivirusEnabled           $true  -BehaviorMonitorEnabled     $true `
            -IoavProtectionEnabled      $true  -OnAccessProtectionEnabled  $true `
            -RecentThreatCount          10     -ThreatSpikeThreshold       1
        $r.OverallStatus | Should -Be 'Degraded'
    }

    It 'returns Healthy when threats are below threshold' {
        $r = Get-DefenderHealthClassification `
            -RealTimeProtectionEnabled  $true  -AntimalwareServiceEnabled  $true `
            -AntivirusEnabled           $true  -BehaviorMonitorEnabled     $true `
            -IoavProtectionEnabled      $true  -OnAccessProtectionEnabled  $true `
            -RecentThreatCount          2      -ThreatSpikeThreshold       5
        $r.OverallStatus | Should -Be 'Healthy'
    }
}

Describe 'Get-DefenderHealthProbe — parameter surface' {

    It 'requires either -ComputerName or -Session' {
        # Pester-friendly param assertion via Get-Command
        $cmd = Get-Command Get-DefenderHealthProbe
        $cmd.ParameterSets.Name | Should -Contain 'ComputerName'
        $cmd.ParameterSets.Name | Should -Contain 'Session'
    }

    It 'validates ThreatWindowHours in 1..720' {
        $cmd = Get-Command Get-DefenderHealthProbe
        $attr = $cmd.Parameters['ThreatWindowHours'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
        $attr.MinRange | Should -Be 1
        $attr.MaxRange | Should -Be 720
    }

    It 'defaults ThreatWindowHours to 24' {
        # Function default — read via the parameter's default value string
        # (Get-Help is the only PS-native way to surface defaults from a script function)
        $help = Get-Help Get-DefenderHealthProbe -Parameter ThreatWindowHours
        $help.defaultValue | Should -Be '24'
    }

    It 'defaults ThreatSpikeThreshold to 1' {
        $help = Get-Help Get-DefenderHealthProbe -Parameter ThreatSpikeThreshold
        $help.defaultValue | Should -Be '1'
    }
}

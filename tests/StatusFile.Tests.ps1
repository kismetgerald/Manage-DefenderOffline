#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for the conf/dashboard.status file contract.

The status file is written by Start-DefenderDashboard.ps1 at startup and
deleted on clean shutdown. It uses the same key=value format as config.conf
so Read-ConfigFile can parse it. The installer's -StartImmediately probe
reads it to discover the actual bound port.

The write logic is inline in Start-DefenderDashboard.ps1 (not a separate
function), so these tests cover the parse side of the contract — given a
status file in the documented shape, Read-ConfigFile must return the
expected keys with the expected values.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Start-DefenderDashboard.ps1')
}

Describe 'conf/dashboard.status contract' {

    Context 'Read-ConfigFile parses the documented shape' {

        It 'parses Port, PrimaryPort, IsFallback, StartTime, ProcessId, Hostname' {
            $statusPath = Join-Path $TestDrive 'dashboard.status'
            Set-Content $statusPath -Value @(
                '# Manage-DefenderOffline Dashboard – Runtime Status'
                '# Written by Start-DefenderDashboard.ps1 at each startup.'
                'Port=8090'
                'PrimaryPort=8080'
                'IsFallback=True'
                'StartTime=2026-05-25 09:39:07'
                'ProcessId=12345'
                'Hostname=HOME-DH01'
            )
            $result = Read-ConfigFile -Path $statusPath
            $result['Port']        | Should -Be '8090'
            $result['PrimaryPort'] | Should -Be '8080'
            $result['IsFallback']  | Should -Be 'True'
            $result['ProcessId']   | Should -Be '12345'
            $result['Hostname']    | Should -Be 'HOME-DH01'
            $result['StartTime']   | Should -Be '2026-05-25 09:39:07'
        }

        It 'is case-insensitive on key lookup (installer relies on this)' {
            $statusPath = Join-Path $TestDrive 'dashboard.status'
            Set-Content $statusPath -Value 'Port=8443'
            $result = Read-ConfigFile -Path $statusPath
            $result['port'] | Should -Be '8443'
            $result['PORT'] | Should -Be '8443'
        }
    }

    Context 'IsFallback semantics' {

        It "treats 'True' (string) as the truthy value" {
            $statusPath = Join-Path $TestDrive 'dashboard.status'
            Set-Content $statusPath -Value 'IsFallback=True'
            $result = Read-ConfigFile -Path $statusPath
            # The installer compares with: if ($runtimeStatus['IsFallback'] -eq 'True')
            ($result['IsFallback'] -eq 'True') | Should -BeTrue
        }

        It "treats 'False' (string) as the falsy value" {
            $statusPath = Join-Path $TestDrive 'dashboard.status'
            Set-Content $statusPath -Value 'IsFallback=False'
            $result = Read-ConfigFile -Path $statusPath
            ($result['IsFallback'] -eq 'True') | Should -BeFalse
        }
    }

    Context 'Missing status file' {

        It 'returns an empty dictionary so the installer can detect "not yet started"' {
            $missing = Join-Path $TestDrive 'no-status-file-here.status'
            $result  = Read-ConfigFile -Path $missing
            $result.Count | Should -Be 0
        }
    }
}

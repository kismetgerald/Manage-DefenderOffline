#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Pester tests deliberately assign variables that the dot-sourced function
# reads via dynamic scoping — PSScriptAnalyzer can't see this and flags
# them as unused. Suppress at file scope.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Variables consumed by dot-sourced Resolve-TargetComputers via dynamic scope')]
param()
<#
Tests for the hosts.conf parsing path in Resolve-TargetComputers.
Resolve-TargetComputers has three discovery paths in priority order:
  1. -ComputerName parameter
  2. hosts.conf file
  3. Active Directory auto-discovery

This file exercises path 2 (with one test for the -ComputerName
precedence). Path 3 (AD) is exercised by Classification.Tests.ps1.

Note on variable scoping: Resolve-TargetComputers reads $HostsFile,
$ComputerName, and $ADCredential from script scope (these are bound at
script-parse time). PowerShell uses dynamic scoping for function variable
lookup, so when our test code sets these in its own scope before calling
the function, the function finds the test-scope values first.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Update-DefenderOffline.ps1')
}

Describe 'Resolve-TargetComputers hosts.conf path' {

    Context 'Basic parsing' {

        It 'reads one hostname per line' {
            $HostsFile    = Join-Path $TestDrive 'hosts.conf'
            $ComputerName = $null
            $ADCredential = $null
            Set-Content $HostsFile -Value @(
                'WIN10-01'
                'SRV-01'
                'DC01'
            )
            $result = Resolve-TargetComputers
            $result.Count | Should -Be 3
            $result | Should -Contain 'WIN10-01'
            $result | Should -Contain 'SRV-01'
            $result | Should -Contain 'DC01'
        }

        It 'returns hostnames in uppercase' {
            $HostsFile    = Join-Path $TestDrive 'hosts.conf'
            $ComputerName = $null
            $ADCredential = $null
            Set-Content $HostsFile -Value @(
                'win10-01'
                'srv-01'
            )
            $result = Resolve-TargetComputers
            $result | Should -Contain 'WIN10-01'
            $result | Should -Contain 'SRV-01'
        }

        It 'trims whitespace around hostnames' {
            $HostsFile    = Join-Path $TestDrive 'hosts.conf'
            $ComputerName = $null
            $ADCredential = $null
            Set-Content $HostsFile -Value @(
                '   WIN10-01   '
                "`tSRV-01`t"
            )
            $result = Resolve-TargetComputers
            $result | Should -Contain 'WIN10-01'
            $result | Should -Contain 'SRV-01'
        }
    }

    Context 'Comments and blank lines' {

        It 'skips lines starting with #' {
            $HostsFile    = Join-Path $TestDrive 'hosts.conf'
            $ComputerName = $null
            $ADCredential = $null
            Set-Content $HostsFile -Value @(
                '# This is the production fleet'
                'WIN10-01'
                '# WIN10-02 is offline, commented out'
                'SRV-01'
            )
            $result = Resolve-TargetComputers
            $result.Count | Should -Be 2
            $result | Should -Not -Contain 'WIN10-02'
        }

        It 'skips indented comment lines' {
            $HostsFile    = Join-Path $TestDrive 'hosts.conf'
            $ComputerName = $null
            $ADCredential = $null
            Set-Content $HostsFile -Value @(
                '   # indented comment'
                'WIN10-01'
            )
            $result = Resolve-TargetComputers
            $result.Count | Should -Be 1
        }

        It 'skips blank and whitespace-only lines' {
            $HostsFile    = Join-Path $TestDrive 'hosts.conf'
            $ComputerName = $null
            $ADCredential = $null
            Set-Content $HostsFile -Value @(
                ''
                'WIN10-01'
                '   '
                "`t"
                'SRV-01'
                ''
            )
            $result = Resolve-TargetComputers
            $result.Count | Should -Be 2
        }
    }

    Context '-ComputerName parameter takes precedence' {

        It 'returns the CLI list, not hosts.conf, when -ComputerName is set' {
            $HostsFile    = Join-Path $TestDrive 'hosts.conf'
            $ComputerName = @('FROM-CLI-01', 'FROM-CLI-02')
            $ADCredential = $null
            Set-Content $HostsFile -Value @(
                'FROM-HOSTS-FILE-01'
                'FROM-HOSTS-FILE-02'
            )
            $result = Resolve-TargetComputers
            $result | Should -Contain 'FROM-CLI-01'
            $result | Should -Contain 'FROM-CLI-02'
            $result | Should -Not -Contain 'FROM-HOSTS-FILE-01'
        }
    }
}

#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for lib/Get-PortBusyDiagnostic.ps1 — the helper that explains *why*
a TCP port is unavailable.

We can't reliably create a real PID-4-System listener in a unit test, so
Get-NetTCPConnection is mocked to synthesise the cases we care about:
HTTP.sys orphan (PID 4), normal userland process, and the no-enumeration
edge case.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Get-PortBusyDiagnostic.ps1')

    function script:New-FakeTcpConnection {
        param([int]$PidValue)
        [pscustomobject]@{
            LocalPort      = 8443
            State          = 'Listen'
            OwningProcess  = $PidValue
        }
    }
}

Describe 'lib/Get-PortBusyDiagnostic.ps1' {

    Context 'PID 4 / HTTP.sys orphan (the v0.0.19 lab pass case)' {

        It 'surfaces the HTTP.sys-specific remediation when the holder is PID 4' {
            Mock Get-NetTCPConnection { New-FakeTcpConnection -PidValue 4 }

            $result = Get-PortBusyDiagnostic -BusyPort 8443
            $result | Should -Match 'HTTP\.sys'
            $result | Should -Match 'PID 4'
            $result | Should -Match 'Stop-Service http -Force'
            $result | Should -Match 'Start-Service http'
            $result | Should -Match '8443'
        }

        It 'does not call Get-Process when PID 4 is detected (no userland lookup needed)' {
            Mock Get-NetTCPConnection { New-FakeTcpConnection -PidValue 4 }
            Mock Get-Process { throw 'should not be called' }

            { Get-PortBusyDiagnostic -BusyPort 8443 } | Should -Not -Throw
        }
    }

    Context 'Userland process holds the port' {

        It 'names the process when Get-Process finds the PID' {
            Mock Get-NetTCPConnection { New-FakeTcpConnection -PidValue 1234 }
            Mock Get-Process { [pscustomobject]@{ ProcessName = 'Tomcat' } }

            $result = Get-PortBusyDiagnostic -BusyPort 8443
            $result | Should -Match 'PID 1234'
            $result | Should -Match 'Tomcat'
            $result | Should -Match '8443'
        }

        It 'falls back to PID-only message when Get-Process returns nothing' {
            Mock Get-NetTCPConnection { New-FakeTcpConnection -PidValue 9999 }
            Mock Get-Process { $null }

            $result = Get-PortBusyDiagnostic -BusyPort 8443
            $result | Should -Match 'PID 9999'
            $result | Should -Match 'process info unavailable'
        }
    }

    Context 'No enumerable owner (kernel-driver or transient state)' {

        It 'returns the no-listener-enumerated message when Get-NetTCPConnection finds nothing' {
            Mock Get-NetTCPConnection { @() }

            $result = Get-PortBusyDiagnostic -BusyPort 8443
            $result | Should -Match 'no listener could be enumerated'
            $result | Should -Match 'HTTP\.sys'
            $result | Should -Match 'Stop-Service http'
        }
    }

    Context 'Failure tolerance' {

        It 'returns $null when Get-NetTCPConnection throws (does not propagate)' {
            Mock Get-NetTCPConnection { throw 'simulated cmdlet failure' }

            $result = Get-PortBusyDiagnostic -BusyPort 8443
            $result | Should -BeNullOrEmpty
        }
    }
}

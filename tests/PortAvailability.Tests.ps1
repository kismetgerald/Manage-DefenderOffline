#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for Test-PortFree and Find-AvailablePort in Start-DefenderDashboard.ps1.

These tests use real TcpListener instances on loopback to create a deterministic
"port is taken" state. We pick ports in the ephemeral range to avoid clashing
with anything operators have installed.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Start-DefenderDashboard.ps1')

    function Reserve-TestPort {
        param([int]$Port)
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        return $listener
    }

    function Release-TestPort {
        param([System.Net.Sockets.TcpListener]$Listener)
        if ($Listener) { try { $Listener.Stop() } catch {} }
    }

    # Pick high ports unlikely to collide with anything else on the CI runner.
    $script:PrimaryPort  = 47100
    $script:FallbackPort = 47200
}

Describe 'Test-PortFree' {

    It 'returns true when the port is free' {
        Test-PortFree -TestPort $script:PrimaryPort | Should -BeTrue
    }

    It 'returns false when the port is in use' {
        $blocker = Reserve-TestPort -Port $script:PrimaryPort
        try {
            Test-PortFree -TestPort $script:PrimaryPort | Should -BeFalse
        } finally {
            Release-TestPort -Listener $blocker
        }
    }

    It 'returns true again after the port is released' {
        $blocker = Reserve-TestPort -Port $script:PrimaryPort
        Release-TestPort -Listener $blocker
        # Small delay so the OS releases the bind
        Start-Sleep -Milliseconds 200
        Test-PortFree -TestPort $script:PrimaryPort | Should -BeTrue
    }
}

Describe 'Find-AvailablePort' {

    It 'returns the primary when it is free' {
        $result = Find-AvailablePort -Primary $script:PrimaryPort -Fallback $script:FallbackPort
        $result.Port        | Should -Be $script:PrimaryPort
        $result.IsFallback  | Should -BeFalse
        $result.PrimaryPort | Should -Be $script:PrimaryPort
    }

    It 'falls back when the primary is in use' {
        $blocker = Reserve-TestPort -Port $script:PrimaryPort
        try {
            $result = Find-AvailablePort -Primary $script:PrimaryPort -Fallback $script:FallbackPort
            $result.Port        | Should -Be $script:FallbackPort
            $result.IsFallback  | Should -BeTrue
            $result.PrimaryPort | Should -Be $script:PrimaryPort
        } finally {
            Release-TestPort -Listener $blocker
        }
    }

    It 'walks sequentially past a busy fallback to the next free port' {
        $blockerPrimary  = Reserve-TestPort -Port $script:PrimaryPort
        $blockerFallback = Reserve-TestPort -Port $script:FallbackPort
        try {
            $result = Find-AvailablePort -Primary $script:PrimaryPort -Fallback $script:FallbackPort
            $result.Port        | Should -Be ($script:FallbackPort + 1)
            $result.IsFallback  | Should -BeTrue
            $result.PrimaryPort | Should -Be $script:PrimaryPort
        } finally {
            Release-TestPort -Listener $blockerPrimary
            Release-TestPort -Listener $blockerFallback
        }
    }
}

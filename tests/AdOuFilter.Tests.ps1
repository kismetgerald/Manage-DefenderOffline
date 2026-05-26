#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for lib/Get-DefenderComputers.ps1 — the shared OU-filtered AD
discovery helper used by Update-DefenderOffline, Show-DefenderStatus,
and Start-DefenderDashboard.

The helper has three orthogonal behaviors to cover:
  1. SearchBase string parsing (semicolon split, trim, empty handling)
  2. Per-DN status reporting and union/dedupe of results
  3. RSAT vs ADSI dispatch (we mock Get-Module / Import-Module / Get-ADComputer)

All AD calls are mocked. The 'ActiveDirectory module is available' code
path is the one exercised here; the ADSI fallback uses .NET types
([adsisearcher], DirectoryEntry, DirectorySearcher) which are harder to
mock — those paths are validated by the maintainer during live-fire.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Get-DefenderComputers.ps1')

    # Stub Get-ADComputer when the test host doesn't have RSAT installed.
    # Pester's Mock requires the underlying command to already exist; without
    # this, the mock setup itself errors with "Could not find Command".
    if (-not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) {
        function global:Get-ADComputer {
            param(
                [string]$Filter,
                [string[]]$Properties,
                [string]$SearchBase,
                [string]$SearchScope,
                [pscredential]$Credential
            )
            throw 'Get-ADComputer stub: should always be mocked in tests.'
        }
    }

    # Helper: synthesize Get-ADComputer responses keyed by SearchBase. The
    # mock returns objects shaped like Get-ADComputer's output (Name property)
    # so the helper's Select-Object -ExpandProperty Name works.
    function script:Set-AdMockResponses {
        param([hashtable]$ResponseMap)
        # ResponseMap keys are SearchBase strings (or '' for whole-domain);
        # values are string[] of computer names to return.
        $script:AdMockMap = $ResponseMap
        Mock Get-Module    { [pscustomobject]@{ Name = 'ActiveDirectory' } } -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Import-Module { } -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADComputer {
            param(
                [string]$Filter,
                [string[]]$Properties,
                [string]$SearchBase,
                [string]$SearchScope,
                [pscredential]$Credential
            )
            $key = if ($SearchBase) { $SearchBase } else { '' }
            if (-not $script:AdMockMap.ContainsKey($key)) {
                throw "Cannot find object with identity '$key' under: 'DC=test,DC=local'."
            }
            $script:AdMockMap[$key] | ForEach-Object {
                [pscustomobject]@{ Name = $_ }
            }
        }
    }
}

AfterAll {
    # Tear down the global stub so it doesn't pollute the shell session.
    if (Test-Path Function:\global:Get-ADComputer) {
        Remove-Item Function:\global:Get-ADComputer -ErrorAction SilentlyContinue
    }
}

Describe 'Get-DefenderComputers — search-base parsing' {

    It 'treats empty SearchBase as whole-domain (one unfiltered pass)' {
        Set-AdMockResponses @{ '' = @('WS01', 'WS02', 'SRV01') }
        $r = Get-DefenderComputers -SearchBase ''
        $r.WasFiltered          | Should -BeFalse
        $r.SearchBases.Count    | Should -Be 1
        $r.SearchBases[0].DN    | Should -Be '(whole domain)'
        $r.SearchBases[0].Resolved | Should -BeTrue
        $r.Computers.Count      | Should -Be 3
    }

    It 'treats whitespace-only SearchBase as whole-domain' {
        Set-AdMockResponses @{ '' = @('WS01') }
        $r = Get-DefenderComputers -SearchBase '   '
        $r.WasFiltered | Should -BeFalse
    }

    It 'splits on semicolons (commas inside DNs are preserved)' {
        Set-AdMockResponses @{
            'OU=A,DC=test,DC=local' = @('A-WS01', 'A-WS02')
            'OU=B,DC=test,DC=local' = @('B-WS01')
        }
        $r = Get-DefenderComputers -SearchBase 'OU=A,DC=test,DC=local;OU=B,DC=test,DC=local'
        $r.WasFiltered          | Should -BeTrue
        $r.SearchBases.Count    | Should -Be 2
        ($r.SearchBases | Where-Object Resolved).Count | Should -Be 2
        $r.Computers.Count      | Should -Be 3
        $r.Computers            | Should -Contain 'A-WS01'
        $r.Computers            | Should -Contain 'B-WS01'
    }

    It 'trims whitespace and tolerates empty segments' {
        Set-AdMockResponses @{
            'OU=A,DC=test,DC=local' = @('A1')
            'OU=B,DC=test,DC=local' = @('B1')
        }
        $r = Get-DefenderComputers -SearchBase '  OU=A,DC=test,DC=local ; ; OU=B,DC=test,DC=local  ;'
        $r.SearchBases.Count | Should -Be 2
    }
}

Describe 'Get-DefenderComputers — union and deduplication' {

    It 'deduplicates computers that appear in more than one OU' {
        Set-AdMockResponses @{
            'OU=Servers,DC=test,DC=local'   = @('DUAL01', 'SRVONLY01')
            'OU=DCs,DC=test,DC=local'       = @('DUAL01', 'DCONLY01')
        }
        $r = Get-DefenderComputers -SearchBase 'OU=Servers,DC=test,DC=local;OU=DCs,DC=test,DC=local'
        $r.Computers.Count            | Should -Be 3
        @($r.Computers | Where-Object { $_ -eq 'DUAL01' }).Count | Should -Be 1
    }

    It 'returns sorted, distinct names' {
        Set-AdMockResponses @{
            'OU=A,DC=test,DC=local' = @('ZZZ', 'AAA', 'mmm')
        }
        $r = Get-DefenderComputers -SearchBase 'OU=A,DC=test,DC=local'
        $r.Computers[0] | Should -Be 'AAA'
        $r.Computers[1] | Should -Be 'mmm'
        $r.Computers[2] | Should -Be 'ZZZ'
    }

    It 'is case-insensitive when deduplicating' {
        Set-AdMockResponses @{
            'OU=A,DC=test,DC=local' = @('Host01', 'host01', 'HOST01')
        }
        $r = Get-DefenderComputers -SearchBase 'OU=A,DC=test,DC=local'
        $r.Computers.Count | Should -Be 1
    }
}

Describe 'Get-DefenderComputers — hybrid validation' {

    It 'records per-DN status in the result (resolved + unresolved mixed)' {
        Set-AdMockResponses @{
            'OU=Good,DC=test,DC=local' = @('GOOD-WS01', 'GOOD-WS02')
            # 'OU=Bad,DC=test,DC=local' deliberately not in the map -> mock throws
        }
        $r = Get-DefenderComputers -SearchBase 'OU=Good,DC=test,DC=local;OU=Bad,DC=test,DC=local'
        $r.SearchBases.Count                                     | Should -Be 2
        # @(...).Count forces array semantics so .Count returns the filter
        # result size, not the unwrapped object's own .Count property.
        $resolved   = @($r.SearchBases | Where-Object Resolved)
        $unresolved = @($r.SearchBases | Where-Object { -not $_.Resolved })
        $resolved.Count                                          | Should -Be 1
        $resolved[0].DN                                          | Should -Be 'OU=Good,DC=test,DC=local'
        $resolved[0].Count                                       | Should -Be 2
        $unresolved.Count                                        | Should -Be 1
        $unresolved[0].DN                                        | Should -Be 'OU=Bad,DC=test,DC=local'
        $unresolved[0].Error                                     | Should -Match 'Cannot find object'
        $r.Computers.Count                                       | Should -Be 2
    }

    It 'does NOT throw when at least one DN resolves (caller decides to WARN)' {
        Set-AdMockResponses @{
            'OU=Good,DC=test,DC=local' = @('GOOD-WS01')
        }
        # 'OU=Bad,...' is missing from the map; mock throws for it.
        { Get-DefenderComputers -SearchBase 'OU=Good,DC=test,DC=local;OU=Bad,DC=test,DC=local' } |
            Should -Not -Throw
    }

    It 'does NOT throw even when ALL DNs fail (caller decides to hard-fail)' {
        # Mock map is empty; every SearchBase will throw inside the mock.
        Set-AdMockResponses @{}
        $r = Get-DefenderComputers -SearchBase 'OU=Bad1,DC=test,DC=local;OU=Bad2,DC=test,DC=local'
        ($r.SearchBases | Where-Object Resolved).Count    | Should -Be 0
        $r.Computers.Count                                | Should -Be 0
    }
}

Describe 'Get-DefenderComputers — RSAT dispatch' {

    It 'reports UsedAdModule=true when the ActiveDirectory module is present' {
        Set-AdMockResponses @{ '' = @('WS01') }
        $r = Get-DefenderComputers -SearchBase ''
        $r.UsedAdModule | Should -BeTrue
    }

    It 'passes -SearchBase and -SearchScope Subtree to Get-ADComputer when filtered' {
        Set-AdMockResponses @{ 'OU=A,DC=test,DC=local' = @('WS01') }
        Get-DefenderComputers -SearchBase 'OU=A,DC=test,DC=local' | Out-Null
        Should -Invoke Get-ADComputer -ParameterFilter {
            $SearchBase  -eq 'OU=A,DC=test,DC=local' -and
            $SearchScope -eq 'Subtree'
        }
    }

    It 'does NOT pass -SearchBase to Get-ADComputer when whole-domain' {
        Set-AdMockResponses @{ '' = @('WS01') }
        Get-DefenderComputers -SearchBase '' | Out-Null
        Should -Invoke Get-ADComputer -ParameterFilter {
            -not $PSBoundParameters.ContainsKey('SearchBase')
        }
    }
}

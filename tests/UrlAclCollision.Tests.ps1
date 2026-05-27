#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester test scopes share state via $script:')]
param()
<#
Tests for lib/Test-UrlAclCollision.ps1 — added in v0.0.12 to diagnose
HTTP redirect-listener bind failures caused by pre-existing URL-ACL
reservations. Parser is exercised with synthetic netsh output (no
actual netsh shell-out).
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Test-UrlAclCollision.ps1')

    # Single-owner reservation (typical case — one process registered the URL ACL).
    $script:NetshSingleOwner = @(
        ''
        'URL Reservations:'
        '-----------------'
        ''
        '    Reserved URL            : http://+:8080/'
        '        User: NT AUTHORITY\NetworkService'
        '            Listen: Yes'
        '            Delegate: No'
        '            SDDL: D:(A;;GX;;;NS)'
        ''
    )

    # Two-owner reservation (rare — multiple SIDs in the SDDL).
    $script:NetshMultiOwner = @(
        ''
        '    Reserved URL            : http://+:8080/'
        '        User: BUILTIN\Administrators'
        '            Listen: Yes'
        '            Delegate: No'
        '        User: NT AUTHORITY\NetworkService'
        '            Listen: Yes'
        '            Delegate: No'
        '        SDDL: D:(A;;GX;;;BA)(A;;GX;;;NS)'
        ''
    )

    # No matching reservation — netsh returns a friendly "not found" message.
    $script:NetshNoReservation = @(
        ''
        'The system cannot find the file specified.'
        ''
    )

    # SDDL-only output with no parseable User line. Should yield no owners.
    $script:NetshSddlOnly = @(
        ''
        '    Reserved URL            : http://+:9999/'
        '        SDDL: D:(A;;GX;;;LS)'
        ''
    )
}

Describe 'Get-NetshUrlAclOwners' {

    It 'extracts a single owner from typical netsh output' {
        $owners = Get-NetshUrlAclOwners -NetshOutput $script:NetshSingleOwner
        $owners | Should -HaveCount 1
        $owners[0] | Should -Be 'NT AUTHORITY\NetworkService'
    }

    It 'extracts multiple owners and de-duplicates' {
        $owners = Get-NetshUrlAclOwners -NetshOutput $script:NetshMultiOwner
        $owners | Should -HaveCount 2
        $owners | Should -Contain 'BUILTIN\Administrators'
        $owners | Should -Contain 'NT AUTHORITY\NetworkService'
    }

    It 'returns an empty array when no reservation exists' {
        $owners = Get-NetshUrlAclOwners -NetshOutput $script:NetshNoReservation
        $owners | Should -BeNullOrEmpty
    }

    It 'returns an empty array when output is SDDL-only (no User: line)' {
        $owners = Get-NetshUrlAclOwners -NetshOutput $script:NetshSddlOnly
        $owners | Should -BeNullOrEmpty
    }

    It 'returns an empty array for null input' {
        ,(Get-NetshUrlAclOwners -NetshOutput $null) | Should -BeOfType [string[]]
        (Get-NetshUrlAclOwners -NetshOutput $null).Count | Should -Be 0
    }

    It 'returns an empty array for empty input' {
        (Get-NetshUrlAclOwners -NetshOutput @()).Count | Should -Be 0
    }
}

Describe 'Test-UrlAclCollision' {

    Context 'HasCollision = $true' {
        It 'reports a single conflicting owner' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshSingleOwner
            $r.HasCollision | Should -BeTrue
            $r.Owners       | Should -HaveCount 1
            $r.Owners[0]    | Should -Be 'NT AUTHORITY\NetworkService'
            $r.Url          | Should -Be 'http://+:8080/'
            $r.Scheme       | Should -Be 'http'
            $r.Port         | Should -Be 8080
        }

        It 'reports multiple conflicting owners' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshMultiOwner
            $r.HasCollision | Should -BeTrue
            $r.Owners       | Should -HaveCount 2
        }
    }

    Context 'HasCollision = $false' {
        It 'reports no collision when netsh returns the not-found message' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshNoReservation
            $r.HasCollision | Should -BeFalse
            $r.Owners.Count | Should -Be 0
        }

        It 'reports no collision for SDDL-only output' {
            $r = Test-UrlAclCollision -Port 9999 -NetshOutput $script:NetshSddlOnly
            $r.HasCollision | Should -BeFalse
        }
    }

    Context 'Scheme handling' {
        It 'builds the right URL for https' {
            $r = Test-UrlAclCollision -Port 8443 -Scheme https -NetshOutput @()
            $r.Url    | Should -Be 'https://+:8443/'
            $r.Scheme | Should -Be 'https'
        }
    }

    Context 'Output shape' {
        It 'always emits the same property set' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput @()
            $names = $r.PSObject.Properties.Name
            $names | Should -Contain 'HasCollision'
            $names | Should -Contain 'Owners'
            $names | Should -Contain 'Url'
            $names | Should -Contain 'Port'
            $names | Should -Contain 'Scheme'
        }
    }
}

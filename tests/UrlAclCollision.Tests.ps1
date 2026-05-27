#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester test scopes share state via $script:')]
param()
<#
Tests for lib/Test-UrlAclCollision.ps1 — diagnoses HTTP redirect-listener
bind failures caused by URL-ACL reservations. Helper queries
`netsh http show urlacl` (no URL filter) and finds any reservation
whose prefix targets the requested port — covering the case where the
operator's bind prefix doesn't exactly match an existing reservation
shape (e.g. `http://+:8080/` vs `http://*:8080/`).
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Test-UrlAclCollision.ps1')

    # Single reservation on the requested port — most common case.
    $script:NetshSingleReservation = @(
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

    # Multiple reservations across different ports — only one matches 8080.
    # This is what `netsh http show urlacl` (no filter) typically returns on a
    # real machine.
    $script:NetshMultiReservations = @(
        ''
        'URL Reservations:'
        '-----------------'
        ''
        '    Reserved URL            : http://+:80/Temporary_Listen_Addresses/'
        '        User: \LocalSystem'
        '            Listen: Yes'
        '            Delegate: No'
        '            SDDL: D:(A;;GX;;;LS)'
        ''
        '    Reserved URL            : http://*:8080/legacy-app/'
        '        User: BUILTIN\Users'
        '            Listen: Yes'
        '            Delegate: No'
        '            SDDL: D:(A;;GA;;;BU)'
        ''
        '    Reserved URL            : https://+:8443/api/'
        '        User: BUILTIN\Administrators'
        '            Listen: Yes'
        '            Delegate: No'
        '            SDDL: D:(A;;GA;;;BA)'
        ''
    )

    # Multiple reservations all on the same port — the exact case where
    # HttpListener's port-level conflict detection bites operators.
    $script:NetshSamePortDifferentPrefixes = @(
        ''
        '    Reserved URL            : http://*:8080/'
        '        User: BUILTIN\Users'
        '            Listen: Yes'
        '            Delegate: No'
        ''
        '    Reserved URL            : http://hostname.example.com:8080/api/'
        '        User: NT AUTHORITY\NetworkService'
        '            Listen: Yes'
        '            Delegate: No'
        ''
    )

    # No reservations at all (empty machine state).
    $script:NetshEmpty = @(
        ''
        'URL Reservations:'
        '-----------------'
        ''
    )

    # SDDL-only block (no parseable User: line). We still record the URL but
    # the Owners list is empty.
    $script:NetshSddlOnly = @(
        ''
        '    Reserved URL            : http://+:8080/'
        '        SDDL: D:(A;;GX;;;LS)'
        ''
    )
}

Describe 'Get-NetshUrlAclReservations' {

    It 'parses a single reservation block' {
        $r = Get-NetshUrlAclReservations -NetshOutput $script:NetshSingleReservation
        $r | Should -HaveCount 1
        $r[0].Url       | Should -Be 'http://+:8080/'
        $r[0].Owners    | Should -HaveCount 1
        $r[0].Owners[0] | Should -Be 'NT AUTHORITY\NetworkService'
    }

    It 'parses multiple reservations on different ports' {
        $r = Get-NetshUrlAclReservations -NetshOutput $script:NetshMultiReservations
        $r | Should -HaveCount 3
        $r[0].Url | Should -Be 'http://+:80/Temporary_Listen_Addresses/'
        $r[1].Url | Should -Be 'http://*:8080/legacy-app/'
        $r[2].Url | Should -Be 'https://+:8443/api/'
    }

    It 'parses an SDDL-only block as a reservation with no owners' {
        $r = Get-NetshUrlAclReservations -NetshOutput $script:NetshSddlOnly
        $r | Should -HaveCount 1
        $r[0].Url    | Should -Be 'http://+:8080/'
        $r[0].Owners | Should -BeNullOrEmpty
    }

    It 'returns an empty array when there are no reservations' {
        $r = Get-NetshUrlAclReservations -NetshOutput $script:NetshEmpty
        $r.Count | Should -Be 0
    }

    It 'returns an empty array for null input' {
        $r = Get-NetshUrlAclReservations -NetshOutput $null
        $r.Count | Should -Be 0
    }
}

Describe 'Test-UrlAclCollision' {

    Context 'HasCollision = $true' {

        It 'finds a same-prefix reservation on the requested port' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshSingleReservation
            $r.HasCollision        | Should -BeTrue
            $r.Reservations        | Should -HaveCount 1
            $r.Reservations[0].Url | Should -Be 'http://+:8080/'
            $r.Owners              | Should -Contain 'NT AUTHORITY\NetworkService'
            $r.Url                 | Should -Be 'http://+:8080/'
        }

        It 'finds a different-prefix reservation on the requested port' {
            # The operator wants 'http://+:8080/' but the existing reservation
            # is 'http://*:8080/legacy-app/'. Same port, different wildcard +
            # different path — still a port-level conflict for HttpListener.
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshMultiReservations
            $r.HasCollision         | Should -BeTrue
            $r.Reservations         | Should -HaveCount 1
            $r.Reservations[0].Url  | Should -Be 'http://*:8080/legacy-app/'
            $r.Owners               | Should -Contain 'BUILTIN\Users'
        }

        It 'finds multiple conflicting reservations on the same port' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshSamePortDifferentPrefixes
            $r.HasCollision         | Should -BeTrue
            $r.Reservations         | Should -HaveCount 2
            $r.Owners               | Should -Contain 'BUILTIN\Users'
            $r.Owners               | Should -Contain 'NT AUTHORITY\NetworkService'
        }
    }

    Context 'HasCollision = $false' {

        It 'reports no collision on a port with no reservations' {
            $r = Test-UrlAclCollision -Port 9999 -NetshOutput $script:NetshMultiReservations
            $r.HasCollision   | Should -BeFalse
            $r.Reservations.Count | Should -Be 0
            $r.Owners.Count       | Should -Be 0
        }

        It 'reports no collision when input is empty' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshEmpty
            $r.HasCollision | Should -BeFalse
        }

        It 'does not false-positive on a port substring (8080 vs 18080)' {
            $multiPortMix = @(
                '    Reserved URL            : http://+:18080/'
                '        User: BUILTIN\Users'
                ''
            )
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $multiPortMix
            $r.HasCollision | Should -BeFalse
        }
    }

    Context 'Output shape' {

        It 'always emits the same property set' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput @()
            $names = $r.PSObject.Properties.Name
            $names | Should -Contain 'HasCollision'
            $names | Should -Contain 'Owners'
            $names | Should -Contain 'Reservations'
            $names | Should -Contain 'Url'
            $names | Should -Contain 'Port'
            $names | Should -Contain 'Scheme'
        }

        It 'records SDDL-only conflicting reservations even without owners' {
            $r = Test-UrlAclCollision -Port 8080 -NetshOutput $script:NetshSddlOnly
            $r.HasCollision         | Should -BeTrue
            $r.Reservations         | Should -HaveCount 1
            $r.Reservations[0].Url  | Should -Be 'http://+:8080/'
            $r.Owners.Count         | Should -Be 0
        }
    }
}

Describe 'Get-NetshUrlAclOwners (backward-compat wrapper)' {

    It 'flattens owners across all reservations in the input' {
        $owners = Get-NetshUrlAclOwners -NetshOutput $script:NetshMultiReservations
        $owners | Should -HaveCount 3
        $owners | Should -Contain '\LocalSystem'
        $owners | Should -Contain 'BUILTIN\Users'
        $owners | Should -Contain 'BUILTIN\Administrators'
    }

    It 'returns an empty array for null input' {
        (Get-NetshUrlAclOwners -NetshOutput $null).Count | Should -Be 0
    }
}

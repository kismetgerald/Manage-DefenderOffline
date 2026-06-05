#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for v0.0.23 stale netsh reservation cleanup:
  - lib/Get-StaleHttpReservations.ps1 — parser (Get-NetshSslcertBindings),
    two filter functions (Get-StaleUrlAclReservations,
    Get-StaleSslcertBindings), and the top-level orchestrator
    (Get-StaleHttpReservations).

URL-ACL identity matching uses well-known SIDs (BUILTIN\Administrators,
BUILTIN\Guests, NT AUTHORITY\SYSTEM) so the tests are AD-independent.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Test-UrlAclCollision.ps1')
    . (Join-Path $script:RepoRoot 'lib\Get-StaleHttpReservations.ps1')

    # Well-known SIDs reused across cases. Translations work without AD.
    $script:AdminSid  = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $script:GuestSid  = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-546')
    $script:SystemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')

    # Our installer's stable AppID. Matches $script:HttpsAppId in
    # Install-ManageDefender.ps1.
    $script:OurAppId    = '{a3f9b1c2-d4e5-46f7-8901-234567890abc}'
    $script:OtherAppId  = '{00000000-1111-2222-3333-444444444444}'

    # Representative netsh http show sslcert output with two bindings.
    $script:SslcertTwoBindings = @(
        ''
        'SSL Certificate bindings:'
        '-------------------------'
        ''
        '    IP:port                      : 0.0.0.0:8443'
        '    Certificate Hash             : AABBCCDDEEFF00112233445566778899AABBCCDD'
        "    Application ID               : $script:OurAppId"
        '    Certificate Store Name       : My'
        ''
        '    IP:port                      : 0.0.0.0:8444'
        '    Certificate Hash             : 1122334455667788990011223344556677889900'
        "    Application ID               : $script:OurAppId"
        '    Certificate Store Name       : My'
        ''
    )

    $script:SslcertNotOurs = @(
        ''
        '    IP:port                      : 0.0.0.0:9443'
        '    Certificate Hash             : FFEEDDCCBBAA99887766554433221100FFEEDDCC'
        "    Application ID               : $script:OtherAppId"
        ''
    )

    $script:UrlAclMixedOwners = @(
        ''
        'Reserved URL            : https://+:8080/'
        '    User: BUILTIN\Administrators'
        '        Listen: Yes'
        '        Delegate: No'
        ''
        'Reserved URL            : https://+:8443/'
        '    User: BUILTIN\Guests'
        '        Listen: Yes'
        ''
        'Reserved URL            : https://+:8444/'
        '    User: BUILTIN\Administrators'
        '        Listen: Yes'
        ''
        # hostname-bound reservation — NOT our shape; should be ignored
        'Reserved URL            : https://wgsdac-host:8081/'
        '    User: BUILTIN\Administrators'
        '        Listen: Yes'
        ''
    )
}

Describe 'Get-NetshSslcertBindings (parser)' {

    It 'parses two bindings into two records with IpPort + Port + Hash + AppId' {
        $bindings = Get-NetshSslcertBindings -NetshOutput $script:SslcertTwoBindings
        $bindings.Count | Should -Be 2

        $b0 = $bindings | Where-Object IpPort -eq '0.0.0.0:8443'
        $b0.Port  | Should -Be 8443
        $b0.Hash  | Should -Be 'AABBCCDDEEFF00112233445566778899AABBCCDD'
        $b0.AppId | Should -Be $script:OurAppId.ToLowerInvariant()

        $b1 = $bindings | Where-Object IpPort -eq '0.0.0.0:8444'
        $b1.Port  | Should -Be 8444
        $b1.Hash  | Should -Be '1122334455667788990011223344556677889900'
    }

    It 'uppercases the hash and lowercases the AppId for stable comparison' {
        $bindings = Get-NetshSslcertBindings -NetshOutput $script:SslcertTwoBindings
        ($bindings | Select-Object -First 1).Hash  | Should -MatchExactly '^[0-9A-F]+$'
        ($bindings | Select-Object -First 1).AppId | Should -MatchExactly '^\{[0-9a-f-]+\}$'
    }

    It 'returns an empty array on null input' {
        Get-NetshSslcertBindings -NetshOutput $null | Should -BeNullOrEmpty
    }

    It 'returns an empty array on empty input' {
        Get-NetshSslcertBindings -NetshOutput @() | Should -BeNullOrEmpty
    }

    It 'skips an IpPort entry that has no hash or AppID following it' {
        # netsh sometimes prints headers without follow-up data when no
        # bindings exist; the parser shouldn't emit phantom records.
        $stub = @('SSL Certificate bindings:','-------------------------','')
        Get-NetshSslcertBindings -NetshOutput $stub | Should -BeNullOrEmpty
    }
}

Describe 'Get-StaleUrlAclReservations (filter)' {

    BeforeEach {
        $script:ParsedUrlAcls = Get-NetshUrlAclReservations -NetshOutput $script:UrlAclMixedOwners
    }

    It 'returns only Administrators-owned reservations on inactive ports with the +:<port>/ shape' {
        $stale = Get-StaleUrlAclReservations `
            -Reservations       $script:ParsedUrlAcls `
            -ServiceIdentitySid $script:AdminSid `
            -ActivePorts        @(8444, 8080)
        # 8080 (Administrators) is ACTIVE → excluded
        # 8443 (Guests)         is INACTIVE but wrong-owner → excluded
        # 8444 (Administrators) is ACTIVE → excluded
        # hostname:8081 (Administrators) → wrong shape → excluded
        # Expected: empty
        $stale | Should -BeNullOrEmpty
    }

    It 'returns the inactive-port Administrators reservation when only 8444 is active' {
        $stale = Get-StaleUrlAclReservations `
            -Reservations       $script:ParsedUrlAcls `
            -ServiceIdentitySid $script:AdminSid `
            -ActivePorts        @(8444)
        # 8080 (Administrators) is INACTIVE → IN
        # 8443 (Guests)         is INACTIVE but wrong owner → OUT
        # 8444 (Administrators) is ACTIVE → OUT
        # hostname:8081 (Administrators) wrong shape → OUT
        $stale.Count        | Should -Be 1
        $stale[0].Url       | Should -Be 'https://+:8080/'
        $stale[0].Port      | Should -Be 8080
    }

    It 'never returns wrong-owner reservations' {
        $stale = Get-StaleUrlAclReservations `
            -Reservations       $script:ParsedUrlAcls `
            -ServiceIdentitySid $script:AdminSid `
            -ActivePorts        @()
        # All four reservations are on inactive ports now.
        # Only Administrators-owned + shape-matching survive.
        # That's 8080 (Admins, +:8080/) and 8444 (Admins, +:8444/).
        # hostname:8081 is wrong shape; 8443 is wrong owner.
        $stale.Count            | Should -Be 2
        ($stale.Url -join ',')  | Should -Match '^(https://\+:8080/,https://\+:8444/|https://\+:8444/,https://\+:8080/)$'
    }

    It 'skips reservations whose URL is not the +:<port>/ shape' {
        $stale = Get-StaleUrlAclReservations `
            -Reservations       $script:ParsedUrlAcls `
            -ServiceIdentitySid $script:AdminSid `
            -ActivePorts        @()
        $stale.Url | Should -Not -Contain 'https://wgsdac-host:8081/'
    }

    It 'returns an empty array when there are no parsed reservations' {
        $stale = Get-StaleUrlAclReservations `
            -Reservations       @() `
            -ServiceIdentitySid $script:AdminSid `
            -ActivePorts        @(8080)
        $stale | Should -BeNullOrEmpty
    }
}

Describe 'Get-StaleSslcertBindings (filter)' {

    It 'returns only our-AppID bindings on inactive ports' {
        $bindings = Get-NetshSslcertBindings -NetshOutput $script:SslcertTwoBindings
        $stale = Get-StaleSslcertBindings `
            -Bindings    $bindings `
            -OurAppId    $script:OurAppId `
            -ActivePorts @(8444)
        # 8443 (our AppID) is INACTIVE → IN
        # 8444 (our AppID) is ACTIVE → OUT
        $stale.Count        | Should -Be 1
        $stale[0].IpPort    | Should -Be '0.0.0.0:8443'
        $stale[0].Port      | Should -Be 8443
    }

    It 'never returns bindings tagged with someone else AppID, even on inactive ports' {
        $bindings = Get-NetshSslcertBindings -NetshOutput $script:SslcertNotOurs
        $stale = Get-StaleSslcertBindings `
            -Bindings    $bindings `
            -OurAppId    $script:OurAppId `
            -ActivePorts @()
        $stale | Should -BeNullOrEmpty
    }

    It 'is case-insensitive on the AppID comparison' {
        $bindings = Get-NetshSslcertBindings -NetshOutput $script:SslcertTwoBindings
        $stale = Get-StaleSslcertBindings `
            -Bindings    $bindings `
            -OurAppId    $script:OurAppId.ToUpperInvariant() `
            -ActivePorts @(8444)
        $stale.Count | Should -Be 1
    }

    It 'returns empty when all bindings are on active ports' {
        $bindings = Get-NetshSslcertBindings -NetshOutput $script:SslcertTwoBindings
        $stale = Get-StaleSslcertBindings `
            -Bindings    $bindings `
            -OurAppId    $script:OurAppId `
            -ActivePorts @(8443, 8444)
        $stale | Should -BeNullOrEmpty
    }
}

Describe 'Get-StaleHttpReservations (orchestrator)' {

    It 'returns a result object with combined Count when invoked with injected netsh output' {
        $result = Get-StaleHttpReservations `
            -ServiceIdentitySid    $script:AdminSid `
            -OurAppId              $script:OurAppId `
            -ActivePorts           @(8444) `
            -UrlAclNetshOutput     $script:UrlAclMixedOwners `
            -SslcertNetshOutput    $script:SslcertTwoBindings

        # Stale URL-ACLs: 8080 (Administrators on inactive port)
        # Stale sslcerts: 0.0.0.0:8443 (our AppID on inactive port)
        $result.StaleUrlAcls.Count  | Should -Be 1
        $result.StaleSslcerts.Count | Should -Be 1
        $result.Count               | Should -Be 2
    }

    It 'returns zero when active ports cover everything ours' {
        $result = Get-StaleHttpReservations `
            -ServiceIdentitySid    $script:AdminSid `
            -OurAppId              $script:OurAppId `
            -ActivePorts           @(8080, 8443, 8444) `
            -UrlAclNetshOutput     $script:UrlAclMixedOwners `
            -SslcertNetshOutput    $script:SslcertTwoBindings

        $result.StaleUrlAcls  | Should -BeNullOrEmpty
        $result.StaleSslcerts | Should -BeNullOrEmpty
        $result.Count         | Should -Be 0
    }

    It 'still returns a structured result when both netsh outputs are empty' {
        $result = Get-StaleHttpReservations `
            -ServiceIdentitySid    $script:AdminSid `
            -OurAppId              $script:OurAppId `
            -ActivePorts           @(8444) `
            -UrlAclNetshOutput     @() `
            -SslcertNetshOutput    @()
        $result.StaleUrlAcls  | Should -BeNullOrEmpty
        $result.StaleSslcerts | Should -BeNullOrEmpty
        $result.Count         | Should -Be 0
    }
}

#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for dashboard authentication.

  PR-D1 (this PR): None mode, Token mode, helper primitives
    (Test-ConstantTimeEqual, New-RandomToken). /health-bypass behavior
    verified in every mode.

  PR-D2 (queued): Basic, ADIntegrated (with deny-syntax). Those
    contexts stay -Skip below until PR-D2 lands.

Approach: build a fake HttpListenerContext (PSObject duck-type with
the properties Test-DashboardAuth actually reads) so we can exercise
the auth decision logic without spinning up a real HTTP listener.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Start-DefenderDashboard.ps1')

    # Helper: build a Basic-auth Authorization header value from a username +
    # cleartext secret. Test-only — we deliberately build the cleartext here so
    # we can encode it; the production surface never accepts cleartext on its
    # public API.
    function Get-BasicHeader {
        param([string]$User, [string]$Secret)
        @{ Authorization = 'Basic ' + [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes("${User}:${Secret}")) }
    }

    # Helper: build a mock HttpListenerContext-shaped object. Only the
    # properties Test-DashboardAuth touches are populated.
    function New-FakeContext {
        param(
            [string]$Path        = '/defender',
            [hashtable]$Headers  = @{},
            [hashtable]$Query    = @{},
            # ADIntegrated: a duck-type principal with .Identity having
            # .IsAuthenticated, .Name, .User (SID), and .Groups (SID[]).
            $User                = $null
        )
        $headerCollection = [System.Collections.Specialized.NameValueCollection]::new()
        foreach ($k in $Headers.Keys) { $headerCollection.Add($k, $Headers[$k]) }
        $queryCollection  = [System.Collections.Specialized.NameValueCollection]::new()
        foreach ($k in $Query.Keys)   { $queryCollection.Add($k, $Query[$k]) }
        [pscustomobject]@{
            Request = [pscustomobject]@{
                Url         = [pscustomobject]@{ LocalPath = $Path }
                Headers     = $headerCollection
                QueryString = $queryCollection
            }
            User = $User
        }
    }

    # Helper: build a WindowsIdentity-shaped duck-type. SecurityIdentifier
    # is unsealed-and-equatable, so we use real SIDs (well-known SID strings)
    # and assemble them into the .Groups collection.
    function New-FakePrincipal {
        param(
            [Parameter(Mandatory)] [string]$UserSidString,
            [string]$Name = 'WGSDAC\testuser',
            [string[]]$GroupSidStrings = @(),
            [bool]$IsAuthenticated = $true
        )
        $userSid  = [System.Security.Principal.SecurityIdentifier]::new($UserSidString)
        $groupSids = @($GroupSidStrings | ForEach-Object {
            [System.Security.Principal.SecurityIdentifier]::new($_)
        })
        [pscustomobject]@{
            Identity = [pscustomobject]@{
                IsAuthenticated = $IsAuthenticated
                Name            = $Name
                User            = $userSid
                Groups          = $groupSids
            }
        }
    }
}

Describe 'Test-ConstantTimeEqual' {

    It 'returns true for identical strings' {
        Test-ConstantTimeEqual -A 'hunter2' -B 'hunter2' | Should -BeTrue
    }

    It 'returns false for different strings of same length' {
        Test-ConstantTimeEqual -A 'hunter2' -B 'hunter3' | Should -BeFalse
    }

    It 'returns false for different lengths (constant-time short-circuit)' {
        Test-ConstantTimeEqual -A 'short'   -B 'much longer string' | Should -BeFalse
    }

    It 'returns false when either side is null' {
        Test-ConstantTimeEqual -A $null -B 'x'   | Should -BeFalse
        Test-ConstantTimeEqual -A 'x'   -B $null | Should -BeFalse
    }

    It 'returns true for two empty strings' {
        Test-ConstantTimeEqual -A '' -B '' | Should -BeTrue
    }

    It 'handles unicode characters' {
        Test-ConstantTimeEqual -A 'pässwörd' -B 'pässwörd' | Should -BeTrue
        Test-ConstantTimeEqual -A 'pässwörd' -B 'passwörd' | Should -BeFalse
    }
}

Describe 'New-RandomToken' {

    It 'produces a base64-encoded string' {
        $t = New-RandomToken
        $t | Should -Match '^[A-Za-z0-9+/]+={0,2}$'
    }

    It 'default length is 32 bytes (44 base64 chars)' {
        $t = New-RandomToken
        $t.Length | Should -Be 44
    }

    It 'honors -ByteLength parameter' {
        # 16 bytes encodes to 24 base64 chars (incl. padding)
        $t = New-RandomToken -ByteLength 16
        $t.Length | Should -Be 24
    }

    It 'two consecutive tokens are not equal (cryptographically random)' {
        (New-RandomToken) | Should -Not -Be (New-RandomToken)
    }
}

Describe 'Test-DashboardAuth — /health bypass' {

    It '/health stays anonymous in AuthMethod=None' {
        $ctx = New-FakeContext -Path '/health'
        $r   = Test-DashboardAuth -Context $ctx -Method 'None'
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'health-bypass'
    }

    It '/health stays anonymous in AuthMethod=Token (no token provided)' {
        $ctx = New-FakeContext -Path '/health'
        $r   = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'secret-token'
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'health-bypass'
    }

    It '/health stays anonymous in AuthMethod=Basic (no creds; would otherwise fail)' {
        $ctx = New-FakeContext -Path '/health'
        $r   = Test-DashboardAuth -Context $ctx -Method 'Basic'
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'health-bypass'
    }
}

Describe 'Test-DashboardAuth — AuthMethod=None' {

    It 'allows any caller to /defender' {
        $ctx = New-FakeContext -Path '/defender'
        $r   = Test-DashboardAuth -Context $ctx -Method 'None'
        $r.Authorized | Should -BeTrue
        $r.StatusCode | Should -Be 200
        $r.User       | Should -Be 'anonymous'
        $r.Reason     | Should -Be 'auth-disabled'
    }

    It 'allows any caller to /status' {
        $ctx = New-FakeContext -Path '/status'
        $r   = Test-DashboardAuth -Context $ctx -Method 'None'
        $r.Authorized | Should -BeTrue
    }
}

Describe 'Test-DashboardAuth — AuthMethod=Token' {

    Context 'Token in Authorization: Bearer header' {

        It 'accepts a matching token' {
            $ctx = New-FakeContext -Path '/defender' -Headers @{ Authorization = 'Bearer my-secret-token' }
            $r   = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'my-secret-token'
            $r.Authorized | Should -BeTrue
            $r.StatusCode | Should -Be 200
            $r.User       | Should -Be 'token-bearer'
            $r.Reason     | Should -Be 'token-matched'
        }

        It 'rejects a mismatched token with 403' {
            $ctx = New-FakeContext -Path '/defender' -Headers @{ Authorization = 'Bearer wrong-token' }
            $r   = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'my-secret-token'
            $r.Authorized | Should -BeFalse
            $r.StatusCode | Should -Be 403
            $r.Reason     | Should -Be 'token-mismatch'
        }

        It 'ignores Authorization header that does not start with Bearer' {
            $ctx = New-FakeContext -Path '/defender' -Headers @{ Authorization = 'Basic dXNlcjpwYXNz' }
            $r   = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'my-secret-token'
            $r.Authorized | Should -BeFalse
            $r.StatusCode | Should -Be 401
            $r.Reason     | Should -Be 'no-token'
        }
    }

    Context 'Token in ?token= query string' {

        It 'accepts a matching token' {
            $ctx = New-FakeContext -Path '/defender' -Query @{ token = 'my-secret-token' }
            $r   = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'my-secret-token'
            $r.Authorized | Should -BeTrue
            $r.Reason     | Should -Be 'token-matched'
        }

        It 'rejects a mismatched token with 403' {
            $ctx = New-FakeContext -Path '/defender' -Query @{ token = 'wrong-token' }
            $r   = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'my-secret-token'
            $r.Authorized | Should -BeFalse
            $r.StatusCode | Should -Be 403
        }
    }

    Context 'Precedence and edge cases' {

        It 'returns 401 (not 403) when no token is supplied at all' {
            $ctx = New-FakeContext -Path '/defender'
            $r   = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'my-secret-token'
            $r.Authorized | Should -BeFalse
            $r.StatusCode | Should -Be 401
            $r.Reason     | Should -Be 'no-token'
        }

        It 'prefers the Authorization header over the query string' {
            $ctx = New-FakeContext `
                -Path    '/defender' `
                -Headers @{ Authorization = 'Bearer correct-token' } `
                -Query   @{ token        = 'wrong-token' }
            $r = Test-DashboardAuth -Context $ctx -Method 'Token' -Token 'correct-token'
            $r.Authorized | Should -BeTrue
            $r.Reason     | Should -Be 'token-matched'
        }
    }
}

# ============================================================================
# PR-D2a (this PR): Basic auth + -AddBasicUser helper
# ============================================================================

Describe 'New-DashboardPasswordHash / Test-DashboardPasswordHash (PBKDF2)' {

    It 'produces a salt:iterations:hash string with 3 colon-separated fields' {
        $secure = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
        $h = New-DashboardPasswordHash -Password $secure
        ($h -split ':').Count | Should -Be 3
    }

    It 'uses a different salt on every call (so identical passwords get different hashes)' {
        $secure = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
        (New-DashboardPasswordHash -Password $secure) | Should -Not -Be (New-DashboardPasswordHash -Password $secure)
    }

    It 'verifies a correct password against its hash' {
        $secure = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
        $h = New-DashboardPasswordHash -Password $secure
        Test-DashboardPasswordHash -Password 'hunter2' -StoredHash $h | Should -BeTrue
    }

    It 'rejects a wrong password' {
        $secure = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
        $h = New-DashboardPasswordHash -Password $secure
        Test-DashboardPasswordHash -Password 'hunter3' -StoredHash $h | Should -BeFalse
    }

    It 'returns false on malformed stored hash (wrong field count)' {
        Test-DashboardPasswordHash -Password 'x' -StoredHash 'not:enough' | Should -BeFalse
    }

    It 'returns false on non-base64 salt' {
        Test-DashboardPasswordHash -Password 'x' -StoredHash '!!!:100000:AAAA' | Should -BeFalse
    }

    It 'honors a custom iteration count round-trip' {
        $secure = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
        $h = New-DashboardPasswordHash -Password $secure -Iterations 1000
        ($h -split ':')[1] | Should -Be '1000'
        Test-DashboardPasswordHash -Password 'hunter2' -StoredHash $h | Should -BeTrue
    }
}

Describe 'Read-DashboardUsersFile' {

    BeforeEach {
        # TestDrive is shared across It blocks within one Describe; use a fresh
        # filename per test so users carried over from a prior It don't bleed in.
        $script:UsersPath = Join-Path $TestDrive ("users-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'returns an empty dictionary when the file is missing' {
        $u = Read-DashboardUsersFile -Path (Join-Path $TestDrive 'never.txt')
        $u.Count | Should -Be 0
    }

    It 'parses well-formed lines into a username -> StoredHash map' {
        Set-Content -Path $script:UsersPath -Value @(
            '# comment'
            ''
            'alice:c2FsdA==:100000:aGFzaA=='
            'bob:c2FsdA==:100000:aGFzaA=='
        ) -Encoding UTF8
        $u = Read-DashboardUsersFile -Path $script:UsersPath
        $u.Count | Should -Be 2
        $u['alice'] | Should -Be 'c2FsdA==:100000:aGFzaA=='
        $u.ContainsKey('bob') | Should -BeTrue
    }

    It 'is case-insensitive on lookup' {
        Set-Content -Path $script:UsersPath -Value 'Alice:c2FsdA==:100000:aGFzaA==' -Encoding UTF8
        (Read-DashboardUsersFile -Path $script:UsersPath).ContainsKey('ALICE') | Should -BeTrue
    }

    It 'skips comment lines, blank lines, and lines with no colon' {
        Set-Content -Path $script:UsersPath -Value @(
            '# top comment'
            ''
            'malformed-no-colon'
            'alice:c2FsdA==:100000:aGFzaA=='
        ) -Encoding UTF8
        (Read-DashboardUsersFile -Path $script:UsersPath).Count | Should -Be 1
    }
}

Describe 'Add-DashboardBasicUser' {

    BeforeEach {
        $script:UsersPath = Join-Path $TestDrive ("users-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'creates the file with a header and appends the user' {
        $secure = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
        Add-DashboardBasicUser -Path $script:UsersPath -Username 'alice' -Password $secure | Out-Null
        Test-Path $script:UsersPath | Should -BeTrue
        (Get-Content $script:UsersPath) | Should -Contain '# Manage-DefenderOffline Dashboard – Basic-auth users'
        (Read-DashboardUsersFile -Path $script:UsersPath).ContainsKey('alice') | Should -BeTrue
    }

    It 'appends an additional user without rewriting earlier entries' {
        $secure = ConvertTo-SecureString 'pw' -AsPlainText -Force
        Add-DashboardBasicUser -Path $script:UsersPath -Username 'alice' -Password $secure | Out-Null
        Add-DashboardBasicUser -Path $script:UsersPath -Username 'bob'   -Password $secure | Out-Null
        $u = Read-DashboardUsersFile -Path $script:UsersPath
        $u.Count | Should -Be 2
        $u.ContainsKey('alice') | Should -BeTrue
        $u.ContainsKey('bob')   | Should -BeTrue
    }

    It 'writes a hash that round-trips through Test-DashboardPasswordHash' {
        $secure = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
        Add-DashboardBasicUser -Path $script:UsersPath -Username 'alice' -Password $secure | Out-Null
        $u = Read-DashboardUsersFile -Path $script:UsersPath
        Test-DashboardPasswordHash -Password 'hunter2' -StoredHash $u['alice'] | Should -BeTrue
        Test-DashboardPasswordHash -Password 'wrong'   -StoredHash $u['alice'] | Should -BeFalse
    }

    It 'rejects usernames with characters that would corrupt the file' {
        $secure = ConvertTo-SecureString 'pw' -AsPlainText -Force
        { Add-DashboardBasicUser -Path $script:UsersPath -Username 'al:ice' -Password $secure } |
            Should -Throw -ExpectedMessage '*Allowed: letters, digits*'
    }

    It 'rejects duplicate usernames' {
        $secure = ConvertTo-SecureString 'pw' -AsPlainText -Force
        Add-DashboardBasicUser -Path $script:UsersPath -Username 'alice' -Password $secure | Out-Null
        { Add-DashboardBasicUser -Path $script:UsersPath -Username 'alice' -Password $secure } |
            Should -Throw -ExpectedMessage '*already exists*'
    }
}

Describe 'Test-DashboardAuth — AuthMethod=Basic' {

    BeforeAll {
        # One real users file used across the Basic-auth tests. Two known users
        # with known passwords let us exercise success / wrong-password /
        # unknown-user without re-hashing in every It block.
        $script:BasicUsers = Join-Path $TestDrive 'basic-users.txt'
        $pwdAlice = ConvertTo-SecureString 'alice-secret' -AsPlainText -Force
        $pwdBob   = ConvertTo-SecureString 'bob-secret'   -AsPlainText -Force
        Add-DashboardBasicUser -Path $script:BasicUsers -Username 'alice' -Password $pwdAlice | Out-Null
        Add-DashboardBasicUser -Path $script:BasicUsers -Username 'bob'   -Password $pwdBob   | Out-Null
    }

    It 'accepts a correct username/password (PBKDF2 verified)' {
        $ctx = New-FakeContext -Path '/defender' -Headers (Get-BasicHeader -User 'alice' -Secret 'alice-secret')
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeTrue
        $r.StatusCode | Should -Be 200
        $r.User       | Should -Be 'alice'
        $r.Reason     | Should -Be 'password-matched'
    }

    It 'rejects a wrong password with 401 (reason: password-mismatch)' {
        $ctx = New-FakeContext -Path '/defender' -Headers (Get-BasicHeader -User 'alice' -Secret 'not-the-password')
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 401
        $r.Reason     | Should -Be 'password-mismatch'
    }

    It 'rejects an unknown username with 401 (reason: unknown-user)' {
        $ctx = New-FakeContext -Path '/defender' -Headers (Get-BasicHeader -User 'mallory' -Secret 'whatever')
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 401
        $r.Reason     | Should -Be 'unknown-user'
    }

    It 'rejects requests with no Authorization header (401, no-credentials)' {
        $ctx = New-FakeContext -Path '/defender'
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 401
        $r.Reason     | Should -Be 'no-credentials'
    }

    It 'rejects an Authorization header that does not start with Basic' {
        $ctx = New-FakeContext -Path '/defender' -Headers @{ Authorization = 'Bearer some-token' }
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeFalse
        $r.Reason     | Should -Be 'no-credentials'
    }

    It 'rejects malformed base64 in the Authorization header' {
        $ctx = New-FakeContext -Path '/defender' -Headers @{ Authorization = 'Basic !!!not-base64!!!' }
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeFalse
        $r.Reason     | Should -Be 'malformed-credentials'
    }

    It 'rejects when the decoded credential has no colon separator' {
        $bad = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('no-colon-here'))
        $ctx = New-FakeContext -Path '/defender' -Headers @{ Authorization = "Basic $bad" }
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeFalse
        $r.Reason     | Should -Be 'malformed-credentials'
    }

    It 'returns 500 when AuthBasicUsersFile is missing at runtime' {
        # Startup validation would normally catch this, but defense-in-depth.
        $ctx = New-FakeContext -Path '/defender' -Headers (Get-BasicHeader -User 'alice' -Secret 'alice-secret')
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile (Join-Path $TestDrive 'does-not-exist.txt')
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 500
        $r.Reason     | Should -Be 'users-file-missing'
    }

    It '/health bypass still applies in Basic mode (no credentials needed)' {
        $ctx = New-FakeContext -Path '/health'
        $r = Test-DashboardAuth -Context $ctx -Method 'Basic' -UsersFile $script:BasicUsers
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'health-bypass'
    }
}

# Startup-validation tests live-fire only — they exit() the host process so
# can't run inside Pester without a subprocess wrapper. Validated by the
# maintainer when smoke-testing PR-D2a.
Describe 'AuthMethod = Basic — startup validation (live-fire only)' -Tag 'Integration' {
    It 'rejects at startup when -UseHttps is false (cleartext-Basic protection)' -Skip {}
    It 'rejects when AuthBasicUsersFile does not exist' -Skip {}
    It 'rejects when AuthBasicUsersFile exists but contains no users' -Skip {}
}

Describe '-AddBasicUser helper mode (live-fire only)' -Tag 'Integration' {
    # The helper itself is unit-tested via Add-DashboardBasicUser above.
    # This test confirms the dot-sourced helper-mode block exits 0 without
    # entering the main listener flow — needs a subprocess to validate.
    It 'exits 0 after writing without entering main flow' -Skip {}
}

# ============================================================================
# PR-D2b: ADIntegrated auth — group resolution + membership + branch behavior
# ============================================================================

Describe 'Resolve-DashboardAllowedGroups' {

    It 'returns empty allow/deny/unresolved when given an empty allow-list' {
        $r = Resolve-DashboardAllowedGroups -AllowList ''
        $r.AllowSids.Count  | Should -Be 0
        $r.DenySids.Count   | Should -Be 0
        $r.Unresolved.Count | Should -Be 0
    }

    It 'resolves a single allow entry to a SID (using BUILTIN\Administrators)' {
        # BUILTIN\Administrators is present on every Windows host, so this
        # works on a workgroup test box as well as a domain-joined one.
        $r = Resolve-DashboardAllowedGroups -AllowList 'BUILTIN\Administrators'
        $r.AllowSids.Count | Should -Be 1
        $r.AllowSids[0].Value | Should -Be 'S-1-5-32-544'
        $r.DenySids.Count  | Should -Be 0
        $r.Unresolved.Count | Should -Be 0
    }

    It 'treats !Group entries as denies (deny list separate from allow list)' {
        $r = Resolve-DashboardAllowedGroups -AllowList 'BUILTIN\Users,!BUILTIN\Guests'
        $r.AllowSids.Count | Should -Be 1
        $r.AllowSids[0].Value | Should -Be 'S-1-5-32-545'   # Users
        $r.DenySids.Count  | Should -Be 1
        $r.DenySids[0].Value  | Should -Be 'S-1-5-32-546'   # Guests
    }

    It 'collects unresolvable entries in .Unresolved instead of throwing' {
        $r = Resolve-DashboardAllowedGroups -AllowList 'BUILTIN\Administrators,NOSUCHDOMAIN\NoSuchGroup-NonExistent'
        $r.AllowSids.Count  | Should -Be 1
        $r.Unresolved.Count | Should -Be 1
        $r.Unresolved[0]    | Should -Match 'NoSuchGroup-NonExistent'
    }

    It 'tolerates whitespace around entries and empty segments' {
        $r = Resolve-DashboardAllowedGroups -AllowList '  BUILTIN\Administrators ,, ! BUILTIN\Guests ,'
        $r.AllowSids.Count | Should -Be 1
        $r.DenySids.Count  | Should -Be 1
    }

    Context 'Resolutions property (v0.0.13+ diagnostic surface)' {

        It 'emits one Resolutions entry per input — resolved entries include Account + Sid' {
            $r = Resolve-DashboardAllowedGroups -AllowList 'BUILTIN\Administrators,!BUILTIN\Guests'
            $r.Resolutions | Should -HaveCount 2

            $admins = $r.Resolutions | Where-Object Input -eq 'BUILTIN\Administrators'
            $admins.IsDeny  | Should -BeFalse
            $admins.Status  | Should -Be 'ok'
            $admins.Account | Should -Be 'BUILTIN\Administrators'
            $admins.Sid     | Should -Be 'S-1-5-32-544'
            $admins.Error   | Should -BeNullOrEmpty

            $guests = $r.Resolutions | Where-Object Input -eq 'BUILTIN\Guests'
            $guests.IsDeny  | Should -BeTrue
            $guests.Status  | Should -Be 'ok'
            $guests.Sid     | Should -Be 'S-1-5-32-546'
        }

        It 'records unresolvable entries with status=unresolved and an Error message' {
            $r = Resolve-DashboardAllowedGroups -AllowList 'BUILTIN\Administrators,NOSUCHDOMAIN\NoSuchGroup-NonExistent'
            $r.Resolutions | Should -HaveCount 2

            $bad = $r.Resolutions | Where-Object Input -eq 'NOSUCHDOMAIN\NoSuchGroup-NonExistent'
            $bad.Status  | Should -Be 'unresolved'
            $bad.Sid     | Should -BeNullOrEmpty
            $bad.Account | Should -BeNullOrEmpty
            $bad.Error   | Should -Not -BeNullOrEmpty
        }

        It 'returns an empty Resolutions array for an empty allow-list' {
            $r = Resolve-DashboardAllowedGroups -AllowList ''
            $r.Resolutions.Count | Should -Be 0
        }

        It 'Resolutions[].Account holds the canonical DOMAIN\Group form for downstream logging' {
            # Operator-friendly: even when the input was a short or alternate
            # form, .Account is the form Windows actually uses internally.
            $r = Resolve-DashboardAllowedGroups -AllowList 'BUILTIN\Administrators'
            ($r.Resolutions | Select-Object -First 1).Account | Should -Be 'BUILTIN\Administrators'
        }
    }
}

Describe 'Test-IdentityInAllowedGroups' {

    BeforeAll {
        # Reusable well-known SIDs so the tests don't depend on actual AD.
        $script:UserSid       = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
        $script:AdminsSid     = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')  # BUILTIN\Administrators
        $script:UsersSid      = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')  # BUILTIN\Users
        $script:GuestsSid     = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-546')  # BUILTIN\Guests
        $script:AuthUsersSid  = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')      # NT AUTHORITY\Authenticated Users
    }

    It 'allows any authenticated user when allow-list is empty' {
        $allowed = [pscustomobject]@{ AllowSids = @(); DenySids = @(); Unresolved = @() }
        $r = Test-IdentityInAllowedGroups -UserSid $script:UserSid -GroupSids @($script:UsersSid) -AllowedGroups $allowed
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'no-allow-list'
    }

    It 'allows when user is a member of an allowed group' {
        $allowed = [pscustomobject]@{ AllowSids = @($script:AdminsSid); DenySids = @(); Unresolved = @() }
        $r = Test-IdentityInAllowedGroups -UserSid $script:UserSid `
            -GroupSids @($script:AdminsSid, $script:UsersSid) `
            -AllowedGroups $allowed
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'group-allowed'
        $r.MatchedSid.Value | Should -Be 'S-1-5-32-544'
    }

    It 'rejects users with no membership in the allow-list (not-in-allow-list)' {
        $allowed = [pscustomobject]@{ AllowSids = @($script:AdminsSid); DenySids = @(); Unresolved = @() }
        $r = Test-IdentityInAllowedGroups -UserSid $script:UserSid `
            -GroupSids @($script:UsersSid) `
            -AllowedGroups $allowed
        $r.Authorized | Should -BeFalse
        $r.Reason     | Should -Be 'not-in-allow-list'
    }

    It 'rejects when user matches a deny entry — deny wins over allow' {
        # User is BOTH in Administrators (allowed) AND Guests (denied). Deny wins.
        $allowed = [pscustomobject]@{
            AllowSids = @($script:AdminsSid)
            DenySids  = @($script:GuestsSid)
            Unresolved = @()
        }
        $r = Test-IdentityInAllowedGroups -UserSid $script:UserSid `
            -GroupSids @($script:AdminsSid, $script:GuestsSid) `
            -AllowedGroups $allowed
        $r.Authorized | Should -BeFalse
        $r.Reason     | Should -Be 'group-denied'
        $r.MatchedSid.Value | Should -Be 'S-1-5-32-546'
    }

    It 'matches against the user SID itself (not just group SIDs)' {
        # AllowSids contains the user's own SID; user has no group memberships.
        $allowed = [pscustomobject]@{ AllowSids = @($script:UserSid); DenySids = @(); Unresolved = @() }
        $r = Test-IdentityInAllowedGroups -UserSid $script:UserSid -GroupSids @() -AllowedGroups $allowed
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'group-allowed'
    }
}

Describe 'Test-DashboardAuth — AuthMethod=ADIntegrated' {

    BeforeAll {
        $script:UserSid    = 'S-1-5-21-1-2-3-1001'
        $script:AdminsSid  = 'S-1-5-32-544'
        $script:UsersSid   = 'S-1-5-32-545'
        $script:GuestsSid  = 'S-1-5-32-546'

        function script:Build-AllowedGroups {
            param([string[]]$Allow = @(), [string[]]$Deny = @())
            [pscustomobject]@{
                AllowSids  = @($Allow | ForEach-Object { [System.Security.Principal.SecurityIdentifier]::new($_) })
                DenySids   = @($Deny  | ForEach-Object { [System.Security.Principal.SecurityIdentifier]::new($_) })
                Unresolved = @()
            }
        }
    }

    It 'returns 401 with no-windows-identity when context.User is null' {
        $ctx = New-FakeContext -Path '/defender' -User $null
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated' -AllowedGroupSids (script:Build-AllowedGroups)
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 401
        $r.Reason     | Should -Be 'no-windows-identity'
    }

    It 'returns 401 when the identity is not authenticated' {
        $principal = New-FakePrincipal -UserSidString $script:UserSid -IsAuthenticated $false
        $ctx = New-FakeContext -Path '/defender' -User $principal
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated' -AllowedGroupSids (script:Build-AllowedGroups)
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 401
        $r.Reason     | Should -Be 'no-windows-identity'
    }

    It 'allows when the user is in an allowed group' {
        $principal = New-FakePrincipal -UserSidString $script:UserSid -GroupSidStrings @($script:AdminsSid)
        $ctx = New-FakeContext -Path '/defender' -User $principal
        $allowed = script:Build-AllowedGroups -Allow @($script:AdminsSid)
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated' -AllowedGroupSids $allowed
        $r.Authorized | Should -BeTrue
        $r.StatusCode | Should -Be 200
        $r.Reason     | Should -Be 'group-allowed'
        $r.User       | Should -Be 'WGSDAC\testuser'
    }

    It 'rejects (403) when the user is not in any allowed group' {
        $principal = New-FakePrincipal -UserSidString $script:UserSid -GroupSidStrings @($script:UsersSid)
        $ctx = New-FakeContext -Path '/defender' -User $principal
        $allowed = script:Build-AllowedGroups -Allow @($script:AdminsSid)
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated' -AllowedGroupSids $allowed
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 403
        $r.Reason     | Should -Be 'not-in-allow-list'
    }

    It 'rejects (403) when the user is in a denied group — deny wins over allow' {
        $principal = New-FakePrincipal -UserSidString $script:UserSid `
            -GroupSidStrings @($script:AdminsSid, $script:GuestsSid)
        $ctx = New-FakeContext -Path '/defender' -User $principal
        $allowed = script:Build-AllowedGroups -Allow @($script:AdminsSid) -Deny @($script:GuestsSid)
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated' -AllowedGroupSids $allowed
        $r.Authorized | Should -BeFalse
        $r.StatusCode | Should -Be 403
        $r.Reason     | Should -Be 'group-denied'
    }

    It 'allows any authenticated user when allow-list and deny-list are both empty' {
        $principal = New-FakePrincipal -UserSidString $script:UserSid
        $ctx = New-FakeContext -Path '/defender' -User $principal
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated' -AllowedGroupSids (script:Build-AllowedGroups)
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'no-allow-list'
    }

    It '/health bypass still anonymous in ADIntegrated mode' {
        # The selector delegate sets /health to Anonymous at the listener level;
        # this verifies the in-function bypass also handles a request that
        # arrived without a populated User (matches the listener's behavior).
        $ctx = New-FakeContext -Path '/health' -User $null
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated' -AllowedGroupSids (script:Build-AllowedGroups)
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'health-bypass'
    }

    It 'tolerates AllowedGroupSids being omitted entirely (defaults to any authenticated user)' {
        $principal = New-FakePrincipal -UserSidString $script:UserSid
        $ctx = New-FakeContext -Path '/defender' -User $principal
        $r = Test-DashboardAuth -Context $ctx -Method 'ADIntegrated'
        $r.Authorized | Should -BeTrue
        $r.Reason     | Should -Be 'no-allow-list'
    }
}

# Startup-validation tests live-fire only — they exit() the host process so
# can't run inside Pester without a subprocess wrapper. Validated by the
# maintainer when smoke-testing PR-D2b.
Describe 'AuthMethod = ADIntegrated — startup validation (live-fire only)' -Tag 'Integration' {
    It 'warns at startup when host is not domain-joined' -Skip {}
    It 'warns at startup for each unresolvable AuthAllowedGroups entry' -Skip {}
    It 'logs "any authenticated user permitted" when allow-list is empty' -Skip {}
}

Describe 'Installer pass-through — -AuthMethod/-AuthAllowedGroups/-AuthBasicUsersFile/-AuthToken' {
    # Exercises Update-ConfigValue via the same path the installer uses,
    # so we can assert the [Dashboard] section ends up with the expected
    # keys regardless of which Auth* params were supplied.
    BeforeAll {
        . (Join-Path $script:RepoRoot 'lib\Update-ConfigValue.ps1')
    }

    BeforeEach {
        $script:TestConfig = Join-Path $TestDrive 'config.conf'
        Set-Content -Path $script:TestConfig -Value @(
            '[Dashboard]'
            'Port = 8080'
            'AuthMethod = None'
            'AuthAllowedGroups ='
            'AuthBasicUsersFile = conf\dashboard.users'
            'AuthToken ='
        ) -Encoding UTF8
    }

    It 'persists AuthMethod to [Dashboard]' {
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'AuthMethod' -Value 'ADIntegrated'
        (Get-Content $script:TestConfig -Raw) | Should -Match '(?m)^AuthMethod = ADIntegrated'
    }

    It 'persists AuthAllowedGroups (allow+deny syntax)' {
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'AuthAllowedGroups' `
            -Value 'Domain Admins,Helpdesk,!Contractors'
        (Get-Content $script:TestConfig -Raw) | Should -Match 'Domain Admins,Helpdesk,!Contractors'
    }

    It 'persists AuthToken without disturbing other keys' {
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'AuthToken' -Value 'opaque-token'
        $content = Get-Content $script:TestConfig -Raw
        $content | Should -Match 'AuthToken = opaque-token'
        $content | Should -Match '(?m)^Port = 8080'
    }
}

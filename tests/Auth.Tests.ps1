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
            [hashtable]$Query    = @{}
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
# Stubs queued for PR-D2b — ADIntegrated, deny syntax, installer pass-through
# ============================================================================

Describe 'AuthMethod = ADIntegrated (PR-D2b placeholder)' -Tag 'Skip-Until-PR-D2b' {
    It 'rejects requests with no credentials (401)' -Skip {}
    It 'allows users whose group is in AuthAllowedGroups' -Skip {}
    It 'rejects users not in any allowed group (403)' -Skip {}
    It 'rejects users in a denied group via !Group syntax (deny precedence)' -Skip {}
    It 'allows when AuthAllowedGroups is empty (any authenticated user)' -Skip {}
    It 'warns at startup when host is not domain-joined' -Skip {}
}

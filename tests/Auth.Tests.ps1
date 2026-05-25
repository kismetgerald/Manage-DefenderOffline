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
# Stubs queued for PR-D2 — Basic, ADIntegrated, deny syntax, -AddBasicUser
# ============================================================================

Describe 'AuthMethod = Basic (PR-D2 placeholder)' -Tag 'Skip-Until-PR-D2' {
    It 'rejects at startup when -UseHttps is false (cleartext-Basic protection)' -Skip {}
    It 'rejects when AuthBasicUsersFile does not exist' -Skip {}
    It 'accepts credentials matching a user in the file (PBKDF2 verified)' -Skip {}
    It 'rejects wrong password' -Skip {}
    It 'rejects unknown username' -Skip {}
}

Describe 'AuthMethod = ADIntegrated (PR-D2 placeholder)' -Tag 'Skip-Until-PR-D2' {
    It 'rejects requests with no credentials (401)' -Skip {}
    It 'allows users whose group is in AuthAllowedGroups' -Skip {}
    It 'rejects users not in any allowed group (403)' -Skip {}
    It 'rejects users in a denied group via !Group syntax (deny precedence)' -Skip {}
    It 'allows when AuthAllowedGroups is empty (any authenticated user)' -Skip {}
    It 'warns at startup when host is not domain-joined' -Skip {}
}

Describe '-AddBasicUser helper mode (PR-D2 placeholder)' -Tag 'Skip-Until-PR-D2' {
    It 'appends username:bcrypt-hash to AuthBasicUsersFile' -Skip {}
    It 'exits 0 after writing without entering main flow' -Skip {}
}

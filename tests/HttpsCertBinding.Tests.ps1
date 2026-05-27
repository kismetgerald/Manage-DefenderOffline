#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester test scopes share state via $script:')]
param()
<#
Tests for lib/Test-HttpsCertBinding.ps1 — the dashboard's HTTPS pre-flight
cert-binding check added in v0.0.11. Parser is exercised with synthetic
netsh output (no actual netsh shell-out).
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Test-HttpsCertBinding.ps1')

    # Representative netsh http show sslcert output for a successful binding.
    # The first SSL Certificate block shows the cert hash; the rest is metadata
    # we don't parse but want to make sure doesn't trip the regex.
    $script:NetshHappyPath = @(
        ''
        'SSL Certificate bindings:'
        '-------------------------'
        ''
        '    IP:port                      : 0.0.0.0:8443'
        '    Certificate Hash             : ABCDEF0123456789ABCDEF0123456789ABCDEF01'
        '    Application ID               : {12345678-1234-1234-1234-123456789012}'
        '    Certificate Store Name       : My'
        '    Verify Client Certificate Revocation : Enabled'
        '    Negotiate Client Certificate : Disabled'
        ''
    )

    $script:NetshNoBinding = @(
        ''
        'The following command was not found: http show sslcert ipport=0.0.0.0:9999.'
        ''
    )

    $script:NetshWrongCert = @(
        ''
        'SSL Certificate bindings:'
        '-------------------------'
        ''
        '    IP:port                      : 0.0.0.0:8443'
        '    Certificate Hash             : 1111111111111111111111111111111111111111'
        '    Application ID               : {12345678-1234-1234-1234-123456789012}'
        ''
    )
}

Describe 'Get-NetshSslcertHash' {

    It 'extracts the hash from happy-path output' {
        Get-NetshSslcertHash -NetshOutput $script:NetshHappyPath |
            Should -Be 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
    }

    It 'is case-insensitive and uppercases the result' {
        $lower = @('    Certificate Hash : aabbccddeeff00112233445566778899aabbccdd')
        Get-NetshSslcertHash -NetshOutput $lower |
            Should -Be 'AABBCCDDEEFF00112233445566778899AABBCCDD'
    }

    It 'returns $null when no binding line is present' {
        Get-NetshSslcertHash -NetshOutput $script:NetshNoBinding | Should -BeNullOrEmpty
    }

    It 'returns $null for null input' {
        Get-NetshSslcertHash -NetshOutput $null | Should -BeNullOrEmpty
    }

    It 'returns $null for empty input' {
        Get-NetshSslcertHash -NetshOutput @() | Should -BeNullOrEmpty
    }
}

Describe 'Test-HttpsCertBinding' {

    Context 'IsBound = $true (happy path)' {
        It 'matches the bound cert against the expected thumbprint (case-insensitive)' {
            $result = Test-HttpsCertBinding `
                -Port 8443 `
                -ExpectedThumbprint 'abcdef0123456789abcdef0123456789abcdef01' `
                -NetshOutput $script:NetshHappyPath
            $result.IsBound         | Should -BeTrue
            $result.BoundThumbprint | Should -Be 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
            $result.Port            | Should -Be 8443
        }

        It 'tolerates whitespace in the expected thumbprint' {
            # Some operators copy the thumbprint from MMC, which inserts spaces.
            $result = Test-HttpsCertBinding `
                -Port 8443 `
                -ExpectedThumbprint 'ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01' `
                -NetshOutput $script:NetshHappyPath
            $result.IsBound | Should -BeTrue
        }
    }

    Context 'IsBound = $false' {

        It 'fails when no binding exists at the port' {
            $result = Test-HttpsCertBinding `
                -Port 9999 `
                -ExpectedThumbprint ('A' * 40) `
                -NetshOutput $script:NetshNoBinding
            $result.IsBound         | Should -BeFalse
            $result.BoundThumbprint | Should -BeNullOrEmpty
            $result.Reason          | Should -Match 'No sslcert binding found'
        }

        It 'fails when a different cert is bound to the port' {
            $result = Test-HttpsCertBinding `
                -Port 8443 `
                -ExpectedThumbprint ('A' * 40) `
                -NetshOutput $script:NetshWrongCert
            $result.IsBound         | Should -BeFalse
            $result.BoundThumbprint | Should -Be '1111111111111111111111111111111111111111'
            $result.Reason          | Should -Match 'Wrong cert bound'
        }

        It 'fails when ExpectedThumbprint is empty' {
            $result = Test-HttpsCertBinding `
                -Port 8443 `
                -ExpectedThumbprint '' `
                -NetshOutput $script:NetshHappyPath
            $result.IsBound | Should -BeFalse
            $result.Reason  | Should -Match 'ExpectedThumbprint is empty'
        }
    }

    Context 'Output shape' {
        It 'always returns the same property set' {
            $result = Test-HttpsCertBinding `
                -Port 8443 `
                -ExpectedThumbprint ('A' * 40) `
                -NetshOutput $script:NetshNoBinding
            $names = $result.PSObject.Properties.Name
            $names | Should -Contain 'IsBound'
            $names | Should -Contain 'BoundThumbprint'
            $names | Should -Contain 'Reason'
            $names | Should -Contain 'Port'
        }
    }
}

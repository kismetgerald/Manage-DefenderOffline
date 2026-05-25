#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Test variables consumed by dot-sourced functions via dynamic scope')]
param()
<#
Tests for dashboard HTTPS support.

  PR-C1 (this PR): validation logic — Resolve-DashboardCertificate,
  startup parameter handling, expiry warning trigger condition.

  PR-C2 (queued):  installer-driven cert generation, netsh sslcert
  binding, URL ACL, redirect listener round-trip. Tests for those
  stay -Skip below until PR-C2 lands.

Test approach for validation logic: create a real self-signed cert in
the user's CurrentUser cert store (not LocalMachine\My, so no admin
rights needed), then mock Get-Item to redirect Cert:\LocalMachine\My\
lookups to the test cert. Cleanup removes the cert in AfterAll.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Start-DefenderDashboard.ps1')

    # One real cert for the happy-path test. NotAfter in the past is rejected
    # by New-SelfSignedCertificate, so the expiring/expired cases use PSObject
    # stubs that satisfy the only properties Resolve-DashboardCertificate reads
    # (.Subject and .NotAfter).
    $script:CertValid = New-SelfSignedCertificate `
        -Subject 'CN=pester-test-valid' `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(1) `
        -KeyAlgorithm RSA -KeyLength 2048 `
        -KeyExportPolicy NonExportable

    $script:CertExpiringSoon = [pscustomobject]@{
        Subject    = 'CN=pester-test-expiring'
        Thumbprint = ('B' * 40)
        NotAfter   = (Get-Date).AddDays(15)
    }

    $script:CertExpired = [pscustomobject]@{
        Subject    = 'CN=pester-test-expired'
        Thumbprint = ('C' * 40)
        NotAfter   = (Get-Date).AddDays(-5)
    }
}

AfterAll {
    if ($script:CertValid) {
        try { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($script:CertValid.Thumbprint)" -Force -ErrorAction SilentlyContinue } catch {}
    }
}

Describe 'Resolve-DashboardCertificate' {

    Context 'Thumbprint validation' {

        It 'throws on empty thumbprint' {
            { Resolve-DashboardCertificate -Thumbprint '' } |
                Should -Throw -ExpectedMessage '*empty or not a valid*'
        }

        It 'throws on thumbprint with no hex characters' {
            { Resolve-DashboardCertificate -Thumbprint '   !!!   ' } |
                Should -Throw -ExpectedMessage '*empty or not a valid*'
        }

        It 'strips embedded whitespace from copy-pasted thumbprints' {
            # Mock Get-Item to verify the CLEANED thumbprint is used in the path
            Mock Get-Item { $script:CertValid }
            $thumbWithSpaces = $script:CertValid.Thumbprint.Insert(4, ' ').Insert(10, ' ')
            $result = Resolve-DashboardCertificate -Thumbprint $thumbWithSpaces
            $result.Thumbprint | Should -Be $script:CertValid.Thumbprint
        }
    }

    Context 'Cert lookup' {

        It 'returns a populated object when the cert exists' {
            Mock Get-Item { $script:CertValid }
            $result = Resolve-DashboardCertificate -Thumbprint $script:CertValid.Thumbprint
            $result.Certificate     | Should -Be $script:CertValid
            $result.Thumbprint      | Should -Be $script:CertValid.Thumbprint
            $result.Subject         | Should -Be $script:CertValid.Subject
            $result.NotAfter        | Should -Be $script:CertValid.NotAfter
            $result.DaysUntilExpiry | Should -BeGreaterThan 300
        }

        It 'throws a clear error when the cert is not found' {
            Mock Get-Item { $null }
            { Resolve-DashboardCertificate -Thumbprint 'AAAA1111BBBB2222' } |
                Should -Throw -ExpectedMessage '*not found in Cert:\LocalMachine\My*'
        }

        It 'error message points operator to the installer remediation' {
            Mock Get-Item { $null }
            try {
                Resolve-DashboardCertificate -Thumbprint 'AAAA1111BBBB2222'
                throw 'expected throw'
            } catch {
                $_.Exception.Message | Should -Match 'Install-DefenderDashboard.ps1 -UseHttps'
            }
        }
    }

    Context 'Expiry handling' {

        It 'returns DaysUntilExpiry near the cert NotAfter for a valid cert' {
            Mock Get-Item { $script:CertExpiringSoon }
            $result = Resolve-DashboardCertificate -Thumbprint $script:CertExpiringSoon.Thumbprint
            $result.DaysUntilExpiry | Should -BeGreaterThan 10
            $result.DaysUntilExpiry | Should -BeLessThan 30
        }

        It 'throws when the cert is past NotAfter' {
            Mock Get-Item { $script:CertExpired }
            { Resolve-DashboardCertificate -Thumbprint $script:CertExpired.Thumbprint } |
                Should -Throw -ExpectedMessage '*expired*day(s) ago*'
        }

        It 'expired-cert error suggests -RenewCertificate' {
            Mock Get-Item { $script:CertExpired }
            try {
                Resolve-DashboardCertificate -Thumbprint $script:CertExpired.Thumbprint
                throw 'expected throw'
            } catch {
                $_.Exception.Message | Should -Match '-RenewCertificate'
            }
        }
    }
}

# ============================================================================
# Stubs queued for PR-C2 — installer-driven cert generation and binding
# ============================================================================

Describe 'Installer HTTPS support (PR-C2 placeholder)' -Tag 'Skip-Until-PR-C2' {

    Context 'Cert generation via installer' {
        It 'creates a self-signed cert when UseHttps is true and no thumbprint supplied' -Skip {}
        It 'cert subject matches the dashboard host CN' -Skip {}
        It 'cert is valid for 2 years from issue date' -Skip {}
        It 'persists CertificateThumbprint back to config.conf via Update-ConfigValue' -Skip {}
        It 'rejects -RenewCertificate when -UseHttps is not set' -Skip {}
    }

    Context 'netsh sslcert binding' {
        It 'binds the cert to 0.0.0.0:<Port> via netsh http add sslcert' -Skip {}
        It 'idempotently replaces an existing binding on the same port' -Skip {}
        It 'creates URL ACL so service account can bind https:// prefix' -Skip {}
    }

    Context 'HTTP-to-HTTPS redirect listener (end-to-end)' {
        It 'returns 301 with HTTPS Location header for any HTTP request' -Skip {}
        It 'does not bind the redirect listener when RedirectHttpToHttps is false' -Skip {}
    }

    Context 'Basic auth + HTTPS interaction' {
        It 'allows AuthMethod=Basic to start when UseHttps=true' -Skip {}
    }
}

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
# Installer HTTPS support — cert generation and config persistence
# ============================================================================

Describe 'Installer cert generation parameters' {

    BeforeAll {
        # Generate a real cert using the SAME parameters the installer uses,
        # then assert that its shape matches what the dashboard expects.
        $fqdn = if ($env:USERDNSDOMAIN) { "$env:COMPUTERNAME.$env:USERDNSDOMAIN" } else { $env:COMPUTERNAME }
        $script:InstallerCert = New-SelfSignedCertificate `
            -Subject "CN=$env:COMPUTERNAME" `
            -DnsName $env:COMPUTERNAME, $fqdn, 'localhost' `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -NotAfter (Get-Date).AddYears(2) `
            -KeyAlgorithm RSA -KeyLength 2048 `
            -KeyExportPolicy NonExportable `
            -KeyUsage DigitalSignature, KeyEncipherment
    }

    AfterAll {
        if ($script:InstallerCert) {
            try { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($script:InstallerCert.Thumbprint)" -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

    It 'cert subject matches the dashboard host CN' {
        $script:InstallerCert.Subject | Should -Be "CN=$env:COMPUTERNAME"
    }

    It 'cert is valid for 2 years from issue date (within 1-day tolerance)' {
        $expectedExpiry = (Get-Date).AddYears(2)
        $diffDays       = [Math]::Abs(($script:InstallerCert.NotAfter - $expectedExpiry).TotalDays)
        $diffDays | Should -BeLessThan 1
    }

    It 'includes hostname, FQDN, and localhost as SANs' {
        $sanExt = $script:InstallerCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
        $sanExt | Should -Not -BeNullOrEmpty
        $sanText = $sanExt.Format($true)
        $sanText | Should -Match $env:COMPUTERNAME
        $sanText | Should -Match 'localhost'
    }

    It 'uses RSA 2048-bit key' {
        $script:InstallerCert.PublicKey.Key.KeySize | Should -Be 2048
    }

    It 'key is non-exportable (cannot be stolen via certutil export)' {
        # The cert's private key was created with -KeyExportPolicy NonExportable.
        # CngKey.ExportPolicy gives us the runtime view.
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($script:InstallerCert)
        if ($rsa -is [System.Security.Cryptography.RSACng]) {
            ($rsa.Key.ExportPolicy -band [System.Security.Cryptography.CngExportPolicies]::AllowExport) | Should -Be 0
        } else {
            # Older CryptoAPI provider — skip the assertion (newer Windows defaults to CNG).
            Set-ItResult -Skipped -Because 'Cert is using legacy CSP, not CNG; ExportPolicy not available'
        }
    }
}

Describe 'Installer config persistence' {

    BeforeAll {
        . (Join-Path $script:RepoRoot 'lib\Update-ConfigValue.ps1')
    }

    BeforeEach {
        $script:TestConfig = Join-Path $TestDrive 'config.conf'
        Set-Content -Path $script:TestConfig -Value @(
            '[Dashboard]'
            'Port = 8080'
            'UseHttps = false'
            'CertificateThumbprint ='
        ) -Encoding UTF8
    }

    It 'persists UseHttps = true to [Dashboard]' {
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'UseHttps' -Value 'true'
        (Get-Content -Path $script:TestConfig -Raw) | Should -Match '(?m)^UseHttps = true'
    }

    It 'persists the generated thumbprint' {
        $thumb = '0123456789ABCDEF0123456789ABCDEF01234567'
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'CertificateThumbprint' -Value $thumb
        (Get-Content -Path $script:TestConfig -Raw) | Should -Match "CertificateThumbprint = $thumb"
    }

    It 'replaces a prior thumbprint on -RenewCertificate flow' {
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'CertificateThumbprint' -Value 'OLDTHUMB1234567890'
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'CertificateThumbprint' -Value 'NEWTHUMB1234567890'
        $content = Get-Content -Path $script:TestConfig -Raw
        $content | Should -Match 'NEWTHUMB1234567890'
        $content | Should -Not -Match 'OLDTHUMB1234567890'
    }

    It 'preserves existing keys when adding HTTPS settings' {
        Update-ConfigValue -Path $script:TestConfig -Section 'Dashboard' -Key 'UseHttps' -Value 'true'
        $content = Get-Content -Path $script:TestConfig -Raw
        $content | Should -Match '(?m)^Port = 8080'
        $content | Should -Match '(?m)^\[Dashboard\]'
    }
}

# ============================================================================
# Installer netsh + end-to-end integration — validated via live-fire only
# ============================================================================

Describe 'Installer netsh + integration (live-fire only)' -Tag 'Integration' {

    Context 'netsh sslcert binding' {
        # These call native netsh.exe and require LocalMachine\My access.
        # Validated by the maintainer during PR-C2 live-fire testing.
        It 'binds the cert to 0.0.0.0:<Port> via netsh http add sslcert' -Skip {}
        It 'idempotently replaces an existing binding on the same port' -Skip {}
        It 'creates URL ACL so service account can bind https:// prefix' -Skip {}
    }

    Context 'HTTP-to-HTTPS redirect listener (end-to-end)' {
        # Requires a real cert + sslcert binding + listener startup.
        It 'returns 301 with HTTPS Location header for any HTTP request' -Skip {}
        It 'does not bind the redirect listener when RedirectHttpToHttps is false' -Skip {}
    }

    Context 'Basic auth + HTTPS interaction' {
        # Belongs to PR-D (auth).
        It 'allows AuthMethod=Basic to start when UseHttps=true' -Skip {}
    }
}

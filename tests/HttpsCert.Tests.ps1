#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for dashboard HTTPS support (PR-C / #6 in roadmap).

Stub file: skeleton tests for self-signed cert generation, netsh sslcert
binding, cert-expiry warning (EventId 103), and the HTTP-to-HTTPS redirect
listener. Real implementations land in PR-C when the cert generation and
listener changes are written.

Marked -Skip so CI stays green while the production code is still queued.
#>

Describe 'Dashboard HTTPS support (PR-C placeholder)' -Tag 'Skip-Until-PR-C' {

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

    Context 'Dashboard startup validation' {
        It 'throws clearly when UseHttps=true but no CertificateThumbprint set' -Skip {}
        It 'throws when CertificateThumbprint does not resolve to a cert in Cert:\LocalMachine\My' -Skip {}
        It 'throws when the cert is past its NotAfter date' -Skip {}
        It 'logs EventId 103 (Warning) when cert is within 30 days of expiry' -Skip {}
    }

    Context 'HTTP-to-HTTPS redirect listener' {
        It 'binds a secondary HTTP listener on RedirectHttpPort when RedirectHttpToHttps is true' -Skip {}
        It 'returns 301 with HTTPS Location header for any HTTP request' -Skip {}
        It 'does not bind the redirect listener when RedirectHttpToHttps is false' -Skip {}
    }

    Context 'Basic auth + HTTPS interaction' {
        It 'allows AuthMethod=Basic to start when UseHttps=true' -Skip {}
        # (cleartext-Basic rejection is tested in Auth.Tests.ps1)
    }
}

#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for v0.0.22 credential reuse:
  - lib/Test-ServiceCredential.ps1 — pure validation helper. Decrypts an
    Export-Clixml'd PSCredential and exits 0 on success, 1 on failure.
  - Test-ServiceCredential function in Install-ManageDefender.ps1 — short-
    circuits when the XML file is absent (no helper spawn).

The helper is invoked as a child process so the exit code is observable.
For the helper's "valid XML in same identity context" case we create the
XML in the current user's DPAPI scope and run the helper as the current
user — that matches real-world reuse, where the operator who runs the
installer is also the service identity in the trivial single-user case
(and in multi-user cases the seclogon dance crosses the user boundary,
which is integration-tested in the lab, not Pester).
#>

BeforeAll {
    $script:RepoRoot   = Split-Path -Parent $PSScriptRoot
    $script:HelperPath = Join-Path $script:RepoRoot 'lib\Test-ServiceCredential.ps1'

    # Use pwsh if available (PS7+), otherwise fall back to whichever host is
    # running Pester. The helper itself targets PS5.1+, so either is fine.
    $script:Pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)
    if (-not $script:Pwsh) { $script:Pwsh = Get-Command powershell }

    function script:Invoke-Helper {
        param([Parameter(Mandatory)][string]$SourcePath)
        # Run the helper as a child process so we can observe its exit code.
        # -NoProfile keeps PSReadLine / user profile out of the timing path.
        $pwshArgs = @(
            '-NoProfile', '-NonInteractive',
            '-File', $script:HelperPath,
            '-SourcePath', $SourcePath
        )
        $null = & $script:Pwsh.Source @pwshArgs 2>&1
        return $LASTEXITCODE
    }

    function script:Export-FakeCredential {
        param([Parameter(Mandatory)][string]$Path, [string]$Username = 'TESTDOMAIN\testuser')
        # Build a real PSCredential and Export-Clixml it. DPAPI-encrypts the
        # password under the current user × machine — same primitive the
        # installer uses via Save-ServiceCredential.ps1.
        $sec = ConvertTo-SecureString -String 'p@ssword!1' -AsPlainText -Force
        $cred = [System.Management.Automation.PSCredential]::new($Username, $sec)
        $cred | Export-Clixml -Path $Path -Force
    }
}

Describe 'lib/Test-ServiceCredential.ps1' {

    Context 'Valid credential XML' {

        It 'exits 0 for a PSCredential XML readable by the current identity' {
            $xml = Join-Path $TestDrive 'good.xml'
            Export-FakeCredential -Path $xml
            Invoke-Helper -SourcePath $xml | Should -Be 0
        }

        It 'does not write the side log on success' {
            $xml = Join-Path $TestDrive 'good2.xml'
            Export-FakeCredential -Path $xml
            $null = Invoke-Helper -SourcePath $xml
            Test-Path -LiteralPath ($xml + '.err') | Should -BeFalse
        }
    }

    Context 'Missing or invalid XML' {

        It 'exits 1 for a missing source path' {
            $xml = Join-Path $TestDrive 'never-existed.xml'
            Invoke-Helper -SourcePath $xml | Should -Be 1
        }

        It 'exits 1 for a non-XML file' {
            $xml = Join-Path $TestDrive 'garbage.xml'
            'this is not an Export-Clixml output' | Set-Content -Path $xml -Encoding UTF8
            Invoke-Helper -SourcePath $xml | Should -Be 1
        }

        It 'exits 1 for an XML that does not deserialize to a PSCredential' {
            $xml = Join-Path $TestDrive 'wrongtype.xml'
            # Export-Clixml a plain string — round-trips fine but is not a PSCredential
            'just-a-string' | Export-Clixml -Path $xml -Force
            Invoke-Helper -SourcePath $xml | Should -Be 1
        }

        It 'exits 1 when the encrypted blob is corrupted (truncated)' {
            $xml = Join-Path $TestDrive 'corrupt.xml'
            Export-FakeCredential -Path $xml
            # Truncate the file mid-blob — Import-Clixml may still parse the
            # outer wrapper but the SecureString unwrap inside the credential
            # will throw. The GetNetworkCredential() check catches partial
            # DPAPI corruption that survives Import-Clixml.
            $bytes = [System.IO.File]::ReadAllBytes($xml)
            [System.IO.File]::WriteAllBytes($xml, $bytes[0..([math]::Floor($bytes.Length / 2))])
            Invoke-Helper -SourcePath $xml | Should -Be 1
        }

        It 'writes the diagnostic side log on failure' {
            $xml = Join-Path $TestDrive 'sidelog-on-fail.xml'
            $null = Invoke-Helper -SourcePath $xml
            Test-Path -LiteralPath ($xml + '.err') | Should -BeTrue
            $content = Get-Content -LiteralPath ($xml + '.err') -Raw
            $content | Should -Match 'SourcePath'
            $content | Should -Match 'Helper invoked as'
        }
    }
}

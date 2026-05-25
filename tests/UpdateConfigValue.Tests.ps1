#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for lib/Update-ConfigValue.ps1: in-place config writer.
Verifies key updates preserve comments, blank lines, and section structure.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Update-ConfigValue.ps1')
}

Describe 'lib/Update-ConfigValue.ps1' {

    BeforeEach {
        # Sample config covering all the structural elements we need to preserve.
        $script:SampleConfig = @'
# Manage-DefenderOffline configuration

[Common]
# Where the definition files live.
SourceSharePath =
ParallelThreads = 16

[Dashboard]
Port = 8080
RefreshInterval = 300
DashboardTheme = Dark

[Email]
SendEmail = false
'@
        $script:TestPath = Join-Path $TestDrive 'sample.conf'
        Set-Content -Path $script:TestPath -Value $script:SampleConfig -Encoding UTF8
    }

    Context 'Updating an existing key' {

        It 'updates the value in place when key exists in the named section' {
            Update-ConfigValue -Path $script:TestPath -Section 'Dashboard' -Key 'Port' -Value '8443'
            $content = Get-Content -Path $script:TestPath -Raw
            $content | Should -Match 'Port = 8443'
            $content | Should -Not -Match 'Port = 8080'
        }

        It 'preserves the rest of the file unchanged' {
            $before = Get-Content -Path $script:TestPath
            Update-ConfigValue -Path $script:TestPath -Section 'Dashboard' -Key 'Port' -Value '8443'
            $after  = Get-Content -Path $script:TestPath
            $before.Count | Should -Be $after.Count
            # Same number of comment lines
            ($before | Where-Object { $_ -match '^\s*#' }).Count |
                Should -Be ($after | Where-Object { $_ -match '^\s*#' }).Count
            # Same number of section headers
            ($before | Where-Object { $_ -match '^\s*\[' }).Count |
                Should -Be ($after | Where-Object { $_ -match '^\s*\[' }).Count
        }

        It 'updates an empty value (key = blank)' {
            Update-ConfigValue -Path $script:TestPath -Section 'Common' -Key 'SourceSharePath' -Value '\\NAS\Share'
            (Get-Content -Path $script:TestPath -Raw) | Should -Match 'SourceSharePath = \\\\NAS\\Share'
        }

        It 'is case-insensitive on the key name' {
            Update-ConfigValue -Path $script:TestPath -Section 'Dashboard' -Key 'PORT' -Value '9999'
            (Get-Content -Path $script:TestPath -Raw) | Should -Match '(?m)^\s*Port = 9999'
        }
    }

    Context 'Appending a new key' {

        It 'appends to an existing section when the key is new' {
            Update-ConfigValue -Path $script:TestPath -Section 'Dashboard' -Key 'CertificateThumbprint' -Value 'ABC123'
            $content = Get-Content -Path $script:TestPath -Raw
            $content | Should -Match 'CertificateThumbprint = ABC123'
            # Make sure it landed in the Dashboard section, not at file end
            $lines = Get-Content -Path $script:TestPath
            $dashIdx = ($lines | Select-String -Pattern '^\[Dashboard\]$').LineNumber
            $emailIdx = ($lines | Select-String -Pattern '^\[Email\]$').LineNumber
            $certIdx = ($lines | Select-String -Pattern 'CertificateThumbprint').LineNumber
            $certIdx | Should -BeGreaterThan $dashIdx
            $certIdx | Should -BeLessThan $emailIdx
        }

        It 'creates a new section and appends the key when the section does not exist' {
            Update-ConfigValue -Path $script:TestPath -Section 'Telemetry' -Key 'SplunkUrl' -Value 'https://splunk:8088'
            $content = Get-Content -Path $script:TestPath -Raw
            $content | Should -Match '\[Telemetry\]'
            $content | Should -Match 'SplunkUrl = https://splunk:8088'
        }
    }

    Context 'Error handling' {

        It 'throws when the config file does not exist' {
            $missing = Join-Path $TestDrive 'does-not-exist.conf'
            { Update-ConfigValue -Path $missing -Section 'X' -Key 'Y' -Value 'Z' } |
                Should -Throw -ExpectedMessage '*not found*'
        }
    }

    Context 'WhatIf support' {

        It 'does not modify the file under -WhatIf' {
            $before = Get-Content -Path $script:TestPath -Raw
            Update-ConfigValue -Path $script:TestPath -Section 'Dashboard' -Key 'Port' -Value '9999' -WhatIf
            $after  = Get-Content -Path $script:TestPath -Raw
            $after | Should -Be $before
        }
    }
}

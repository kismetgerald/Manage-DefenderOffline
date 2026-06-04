#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for Get-DefenderDefinitions.ps1 -WhatIf.

v0.0.20.1 adds [CmdletBinding(SupportsShouldProcess)] and a ShouldProcess
gate around the Invoke-WebRequest call so an operator can dry-run the
downloader to validate config, proxy resolution, and the existing-folder
fast-path without pulling ~200 MB per architecture.

Invoked as a child process (pwsh -File ...) rather than dot-sourced
because the script's main-flow guard returns early on dot-source, which
hides the very code path we want to exercise.
#>

BeforeAll {
    $script:RepoRoot   = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:RepoRoot 'Get-DefenderDefinitions.ps1'

    # Use pwsh if available (PS7), otherwise the legacy host. Pester itself
    # runs under whichever host the operator invoked it from.
    $script:Pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)
    if (-not $script:Pwsh) { $script:Pwsh = Get-Command powershell }
}

Describe 'Get-DefenderDefinitions.ps1 -WhatIf' {

    BeforeEach {
        $script:OutDir = Join-Path $TestDrive ("out-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    }

    It 'declares SupportsShouldProcess (the v0.0.20.1 fix)' {
        # Static check on the script header — fails fast if a future refactor
        # drops SupportsShouldProcess and silently re-breaks -WhatIf.
        $header = (Get-Content -Path $script:ScriptPath -TotalCount 120) -join "`n"
        $header | Should -Match 'CmdletBinding\s*\(\s*SupportsShouldProcess'
    }

    It 'gates the network call: no file is created under TestDrive when -WhatIf is set' {
        $pwshArgs = @(
            '-NoProfile', '-NonInteractive', '-File', $script:ScriptPath,
            '-OutputPath', $script:OutDir,
            '-Architecture', 'x64',
            '-WhatIf'
        )
        $output = & $script:Pwsh.Source @pwshArgs 2>&1
        $LASTEXITCODE | Should -Be 0

        # Under -WhatIf the date-stamped folder must not be created and no
        # mpam-fe.exe / mpam-fe.sha256 / transfer-manifest.json must appear.
        $created = Get-ChildItem -Path $script:OutDir -Recurse -File -ErrorAction SilentlyContinue
        $created | Should -BeNullOrEmpty

        # And the operator-facing WhatIf message must explain what would happen.
        ($output -join "`n") | Should -Match '\[WHATIF\] Would download'
    }

    It 'still runs the banner and architecture resolution under -WhatIf' {
        # WhatIf should be a read-only validation pass, not a no-op. The
        # banner + arch list are how the operator confirms config/proxy
        # resolution worked.
        $pwshArgs = @(
            '-NoProfile', '-NonInteractive', '-File', $script:ScriptPath,
            '-OutputPath', $script:OutDir,
            '-Architecture', 'x64',
            '-WhatIf'
        )
        $output = (& $script:Pwsh.Source @pwshArgs 2>&1) -join "`n"
        $output | Should -Match 'Microsoft Defender Definitions Downloader'
        $output | Should -Match 'Architectures\s+:\s+x64'
    }
}

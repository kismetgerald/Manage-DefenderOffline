#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester test scopes share state via $script:')]
param()
<#
Tests for the multi-architecture support introduced in v0.0.8.

Three surfaces are exercised here:

  1. Get-AvailableMpamFiles (in Update-DefenderOffline.ps1) — walks a share
     and classifies mpam-fe.exe files by version + architecture. Supports both
     the legacy flat layout (<version>\mpam-fe.exe, treated as x64) and the
     new per-arch layout (<version>\<arch>\mpam-fe.exe).

  2. Get-LatestMpamFile — thin wrapper that returns the latest entry, with
     an optional -Architecture filter for per-host dispatch.

  3. Resolve-Architectures (in Get-DefenderDefinitions.ps1) — input parser
     for the -Architecture parameter. Handles 'All', single values, array
     form, comma-separated strings, dedup, case-insensitivity, whitespace,
     and invalid input. Reachable via dot-source because the script gates
     its main flow on $MyInvocation.InvocationName -eq '.' (v0.0.9).

The download loop itself talks to the public Microsoft download endpoint
and is exercised in live-fire rather than Pester.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot

    # Dot-source Update-DefenderOffline to bring Get-AvailableMpamFiles and
    # Get-LatestMpamFile into scope. The script is gated against running its
    # main flow at dot-source time when no -SourceSharePath / no args are
    # provided — and Pester invocation provides neither, so just the function
    # definitions land.
    . (Join-Path $script:RepoRoot 'Update-DefenderOffline.ps1')
}

Describe 'Get-AvailableMpamFiles — share layout discovery' {

    BeforeEach {
        # Fresh per-test share root so layouts don't leak between tests.
        $script:Share = Join-Path $TestDrive ("share-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $script:Share -Force | Out-Null
    }

    function script:New-MpamFile {
        param([string]$Root, [string]$Date, [string]$Version, [string]$Architecture)
        # Architecture='' means "flat layout" (no arch subfolder).
        $folder = if ($Architecture) {
            Join-Path $Root (Join-Path $Date (Join-Path "v$Version" $Architecture))
        } else {
            Join-Path $Root (Join-Path $Date "v$Version")
        }
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $file = Join-Path $folder 'mpam-fe.exe'
        # Content doesn't matter; the function only cares about path shape.
        Set-Content -Path $file -Value 'stub' -Encoding ASCII
        $file
    }

    It 'discovers flat-layout files and classifies them as x64' {
        New-MpamFile -Root $script:Share -Date '20260520' -Version '1.451.85.0' -Architecture ''
        $r = Get-AvailableMpamFiles -Root $script:Share
        $r.Count | Should -Be 1
        $r[0].Architecture | Should -Be 'x64'
        $r[0].IsFlatLayout | Should -BeTrue
        $r[0].Version.ToString() | Should -Be '1.451.85.0'
    }

    It 'discovers per-arch-layout files and reads the arch from the parent folder' {
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'x64'
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'x86'
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'arm64'
        $r = Get-AvailableMpamFiles -Root $script:Share
        $r.Count | Should -Be 3
        @($r | Where-Object Architecture -eq 'x64').Count   | Should -Be 1
        @($r | Where-Object Architecture -eq 'x86').Count   | Should -Be 1
        @($r | Where-Object Architecture -eq 'arm64').Count | Should -Be 1
        # IsFlatLayout is false for all three since they live in arch subfolders
        @($r | Where-Object { -not $_.IsFlatLayout }).Count | Should -Be 3
    }

    It 'sorts results by Version descending' {
        New-MpamFile -Root $script:Share -Date '20260520' -Version '1.451.85.0' -Architecture 'x64'
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'x64'
        New-MpamFile -Root $script:Share -Date '20260518' -Version '1.450.10.0' -Architecture 'x64'
        $r = Get-AvailableMpamFiles -Root $script:Share
        $r[0].Version.ToString() | Should -Be '1.451.95.0'
        $r[1].Version.ToString() | Should -Be '1.451.85.0'
        $r[2].Version.ToString() | Should -Be '1.450.10.0'
    }

    It 'is case-insensitive on the arch subfolder name' {
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'X64'
        $r = Get-AvailableMpamFiles -Root $script:Share
        # Architecture is normalized to lowercase regardless of folder case
        $r[0].Architecture | Should -Be 'x64'
    }

    It 'mixes both layouts in the same share (legacy + new)' {
        # Flat layout from a prior run, plus a freshly-staged multi-arch drop:
        New-MpamFile -Root $script:Share -Date '20260518' -Version '1.450.10.0' -Architecture ''
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'x64'
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'arm64'
        $r = Get-AvailableMpamFiles -Root $script:Share
        $r.Count | Should -Be 3
        # The flat entry is classified as x64 → there are TWO x64 entries
        @($r | Where-Object Architecture -eq 'x64').Count | Should -Be 2
    }

    It 'ignores files outside a v#.#.#.# folder' {
        $folder = Join-Path $script:Share 'random-folder'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Set-Content -Path (Join-Path $folder 'mpam-fe.exe') -Value 'stub' -Encoding ASCII
        { Get-AvailableMpamFiles -Root $script:Share } | Should -Throw -ExpectedMessage '*none reside in a*'
    }

    It 'skips files under an _archive subfolder' {
        # Path: <share>\_archive\20240101\v1.0.0.0\mpam-fe.exe — should be ignored
        $arc = Join-Path $script:Share '_archive\20240101\v1.0.0.0'
        New-Item -ItemType Directory -Path $arc -Force | Out-Null
        Set-Content -Path (Join-Path $arc 'mpam-fe.exe') -Value 'stub' -Encoding ASCII
        # Add a real one so we don't trip the "none found" exception
        New-MpamFile -Root $script:Share -Date '20260526' -Version '1.451.95.0' -Architecture 'x64'
        $r = Get-AvailableMpamFiles -Root $script:Share
        $r.Count | Should -Be 1
        $r[0].Version.ToString() | Should -Be '1.451.95.0'
    }

    It 'throws when no mpam-fe.exe is present' {
        { Get-AvailableMpamFiles -Root $script:Share } | Should -Throw -ExpectedMessage '*No mpam-fe.exe files found*'
    }
}

Describe 'Get-LatestMpamFile — wrapper with optional arch filter' {

    BeforeAll {
        # One share with files across all three arches at multiple versions.
        $script:Share = Join-Path $TestDrive 'latest-share'
        New-Item -ItemType Directory -Path $script:Share -Force | Out-Null
        foreach ($a in 'x64','x86','arm64') {
            foreach ($v in '1.451.85.0','1.451.95.0') {
                $folder = Join-Path $script:Share "20260526\v$v\$a"
                New-Item -ItemType Directory -Path $folder -Force | Out-Null
                Set-Content -Path (Join-Path $folder 'mpam-fe.exe') -Value 'stub' -Encoding ASCII
            }
        }
    }

    It 'returns the absolute latest when -Architecture is omitted' {
        $r = Get-LatestMpamFile -Root $script:Share
        $r.Version.ToString() | Should -Be '1.451.95.0'
    }

    It 'returns the latest for a specific architecture when -Architecture is set' {
        $r = Get-LatestMpamFile -Root $script:Share -Architecture 'arm64'
        $r.Version.ToString() | Should -Be '1.451.95.0'
        $r.Architecture        | Should -Be 'arm64'
        $r.File                | Should -Match 'arm64'
    }

    It 'throws when the requested architecture is not present in the share' {
        # Build a fresh share with x64-only, then ask for arm64
        $bare = Join-Path $TestDrive 'x64-only-share'
        $folder = Join-Path $bare '20260526\v1.451.95.0\x64'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Set-Content -Path (Join-Path $folder 'mpam-fe.exe') -Value 'stub' -Encoding ASCII
        { Get-LatestMpamFile -Root $bare -Architecture 'arm64' } |
            Should -Throw -ExpectedMessage "*No mpam-fe.exe found for architecture 'arm64'*"
    }
}

Describe 'Get-DefenderDefinitions.ps1 — Resolve-Architectures' {
    # Get-DefenderDefinitions is gated on $MyInvocation.InvocationName -eq '.'
    # so dot-sourcing brings the function definitions into scope without
    # firing the banner / download loop.

    BeforeAll {
        . (Join-Path $script:RepoRoot 'Get-DefenderDefinitions.ps1')
    }

    Context "'All' / empty / null inputs expand to every supported arch" {
        It "returns x64 + x86 + arm64 when -Spec is 'All'" {
            $r = Resolve-Architectures -Spec 'All'
            @($r) | Should -Be @('x64','x86','arm64')
        }

        It 'returns x64 + x86 + arm64 when -Spec is an empty array' {
            $r = Resolve-Architectures -Spec @()
            @($r) | Should -Be @('x64','x86','arm64')
        }

        It "is case-insensitive on 'ALL'" {
            $r = Resolve-Architectures -Spec 'ALL'
            @($r) | Should -Be @('x64','x86','arm64')
        }
    }

    Context 'Single-architecture inputs' {
        It "honors a single 'x64'" {
            $r = Resolve-Architectures -Spec 'x64'
            @($r) | Should -Be @('x64')
        }

        It 'normalizes uppercase to lowercase' {
            $r = Resolve-Architectures -Spec 'X64'
            @($r) | Should -Be @('x64')
        }

        It 'trims surrounding whitespace' {
            $r = Resolve-Architectures -Spec '  arm64  '
            @($r) | Should -Be @('arm64')
        }
    }

    Context 'Multi-architecture inputs' {
        It 'honors array form @(x64, arm64)' {
            $r = Resolve-Architectures -Spec @('x64','arm64')
            @($r) | Should -Be @('x64','arm64')
        }

        It "honors comma-separated single string 'x64,arm64'" {
            $r = Resolve-Architectures -Spec 'x64,arm64'
            @($r) | Should -Be @('x64','arm64')
        }

        It 'flattens array of comma-separated strings' {
            $r = Resolve-Architectures -Spec @('x64,x86','arm64')
            @($r) | Should -Be @('x64','x86','arm64')
        }

        It 'dedupes repeated entries while preserving first-seen order' {
            $r = Resolve-Architectures -Spec 'x64,x64,arm64,x64'
            @($r) | Should -Be @('x64','arm64')
        }

        It "treats whitespace around commas correctly: 'x64 , arm64'" {
            $r = Resolve-Architectures -Spec 'x64 , arm64'
            @($r) | Should -Be @('x64','arm64')
        }
    }

    Context 'Invalid inputs' {
        It 'throws on an unknown architecture name' {
            { Resolve-Architectures -Spec 'invalid' } |
                Should -Throw -ExpectedMessage "*Unknown architecture 'invalid'*"
        }

        It 'throws when any value in a multi-arch list is invalid' {
            { Resolve-Architectures -Spec 'x64,bogus' } |
                Should -Throw -ExpectedMessage "*Unknown architecture 'bogus'*"
        }

        It 'error message lists the supported architectures' {
            { Resolve-Architectures -Spec 'sparc' } |
                Should -Throw -ExpectedMessage '*Supported: x64, x86, ARM64, All*'
        }
    }
}

Describe 'Get-DefenderDefinitions.ps1 — parameter surface' {
    # Static parameter-existence checks. Verifies the script exposes the
    # documented parameters so renames or accidental deletions are caught
    # at unit-test time, not by an operator hitting "param not found" in
    # the field.

    BeforeAll {
        $script:CmdInfo = Get-Command (Join-Path $script:RepoRoot 'Get-DefenderDefinitions.ps1')
    }

    It 'declares -Proxy as a [string]' {
        $script:CmdInfo.Parameters.ContainsKey('Proxy') | Should -BeTrue
        $script:CmdInfo.Parameters['Proxy'].ParameterType | Should -Be ([string])
    }

    It 'declares -ProxyCredential as a [pscredential]' {
        $script:CmdInfo.Parameters.ContainsKey('ProxyCredential') | Should -BeTrue
        $script:CmdInfo.Parameters['ProxyCredential'].ParameterType | Should -Be ([pscredential])
    }

    It 'declares -Force as a [switch]' {
        $script:CmdInfo.Parameters['Force'].ParameterType | Should -Be ([switch])
    }

    It 'declares -Architecture as [string[]]' {
        # Regression: v0.0.8 PR-Download originally bound this as [string],
        # so unquoted commas on the CLI (-Architecture x64,arm64) failed
        # parameter binding. Must remain [string[]].
        $script:CmdInfo.Parameters['Architecture'].ParameterType | Should -Be ([string[]])
    }
}

#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for Read-ConfigFile (defined identically in all four scripts).
We dot-source Update-DefenderOffline.ps1 as the canonical source; the
copies in Show/Start/Install are byte-equivalent for this function.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Update-DefenderOffline.ps1')
}

Describe 'Read-ConfigFile' {

    BeforeEach {
        $script:TestPath = Join-Path $TestDrive 'test.conf'
    }

    Context 'Basic key/value parsing' {

        It 'returns an empty dictionary for a missing file' {
            $result = Read-ConfigFile -Path (Join-Path $TestDrive 'does-not-exist.conf')
            # Pester's -BeOfType has trouble with closed generic types, so just
            # verify the duck-typed contract: count + indexer + case-insensitive
            $result.Count | Should -Be 0
            $result.GetType().Name | Should -BeLike 'Dictionary*'
        }

        It 'parses simple Key = Value pairs' {
            Set-Content $script:TestPath -Value @(
                'SourceSharePath = \\NAS\Share'
                'ParallelThreads = 16'
            )
            $result = Read-ConfigFile -Path $script:TestPath
            $result['SourceSharePath'] | Should -Be '\\NAS\Share'
            $result['ParallelThreads'] | Should -Be '16'
        }

        It 'trims leading and trailing whitespace around keys and values' {
            Set-Content $script:TestPath -Value '    Port   =     8080    '
            $result = Read-ConfigFile -Path $script:TestPath
            $result['Port'] | Should -Be '8080'
        }

        It 'is case-insensitive on key lookup' {
            Set-Content $script:TestPath -Value 'Port = 8080'
            $result = Read-ConfigFile -Path $script:TestPath
            $result['PORT'] | Should -Be '8080'
            $result['port'] | Should -Be '8080'
            $result['Port'] | Should -Be '8080'
        }
    }

    Context 'Comments and blank lines' {

        It 'skips lines that start with #' {
            Set-Content $script:TestPath -Value @(
                '# This is a comment'
                'Port = 8080'
                '# Another comment'
            )
            $result = Read-ConfigFile -Path $script:TestPath
            $result.Count | Should -Be 1
            $result['Port'] | Should -Be '8080'
        }

        It 'skips blank lines' {
            Set-Content $script:TestPath -Value @(
                ''
                'Port = 8080'
                ''
                ''
            )
            $result = Read-ConfigFile -Path $script:TestPath
            $result.Count | Should -Be 1
        }

        It 'skips section headers [Section]' {
            Set-Content $script:TestPath -Value @(
                '[Common]'
                'Port = 8080'
                '[Dashboard]'
                'RefreshInterval = 300'
            )
            $result = Read-ConfigFile -Path $script:TestPath
            $result.Count | Should -Be 2
            $result['Port'] | Should -Be '8080'
            $result['RefreshInterval'] | Should -Be '300'
        }

        It 'skips comments with leading whitespace' {
            Set-Content $script:TestPath -Value @(
                '    # indented comment'
                'Port = 8080'
            )
            $result = Read-ConfigFile -Path $script:TestPath
            $result.Count | Should -Be 1
        }
    }

    Context 'Quoted values' {

        It 'strips surrounding double quotes' {
            Set-Content $script:TestPath -Value 'Path = "\\NAS\Share with spaces"'
            $result = Read-ConfigFile -Path $script:TestPath
            $result['Path'] | Should -Be '\\NAS\Share with spaces'
        }

        It 'strips surrounding single quotes' {
            Set-Content $script:TestPath -Value "Path = '\\NAS\Share'"
            $result = Read-ConfigFile -Path $script:TestPath
            $result['Path'] | Should -Be '\\NAS\Share'
        }

        It 'does not strip mismatched quotes' {
            Set-Content $script:TestPath -Value "Path = `"value'"
            $result = Read-ConfigFile -Path $script:TestPath
            # Mismatched quotes left as-is
            $result['Path'] | Should -Be "`"value'"
        }
    }

    Context 'Edge cases' {

        It 'handles equals signs inside values' {
            Set-Content $script:TestPath -Value 'ConnectionString = Server=foo;Trusted=true'
            $result = Read-ConfigFile -Path $script:TestPath
            $result['ConnectionString'] | Should -Be 'Server=foo;Trusted=true'
        }

        It 'ignores lines without an equals sign' {
            Set-Content $script:TestPath -Value @(
                'this line has no equals'
                'Port = 8080'
                'another non-config line'
            )
            $result = Read-ConfigFile -Path $script:TestPath
            $result.Count | Should -Be 1
            $result['Port'] | Should -Be '8080'
        }
    }
}

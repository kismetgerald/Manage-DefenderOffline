#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for the version comparison and delta semantics used inline in
Update-DefenderOffline.ps1 (and Get-LatestMpamFile sort logic).

The version logic itself is not in a separate function. These tests
document the [version] type behavior the script depends on, so a future
PowerShell change or accidental refactor that breaks these assumptions
is caught immediately.
#>

Describe '[version] type semantics relied upon by the toolkit' {

    Context 'Comparison ordering' {

        It 'sorts versions numerically, not lexicographically' {
            # Plain string sort would put "1.451.66.0" after "1.451.7.0".
            # [version] comparison is by component, so 66 > 7.
            $sorted = @('1.451.7.0', '1.451.66.0', '1.451.5.0') |
                Sort-Object { [version]$_ }
            $sorted[0] | Should -Be '1.451.5.0'
            $sorted[1] | Should -Be '1.451.7.0'
            $sorted[2] | Should -Be '1.451.66.0'
        }

        It 'treats equal versions as equal' {
            ([version]'1.451.85.0' -eq [version]'1.451.85.0') | Should -BeTrue
        }

        It 'returns true for -ge when installed version equals available' {
            $installed = [version]'1.451.85.0'
            $available = [version]'1.451.85.0'
            ($installed -ge $available) | Should -BeTrue
        }

        It 'returns true for -ge when installed version exceeds available' {
            $installed = [version]'1.451.86.0'
            $available = [version]'1.451.85.0'
            ($installed -ge $available) | Should -BeTrue
        }

        It 'returns false for -ge when installed version is older' {
            $installed = [version]'1.451.84.0'
            $available = [version]'1.451.85.0'
            ($installed -ge $available) | Should -BeFalse
        }
    }

    Context 'Delta calculation (NewBuild - OldBuild) within same Minor' {
        # This mirrors the inline logic in Update-DefenderOffline.ps1:
        #   if ($vOld.Minor -eq $vNew.Minor) {
        #       $delta = $vNew.Build - $vOld.Build
        #   } else {
        #       $delta = 'N/A'
        #   }

        It 'computes positive delta when Build advances' {
            $vOld = [version]'1.451.66.0'
            $vNew = [version]'1.451.85.0'
            $delta = if ($vOld.Minor -eq $vNew.Minor) { $vNew.Build - $vOld.Build } else { 'N/A' }
            $delta | Should -Be 19
        }

        It 'computes zero delta for the same version' {
            $v = [version]'1.451.85.0'
            $delta = if ($v.Minor -eq $v.Minor) { $v.Build - $v.Build } else { 'N/A' }
            $delta | Should -Be 0
        }

        It "yields 'N/A' when Minor changes (build numbers reset across minor versions)" {
            $vOld = [version]'1.450.999.0'
            $vNew = [version]'1.451.5.0'
            $delta = if ($vOld.Minor -eq $vNew.Minor) { $vNew.Build - $vOld.Build } else { 'N/A' }
            $delta | Should -Be 'N/A'
        }
    }

    Context 'Folder-name regex used by Get-LatestMpamFile' {

        It "matches the 'v#.#.#.#' folder naming convention" {
            $names = @('v1.451.85.0', 'v1.0.0.0', 'v1.451.66.123')
            foreach ($n in $names) {
                $n -match '^v(\d+\.\d+\.\d+\.\d+)$' | Should -BeTrue
            }
        }

        It 'rejects malformed version folders' {
            $bad = @('v1.451.85', '1.451.85.0', 'version1.451.85.0', 'v1.451.85.0.extra')
            foreach ($n in $bad) {
                $n -match '^v(\d+\.\d+\.\d+\.\d+)$' | Should -BeFalse
            }
        }
    }
}

#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for New-HtmlReport in Update-DefenderOffline.ps1.

v0.0.20 adds a -Mode parameter that conditionally suppresses
JavaScript-dependent affordances when the report is rendered for an
email body (because email clients strip JS, leaving the affordance text
as a misleading instruction).
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Update-DefenderOffline.ps1')

    function script:New-SampleData {
        $list = [System.Collections.Generic.List[pscustomobject]]::new()
        $list.Add([pscustomobject]@{
            ComputerName = 'WS01'; Status = 'Success'
            OldVersion = '1.405.0.0'; NewVersion = '1.450.0.0'
            HealthState = 'Healthy'; ErrorMessage = ''
        }) | Out-Null
        $list.Add([pscustomobject]@{
            ComputerName = 'WS02'; Status = 'Failed'
            OldVersion = '1.405.0.0'; NewVersion = ''
            HealthState = 'ProbeFailed'; ErrorMessage = 'WinRM unreachable'
        }) | Out-Null
        return $list
    }
}

Describe 'New-HtmlReport -Mode' {

    BeforeEach {
        $script:Sample  = New-SampleData
        $script:Runtime = [timespan]::FromMinutes(2)
    }

    Context 'Default Mode (Standalone)' {

        It 'defaults to Standalone when -Mode is not specified' {
            $html = New-HtmlReport -Data $script:Sample -RunTime $script:Runtime
            $html | Should -Match 'Click a badge to filter'
        }

        It 'Standalone produces the click-to-filter affordance' {
            $html = New-HtmlReport -Data $script:Sample -RunTime $script:Runtime -Mode Standalone
            $html | Should -Match 'Click a badge to filter the results table'
            $html | Should -Match 'Click again to clear'
        }
    }

    Context 'Email Mode' {

        It 'suppresses the click-to-filter affordance (the misleading instruction)' {
            $html = New-HtmlReport -Data $script:Sample -RunTime $script:Runtime -Mode Email
            $html | Should -Not -Match 'Click a badge to filter'
            $html | Should -Not -Match 'Click again to clear'
        }

        It 'still renders fleet data (host rows, summary, badges)' {
            $html = New-HtmlReport -Data $script:Sample -RunTime $script:Runtime -Mode Email
            $html | Should -Match 'WS01'
            $html | Should -Match 'WS02'
            $html | Should -Match 'Success'
            $html | Should -Match 'Failed'
            $html | Should -Match 'Fleet Version Summary'
        }

        It 'leaves the badge counts intact (so the email still summarises)' {
            $html = New-HtmlReport -Data $script:Sample -RunTime $script:Runtime -Mode Email
            $html | Should -Match 'stat-card'   # the badge widgets are still rendered
            $html | Should -Match '>Success<'
            $html | Should -Match '>Failed<'
        }
    }

    Context 'Mode validation' {

        It 'rejects an unknown -Mode value' {
            { New-HtmlReport -Data $script:Sample -RunTime $script:Runtime -Mode 'Invalid' } |
                Should -Throw
        }
    }
}

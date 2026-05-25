#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Test variables intentionally provided for clarity')]
param()
<#
Tests for Get-EndpointClassification.

Three classification methods:
  - Single  : every host returns 'MemberServer' (no classification logic).
  - Pattern : regex matching against -WorkstationPattern / -DomainControllerPattern;
              unmatched -> MemberServer.
  - AD      : queries Active Directory; tested separately as integration (requires AD).

This file unit-tests the Single and Pattern paths. AD path is exercised only
during live-fire (see test-plan-v0.0.6 PASS notes).
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Update-DefenderOffline.ps1')
}

Describe 'Get-EndpointClassification' {

    Context 'Single method' {

        It 'returns MemberServer for every host' {
            $hosts = @('WIN10-01', 'SRV-01', 'DC01')
            $result = Get-EndpointClassification -Computers $hosts -Method 'Single'
            $hosts | ForEach-Object {
                $result[$_] | Should -Be 'MemberServer'
            }
        }

        It 'returns an empty dictionary for an empty input' {
            $result = Get-EndpointClassification -Computers @() -Method 'Single'
            $result.Count | Should -Be 0
        }
    }

    Context 'Pattern method' {

        It 'classifies hosts matching WorkstationPattern as Workstation' {
            $hosts = @('DESKTOP-01', 'LAPTOP-02', 'SRV-03')
            $result = Get-EndpointClassification `
                -Computers   $hosts `
                -Method      'Pattern' `
                -WsPattern   '^(DESKTOP|LAPTOP)' `
                -DcPattern   '^DC'
            $result['DESKTOP-01'] | Should -Be 'Workstation'
            $result['LAPTOP-02']  | Should -Be 'Workstation'
            $result['SRV-03']     | Should -Be 'MemberServer'
        }

        It 'classifies hosts matching DomainControllerPattern as DomainController' {
            $hosts = @('DC01', 'DC02', 'SRV-01')
            $result = Get-EndpointClassification `
                -Computers   $hosts `
                -Method      'Pattern' `
                -WsPattern   '^(DESKTOP|LAPTOP)' `
                -DcPattern   '^DC'
            $result['DC01']   | Should -Be 'DomainController'
            $result['DC02']   | Should -Be 'DomainController'
            $result['SRV-01'] | Should -Be 'MemberServer'
        }

        It 'matches case-insensitively' {
            $hosts = @('desktop-lower', 'DESKTOP-UPPER')
            $result = Get-EndpointClassification `
                -Computers   $hosts `
                -Method      'Pattern' `
                -WsPattern   '^DESKTOP' `
                -DcPattern   '^DC'
            $result['desktop-lower']  | Should -Be 'Workstation'
            $result['DESKTOP-UPPER']  | Should -Be 'Workstation'
        }

        It 'falls back to MemberServer when no pattern matches' {
            $hosts = @('RANDOM-HOST-01')
            $result = Get-EndpointClassification `
                -Computers   $hosts `
                -Method      'Pattern' `
                -WsPattern   '^DESKTOP' `
                -DcPattern   '^DC'
            $result['RANDOM-HOST-01'] | Should -Be 'MemberServer'
        }

        It 'treats DC pattern as higher priority than WS pattern when both match' {
            # If a hostname somehow matches both regexes, the function checks
            # DC first (see Pattern-method loop in Get-EndpointClassification).
            $hosts = @('DCDESKTOP')
            $result = Get-EndpointClassification `
                -Computers   $hosts `
                -Method      'Pattern' `
                -WsPattern   'DESKTOP' `
                -DcPattern   '^DC'
            $result['DCDESKTOP'] | Should -Be 'DomainController'
        }

        It 'handles empty patterns gracefully' {
            $hosts = @('ANY-HOST')
            $result = Get-EndpointClassification `
                -Computers   $hosts `
                -Method      'Pattern' `
                -WsPattern   '' `
                -DcPattern   ''
            $result['ANY-HOST'] | Should -Be 'MemberServer'
        }
    }
}

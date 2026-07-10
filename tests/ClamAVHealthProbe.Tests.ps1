#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester test scopes share state via $script:')]
param()
<#
Tests for lib/Get-ClamAVHealthProbe.ps1 — the ClamAV fleet health consumer
added in v0.0.24.

Structure:
  1. Pure logic helpers — Get-ClamAVStatusRank, Format-ClamAVAgeLabel,
     Merge-ClamAVStatusOverride, Get-ClamAVStalenessOverride. No mocks.
  2. ConvertFrom-ClamAVHostDocument — per-host doc → row shape. No mocks;
     tests pass synthetic host docs directly.
  3. Get-ClamAVHealthProbe — full flow with Invoke-RestMethod mocked to
     return synthetic envelope / single-host / error responses.

All time-sensitive tests use a fixed UTC reference time ($script:RefNow)
so age computations are deterministic across test-host timezones.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Get-ClamAVHealthProbe.ps1')

    # Reference "now" for all tests — UTC, deterministic.
    $script:RefNow = [datetime]::new(2026, 7, 8, 13, 20, 0, [DateTimeKind]::Utc)

    # Build an ISO-8601 generated_at N seconds before RefNow.
    function script:New-GeneratedAt {
        param([int]$SecondsAgo)
        ($script:RefNow.AddSeconds(-$SecondsAgo)).ToString('o')
    }

    # Build a synthetic host document. All defaults produce a Healthy host.
    function script:New-HostDoc {
        param(
            [string]$Name = 'linux-01',
            [string]$Status = 'Healthy',
            [int]$SecondsAgo = 30,
            [int]$RecentThreatCount = 0,
            [string]$Role = 'client',
            [string]$InstallerVersion = '0.0.6',
            $SchemaVersion = 1,   # untyped so tests can pass string / null
            [string]$StatusReason = $null,
            [string]$ProbeError = $null,
            [Nullable[int]]$SignatureAgeDays = 0,
            [Nullable[bool]]$SignatureStale = $false
        )
        $doc = [pscustomobject]@{
            schema_version      = $SchemaVersion
            product             = 'Deploy-ClamAV'
            installer_version   = $InstallerVersion
            hostname            = $Name
            role                = $Role
            generated_at        = (New-GeneratedAt -SecondsAgo $SecondsAgo)
            overall_status      = $Status
            status_reason       = $StatusReason
            engine_version      = '1.5.1'
            signature           = [pscustomobject]@{
                version      = 28049
                build_time   = (New-GeneratedAt -SecondsAgo ($SecondsAgo + 3600))
                age_days     = $SignatureAgeDays
                max_age_days = 7
                stale        = $SignatureStale
            }
            capabilities        = [pscustomobject]@{
                clamd_active             = $true
                freshclam_active         = $true
                onaccess_active          = $true
                autoupgrade_timer_active = $false
                selftest_passing         = $true
                mirror_active            = $false
            }
            recent_threat_count = $RecentThreatCount
            probe_error         = $ProbeError
        }
        return $doc
    }

    # Build a synthetic envelope wrapping N host docs.
    function script:New-Envelope {
        param(
            [pscustomobject[]]$Hosts,
            [int]$SecondsAgo = 30,
            [int]$SchemaVersion = 1,
            [string]$PublisherVersion = '0.0.7',
            [switch]$OmitKind,
            [switch]$OmitHosts,
            [switch]$OmitGeneratedAt,
            [switch]$OmitSchemaVersion
        )
        $props = [ordered]@{ }
        if (-not $OmitSchemaVersion) { $props['schema_version']    = $SchemaVersion }
        $props['product']            = 'Deploy-ClamAV'
        if (-not $OmitKind)          { $props['kind']              = 'fleet-status' }
        $props['installer_version']  = $PublisherVersion
        if (-not $OmitGeneratedAt)   { $props['generated_at']      = (New-GeneratedAt -SecondsAgo $SecondsAgo) }
        $props['host_count']         = @($Hosts).Count
        if (-not $OmitHosts)         { $props['hosts']             = @($Hosts) }
        return [pscustomobject]$props
    }
}

Describe 'Format-ClamAVAgeLabel' {
    It 'formats seconds under 60 as "Xs"'    { Format-ClamAVAgeLabel -Seconds 45   | Should -Be '45s' }
    It 'formats minutes under 60 as "Xm"'    { Format-ClamAVAgeLabel -Seconds 900  | Should -Be '15m' }
    It 'formats whole hours as "Xh"'         { Format-ClamAVAgeLabel -Seconds 7200 | Should -Be '2h' }
    It 'formats hour + minute as "Xh Ym"'    { Format-ClamAVAgeLabel -Seconds 5400 | Should -Be '1h 30m' }
}

Describe 'Get-ClamAVStatusRank' {
    It 'ranks Healthy at 0'         { Get-ClamAVStatusRank -Status 'Healthy'         | Should -Be 0 }
    It 'ranks ThreatsDetected at 1' { Get-ClamAVStatusRank -Status 'ThreatsDetected' | Should -Be 1 }
    It 'ranks Degraded above ThreatsDetected' {
        (Get-ClamAVStatusRank -Status 'Degraded') -gt (Get-ClamAVStatusRank -Status 'ThreatsDetected') | Should -BeTrue
    }
    It 'ranks ProbeFailed at 3 (highest)' { Get-ClamAVStatusRank -Status 'ProbeFailed' | Should -Be 3 }
    It 'ranks unknown status at -1' { Get-ClamAVStatusRank -Status 'Whatever' | Should -Be -1 }
}

Describe 'Merge-ClamAVStatusOverride' {

    It 'null override returns underlying unchanged' {
        $r = Merge-ClamAVStatusOverride -UnderlyingStatus 'Healthy' -UnderlyingReason $null -Override $null
        $r.Status | Should -Be 'Healthy'
        $r.Reason | Should -BeNullOrEmpty
    }

    It 'escalates Healthy → Degraded when override is Degraded' {
        $override = [pscustomobject]@{ Status = 'Degraded'; Reason = 'stale' }
        $r = Merge-ClamAVStatusOverride -UnderlyingStatus 'Healthy' -UnderlyingReason $null -Override $override
        $r.Status | Should -Be 'Degraded'
        $r.Reason | Should -Be 'stale'
    }

    It 'preserves ProbeFailed underlying even when override is Degraded (escalate-only)' {
        $override = [pscustomobject]@{ Status = 'Degraded'; Reason = 'stale' }
        $r = Merge-ClamAVStatusOverride -UnderlyingStatus 'ProbeFailed' -UnderlyingReason 'clamd dead' -Override $override
        $r.Status | Should -Be 'ProbeFailed'
        $r.Reason | Should -Be 'clamd dead'
    }

    It 'escalates Degraded → ProbeFailed when override is ProbeFailed' {
        $override = [pscustomobject]@{ Status = 'ProbeFailed'; Reason = 'aggregate too stale' }
        $r = Merge-ClamAVStatusOverride -UnderlyingStatus 'Degraded' -UnderlyingReason 'clamonacc off' -Override $override
        $r.Status | Should -Be 'ProbeFailed'
        $r.Reason | Should -Be 'aggregate too stale'
    }

    It 'preserves ThreatsDetected when override is Healthy-rank (not possible — sanity)' {
        # Override should never be Healthy but if it were, escalate-only still holds.
        $override = [pscustomobject]@{ Status = 'Healthy'; Reason = $null }
        $r = Merge-ClamAVStatusOverride -UnderlyingStatus 'ThreatsDetected' -UnderlyingReason '3 threats' -Override $override
        $r.Status | Should -Be 'ThreatsDetected'
    }
}

Describe 'Get-ClamAVStalenessOverride' {

    Context 'null age (missing generated_at)' {
        It 'returns ProbeFailed with axis-specific reason' {
            $r = Get-ClamAVStalenessOverride -Age $null -StaleSeconds 900 -ProbeFailedSeconds 1800 -Axis 'aggregate'
            $r.Status | Should -Be 'ProbeFailed'
            $r.Reason | Should -Match 'aggregate.*missing'
        }
        It 'differentiates aggregate vs host axis in the reason' {
            $rHost = Get-ClamAVStalenessOverride -Age $null -StaleSeconds 900 -ProbeFailedSeconds 1800 -Axis 'host'
            $rHost.Reason | Should -Match 'host.*missing'
        }
    }

    Context 'fresh (< StaleSeconds)' {
        It 'returns $null' {
            $r = Get-ClamAVStalenessOverride -Age (New-TimeSpan -Seconds 100) -StaleSeconds 900 -ProbeFailedSeconds 1800 -Axis 'aggregate'
            $r | Should -BeNullOrEmpty
        }
    }

    Context 'negative age (clock skew — future timestamp)' {
        It 'returns $null (treat as noise)' {
            $r = Get-ClamAVStalenessOverride -Age (New-TimeSpan -Seconds -30) -StaleSeconds 900 -ProbeFailedSeconds 1800 -Axis 'aggregate'
            $r | Should -BeNullOrEmpty
        }
    }

    Context 'stale (> StaleSeconds, <= ProbeFailedSeconds)' {
        It 'returns Degraded for aggregate axis' {
            $r = Get-ClamAVStalenessOverride -Age (New-TimeSpan -Seconds 1000) -StaleSeconds 900 -ProbeFailedSeconds 1800 -Axis 'aggregate'
            $r.Status | Should -Be 'Degraded'
            $r.Reason | Should -Match 'fleet aggregate stale'
        }
        It 'returns Degraded for host axis with different noun' {
            $r = Get-ClamAVStalenessOverride -Age (New-TimeSpan -Seconds 2000) -StaleSeconds 1800 -ProbeFailedSeconds 3600 -Axis 'host'
            $r.Status | Should -Be 'Degraded'
            $r.Reason | Should -Match 'status document stale'
        }
    }

    Context 'very stale (> ProbeFailedSeconds)' {
        It 'returns ProbeFailed for aggregate axis' {
            $r = Get-ClamAVStalenessOverride -Age (New-TimeSpan -Seconds 2000) -StaleSeconds 900 -ProbeFailedSeconds 1800 -Axis 'aggregate'
            $r.Status | Should -Be 'ProbeFailed'
            $r.Reason | Should -Match 'too stale to trust'
        }
        It 'returns ProbeFailed for host axis' {
            $r = Get-ClamAVStalenessOverride -Age (New-TimeSpan -Seconds 4000) -StaleSeconds 1800 -ProbeFailedSeconds 3600 -Axis 'host'
            $r.Status | Should -Be 'ProbeFailed'
        }
    }
}

Describe 'ConvertFrom-ClamAVHostDocument' {

    Context 'valid Healthy host doc' {
        It 'produces a Healthy row with all fields populated' {
            $doc = New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host'

            $r.OverallStatus        | Should -Be 'Healthy'
            $r.StatusReason         | Should -BeNullOrEmpty
            $r.HostName             | Should -Be 'linux-01'
            $r.Platform             | Should -Be 'Linux'
            $r.Product              | Should -Be 'Deploy-ClamAV'
            $r.Role                 | Should -Be 'client'
            $r.EngineVersion        | Should -Be '1.5.1'
            $r.SignatureVersion     | Should -Be 28049
            $r.RecentThreatCount    | Should -Be 0
            $r.HostInstallerVersion | Should -Be '0.0.6'
            $r.PublisherVersion     | Should -BeNullOrEmpty
            $r.Mode                 | Should -Be 'single-host'
            $r.ProbeError           | Should -BeNullOrEmpty
            $r.SchemaWarning        | Should -BeNullOrEmpty
        }

        It 'preserves SignatureAgeDays=0 as 0 (not null) — the "fresh signature" case' {
            $doc = New-HostDoc -SignatureAgeDays 0
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host'
            $r.SignatureAgeDays | Should -Be 0
        }

        It 'preserves recent_threat_count as integer' {
            $doc = New-HostDoc -Status 'ThreatsDetected' -RecentThreatCount 3 -StatusReason '3 threat(s) detected in the last 24h'
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host'
            $r.RecentThreatCount | Should -Be 3
            $r.OverallStatus     | Should -Be 'ThreatsDetected'
            $r.StatusReason      | Should -Be '3 threat(s) detected in the last 24h'
        }
    }

    Context 'malformed host doc' {
        It 'missing schema_version → ProbeFailed row with hostname preserved' {
            $doc = New-HostDoc -Name 'linux-01' -SchemaVersion $null
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'envelope'
            $r.OverallStatus | Should -Be 'ProbeFailed'
            $r.StatusReason  | Should -Match 'schema_version'
            $r.HostName      | Should -Be 'linux-01'
            $r.Mode          | Should -Be 'envelope'
        }

        It 'newer host schema → SchemaWarning populated, row still parses' {
            $doc = New-HostDoc -Name 'linux-01' -SchemaVersion 2
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host' -WarningAction SilentlyContinue
            $r.OverallStatus  | Should -Be 'Healthy'
            $r.SchemaWarning  | Should -Match 'schema v2 > expected v1'
        }

        It 'emits a Write-Warning when host schema is newer' {
            $doc = New-HostDoc -SchemaVersion 2
            $warn = $null
            ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host' `
                -WarningVariable warn -WarningAction SilentlyContinue | Out-Null
            $warn.Count | Should -BeGreaterThan 0
        }
    }

    Context 'probe_error handling' {
        It 'probe_error surfaces as StatusReason when overall_status is ProbeFailed' {
            $doc = New-HostDoc -Status 'ProbeFailed' -ProbeError 'unreachable during aggregation'
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'envelope'
            $r.OverallStatus | Should -Be 'ProbeFailed'
            $r.StatusReason  | Should -Be 'unreachable during aggregation'
            $r.ProbeError    | Should -Be 'unreachable during aggregation'
        }

        It 'probe_error wins over status_reason when both set' {
            # Realistically these are mutually exclusive per contract, but defence-in-depth.
            $doc = New-HostDoc -Status 'ProbeFailed' -ProbeError 'clamd not running' -StatusReason 'ignored'
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'envelope'
            $r.StatusReason | Should -Be 'clamd not running'
        }
    }

    Context 'staleness overrides — host axis' {
        It 'fresh doc → no override applied' {
            $doc = New-HostDoc -Status 'Healthy' -SecondsAgo 30
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host'
            $r.OverallStatus | Should -Be 'Healthy'
        }

        It 'stale host doc (2000s > 1800s) → Degraded' {
            $doc = New-HostDoc -Status 'Healthy' -SecondsAgo 2000
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host'
            $r.OverallStatus | Should -Be 'Degraded'
            $r.StatusReason  | Should -Match 'stale'
        }

        It 'very stale host doc (4000s > 3600s) → ProbeFailed' {
            $doc = New-HostDoc -Status 'Healthy' -SecondsAgo 4000
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host'
            $r.OverallStatus | Should -Be 'ProbeFailed'
        }

        It 'underlying ProbeFailed never de-escalated by staleness (escalate-only)' {
            $doc = New-HostDoc -Status 'ProbeFailed' -SecondsAgo 30 -ProbeError 'clamd dead'
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host'
            $r.OverallStatus | Should -Be 'ProbeFailed'
            $r.StatusReason  | Should -Be 'clamd dead'
        }
    }

    Context 'aggregate override (envelope mode)' {
        It 'aggregate ProbeFailed override → row escalated to ProbeFailed' {
            $doc = New-HostDoc -Status 'Healthy' -SecondsAgo 30
            $override = [pscustomobject]@{ Status = 'ProbeFailed'; Reason = 'fleet aggregate too stale to trust (35m old)' }
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'envelope' -AggregateOverride $override
            $r.OverallStatus | Should -Be 'ProbeFailed'
            $r.StatusReason  | Should -Match 'aggregate'
        }

        It 'aggregate override cannot de-escalate underlying ProbeFailed' {
            $doc = New-HostDoc -Status 'ProbeFailed' -ProbeError 'clamd dead' -SecondsAgo 30
            $override = [pscustomobject]@{ Status = 'Degraded'; Reason = 'aggregate stale' }
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'envelope' -AggregateOverride $override
            $r.OverallStatus | Should -Be 'ProbeFailed'
            $r.StatusReason  | Should -Be 'clamd dead'
        }
    }

    Context 'envelope-only fields' {
        It 'PublisherVersion + EnvelopeGeneratedAt populated in envelope mode' {
            $doc = New-HostDoc
            $envelopeDT = [datetimeoffset]::Parse((New-GeneratedAt -SecondsAgo 30))
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'envelope' `
                -EnvelopePublisherVersion '0.0.7' -EnvelopeGeneratedAt $envelopeDT
            $r.PublisherVersion    | Should -Be '0.0.7'
            $r.EnvelopeGeneratedAt | Should -Not -BeNullOrEmpty
        }

        It 'PublisherVersion + EnvelopeGeneratedAt null in single-host mode' {
            $doc = New-HostDoc
            $r = ConvertFrom-ClamAVHostDocument -HostDoc $doc -Now $script:RefNow `
                -HostStaleSeconds 1800 -HostProbeFailedSeconds 3600 -Mode 'single-host' `
                -EnvelopePublisherVersion '0.0.7' -EnvelopeGeneratedAt ([datetimeoffset]::UtcNow)
            $r.PublisherVersion    | Should -BeNullOrEmpty
            $r.EnvelopeGeneratedAt | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-ClamAVHealthProbe — envelope mode' {

    It 'renders 3 hosts from a fresh envelope' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 30 -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30),
                (New-HostDoc -Name 'linux-02' -Status 'Healthy' -SecondsAgo 30),
                (New-HostDoc -Name 'linux-03' -Status 'Healthy' -SecondsAgo 30)
            )
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 3
        $rows | ForEach-Object { $_.OverallStatus | Should -Be 'Healthy' }
        $rows | ForEach-Object { $_.Mode | Should -Be 'envelope' }
        $rows[0].PublisherVersion | Should -Be '0.0.7'
    }

    It 'detects envelope by "hosts" array even when "kind" is absent' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 30 -OmitKind -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30)
            )
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 1
        $rows[0].Mode | Should -Be 'envelope'
    }

    It 'empty hosts[] → returns empty array (Windows rows unaffected upstream)' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 30 -Hosts @()
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 0
    }

    It 'aggregate stale (1000s > 900s) → all rows Degraded' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 1000 -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30),
                (New-HostDoc -Name 'linux-02' -Status 'Healthy' -SecondsAgo 30)
            )
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 2
        $rows | ForEach-Object {
            $_.OverallStatus | Should -Be 'Degraded'
            $_.StatusReason  | Should -Match 'fleet aggregate stale'
        }
    }

    It 'aggregate very stale (2000s > 1800s) → all rows ProbeFailed' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 2000 -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30)
            )
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows[0].OverallStatus | Should -Be 'ProbeFailed'
        $rows[0].StatusReason  | Should -Match 'too stale to trust'
    }

    It 'aggregate stale + host ProbeFailed → host stays ProbeFailed (escalate-only)' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 1000 -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'ProbeFailed' -SecondsAgo 30 -ProbeError 'unreachable during aggregation')
            )
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows[0].OverallStatus | Should -Be 'ProbeFailed'
        $rows[0].StatusReason  | Should -Be 'unreachable during aggregation'
    }

    It 'envelope missing schema_version → single ProbeFailed row' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 30 -OmitSchemaVersion -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30)
            )
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 1
        $rows[0].OverallStatus | Should -Be 'ProbeFailed'
        $rows[0].StatusReason  | Should -Match 'schema_version'
    }

    It 'envelope schema newer than expected → soft-warn, still renders rows' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 30 -SchemaVersion 2 -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30)
            )
        }
        $warn = $null
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow `
            -WarningVariable warn -WarningAction SilentlyContinue)
        $rows.Count | Should -Be 1
        $rows[0].OverallStatus         | Should -Be 'Healthy'
        $rows[0].EnvelopeSchemaWarning | Should -Match 'schema v2 > expected v1'
        $warn.Count | Should -BeGreaterThan 0
    }
}

Describe 'Get-ClamAVHealthProbe — single-host mode' {

    It 'renders a single row when the fetched doc has no kind and no hosts[]' {
        Mock Invoke-RestMethod {
            New-HostDoc -Name 'clamav-mirror.internal' -Status 'Healthy' -Role 'both' -SecondsAgo 30
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/status.json' -Now $script:RefNow)
        $rows.Count           | Should -Be 1
        $rows[0].Mode         | Should -Be 'single-host'
        $rows[0].HostName     | Should -Be 'clamav-mirror.internal'
        $rows[0].Role         | Should -Be 'both'
        $rows[0].PublisherVersion | Should -BeNullOrEmpty
    }

    It 'single-host stale (2000s > 1800s) → Degraded' {
        Mock Invoke-RestMethod {
            New-HostDoc -Name 'clamav-mirror.internal' -Status 'Healthy' -SecondsAgo 2000
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/status.json' -Now $script:RefNow)
        $rows[0].OverallStatus | Should -Be 'Degraded'
    }
}

Describe 'Get-ClamAVHealthProbe — error paths' {

    It 'HTTP failure returns single synthetic ProbeFailed row with mirror hostname' {
        Mock Invoke-RestMethod { throw [System.Net.WebException]::new('connection refused') }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://clamav-mirror.internal/ClamAV/fleet-status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 1
        $rows[0].OverallStatus | Should -Be 'ProbeFailed'
        $rows[0].HostName      | Should -Be 'clamav-mirror.internal'
        $rows[0].StatusReason  | Should -Match 'mirror unreachable'
    }

    It 'empty response body returns single ProbeFailed row' {
        Mock Invoke-RestMethod { $null }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 1
        $rows[0].OverallStatus | Should -Be 'ProbeFailed'
        $rows[0].StatusReason  | Should -Match 'empty'
    }

    It 'HTTP failure with unparseable URL still returns a row' {
        Mock Invoke-RestMethod { throw 'boom' }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'not-a-real-url' -Now $script:RefNow)
        $rows.Count | Should -Be 1
        $rows[0].OverallStatus | Should -Be 'ProbeFailed'
        # HostName falls back to whatever [uri] parses, or the sentinel
        $rows[0].HostName | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-ClamAVHealthProbe — mixed-status envelope' {

    It 'renders each host with its own status independently' {
        Mock Invoke-RestMethod {
            New-Envelope -SecondsAgo 30 -Hosts @(
                (New-HostDoc -Name 'linux-01' -Status 'Healthy' -SecondsAgo 30),
                (New-HostDoc -Name 'linux-02' -Status 'Degraded' -SecondsAgo 30 -StatusReason 'clamonacc inactive'),
                (New-HostDoc -Name 'linux-03' -Status 'ThreatsDetected' -SecondsAgo 30 -RecentThreatCount 3 -StatusReason '3 threat(s) detected in the last 24h'),
                (New-HostDoc -Name 'linux-04' -Status 'ProbeFailed' -SecondsAgo 30 -ProbeError 'unreachable during aggregation')
            )
        }
        $rows = @(Get-ClamAVHealthProbe -MirrorUrl 'http://mirror.test/fleet-status.json' -Now $script:RefNow)
        $rows.Count | Should -Be 4

        $byName = @{}
        $rows | ForEach-Object { $byName[$_.HostName] = $_ }

        $byName['linux-01'].OverallStatus     | Should -Be 'Healthy'
        $byName['linux-02'].OverallStatus     | Should -Be 'Degraded'
        $byName['linux-02'].StatusReason      | Should -Be 'clamonacc inactive'
        $byName['linux-03'].OverallStatus     | Should -Be 'ThreatsDetected'
        $byName['linux-03'].RecentThreatCount | Should -Be 3
        $byName['linux-04'].OverallStatus     | Should -Be 'ProbeFailed'
        $byName['linux-04'].StatusReason      | Should -Be 'unreachable during aggregation'
    }
}

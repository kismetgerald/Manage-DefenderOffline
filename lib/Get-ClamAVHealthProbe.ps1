<#
.SYNOPSIS
    ClamAV fleet health probe — fetches Deploy-ClamAV's published health
    document over HTTP and normalises to the Get-DefenderHealthProbe
    output shape so the dashboard renders both platforms uniformly.

.DESCRIPTION
    Called by Start-DefenderDashboard on each refresh cycle when the
    operator has opted in via [ClamAV].Enabled = true. Fetches the
    mirror URL, auto-detects envelope-vs-single-host shape, validates
    schema versions on both axes, applies two-axis staleness (aggregate
    + per-host, escalate-only), and returns an array of pscustomobject
    rows the dashboard merges with Defender rows.

    Contract reference (authoritative in Deploy-ClamAV repo):
        D:\Dropbox\IT Docs\Scripts\Deploy-ClamAV\docs\health-contract.md
    Cross-project consensus captured in:
        docs/plans/v0.0.24-clamav-consumer.md (v4, 2026-07-08)

    Envelope shape (Deploy-ClamAV v0.0.7):
        { schema_version, product, kind:"fleet-status", installer_version,
          generated_at, host_count, hosts:[ …host docs… ] }
    Single-host shape (Deploy-ClamAV v0.0.6 mirror-only):
        { schema_version, product, installer_version, hostname, role,
          overall_status, generated_at, engine_version, signature{…},
          capabilities{…}, recent_threat_count, status_reason, probe_error }

    Auto-detect rule: presence of `kind:"fleet-status"` OR a `hosts` array
    → envelope; otherwise → single-host. One consumer serves both.

    Enum matches Get-DefenderHealthClassification 1:1 (Healthy, Degraded,
    ThreatsDetected, ProbeFailed). Degraded wins over ThreatsDetected
    when both apply, mirroring the Defender side.

.NOTES
    Dot-source from any script that needs it:
        . (Join-Path $PSScriptRoot 'lib\Get-ClamAVHealthProbe.ps1')
#>


<#
.SYNOPSIS
    Compute a staleness-based status override for a Deploy-ClamAV health
    document, given its age and the applicable thresholds. Pure logic —
    no network calls.

.DESCRIPTION
    Called once per axis. Envelope mode calls it twice (once with the
    envelope's age + aggregate thresholds, once per host with the host's
    age + host thresholds). Single-host mode calls it once with host
    thresholds only.

    Escalate-only is enforced by the caller (Merge-ClamAVStatusOverride);
    this function just says "given this age, the override *would* be X."

    A missing/unparseable generated_at is not an "unknown" — it's a probe
    failure in itself. Consumers can't tell fresh from stale without a
    timestamp, so we surface ProbeFailed rather than silently degrading.

.OUTPUTS
    [pscustomobject]{ Status; Reason } — Status is 'Degraded' or
    'ProbeFailed'; or $null when the document is fresh.
#>
function Get-ClamAVStalenessOverride {
    [CmdletBinding()]
    param(
        [Nullable[timespan]]$Age,
        [Parameter(Mandatory)] [int]$StaleSeconds,
        [Parameter(Mandatory)] [int]$ProbeFailedSeconds,
        [Parameter(Mandatory)] [ValidateSet('aggregate','host')] [string]$Axis
    )

    if ($null -eq $Age) {
        return [pscustomobject]@{
            Status = 'ProbeFailed'
            Reason = "$Axis document missing or unparseable generated_at"
        }
    }

    $seconds = [int]$Age.TotalSeconds
    if ($seconds -lt 0) {
        # Clock skew — future timestamp. Don't treat as stale; treat as noise.
        return $null
    }

    $ageLabel = Format-ClamAVAgeLabel -Seconds $seconds
    $noun     = if ($Axis -eq 'aggregate') { 'fleet aggregate' } else { 'status document' }

    if ($seconds -gt $ProbeFailedSeconds) {
        return [pscustomobject]@{
            Status = 'ProbeFailed'
            Reason = "$noun too stale to trust ($ageLabel old)"
        }
    } elseif ($seconds -gt $StaleSeconds) {
        return [pscustomobject]@{
            Status = 'Degraded'
            Reason = "$noun stale ($ageLabel old)"
        }
    }

    return $null
}


# Format a seconds count as a human-readable "Xs" / "Xm" / "Xh Ym".
function Format-ClamAVAgeLabel {
    param([int]$Seconds)
    if ($Seconds -lt 60) { return "${Seconds}s" }
    $minutes = [math]::Floor($Seconds / 60)
    if ($minutes -lt 60) { return "${minutes}m" }
    $hours  = [math]::Floor($minutes / 60)
    $remMin = $minutes - ($hours * 60)
    if ($remMin -eq 0) { return "${hours}h" }
    return "${hours}h ${remMin}m"
}


# Severity rank for the 4-value overall_status enum. Higher = worse.
# Degraded outranks ThreatsDetected per the contract's classification order.
# Unknown/malformed status ranks at -1 so any real override wins.
function Get-ClamAVStatusRank {
    param([string]$Status)
    switch ($Status) {
        'Healthy'         { 0 }
        'ThreatsDetected' { 1 }
        'Degraded'        { 2 }
        'ProbeFailed'     { 3 }
        default           { -1 }
    }
}


# Escalate-only merge: return whichever of (underlying, override) is
# more severe. Override may be $null (means no override applies).
function Merge-ClamAVStatusOverride {
    param(
        [Parameter(Mandatory)] [string]$UnderlyingStatus,
        [string]$UnderlyingReason,
        $Override
    )
    if ($null -eq $Override) {
        return [pscustomobject]@{ Status = $UnderlyingStatus; Reason = $UnderlyingReason }
    }
    $underlyingRank = Get-ClamAVStatusRank -Status $UnderlyingStatus
    $overrideRank   = Get-ClamAVStatusRank -Status $Override.Status
    if ($underlyingRank -ge $overrideRank) {
        return [pscustomobject]@{ Status = $UnderlyingStatus; Reason = $UnderlyingReason }
    }
    return [pscustomobject]@{ Status = $Override.Status; Reason = $Override.Reason }
}


<#
.SYNOPSIS
    Build a synthetic ProbeFailed row for HTTP / parse / envelope-level
    failures — cases where we don't have any host doc to map from.

.DESCRIPTION
    Extracts a friendly HostName from the MirrorUrl (its hostname portion)
    so operators can see WHICH mirror failed at a glance in the dashboard
    grid. Falls back to '<mirror unreachable>' if the URL can't be parsed.

    Every field is populated (mostly with $null) so the row is
    structurally identical to a real host row — the dashboard sort/render
    code doesn't need to special-case error rows.
#>
function New-ClamAVProbeFailedRow {
    param(
        [Parameter(Mandatory)] [string]$Reason,
        [string]$MirrorUrl,
        [datetime]$Now = (Get-Date)
    )

    $hostName = '<mirror unreachable>'
    if ($MirrorUrl) {
        try {
            $uri = [uri]$MirrorUrl
            if ($uri.Host) { $hostName = $uri.Host }
        } catch { }
    }

    [pscustomobject]@{
        OverallStatus        = 'ProbeFailed'
        StatusReason         = $Reason
        RecentThreatCount    = 0
        ProbedAt             = $Now
        ProbeError           = $Reason
        HostName             = $hostName
        Platform             = 'Linux'
        Product              = 'Deploy-ClamAV'
        Role                 = $null
        EngineVersion        = $null
        SignatureVersion     = $null
        SignatureAgeDays     = $null
        SignatureStale       = $null
        Capabilities         = $null
        HostInstallerVersion = $null
        PublisherVersion     = $null
        HostGeneratedAt      = $null
        EnvelopeGeneratedAt  = $null
        Mode                 = 'error'
        SchemaWarning        = $null
    }
}


<#
.SYNOPSIS
    Convert one Deploy-ClamAV host document (either a bare single-host
    doc or an element from an envelope's hosts[]) into a dashboard row.

.DESCRIPTION
    Applies both axes of staleness (aggregate override + host axis) to
    the host's underlying overall_status, escalate-only. Extracts every
    surfaced field with $null defence so a malformed host doc becomes a
    single ProbeFailed row instead of taking down the whole envelope.

    generated_at is parsed as DateTimeOffset so cross-timezone fleets
    compute age correctly; the returned HostGeneratedAt is the
    DateTimeOffset preserved as-is.

.PARAMETER HostDoc
    A single host document (parsed JSON object from Invoke-RestMethod).

.PARAMETER Now
    Reference time for age computation. Test seams pass a fixed value;
    production defaults to Get-Date.

.PARAMETER Mode
    'envelope' when this host came from an envelope's hosts[] array;
    'single-host' when the fetched doc IS this host doc. Only affects
    the Mode column and whether EnvelopeGeneratedAt is populated.

.PARAMETER AggregateOverride
    Pre-computed aggregate-axis override, or $null if none. Envelope
    mode passes what Get-ClamAVStalenessOverride returned for the
    envelope's generated_at. Single-host mode passes $null.

.OUTPUTS
    [pscustomobject] with the full row shape — see file-level doc for
    the field list.
#>
function ConvertFrom-ClamAVHostDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $HostDoc,
        [datetime]$Now = (Get-Date),
        [Parameter(Mandatory)] [int]$HostStaleSeconds,
        [Parameter(Mandatory)] [int]$HostProbeFailedSeconds,
        [int]$ExpectedHostSchemaVersion = 1,
        $AggregateOverride = $null,
        $EnvelopeGeneratedAt = $null,
        [string]$EnvelopePublisherVersion = $null,
        [string]$EnvelopeSchemaWarning = $null,
        [ValidateSet('envelope','single-host')] [string]$Mode = 'single-host'
    )

    # 1. Host schema version — bail out to ProbeFailed if invalid.
    $hostSchemaVersion = 0
    if ($null -ne $HostDoc.schema_version) {
        [void][int]::TryParse("$($HostDoc.schema_version)", [ref]$hostSchemaVersion)
    }

    if ($hostSchemaVersion -eq 0) {
        $row = New-ClamAVProbeFailedRow `
            -Reason 'host document missing or invalid schema_version' `
            -MirrorUrl $null `
            -Now $Now
        $row.HostName = "$($HostDoc.hostname)"
        $row.Mode     = $Mode
        return $row
    }

    $schemaWarning = $null
    if ($hostSchemaVersion -gt $ExpectedHostSchemaVersion) {
        $schemaWarning = "host doc schema v$hostSchemaVersion > expected v$ExpectedHostSchemaVersion; parsing best-effort"
        Write-Warning "Deploy-ClamAV host '$($HostDoc.hostname)': $schemaWarning"
    }

    # 2. Parse host generated_at as DateTimeOffset for tz-safe age math.
    $hostGeneratedAt = $null
    $hostAge         = $null
    if ($null -ne $HostDoc.generated_at) {
        $parsed = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse("$($HostDoc.generated_at)", [ref]$parsed)) {
            $hostGeneratedAt = $parsed
            # $Now is a local DateTime; cast to DateTimeOffset for subtraction.
            $hostAge = ([datetimeoffset]$Now) - $parsed
        }
    }

    # 3. Compute host-axis staleness override.
    $hostOverride = Get-ClamAVStalenessOverride `
        -Age $hostAge `
        -StaleSeconds $HostStaleSeconds `
        -ProbeFailedSeconds $HostProbeFailedSeconds `
        -Axis 'host'

    # 4. Underlying status + reason (probe_error wins over status_reason).
    $underlyingStatus = "$($HostDoc.overall_status)"
    $underlyingReason = $null
    if ($HostDoc.probe_error)  { $underlyingReason = "$($HostDoc.probe_error)" }
    elseif ($HostDoc.status_reason) { $underlyingReason = "$($HostDoc.status_reason)" }

    # 5. Apply overrides in order: aggregate first, then host. Escalate-only.
    $merged = Merge-ClamAVStatusOverride `
        -UnderlyingStatus $underlyingStatus `
        -UnderlyingReason $underlyingReason `
        -Override $AggregateOverride
    $merged = Merge-ClamAVStatusOverride `
        -UnderlyingStatus $merged.Status `
        -UnderlyingReason $merged.Reason `
        -Override $hostOverride

    # 6. Compose the row. Every extraction is $null-defensive so a
    #    partially-malformed doc still renders sensibly rather than
    #    throwing on a missing property.
    [pscustomobject]@{
        OverallStatus        = $merged.Status
        StatusReason         = $merged.Reason
        RecentThreatCount    = if ($null -ne $HostDoc.recent_threat_count) { [int]$HostDoc.recent_threat_count } else { 0 }
        ProbedAt             = $Now
        ProbeError           = if ($merged.Status -eq 'ProbeFailed') { $merged.Reason } else { $null }
        HostName             = "$($HostDoc.hostname)"
        Platform             = 'Linux'
        Product              = if ($HostDoc.product) { "$($HostDoc.product)" } else { 'Deploy-ClamAV' }
        Role                 = if ($HostDoc.role)    { "$($HostDoc.role)" }    else { $null }
        EngineVersion        = if ($HostDoc.engine_version) { "$($HostDoc.engine_version)" } else { $null }
        SignatureVersion     = if ($HostDoc.signature -and $null -ne $HostDoc.signature.version)  { [int]$HostDoc.signature.version } else { $null }
        SignatureAgeDays     = if ($HostDoc.signature -and $null -ne $HostDoc.signature.age_days) { [int]$HostDoc.signature.age_days } else { $null }
        SignatureStale       = if ($HostDoc.signature -and $null -ne $HostDoc.signature.stale)    { [bool]$HostDoc.signature.stale }  else { $null }
        Capabilities         = $HostDoc.capabilities
        HostInstallerVersion = if ($HostDoc.installer_version) { "$($HostDoc.installer_version)" } else { $null }
        PublisherVersion     = if ($Mode -eq 'envelope') { $EnvelopePublisherVersion } else { $null }
        HostGeneratedAt      = $hostGeneratedAt
        EnvelopeGeneratedAt  = if ($Mode -eq 'envelope') { $EnvelopeGeneratedAt } else { $null }
        Mode                 = $Mode
        SchemaWarning        = $schemaWarning
        EnvelopeSchemaWarning= if ($Mode -eq 'envelope') { $EnvelopeSchemaWarning } else { $null }
    }
}


<#
.SYNOPSIS
    Fetch a Deploy-ClamAV health document from a mirror URL and return
    an array of dashboard rows.

.PARAMETER MirrorUrl
    URL to fetch. Either a single-host doc (Deploy-ClamAV v0.0.6
    ".../ClamAV/status.json") or an envelope (v0.0.7
    ".../ClamAV/fleet-status.json"). Auto-detected.

.PARAMETER TimeoutSec
    HTTP timeout for the fetch. Default 10s (generous — mirrors sit on
    trusted segments per Deploy-ClamAV team, envelope is small even at
    100+ hosts). Bump for slow WAN segments.

.PARAMETER AggregateStaleSeconds
.PARAMETER AggregateProbeFailedSeconds
    Envelope-mode only. Age thresholds against envelope.generated_at.
    Defaults 900 / 1800 = 15/30 min (3 / 6 missed publishes at the
    default 5-min publish cadence).

.PARAMETER HostStaleSeconds
.PARAMETER HostProbeFailedSeconds
    Per-host axis. Age thresholds against each host's generated_at.
    Defaults 1800 / 3600 = 30/60 min.

    Cadence context (Deploy-ClamAV v0.0.7 AS-BUILT): the automated
    mirror timer polls clients read-only via a source-pinned
    forced-command `cat` (no sudo, no `clamav-status --fresh`), so
    per-host generated_at reflects each client's own
    `clamav-status.timer` cadence (default *:0/15, 15 min). Defaults
    give 2 missed cycles → Degraded, 4 missed → ProbeFailed — the
    per-host axis is LOAD-BEARING in the automated path.

    The operator-invoked `provision --status --publish` path uses
    full SSH + --fresh and produces near-simultaneous timestamps; in
    that path this axis is a defensive floor. Unreachable hosts
    surface as explicit ProbeFailed entries in EITHER path.

.PARAMETER ExpectedEnvelopeSchemaVersion
.PARAMETER ExpectedHostSchemaVersion
    Schema versions this consumer was built against. Reads > expected
    are soft warnings (surfaced via SchemaWarning field on the row);
    invalid or missing values are hard ProbeFailed.

.PARAMETER Now
    Test seam. Production callers omit; default is Get-Date. Tests pass
    a fixed value so staleness computations are deterministic.

.OUTPUTS
    [pscustomobject[]] — array of dashboard rows. Even on total failure
    (network unreachable, malformed JSON) returns a one-element array
    with a synthetic ProbeFailed row so the dashboard grid always shows
    something for the operator.
#>
function Get-ClamAVHealthProbe {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$MirrorUrl,

        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 10,

        [ValidateRange(60, 86400)]
        [int]$AggregateStaleSeconds = 900,

        [ValidateRange(60, 86400)]
        [int]$AggregateProbeFailedSeconds = 1800,

        [ValidateRange(60, 86400)]
        [int]$HostStaleSeconds = 1800,

        [ValidateRange(60, 86400)]
        [int]$HostProbeFailedSeconds = 3600,

        [ValidateRange(1, 100)]
        [int]$ExpectedEnvelopeSchemaVersion = 1,

        [ValidateRange(1, 100)]
        [int]$ExpectedHostSchemaVersion = 1,

        [datetime]$Now = (Get-Date)
    )

    # 1. Fetch. Any HTTP / TLS / DNS error → single synthetic row.
    $raw = $null
    try {
        $raw = Invoke-RestMethod -Uri $MirrorUrl -TimeoutSec $TimeoutSec -ErrorAction Stop
    } catch {
        return ,(New-ClamAVProbeFailedRow -Reason "mirror unreachable: $($_.Exception.Message)" -MirrorUrl $MirrorUrl -Now $Now)
    }

    if ($null -eq $raw) {
        return ,(New-ClamAVProbeFailedRow -Reason 'mirror returned empty document' -MirrorUrl $MirrorUrl -Now $Now)
    }

    # 2. Auto-detect envelope vs single-host by the contract's markers.
    $rawProps = $raw.PSObject.Properties.Name
    $isEnvelope = (($rawProps -contains 'kind') -and ($raw.kind -eq 'fleet-status')) -or
                  ($rawProps -contains 'hosts')

    if (-not $isEnvelope) {
        # 3a. Single-host mode — one row, host axis only.
        $row = ConvertFrom-ClamAVHostDocument `
            -HostDoc $raw `
            -Now $Now `
            -HostStaleSeconds $HostStaleSeconds `
            -HostProbeFailedSeconds $HostProbeFailedSeconds `
            -ExpectedHostSchemaVersion $ExpectedHostSchemaVersion `
            -Mode 'single-host'
        return ,$row
    }

    # 3b. Envelope mode.

    # 3b.i Validate envelope schema_version.
    $envelopeSchemaVersion = 0
    if ($null -ne $raw.schema_version) {
        [void][int]::TryParse("$($raw.schema_version)", [ref]$envelopeSchemaVersion)
    }
    if ($envelopeSchemaVersion -eq 0) {
        return ,(New-ClamAVProbeFailedRow -Reason 'envelope missing or invalid schema_version' -MirrorUrl $MirrorUrl -Now $Now)
    }

    $envelopeSchemaWarning = $null
    if ($envelopeSchemaVersion -gt $ExpectedEnvelopeSchemaVersion) {
        $envelopeSchemaWarning = "envelope schema v$envelopeSchemaVersion > expected v$ExpectedEnvelopeSchemaVersion; parsing best-effort"
        Write-Warning "Deploy-ClamAV envelope: $envelopeSchemaWarning"
    }

    # 3b.ii Parse envelope generated_at + compute aggregate-axis override.
    $envelopeGeneratedAt = $null
    $envelopeAge         = $null
    if ($null -ne $raw.generated_at) {
        $parsed = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse("$($raw.generated_at)", [ref]$parsed)) {
            $envelopeGeneratedAt = $parsed
            $envelopeAge = ([datetimeoffset]$Now) - $parsed
        }
    }

    $aggregateOverride = Get-ClamAVStalenessOverride `
        -Age $envelopeAge `
        -StaleSeconds $AggregateStaleSeconds `
        -ProbeFailedSeconds $AggregateProbeFailedSeconds `
        -Axis 'aggregate'

    # 3b.iii Publisher version (envelope-level installer_version).
    $publisherVersion = if ($raw.installer_version) { "$($raw.installer_version)" } else { $null }

    # 3b.iv Iterate hosts[]. Wrap with @() so a single host or empty
    #       array both iterate cleanly.
    $hostArray = @($raw.hosts)
    if ($hostArray.Count -eq 0) {
        # Structurally valid envelope with no hosts — return empty
        # rather than a synthetic row. Dashboard shows no ClamAV rows.
        return @()
    }

    $rows = foreach ($h in $hostArray) {
        ConvertFrom-ClamAVHostDocument `
            -HostDoc $h `
            -Now $Now `
            -HostStaleSeconds $HostStaleSeconds `
            -HostProbeFailedSeconds $HostProbeFailedSeconds `
            -ExpectedHostSchemaVersion $ExpectedHostSchemaVersion `
            -AggregateOverride $aggregateOverride `
            -EnvelopeGeneratedAt $envelopeGeneratedAt `
            -EnvelopePublisherVersion $publisherVersion `
            -EnvelopeSchemaWarning $envelopeSchemaWarning `
            -Mode 'envelope'
    }

    return @($rows)
}

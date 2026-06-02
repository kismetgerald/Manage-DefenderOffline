<#
.SYNOPSIS
    Read and validate the SchemaVersion pragma on a Manage-DefenderOffline
    config artifact (conf/config.conf or hosts.conf).

.DESCRIPTION
    v0.0.20 introduced explicit schema versioning on the two operator-edited
    artifacts so future installers can detect and migrate stale on-disk
    layouts. The versioning is opt-in for backward compatibility — when the
    pragma is absent, this helper treats the artifact as v1 (the implicit
    schema shared by every release up through v0.0.19).

    config.conf: looks up the SchemaVersion key in an already-parsed config
    dictionary (the same dict returned by each script's Read-ConfigFile).
    The key lives in the [Meta] section but the parser is section-flat, so
    a top-level key lookup is sufficient.

    hosts.conf: scans the file for a `# SchemaVersion: N` comment-pragma
    line. The pragma must appear in the first 10 lines (i.e., inside the
    auto-generated header block). hosts.conf has no key=value parser of
    its own — it's a plain hostname list — so the comment-pragma form is
    the only place a version can live without changing the file format.

    The helper does not Write-Warning itself. It returns a structured
    result and lets the caller decide how to surface the message via its
    own log facility (Write-Log / Write-DashLog / Write-Warn).

.PARAMETER ConfigData
    Parsed config dictionary from Read-ConfigFile. Use this parameter set
    for config.conf.

.PARAMETER HostsFilePath
    Path to hosts.conf. Use this parameter set for the hosts list.

.PARAMETER ExpectedVersion
    Schema version the caller was built against. Each script hardcodes this
    as a script-level constant (e.g. `$Script:ExpectedConfigSchemaVersion = 1`)
    and bumps it when it ships a breaking config change.

.PARAMETER ArtifactName
    Friendly name used in the Warning message so the operator knows which
    file is mismatched. Typically 'config.conf' or 'hosts.conf'.

.OUTPUTS
    [pscustomobject] with properties:
      ReadVersion     [int]    The version actually found, or 1 if absent.
      ExpectedVersion [int]    Echoed from the parameter.
      IsCompatible    [bool]   $true when ReadVersion <= ExpectedVersion.
      Warning         [string] Non-null actionable message when something is
                               surprising (newer schema, parse failure).
                               $null when everything looks fine.

.EXAMPLE
    $cfg = Read-ConfigFile $ConfigPath
    $check = Test-SchemaVersion -ConfigData $cfg -ExpectedVersion 1 -ArtifactName 'config.conf'
    if ($check.Warning) { Write-Warn $check.Warning }

.EXAMPLE
    $check = Test-SchemaVersion -HostsFilePath $HostsFile -ExpectedVersion 1 -ArtifactName 'hosts.conf'
    if (-not $check.IsCompatible) { Write-Warn $check.Warning }

.NOTES
    Dot-source from each script that needs it:
        . (Join-Path $PSScriptRoot 'lib\Test-SchemaVersion.ps1')
#>
function Test-SchemaVersion {
    [CmdletBinding(DefaultParameterSetName = 'Config')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Config')]
        [System.Collections.IDictionary]$ConfigData,

        [Parameter(Mandatory, ParameterSetName = 'HostsFile')]
        [string]$HostsFilePath,

        [Parameter(Mandatory)]
        [int]$ExpectedVersion,

        [Parameter(Mandatory)]
        [string]$ArtifactName
    )

    $readVersion = 1   # default when pragma is absent (backward compat)
    $parseFailureRaw = $null

    switch ($PSCmdlet.ParameterSetName) {
        'Config' {
            # Use the IDictionary indexer rather than ContainsKey: the parser
            # uses Dictionary[string,string] (method: ContainsKey) but a
            # caller passing a plain hashtable would have Contains instead.
            # Reading $ConfigData['SchemaVersion'] returns $null for missing
            # keys on both types and keeps the helper duck-typed.
            $maybeValue = $ConfigData['SchemaVersion']
            if ($null -ne $maybeValue) {
                $raw = "$maybeValue".Trim()
                if ($raw) {
                    $parsed = 0
                    if ([int]::TryParse($raw, [ref]$parsed)) {
                        $readVersion = $parsed
                    } else {
                        $parseFailureRaw = $raw
                    }
                }
            }
        }
        'HostsFile' {
            if (Test-Path -LiteralPath $HostsFilePath -ErrorAction SilentlyContinue) {
                # Scan only the first 10 lines — the pragma must live inside
                # the auto-generated header block, not buried in hostnames.
                $headerLines = Get-Content -LiteralPath $HostsFilePath -TotalCount 10 -ErrorAction SilentlyContinue
                foreach ($line in $headerLines) {
                    if ($line -match '^\s*#\s*SchemaVersion\s*:\s*(\S+)') {
                        $raw = $Matches[1].Trim()
                        $parsed = 0
                        if ([int]::TryParse($raw, [ref]$parsed)) {
                            $readVersion = $parsed
                        } else {
                            $parseFailureRaw = $raw
                        }
                        break
                    }
                }
            }
        }
    }

    $warning = $null
    if ($parseFailureRaw) {
        $warning = "$ArtifactName SchemaVersion value '$parseFailureRaw' is not an integer; treating as v1 for compatibility. Fix or remove the pragma to silence this warning."
    } elseif ($readVersion -gt $ExpectedVersion) {
        $warning = "$ArtifactName SchemaVersion is v$readVersion but this script was built for v$ExpectedVersion. Newer keys may be ignored. Update Manage-DefenderOffline scripts to the matching release."
    }

    return [pscustomobject]@{
        ReadVersion     = $readVersion
        ExpectedVersion = $ExpectedVersion
        IsCompatible    = ($readVersion -le $ExpectedVersion -and -not $parseFailureRaw)
        Warning         = $warning
    }
}

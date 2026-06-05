<#
.SYNOPSIS
    Get-StaleHttpReservations.ps1 — enumerate stale netsh URL-ACL and
    sslcert reservations from prior installer runs.

.DESCRIPTION
    Background: when an operator changes the dashboard's Port (or
    RedirectHttpPort) and re-runs Install-ManageDefender.ps1, the prior
    netsh reservations on the old ports are NOT cleaned up by the
    pre-v0.0.23 installer. This produces two latent failures:

      1. URL-ACL conflict: a leftover `https://+:8080/` blocks the new
         redirect listener from binding `http://+:8080/`, because URL-ACL
         conflict detection is by *port*, not by exact prefix string.
      2. Cert mis-routing: a leftover sslcert binding on 0.0.0.0:8443
         still serves the (possibly expired) cert if anything else
         happens to bind 8443 later.

    The dashboard surfaces both as runtime diagnostics today; v0.0.23
    moves the cleanup left to install time so the failures never reach
    runtime.

    Identity matching:
      - URL-ACL: SID comparison via NTAccount.Translate(SecurityIdentifier).
        Handles BUILTIN\X / NT AUTHORITY\X / DOMAIN\X variations and
        per-host renames. Reservations owned by accounts that don't
        translate (deleted users, foreign domains) are skipped.
      - sslcert: Application-ID match. The installer creates bindings
        with a stable AppID ($script:HttpsAppId); any binding tagged
        with that AppID was made by us.

    Shape matching: only `<scheme>://+:<port>/` URL-ACLs are considered
    ours. Hostname-bound or path-prefixed reservations might be from a
    sister service we don't manage and are left alone.

    Active ports: the installer's current configuration (Port +
    RedirectHttpPort + FallbackPort) is preserved — we only clean up
    reservations on ports that don't match any of those.

    Parsers are exposed (Get-NetshSslcertBindings) so they can be
    unit-tested with synthetic netsh output without shelling out.
#>

function Get-NetshSslcertBindings {
    <#
    .SYNOPSIS
        Pure parser. Walk `netsh http show sslcert` output (multi-binding
        form, no ipport filter) and emit one record per binding.
    .OUTPUTS
        Zero or more [pscustomobject]@{ IpPort; Port; Hash; AppId } objects.
        Port is parsed from IpPort when possible; $null otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$NetshOutput
    )

    $bindings = New-Object 'System.Collections.Generic.List[pscustomobject]'
    if (-not $NetshOutput) { return ,([pscustomobject[]]@()) }

    $currentIpPort = $null
    $currentHash   = $null
    $currentAppId  = $null

    function script:Flush-SslcertBlock {
        param($ipport, $hash, $appid, $list)
        if (-not $ipport) { return }
        $port = $null
        if ($ipport -match ':(\d+)\s*$') { $port = [int]$Matches[1] }
        $list.Add([pscustomobject]@{
            IpPort = $ipport
            Port   = $port
            Hash   = if ($hash) { $hash.ToUpperInvariant() } else { $null }
            AppId  = if ($appid) { $appid.ToLowerInvariant() } else { $null }
        })
    }

    foreach ($line in $NetshOutput) {
        if ($null -eq $line) { continue }

        if ($line -match '(?i)^\s*IP:port\s*:\s*(\S+)\s*$') {
            # New binding block — flush previous if any
            script:Flush-SslcertBlock -ipport $currentIpPort -hash $currentHash -appid $currentAppId -list $bindings
            $currentIpPort = $Matches[1].Trim()
            $currentHash   = $null
            $currentAppId  = $null
            continue
        }

        if ($line -match '(?i)^\s*Certificate\s+Hash\s*:\s*([0-9a-fA-F]+)') {
            $currentHash = ($Matches[1] -replace '\s','').Trim()
            continue
        }

        if ($line -match '(?i)^\s*Application\s+ID\s*:\s*(\{[0-9a-fA-F-]+\})') {
            $currentAppId = $Matches[1].Trim()
            continue
        }
    }

    # Flush final block
    script:Flush-SslcertBlock -ipport $currentIpPort -hash $currentHash -appid $currentAppId -list $bindings

    return ,([pscustomobject[]]$bindings.ToArray())
}

function Get-StaleUrlAclReservations {
    <#
    .SYNOPSIS
        Filter parsed URL-ACL reservations down to the ones the
        installer should clean up.
    .DESCRIPTION
        A reservation is "stale" iff ALL of these hold:
          - Url shape is `<http|https>://+:<port>/` exactly
          - Port is NOT in $ActivePorts
          - At least one Owner translates to a SID equal to $ServiceIdentitySid
        Owners that fail to translate (deleted accounts, foreign domains)
        are simply skipped — they don't disqualify the reservation, but
        they also don't match.
    .OUTPUTS
        Zero or more pscustomobject (same shape as input plus Port).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]]$Reservations,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$ServiceIdentitySid,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [int[]]$ActivePorts
    )

    $stale = New-Object 'System.Collections.Generic.List[pscustomobject]'

    foreach ($r in $Reservations) {
        if (-not $r.Url) { continue }
        if ($r.Url -notmatch '^(?i)https?://\+:(\d+)/$') { continue }
        $port = [int]$Matches[1]
        if ($ActivePorts -contains $port) { continue }

        $ours = $false
        foreach ($owner in $r.Owners) {
            if (-not $owner) { continue }
            try {
                $sid = ([System.Security.Principal.NTAccount]::new($owner)).Translate(
                    [System.Security.Principal.SecurityIdentifier])
                if ($sid.Value -eq $ServiceIdentitySid.Value) {
                    $ours = $true
                    break
                }
            } catch {
                # Owner string didn't resolve to a SID (deleted account,
                # foreign domain we can't reach, etc.). Skip and move on.
                continue
            }
        }
        if ($ours) {
            [void]$stale.Add([pscustomobject]@{
                Url    = $r.Url
                Port   = $port
                Owners = $r.Owners
            })
        }
    }

    return ,([pscustomobject[]]$stale.ToArray())
}

function Get-StaleSslcertBindings {
    <#
    .SYNOPSIS
        Filter parsed sslcert bindings down to the ones the installer
        should clean up.
    .DESCRIPTION
        A binding is "stale" iff ALL of these hold:
          - AppId is non-null and case-insensitively equal to $OurAppId
          - IpPort's port is not $null (skip malformed entries)
          - Port is NOT in $ActivePorts
        Bindings tagged with someone else's AppID are left alone, even
        on inactive ports — they're not ours to delete.
    .OUTPUTS
        Zero or more pscustomobject (same shape as input).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]]$Bindings,

        [Parameter(Mandatory)]
        [string]$OurAppId,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [int[]]$ActivePorts
    )

    $stale = New-Object 'System.Collections.Generic.List[pscustomobject]'
    $normOurAppId = ($OurAppId -replace '\s','').ToLowerInvariant()

    foreach ($b in $Bindings) {
        if (-not $b.AppId) { continue }
        if ($null -eq $b.Port) { continue }
        if ($ActivePorts -contains $b.Port) { continue }
        if ($b.AppId -ne $normOurAppId) { continue }
        [void]$stale.Add($b)
    }

    return ,([pscustomobject[]]$stale.ToArray())
}

function Get-StaleHttpReservations {
    <#
    .SYNOPSIS
        Top-level orchestrator. Enumerate stale URL-ACL + sslcert
        reservations owned by the service identity / our AppID on ports
        outside the active set.
    .DESCRIPTION
        Shells out to `netsh http show urlacl` and `netsh http show
        sslcert` when called without injected output, parses each, and
        applies the filters. Returns a single result object so the
        installer can render both lists with one helper call.
    .PARAMETER ServiceIdentitySid
        SID the operator is currently installing under. URL-ACL owners
        translating to this SID are "ours".
    .PARAMETER OurAppId
        Stable GUID the installer uses for its sslcert bindings.
        Matching is case-insensitive after whitespace removal.
    .PARAMETER ActivePorts
        Ports that should NOT be considered stale even if held by us:
        the new Port, the RedirectHttpPort, and the FallbackPort (so
        future fallback transitions don't re-pay an extra netsh trip).
    .OUTPUTS
        [pscustomobject]@{
            StaleUrlAcls  = pscustomobject[]
            StaleSslcerts = pscustomobject[]
            Count         = [int]  # combined
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$ServiceIdentitySid,

        [Parameter(Mandatory)]
        [string]$OurAppId,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [int[]]$ActivePorts,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$UrlAclNetshOutput,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$SslcertNetshOutput
    )

    if ($null -eq $UrlAclNetshOutput) {
        try { $UrlAclNetshOutput = & netsh http show urlacl 2>&1 | ForEach-Object { [string]$_ } }
        catch { $UrlAclNetshOutput = @() }
    }
    if ($null -eq $SslcertNetshOutput) {
        try { $SslcertNetshOutput = & netsh http show sslcert 2>&1 | ForEach-Object { [string]$_ } }
        catch { $SslcertNetshOutput = @() }
    }

    # URL-ACL: reuse the parser from lib/Test-UrlAclCollision.ps1 if it
    # has already been dot-sourced; otherwise inline-dot-source it. This
    # avoids duplicating the parser in two helpers.
    if (-not (Get-Command Get-NetshUrlAclReservations -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Test-UrlAclCollision.ps1')
    }
    $urlAclReservations = Get-NetshUrlAclReservations -NetshOutput $UrlAclNetshOutput
    $staleUrlAcls       = Get-StaleUrlAclReservations -Reservations $urlAclReservations `
                              -ServiceIdentitySid $ServiceIdentitySid `
                              -ActivePorts        $ActivePorts

    $sslcertBindings = Get-NetshSslcertBindings -NetshOutput $SslcertNetshOutput
    $staleSslcerts   = Get-StaleSslcertBindings -Bindings $sslcertBindings `
                          -OurAppId     $OurAppId `
                          -ActivePorts  $ActivePorts

    [pscustomobject]@{
        StaleUrlAcls  = $staleUrlAcls
        StaleSslcerts = $staleSslcerts
        Count         = ($staleUrlAcls.Count + $staleSslcerts.Count)
    }
}

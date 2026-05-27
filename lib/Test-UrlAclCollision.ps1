<#
.SYNOPSIS
    Test-UrlAclCollision.ps1 — diagnose HTTP URL-ACL reservation conflicts.

.DESCRIPTION
    When HttpListener.Start() fails with "Failed to listen on prefix ...
    because it conflicts with an existing registration on the machine",
    the cause is usually a pre-existing URL-ACL reservation on the same
    port — but NOT necessarily the same prefix. A reservation for
    `http://*:8080/`, `http://hostname:8080/foo/`, or even
    `http://+:8080/somepath/` blocks `http://+:8080/` from binding,
    because URL-ACL conflict detection is by *port*, not by exact
    prefix string.

    This helper enumerates every URL-ACL via
    `netsh http show urlacl` (no URL filter), parses each "Reserved URL"
    block + its "User:" line, and returns any reservation whose URL
    targets the requested port. Lets the operator see exactly which
    prefix and which holder is in the way.

    The parser is exposed as Get-NetshUrlAclReservations so it can be
    unit-tested with synthetic netsh output.
#>

function Get-NetshUrlAclReservations {
    <#
    .SYNOPSIS
        Pure parser. Walk netsh urlacl output and emit one
        pscustomobject per reservation block.
    .OUTPUTS
        Zero or more [pscustomobject]@{ Url; Owners } objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$NetshOutput
    )

    $reservations = New-Object 'System.Collections.Generic.List[pscustomobject]'
    if (-not $NetshOutput) { return ,([pscustomobject[]]@()) }

    $currentUrl    = $null
    $currentOwners = New-Object 'System.Collections.Generic.List[string]'

    function script:Flush {
        param($url, $owners, $list)
        if ($url) {
            $list.Add([pscustomobject]@{
                Url    = $url
                Owners = [string[]]$owners.ToArray()
            })
        }
    }

    foreach ($line in $NetshOutput) {
        if ($null -eq $line) { continue }

        if ($line -match '(?i)^\s*Reserved\s+URL\s*:\s*(\S.+?)\s*$') {
            # New reservation block — flush the previous one
            script:Flush -url $currentUrl -owners $currentOwners -list $reservations
            $currentUrl    = $Matches[1].Trim()
            $currentOwners = New-Object 'System.Collections.Generic.List[string]'
            continue
        }

        if ($line -match '(?i)^\s*User\s*:\s*(.+?)\s*$') {
            $user = $Matches[1].Trim()
            if ($user -and -not $currentOwners.Contains($user)) {
                $currentOwners.Add($user)
            }
        }
    }

    # Flush the final block
    script:Flush -url $currentUrl -owners $currentOwners -list $reservations

    return ,([pscustomobject[]]$reservations.ToArray())
}

function Get-NetshUrlAclOwners {
    <#
    .SYNOPSIS
        Backward-compatible thin wrapper. Returns just the User: lines
        from a single-reservation netsh output block.
    .DESCRIPTION
        Kept for any existing callers (or older tests). Internally
        delegates to Get-NetshUrlAclReservations and flattens the
        result.
    .OUTPUTS
        [string[]] — distinct owner names across all reservations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$NetshOutput
    )

    $owners = New-Object 'System.Collections.Generic.List[string]'
    $reservations = Get-NetshUrlAclReservations -NetshOutput $NetshOutput
    foreach ($r in $reservations) {
        foreach ($u in $r.Owners) {
            if ($u -and -not $owners.Contains($u)) { $owners.Add($u) }
        }
    }
    return ,([string[]]$owners.ToArray())
}

function Test-UrlAclCollision {
    <#
    .SYNOPSIS
        Find any URL-ACL reservation on the given TCP port, regardless
        of which exact prefix (hostname/path) it uses.
    .PARAMETER Port
        The TCP port the listener wants to bind.
    .PARAMETER Scheme
        http (default) or https — used only to build the displayed
        target URL when no collision is found.
    .PARAMETER NetshOutput
        Optional. Injected netsh output for unit tests. When omitted,
        the function shells out to `netsh http show urlacl`
        (no URL filter) so it can find reservations whose prefix shape
        doesn't match `<scheme>://+:<port>/` exactly.
    .OUTPUTS
        [pscustomobject]@{
            HasCollision = [bool]
            Owners       = [string[]]   # distinct holders across all matching reservations
            Reservations = [pscustomobject[]]  # @{ Url; Owners } per matching reservation
            Url          = [string]     # the wildcard URL we were trying to bind
            Port         = [int]
            Scheme       = [string]
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [ValidateSet('http','https')]
        [string]$Scheme = 'http',

        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$NetshOutput
    )

    $url = "${Scheme}://+:${Port}/"

    if ($null -eq $NetshOutput) {
        try {
            $NetshOutput = & netsh http show urlacl 2>&1 | ForEach-Object { [string]$_ }
        } catch {
            return [pscustomobject]@{
                HasCollision = $false
                Owners       = [string[]]@()
                Reservations = [pscustomobject[]]@()
                Url          = $url
                Port         = $Port
                Scheme       = $Scheme
            }
        }
    }

    $allReservations = Get-NetshUrlAclReservations -NetshOutput $NetshOutput

    # Match anything whose URL has the requested port in the host:port
    # position — guarded by ':' / '/' to avoid 8080 matching 18080123.
    $portToken = ":${Port}/"
    $matching  = [pscustomobject[]]@($allReservations | Where-Object { $_.Url -like "*$portToken*" })

    $owners = New-Object 'System.Collections.Generic.List[string]'
    foreach ($r in $matching) {
        foreach ($u in $r.Owners) {
            if ($u -and -not $owners.Contains($u)) { $owners.Add($u) }
        }
    }

    [pscustomobject]@{
        HasCollision = ($matching.Count -gt 0)
        Owners       = [string[]]$owners.ToArray()
        Reservations = $matching
        Url          = $url
        Port         = $Port
        Scheme       = $Scheme
    }
}

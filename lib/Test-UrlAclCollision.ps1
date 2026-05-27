<#
.SYNOPSIS
    Test-UrlAclCollision.ps1 — diagnose HTTP URL-ACL reservation conflicts.

.DESCRIPTION
    When HttpListener.Start() fails with "Failed to listen on prefix ...
    because it conflicts with an existing registration on the machine",
    the cause is almost always a pre-existing URL-ACL reservation held
    by a different account / SID. This helper wraps
    `netsh http show urlacl url=<prefix>` and extracts the holding
    User(s) so the dashboard can log who owns the reservation and tell
    the operator exactly how to clear it.

    The parser is exposed as Get-NetshUrlAclOwners so it can be
    unit-tested with synthetic netsh output.
#>

function Get-NetshUrlAclOwners {
    <#
    .SYNOPSIS
        Pure parser. Extract the User: lines from netsh urlacl output.
    .OUTPUTS
        [string[]] — distinct owner names, or empty array.
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
    if (-not $NetshOutput) { return ,([string[]]@()) }

    foreach ($line in $NetshOutput) {
        if ($null -eq $line) { continue }
        if ($line -match '(?i)^\s*User\s*:\s*(.+?)\s*$') {
            $user = $Matches[1].Trim()
            if ($user -and -not $owners.Contains($user)) {
                $owners.Add($user)
            }
        }
    }
    # Comma-wrap forces an array shape through the pipeline so single-element
    # results aren't unwrapped to a bare string by the caller.
    return ,([string[]]$owners.ToArray())
}

function Test-UrlAclCollision {
    <#
    .SYNOPSIS
        Check whether a URL-ACL reservation exists for the given prefix.
    .PARAMETER Port
        The TCP port the listener wants to bind.
    .PARAMETER Scheme
        http (default) or https.
    .PARAMETER NetshOutput
        Optional. Injected netsh output for unit tests. When omitted,
        the function shells out to
        `netsh http show urlacl url=<scheme>://+:<port>/`.
    .OUTPUTS
        [pscustomobject]@{
            HasCollision = [bool]
            Owners       = [string[]]
            Url          = [string]
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
            $NetshOutput = & netsh http show urlacl url=$url 2>&1 | ForEach-Object { [string]$_ }
        } catch {
            return [pscustomobject]@{
                HasCollision = $false
                Owners       = [string[]]@()
                Url          = $url
                Port         = $Port
                Scheme       = $Scheme
            }
        }
    }

    $owners = Get-NetshUrlAclOwners -NetshOutput $NetshOutput

    [pscustomobject]@{
        HasCollision = ($owners.Count -gt 0)
        Owners       = $owners
        Url          = $url
        Port         = $Port
        Scheme       = $Scheme
    }
}

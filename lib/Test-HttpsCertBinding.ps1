<#
.SYNOPSIS
    Test-HttpsCertBinding.ps1 — HTTPS pre-flight cert-binding checker.

.DESCRIPTION
    Wraps `netsh http show sslcert ipport=0.0.0.0:<Port>` and parses the
    Certificate Hash line. Returns a result object indicating whether a
    matching cert is bound to the requested port.

    Used by Start-DefenderDashboard.ps1 at startup to fail-fast when
    HTTPS is requested but no cert is bound to the listener port —
    avoids the "listener starts but TLS handshake fails silently"
    failure mode that surfaces in the browser as NS_ERROR_NET_INADEQUATE_SECURITY.

    The parser is exposed as Get-NetshSslcertHash so it can be unit-tested
    with synthetic netsh output.
#>

function Get-NetshSslcertHash {
    <#
    .SYNOPSIS
        Pure parser. Extract the Certificate Hash from netsh sslcert output.
    .OUTPUTS
        Uppercase hex thumbprint string, or $null if no Certificate Hash line.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$NetshOutput
    )

    if (-not $NetshOutput) { return $null }
    foreach ($line in $NetshOutput) {
        if ($line -match '(?i)Certificate\s+Hash\s*:\s*([0-9a-fA-F]+)') {
            return ($Matches[1] -replace '\s','').ToUpperInvariant()
        }
    }
    return $null
}

function Test-HttpsCertBinding {
    <#
    .SYNOPSIS
        Check whether the expected cert is bound to 0.0.0.0:<Port>.
    .PARAMETER Port
        The TCP port the HTTPS listener will bind to.
    .PARAMETER ExpectedThumbprint
        The cert thumbprint that should be bound (case-insensitive).
    .PARAMETER NetshOutput
        Optional. Injected netsh output for unit tests. When omitted, the
        function shells out to `netsh http show sslcert ipport=0.0.0.0:<Port>`.
    .OUTPUTS
        [pscustomobject]@{
            IsBound          = [bool]  # true only when bound AND thumbprint matches
            BoundThumbprint  = [string] # uppercase hex, or $null
            Reason           = [string] # human-readable explanation
            Port             = [int]
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ExpectedThumbprint,

        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$NetshOutput
    )

    $normExpected = ($ExpectedThumbprint -replace '\s','').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($normExpected)) {
        return [pscustomobject]@{
            IsBound         = $false
            BoundThumbprint = $null
            Reason          = 'ExpectedThumbprint is empty.'
            Port            = $Port
        }
    }

    if ($null -eq $NetshOutput) {
        try {
            $NetshOutput = & netsh http show sslcert ipport=0.0.0.0:$Port 2>&1 | ForEach-Object { [string]$_ }
        } catch {
            return [pscustomobject]@{
                IsBound         = $false
                BoundThumbprint = $null
                Reason          = "netsh invocation failed: $($_.Exception.Message)"
                Port            = $Port
            }
        }
    }

    $bound = Get-NetshSslcertHash -NetshOutput $NetshOutput
    if (-not $bound) {
        return [pscustomobject]@{
            IsBound         = $false
            BoundThumbprint = $null
            Reason          = "No sslcert binding found at 0.0.0.0:$Port (run 'netsh http show sslcert' to enumerate existing bindings)."
            Port            = $Port
        }
    }

    if ($bound -eq $normExpected) {
        return [pscustomobject]@{
            IsBound         = $true
            BoundThumbprint = $bound
            Reason          = "Cert $bound is bound to 0.0.0.0:$Port."
            Port            = $Port
        }
    }

    [pscustomobject]@{
        IsBound         = $false
        BoundThumbprint = $bound
        Reason          = "Wrong cert bound to 0.0.0.0:${Port}: found $bound, expected $normExpected."
        Port            = $Port
    }
}

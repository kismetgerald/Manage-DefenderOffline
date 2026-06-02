<#
.SYNOPSIS
    Explain *why* a TCP port is unavailable so operators get actionable
    remediation instead of a generic "port is in use" error.

.DESCRIPTION
    The dashboard installer hits a port-availability check before binding.
    When the check fails, this helper queries Get-NetTCPConnection to
    identify the holder and returns a human-readable diagnostic.

    The most interesting case is PID 4 (the System process / kernel). A
    listener owned by PID 4 means HTTP.sys is holding the port handle in
    kernel space — typically because a prior HttpListener (a previous
    dashboard run, IIS, or any other HTTP.sys consumer) exited without
    releasing its URL ACL. This is non-obvious to operators staring at
    a generic "in use" error; the diagnostic surfaces the remediation
    (restart the HTTP service to release the handles).

    Side-effect-free: no Write-* calls. Caller decides how to surface
    the message via its own logging facility.

.PARAMETER BusyPort
    The TCP port that failed the availability check.

.OUTPUTS
    [string] A human-readable diagnostic, or $null when no owner could be
    enumerated (rare; tolerated to keep callers simple).

.EXAMPLE
    if (-not (Test-PortFree $Port)) {
        Write-Fail "Port $Port is in use"
        $diag = Get-PortBusyDiagnostic -BusyPort $Port
        if ($diag) { Write-Info $diag }
    }

.NOTES
    Dot-source from each script that needs it:
        . (Join-Path $PSScriptRoot 'lib\Get-PortBusyDiagnostic.ps1')

    Get-NetTCPConnection / Get-Process are mockable in Pester, so this
    helper has full unit-test coverage for the PID-4-System path and the
    common userland-process path.
#>
function Get-PortBusyDiagnostic {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int]$BusyPort
    )

    try {
        $conn = Get-NetTCPConnection -LocalPort $BusyPort -State Listen -ErrorAction SilentlyContinue |
                Select-Object -First 1
        if (-not $conn) {
            return "Port ${BusyPort}: bound but no listener could be enumerated. The handle may be held by a kernel driver or by HTTP.sys with no active userland process. Try 'Stop-Service http -Force; Start-Service http' to release HTTP.sys handles; if that hangs longer than 5 minutes, reboot."
        }
        $pidValue = $conn.OwningProcess
        if ($pidValue -eq 4) {
            return "Port ${BusyPort}: held by HTTP.sys (PID 4 = System / kernel). A prior HttpListener exited without releasing its URL ACL. Release with 'Stop-Service http -Force; Start-Service http' (typically 30-60s; if the Stop hangs longer than 5 minutes, reboot). Then re-run the installer."
        }
        $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
        if ($proc) {
            return "Port ${BusyPort}: held by PID $pidValue ($($proc.ProcessName)). Stop that process (or pick a different port) and re-run."
        }
        return "Port ${BusyPort}: held by PID $pidValue (process info unavailable; the process may have exited or be running under another security boundary)."
    } catch {
        return $null
    }
}

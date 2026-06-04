# Test-ServiceCredential.ps1
#
# Runs in the service identity's context to verify that an existing
# credential XML (saved via Save-ServiceCredential.ps1) can be decrypted
# by that identity's DPAPI master key. Used by Install-ManageDefender.ps1
# to skip credential re-prompts when valid XMLs already exist in conf/.
#
# Validation is intentionally pure: read, decrypt, type-check, retrieve
# the plaintext password (which catches partial DPAPI corruption that
# survives Import-Clixml but fails at GetNetworkCredential). No network
# call, no authentication — we are only proving "this identity could
# decrypt this file at runtime if it needed to".
#
# Exit codes:
#   0 — XML decrypted successfully under the current identity's DPAPI
#   1 — Any failure (file missing, corruption, wrong identity, non-PSCredential)
#
# On exit 1 a diagnostic line is written to <SourcePath>.err; the caller
# (Install-ManageDefender.ps1) reads + surfaces + deletes that file.
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourcePath
)

$ErrorActionPreference = 'Stop'

# Side-log alongside the source: any caught exception is written here
# before exit 1. Same pattern as Save-ServiceCredential.ps1 so the caller
# can read failure context regardless of stdio capture (Start-Process vs
# Task Scheduler for the gMSA path).
$errLog = $SourcePath + '.err'

try {
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "Source path does not exist: $SourcePath"
    }

    $cred = Import-Clixml -Path $SourcePath
    if (-not $cred) {
        throw 'Import-Clixml returned null.'
    }
    if (-not ($cred -is [System.Management.Automation.PSCredential])) {
        throw "Imported object is not a PSCredential (got $($cred.GetType().FullName))."
    }
    if ([string]::IsNullOrWhiteSpace($cred.UserName)) {
        throw 'PSCredential.UserName is empty.'
    }

    # Force a plaintext-password retrieval. Catches partial DPAPI corruption
    # that survives Import-Clixml but blows up when the SecureString is
    # actually unwrapped. The retrieved value is immediately discarded.
    $null = $cred.GetNetworkCredential().Password

    exit 0
} catch {
    $msg = "[{0}] {1}`r`n  Helper invoked as: {2}`r`n  SourcePath:        {3}`r`n  Exception type:    {4}" -f `
        (Get-Date -Format 'o'),
        $_.Exception.Message,
        ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name),
        $SourcePath,
        $_.Exception.GetType().FullName
    try { Set-Content -Path $errLog -Value $msg -Encoding UTF8 -Force -ErrorAction SilentlyContinue } catch {}
    Write-Error $_.Exception.Message
    exit 1
}

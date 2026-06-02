# Save-ServiceCredential.ps1
#
# Runs in the service identity's context to re-encrypt a PSCredential under
# that identity's DPAPI master key. Invoked indirectly by
# Install-ManageDefender.ps1 — see notes there.
#
# The handoff format avoids ever writing the plaintext password to disk:
#   $SourcePath is a 2-line UTF-8 file with:
#     line 1: username
#     line 2: base64 of LocalMachine-DPAPI-encrypted UTF-16 password bytes
# Anyone on this box can decrypt that (LocalMachine scope), so the caller
# deletes the file immediately after this helper returns.
#
# This helper:
#   1. Reads the source file (username + encrypted blob)
#   2. Decrypts the blob via ProtectedData/LocalMachine
#   3. Wraps the plaintext in a SecureString
#   4. Builds a PSCredential and Export-Clixml's it to $DestinationPath
#      under the CURRENT user's DPAPI master key (so the encryption is now
#      tied to the service identity, not the admin who launched the install)
#   5. Exits 0 on success, 1 on failure
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialName',
    Justification = '$CredentialName is a tag ("WinRm"/"AD"/"Smtp"), not credential material; the analyzer false-positives on the substring match.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('WinRm','AD','Smtp')]
    [string]$CredentialName,

    [Parameter(Mandatory)]
    [string]$SourcePath,

    [Parameter(Mandatory)]
    [string]$DestinationPath
)

$ErrorActionPreference = 'Stop'

# Side-log alongside the destination: any caught exception is written here
# before exit 1. The caller (Install-ManageDefender.ps1) reads + surfaces +
# deletes this in its finally block. Works regardless of whether the helper
# was launched via Start-Process (stdio captured) or Task Scheduler (gMSA,
# stdio not captured).
$errLog = $DestinationPath + '.err'

try {
    $lines = Get-Content -Path $SourcePath -ErrorAction Stop
    if ($lines.Count -lt 2) { throw "Source credential payload at $SourcePath is malformed." }
    $userName  = $lines[0]
    $b64Secret = $lines[1]

    Add-Type -AssemblyName System.Security
    $encrypted  = [Convert]::FromBase64String($b64Secret)
    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted, $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    $plainText = [System.Text.Encoding]::Unicode.GetString($plainBytes)
    [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)

    $secure = [System.Security.SecureString]::new()
    foreach ($c in $plainText.ToCharArray()) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    $plainText = $null

    $cred = [System.Management.Automation.PSCredential]::new($userName, $secure)
    $cred | Export-Clixml -Path $DestinationPath -Force

    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        throw "Export-Clixml succeeded but the destination file is missing: $DestinationPath"
    }
    exit 0
} catch {
    $msg = "[{0}] {1}`r`n  Helper invoked as: {2}`r`n  SourcePath:        {3}`r`n  DestinationPath:   {4}`r`n  Exception type:    {5}" -f `
        (Get-Date -Format 'o'),
        $_.Exception.Message,
        ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name),
        $SourcePath,
        $DestinationPath,
        $_.Exception.GetType().FullName
    try { Set-Content -Path $errLog -Value $msg -Encoding UTF8 -Force -ErrorAction SilentlyContinue } catch {}
    Write-Error $_.Exception.Message
    exit 1
}

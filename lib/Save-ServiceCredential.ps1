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
    Write-Error $_.Exception.Message
    exit 1
}

<#
.SYNOPSIS
    Install-DefenderDashboard.ps1 — Backward-compatibility shim that delegates to
    Install-ManageDefender.ps1 -Component Dashboard.

.DESCRIPTION
    Starting in v0.0.19, the toolkit ships a unified installer
    (Install-ManageDefender.ps1) that registers Dashboard, Updates, or both
    components as scheduled tasks under one service identity, with optional
    automated credential setup.

    This script remains as a thin delegate so existing QUICKSTART references,
    automation scripts, and operator muscle memory keep working. Every
    parameter is forwarded verbatim to Install-ManageDefender with
    -Component Dashboard. No deprecation message — the shim is intentionally
    silent.

    Two exceptions to pass-through:
      - `-SaveCredential` (legacy interactive WinRM credential helper) still
        works directly here. It does not delegate to Install-ManageDefender;
        it prompts and writes conf\WinRmCredential.xml under the *current*
        Windows identity's DPAPI master key — same semantics as before.
        For service-identity-aware credential setup, run Install-ManageDefender
        directly (which handles STIG V-253289 seclogon enable/restore + gMSA
        one-shot task path).

    All other behaviour matches Install-ManageDefender -Component Dashboard.

.PARAMETER SaveCredential
    Interactive helper to save a WinRM credential under the *current user's*
    DPAPI master key. Use when you've launched this script as the service
    identity (e.g. via runas / Start-Process -Credential). Mutually
    exclusive with installation parameters; the script exits after the save.

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Version        : 0.0.19  (shim, delegates to Install-ManageDefender.ps1)
#>

[CmdletBinding(DefaultParameterSetName = 'gMSA')]
param(
    [string]$DashboardScriptPath,

    [Parameter(ParameterSetName = 'gMSA', Mandatory)]
    [ValidatePattern('\$$')]
    [string]$GmsaName,

    [Parameter(ParameterSetName = 'ServiceAccount', Mandatory)]
    [string]$ServiceAccount,

    [Parameter(ParameterSetName = 'ServiceAccount', Mandatory)]
    [pscredential]$Credential,

    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [ValidateRange(1024, 65535)]
    [int]$FallbackPort = 8443,

    [ValidateRange(30, 86400)]
    [int]$RefreshInterval = 300,

    [string]$SourceSharePath,
    [string]$LogPath = 'C:\Logs\DefenderDashboard',

    [ValidateRange(1, 32)]
    [int]$ParallelThreads = 16,

    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 30,

    [string]$TaskName   = 'DefenderDashboard',
    [string]$TaskFolder = '\',

    [switch]$UseHttps,
    [string]$CertificateThumbprint,
    [switch]$RenewCertificate,
    [string]$AdditionalSans,

    [switch]$AddFirewallRule,
    [switch]$StartImmediately,
    [switch]$Force,

    [Parameter(ParameterSetName = 'SaveCredential', Mandatory)]
    [switch]$SaveCredential,

    [ValidateSet('None', 'Token', 'Basic', 'ADIntegrated')]
    [string]$AuthMethod,

    [string]$AuthAllowedGroups,
    [string]$AuthBasicUsersFile,
    [string]$AuthToken,

    [string]$ConfigPath
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ===================================================================
# Legacy -SaveCredential helper mode (unchanged from pre-0.0.19)
# ===================================================================
if ($SaveCredential) {
    Write-Host "`n=== WinRM Credential Setup (legacy helper) ===" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  This helper saves conf\WinRmCredential.xml under the *current* identity.' -ForegroundColor Gray
    Write-Host "  Run as the service identity (runas or Start-Process -Credential)" -ForegroundColor Yellow
    Write-Host '  so DPAPI encrypts the credential under the correct master key.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  For service-identity-aware credential setup (incl. gMSA + STIG seclogon dance),' -ForegroundColor DarkGray
    Write-Host '  run Install-ManageDefender.ps1 directly without -SkipCredentialSetup.' -ForegroundColor DarkGray
    Write-Host ''
    $cfgDir = Join-Path $ScriptDir 'conf'
    if (-not (Test-Path $cfgDir)) { New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null }
    try {
        $cred = Get-Credential -Message 'Enter WinRM credentials for the management/service account'
        if ($cred) {
            $cred | Export-Clixml -Path (Join-Path $cfgDir 'WinRmCredential.xml') -Force
            Write-Host "  Saved: $(Join-Path $cfgDir 'WinRmCredential.xml')" -ForegroundColor Green
        } else { Write-Host '  Cancelled.' -ForegroundColor Yellow }
    } catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
    exit 0
}

# ===================================================================
# Delegate to Install-ManageDefender -Component Dashboard
# ===================================================================
$unified = Join-Path $ScriptDir 'Install-ManageDefender.ps1'
if (-not (Test-Path $unified)) {
    Write-Host "[FAIL] Install-ManageDefender.ps1 not found at: $unified" -ForegroundColor Red
    Write-Host "       This shim cannot operate without the unified installer it delegates to." -ForegroundColor Red
    exit 1
}

# Forward every parameter that was actually supplied on the command line.
# Hardcode -Component to Dashboard so this shim's semantics match the
# pre-0.0.19 installer regardless of the unified installer's default.
$forward = @{ Component = 'Dashboard' }
foreach ($k in $PSBoundParameters.Keys) {
    # -SaveCredential was handled above; never forward.
    if ($k -eq 'SaveCredential') { continue }
    $forward[$k] = $PSBoundParameters[$k]
}

& $unified @forward
exit $LASTEXITCODE

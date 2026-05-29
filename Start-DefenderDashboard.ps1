<#
.SYNOPSIS
    Start-DefenderDashboard.ps1 – Headless Microsoft Defender fleet status HTTP dashboard

.DESCRIPTION
    Runs a lightweight HTTP listener that serves a self-refreshing browser dashboard
    showing the Microsoft Defender health status of all Windows endpoints in scope.

    Designed to run continuously as a Windows Scheduled Task under a service account
    or Group Managed Service Account (gMSA). All output is written to a log file;
    no interactive console required.

    Two endpoints are served:
      /defender   – HTML dashboard (auto-refreshes in the browser)
      /status     – JSON snapshot of the current data (for scripting / monitoring tools)
      /health     – Plain-text "OK" liveness probe (for uptime monitors)
      /refresh    – Forces an immediate background data refresh (GET or POST)

    Data is cached and refreshed on a background thread every -RefreshInterval seconds.
    Visitors always receive the most recently cached data; they are never blocked waiting
    for a live query.

    Use Install-DefenderDashboard.ps1 to register this script as a scheduled task.

.PARAMETER Port
    TCP port the HTTP listener binds to. Default: 8080.

.PARAMETER RefreshInterval
    How often (in seconds) background data is refreshed. Default: 300 (5 minutes).

.PARAMETER ComputerName
    Manual list of computers to query. Bypasses hosts.conf and AD auto-discovery.

.PARAMETER SourceSharePath
    Base UNC path for the definitions share. Used to determine version currency.
    Example: \\NAS01\DataShare\Software Installers\_AVDefinitions\Microsoft_Defender

.PARAMETER LogPath
    Directory for dashboard log files. Default: C:\Logs\DefenderDashboard

.PARAMETER ParallelThreads
    Maximum concurrent WinRM queries per refresh cycle. Range: 1-32. Default: 16.

.PARAMETER TimeoutSeconds
    Per-host WinRM query timeout in seconds. Default: 30.

.EXAMPLE
    # Run interactively for testing
    .\Start-DefenderDashboard.ps1 -Port 8080 -SourceSharePath "\\NAS01\Share\_AVDefinitions\Microsoft_Defender"

.EXAMPLE
    # Run on a non-default port with a shorter refresh
    .\Start-DefenderDashboard.ps1 -Port 9090 -RefreshInterval 120

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Requires       : PowerShell 7+ (recommended), WinRM on targets (TCP 5985)
                     Administrator privileges or delegated WinRM access on targets
    Version        : 0.0.6
    Last Updated   : 2026-05-19
#>

[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [ValidateRange(1024, 65535)]
    [int]$FallbackPort = 8443,

    [ValidateRange(30, 86400)]
    [int]$RefreshInterval = 300,

    [string[]]$ComputerName,

    [string]$SourceSharePath,

    [string]$LogPath = 'C:\Logs\DefenderDashboard',

    [ValidateRange(1, 32)]
    [int]$ParallelThreads = 16,

    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 30,

    # WinRM credential (single; auto-loaded from .\conf\WinRmCredential.xml if present)
    [pscredential]$Credential,

    [switch]$SaveCredential,

    # AD discovery credential (auto-loaded from .\conf\ADCredential.xml if present)
    [pscredential]$ADCredential,
    [switch]$SaveADCredential,

    # Restrict AD auto-discovery to one or more OU subtrees. Distinguished-name
    # format; multiple DNs separated by semicolons. Empty = whole-domain search.
    [string]$ADSearchBase,

    [bool]$DisableIPv6 = $true,

    # Default theme applied to /defender when the visiting browser has no
    # localStorage preference yet.  Operators can pick this in conf/config.conf.
    [ValidateSet('Dark','Light')]
    [string]$DashboardTheme = 'Dark',

    # HTTPS support.  When true, Port refers to the HTTPS port.  A certificate
    # must be present in Cert:\LocalMachine\My and bound to the listener URL
    # (the installer handles both with -UseHttps).
    [bool]$UseHttps = $false,

    # Thumbprint of the cert in Cert:\LocalMachine\My to bind.  Required when
    # -UseHttps is set.
    [string]$CertificateThumbprint,

    # Bind a secondary HTTP listener on -RedirectHttpPort that 301s every
    # request to the HTTPS URL.  Only honored when -UseHttps is also true.
    [bool]$RedirectHttpToHttps = $true,

    [ValidateRange(1024, 65535)]
    [int]$RedirectHttpPort = 8080,

    # Authentication for /defender, /status, /refresh. /health stays anonymous
    # in all modes so external monitoring can probe liveness without creds.
    # PR-D1 implements None and Token; PR-D2 fills in Basic and ADIntegrated.
    [ValidateSet('None', 'ADIntegrated', 'Basic', 'Token')]
    [string]$AuthMethod = 'None',

    # ADIntegrated only (PR-D2): comma-separated allow list. Prefix entries with
    # '!' to deny (deny wins over allow). Empty allow-list = any authenticated user.
    [string]$AuthAllowedGroups,

    # Basic only (PR-D2): path to file with 'username:pbkdf2-hash' per line.
    [string]$AuthBasicUsersFile,

    # Token only: bearer token. If blank when AuthMethod=Token, a random
    # 32-byte token is generated at first startup and written to
    # conf\dashboard.token with restricted ACL.
    [string]$AuthToken,

    # Helper mode: prompts for a password, PBKDF2-hashes it, and appends a
    # username:salt:iterations:hash line to AuthBasicUsersFile, then exits.
    [string]$AddBasicUser,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.16'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Single chokepoint for all WinRM execution. Path is also passed into thread
# runspaces (see Invoke-FleetRefresh) so the wrapper is available there too.
$LibInvokeDefenderRemote = Join-Path $ScriptDir 'lib\Invoke-DefenderRemote.ps1'
. $LibInvokeDefenderRemote
$LibGetDefenderComputers = Join-Path $ScriptDir 'lib\Get-DefenderComputers.ps1'
. $LibGetDefenderComputers
$LibGetDefenderHealthProbe = Join-Path $ScriptDir 'lib\Get-DefenderHealthProbe.ps1'
. $LibGetDefenderHealthProbe
$LibTestHttpsCertBinding   = Join-Path $ScriptDir 'lib\Test-HttpsCertBinding.ps1'
. $LibTestHttpsCertBinding
$LibTestUrlAclCollision    = Join-Path $ScriptDir 'lib\Test-UrlAclCollision.ps1'
. $LibTestUrlAclCollision
$HostsFile     = Join-Path $ScriptDir 'hosts.conf'

# ===================================================================
# Credential Helper Mode  (exits after completion)
# ===================================================================
if ($SaveCredential) {
    Write-Host "`n=== WinRM Credential Setup ===" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  The dashboard uses a single WinRM credential (WinRmCredential.xml).'
    Write-Host '  Run this helper as the service account or gMSA that runs the dashboard task.'
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
# AD Credential Helper Mode  (exits after completion)
# ===================================================================
if ($SaveADCredential) {
    Write-Host "`n=== AD Discovery Credential Setup ===" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Used ONLY for the LDAP bind that reads the computer list when no'
    Write-Host '  hosts.conf is present.  Saved to conf\ADCredential.xml (DPAPI).'
    Write-Host '  Run this helper as the dashboard service identity (the account that'
    Write-Host '  will actually decrypt the XML at task start).'
    Write-Host ''
    $cfgDir = Join-Path $ScriptDir 'conf'
    if (-not (Test-Path $cfgDir)) { New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null }
    try {
        $cred = Get-Credential -Message 'Enter AD credential (account with read on the domain naming context)'
        if ($cred) {
            $cred | Export-Clixml -Path (Join-Path $cfgDir 'ADCredential.xml') -Force
            Write-Host "  Saved: $(Join-Path $cfgDir 'ADCredential.xml')" -ForegroundColor Green
        } else { Write-Host '  Cancelled.' -ForegroundColor Yellow }
    } catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
    exit 0
}

# ===================================================================
# Configuration File
# ===================================================================
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'conf\config.conf' }

function Read-ConfigFile {
    param([string]$Path)
    $cfg = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $cfg }
    foreach ($line in Get-Content $Path) {
        $t = $line.Trim()
        if (-not $t -or $t -match '^\s*[#\[]') { continue }
        if ($t -match '^([^=]+?)\s*=\s*(.+)$') {
            $v = $Matches[2].Trim() -replace '^([''"])(.*)\1$', '$2'
            $cfg[$Matches[1].Trim()] = $v
        }
    }
    return $cfg
}

$cfg = Read-ConfigFile $ConfigPath
if (-not $PSBoundParameters.ContainsKey('SourceSharePath') -and $cfg['SourceSharePath']) { $SourceSharePath = $cfg['SourceSharePath'] }

# Auto-load single WinRM credential if not passed on CLI
if (-not $PSBoundParameters.ContainsKey('Credential')) {
    $credPath = Join-Path $ScriptDir 'conf\WinRmCredential.xml'
    if (Test-Path $credPath -ErrorAction SilentlyContinue) {
        try { $Credential = Import-Clixml $credPath }
        catch { Write-Warning "Could not load WinRM credential from '$credPath': $($_.Exception.Message)" }
    }
}
if (-not $PSBoundParameters.ContainsKey('ADCredential')) {
    $adCredPath = Join-Path $ScriptDir 'conf\ADCredential.xml'
    if (Test-Path $adCredPath -ErrorAction SilentlyContinue) {
        try { $ADCredential = Import-Clixml $adCredPath }
        catch { Write-Warning "Could not load AD credential from '$adCredPath': $($_.Exception.Message)" }
    }
}
if (-not $PSBoundParameters.ContainsKey('Port')            -and $cfg['Port'])            { try { $Port            = [int]$cfg['Port']            } catch {} }
if (-not $PSBoundParameters.ContainsKey('FallbackPort')    -and $cfg['FallbackPort'])    { try { $FallbackPort    = [int]$cfg['FallbackPort']    } catch {} }
if (-not $PSBoundParameters.ContainsKey('RefreshInterval') -and $cfg['RefreshInterval']) { try { $RefreshInterval = [int]$cfg['RefreshInterval'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('LogPath')         -and $cfg['DashboardLogPath']) { $LogPath           = $cfg['DashboardLogPath'] }
if (-not $PSBoundParameters.ContainsKey('ParallelThreads') -and $cfg['ParallelThreads']) { try { $ParallelThreads = [int]$cfg['ParallelThreads'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('TimeoutSeconds')  -and $cfg['TimeoutSeconds'])  { try { $TimeoutSeconds  = [int]$cfg['TimeoutSeconds']  } catch {} }
if (-not $PSBoundParameters.ContainsKey('DisableIPv6')     -and $cfg['DisableIPv6'])     { $DisableIPv6 = ($cfg['DisableIPv6'] -match '^(?i)true|1|yes$') }
if (-not $PSBoundParameters.ContainsKey('DashboardTheme')  -and $cfg['DashboardTheme'])  {
    $t = $cfg['DashboardTheme'].Trim()
    if ($t -match '^(?i)light$|^(?i)dark$') { $DashboardTheme = (Get-Culture).TextInfo.ToTitleCase($t.ToLower()) }
}
if (-not $PSBoundParameters.ContainsKey('UseHttps')              -and $cfg['UseHttps'])              { $UseHttps              = ($cfg['UseHttps']              -match '^(?i)true|1|yes$') }
if (-not $PSBoundParameters.ContainsKey('CertificateThumbprint') -and $cfg['CertificateThumbprint']) { $CertificateThumbprint = $cfg['CertificateThumbprint'].Trim() }
if (-not $PSBoundParameters.ContainsKey('RedirectHttpToHttps')   -and $cfg['RedirectHttpToHttps'])   { $RedirectHttpToHttps   = ($cfg['RedirectHttpToHttps']   -match '^(?i)true|1|yes$') }
if (-not $PSBoundParameters.ContainsKey('RedirectHttpPort')      -and $cfg['RedirectHttpPort'])      { try { $RedirectHttpPort = [int]$cfg['RedirectHttpPort'] } catch {} }
if (-not $PSBoundParameters.ContainsKey('AuthMethod')            -and $cfg['AuthMethod'])            {
    $am = $cfg['AuthMethod'].Trim()
    if ($am -match '^(?i)None|ADIntegrated|Basic|Token$') { $AuthMethod = (Get-Culture).TextInfo.ToTitleCase($am.ToLower()) -replace '^Adintegrated$','ADIntegrated' }
}
if (-not $PSBoundParameters.ContainsKey('AuthAllowedGroups')     -and $cfg['AuthAllowedGroups'])     { $AuthAllowedGroups     = $cfg['AuthAllowedGroups'].Trim() }
if (-not $PSBoundParameters.ContainsKey('AuthBasicUsersFile')    -and $cfg['AuthBasicUsersFile'])    { $AuthBasicUsersFile    = $cfg['AuthBasicUsersFile'].Trim() }
if (-not $PSBoundParameters.ContainsKey('ADSearchBase')          -and $cfg['ADSearchBase'])          { $ADSearchBase          = $cfg['ADSearchBase'] }
if (-not $PSBoundParameters.ContainsKey('AuthToken')             -and $cfg['AuthToken'])             { $AuthToken             = $cfg['AuthToken'].Trim() }

# Relative paths in config.conf must resolve against the script directory,
# not the current working directory — Task Scheduler launches pwsh.exe with
# CWD = %SystemRoot%\System32, which makes 'conf\dashboard.users' unreachable.
if ($AuthBasicUsersFile -and -not [System.IO.Path]::IsPathRooted($AuthBasicUsersFile)) {
    $AuthBasicUsersFile = Join-Path $ScriptDir $AuthBasicUsersFile
}

$ExcludeList = @()
if ($cfg['ExcludeComputers']) {
    $ExcludeList = $cfg['ExcludeComputers'] -split ',' | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ }
}

# ===================================================================
# Port Availability
# ===================================================================
function Test-PortFree ([int]$TestPort) {
    try {
        $tcp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $TestPort)
        $tcp.Start(); $tcp.Stop(); return $true
    } catch { return $false }
}

function Find-AvailablePort {
    param([int]$Primary, [int]$Fallback)
    if (Test-PortFree $Primary) {
        return [pscustomobject]@{ Port = $Primary; IsFallback = $false; PrimaryPort = $Primary }
    }
    $candidate = $Fallback
    for ($i = 0; $i -lt 10; $i++) {
        if (Test-PortFree $candidate) {
            return [pscustomobject]@{ Port = $candidate; IsFallback = $true; PrimaryPort = $Primary }
        }
        $candidate++
    }
    throw "No available port found. Primary $Primary was in use; tried fallback range $Fallback–$($candidate - 1)."
}

# ===================================================================
# HTTPS certificate validation
#
# Resolves the configured thumbprint to a cert in Cert:\LocalMachine\My,
# verifies it is not past NotAfter, and returns an object describing
# the cert and how many days until expiry. Throws when the cert is
# missing or expired. Callers decide whether to emit EventId 103 when
# DaysUntilExpiry is below their warning threshold.
# ===================================================================
function Resolve-DashboardCertificate {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]   # validate inside so our error message wins over the binder's
        [string]$Thumbprint
    )
    $clean = $Thumbprint.Trim() -replace '\s', '' -replace '[^0-9A-Fa-f]', ''
    if (-not $clean) {
        throw "CertificateThumbprint is empty or not a valid hexadecimal thumbprint."
    }
    $certPath = "Cert:\LocalMachine\My\$clean"
    $cert = Get-Item -LiteralPath $certPath -ErrorAction SilentlyContinue
    if (-not $cert) {
        throw "Certificate with thumbprint $clean not found in Cert:\LocalMachine\My. " +
              "Use Install-DefenderDashboard.ps1 -UseHttps to generate one, or import a PKI-issued cert into LocalMachine\My."
    }
    $now             = Get-Date
    $daysUntilExpiry = [int]($cert.NotAfter - $now).TotalDays
    if ($daysUntilExpiry -lt 0) {
        throw "Certificate $clean expired $(-$daysUntilExpiry) day(s) ago (NotAfter: $($cert.NotAfter)). " +
              "Re-run Install-DefenderDashboard.ps1 -RenewCertificate to regenerate."
    }
    [pscustomobject]@{
        Certificate     = $cert
        Thumbprint      = $clean
        Subject         = $cert.Subject
        NotAfter        = $cert.NotAfter
        DaysUntilExpiry = $daysUntilExpiry
    }
}

# ===================================================================
# Authentication helpers
#
# Test-ConstantTimeEqual: defends bearer-token comparison against timing
# attacks. Standard equality short-circuits on the first mismatched byte;
# an attacker can use response-timing to discover the token byte by byte.
# This implementation always touches every byte, then ORs the differences.
#
# New-RandomToken: cryptographically random 32-byte token, base64-encoded
# (~43 chars). Used for AuthMethod=Token when no AuthToken is configured.
#
# Test-DashboardAuth: central authorization chokepoint. Returns a result
# object with Authorized, StatusCode, User, and Reason. Always allows
# /health regardless of AuthMethod (liveness probes need to work without
# credentials).
#
# PR-D1 implements None and Token. PR-D2 fills in Basic and ADIntegrated.
# ===================================================================

function Test-ConstantTimeEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$A,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$B
    )
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A.Length -ne $B.Length)        { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) {
        $diff = $diff -bor ([byte][char]$A[$i] -bxor [byte][char]$B[$i])
    }
    return $diff -eq 0
}

function New-RandomToken {
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$ByteLength = 32)
    $bytes = [byte[]]::new($ByteLength)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes)
}

# PBKDF2-SHA256 hashing for the Basic-auth users file. Line format:
#   username:salt-b64:iterations:hash-b64
# 16-byte salt, 100k iterations, 32-byte hash by default.
function New-DashboardPasswordHash {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [securestring]$Password,
        [int]$Iterations = 100000,
        [int]$SaltBytes  = 16,
        [int]$HashBytes  = 32
    )
    $salt = [byte[]]::new($SaltBytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $plain, $salt, $Iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try {
            $hash = $pbkdf2.GetBytes($HashBytes)
        } finally { $pbkdf2.Dispose() }
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    return '{0}:{1}:{2}' -f ([Convert]::ToBase64String($salt)), $Iterations, ([Convert]::ToBase64String($hash))
}

function Test-DashboardPasswordHash {
    [CmdletBinding()]
    [OutputType([bool])]
    # Verify-against-hash necessarily takes the cleartext candidate so we can
    # PBKDF2 it and compare. SecureString conversion would add round-trips
    # without changing the in-memory exposure window.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'Hash-verification cannot avoid receiving the cleartext candidate.')]
    param(
        [Parameter(Mandatory)] [string]$Password,
        [Parameter(Mandatory)] [string]$StoredHash
    )
    # StoredHash is the part AFTER the username colon: salt-b64:iterations:hash-b64
    $parts = $StoredHash.Split(':')
    if ($parts.Count -ne 3) { return $false }
    $salt       = try { [Convert]::FromBase64String($parts[0]) } catch { return $false }
    $iterations = 0
    if (-not [int]::TryParse($parts[1], [ref]$iterations) -or $iterations -lt 1) { return $false }
    $expected   = try { [Convert]::FromBase64String($parts[2]) } catch { return $false }
    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password, $salt, $iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $actual = $pbkdf2.GetBytes($expected.Length)
    } finally { $pbkdf2.Dispose() }
    return Test-ConstantTimeEqual `
        -A ([Convert]::ToBase64String($expected)) `
        -B ([Convert]::ToBase64String($actual))
}

# Reads AuthBasicUsersFile and returns a dictionary of username -> StoredHash.
# Lines beginning with # are comments. Blank lines are ignored. Bad lines are
# logged via Write-DashLog (when available) and skipped.
function Read-DashboardUsersFile {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string,string]])]
    param([Parameter(Mandatory)] [string]$Path)
    $users = [System.Collections.Generic.Dictionary[string,string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    if (-not (Test-Path -LiteralPath $Path)) { return $users }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        # username:salt:iterations:hash → 4 colon-separated fields total
        $idx = $t.IndexOf(':')
        if ($idx -lt 1) { continue }
        $user = $t.Substring(0, $idx).Trim()
        $rest = $t.Substring($idx + 1).Trim()
        if (-not $user -or -not $rest) { continue }
        $users[$user] = $rest
    }
    return $users
}

# Appends a new user to the users file (creates the file if missing). Caller is
# responsible for prompting for the password. Returns the path written.
function Add-DashboardBasicUser {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Username,
        [Parameter(Mandatory)] [securestring]$Password
    )
    if ($Username -notmatch '^[A-Za-z0-9._-]+$') {
        throw "Username '$Username' contains characters that would corrupt the users file. Allowed: letters, digits, dot, underscore, hyphen."
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        @(
            '# Manage-DefenderOffline Dashboard – Basic-auth users'
            '# One user per line: username:salt-b64:iterations:hash-b64'
            '# Generated and appended to by Start-DefenderDashboard.ps1 -AddBasicUser.'
        ) | Out-File -LiteralPath $Path -Encoding UTF8 -Force
    }
    # Reject duplicate usernames so callers do not silently shadow a previous
    # entry. -RemoveBasicUser is the documented way to replace one.
    $existing = Read-DashboardUsersFile -Path $Path
    if ($existing.ContainsKey($Username)) {
        throw "User '$Username' already exists in $Path. Remove the existing line first."
    }
    $hash = New-DashboardPasswordHash -Password $Password
    $line = '{0}:{1}' -f $Username, $hash
    Add-Content -LiteralPath $Path -Value $line -Encoding UTF8

    # Best-effort ACL tightening to the current identity (matches dashboard.token
    # treatment). Silent fallback if Set-Acl fails — e.g. running on a drive
    # where the user lacks SeSecurityPrivilege, or under a sandbox.
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        @($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
        $identity = "$env:USERDOMAIN\$env:USERNAME"
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    } catch {}

    return $Path
}

# ===================================================================
# ADIntegrated group-membership helpers
#
# Resolve-DashboardAllowedGroups: parses the comma-separated AuthAllowedGroups
# string (entries prefixed '!' are denies; deny wins) and translates each
# entry to a SecurityIdentifier so per-request membership checks avoid AD
# round-trips. Entries that can't be resolved are returned in .Unresolved
# so the caller can WARN and continue.
#
# Test-IdentityInAllowedGroups: pure SID-based membership decision. Deny
# entries checked first; empty allow-list = any authenticated user.
# ===================================================================

function Resolve-DashboardAllowedGroups {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyString()] [string]$AllowList)

    $allow       = New-Object 'System.Collections.Generic.List[System.Security.Principal.SecurityIdentifier]'
    $deny        = New-Object 'System.Collections.Generic.List[System.Security.Principal.SecurityIdentifier]'
    $unresolved  = New-Object 'System.Collections.Generic.List[string]'
    $resolutions = New-Object 'System.Collections.Generic.List[pscustomobject]'

    if ($AllowList) {
        foreach ($entry in ($AllowList -split ',')) {
            $e = $entry.Trim()
            if (-not $e) { continue }
            $isDeny = $e.StartsWith('!')
            $name = if ($isDeny) { $e.Substring(1).Trim() } else { $e }
            if (-not $name) { continue }

            $sidObj     = $null
            $accountStr = $null
            $errorMsg   = $null
            try {
                $sidObj = ([System.Security.Principal.NTAccount]::new($name)).Translate(
                    [System.Security.Principal.SecurityIdentifier])
                # Reverse-translate so we can log the canonical DOMAIN\Group form.
                # This is what makes 'Helpdesk' vs 'WGSDAC\Helpdesk' debuggable —
                # operators can see whether their unqualified entry resolved to
                # the domain they expected.
                try {
                    $accountStr = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $accountStr = $name
                }
                if ($isDeny) { [void]$deny.Add($sidObj) } else { [void]$allow.Add($sidObj) }
            } catch {
                [void]$unresolved.Add($e)
                $errorMsg = $_.Exception.Message
            }

            [void]$resolutions.Add([pscustomobject]@{
                Input   = $name
                IsDeny  = $isDeny
                Status  = if ($sidObj) { 'ok' } else { 'unresolved' }
                Account = $accountStr
                Sid     = if ($sidObj) { $sidObj.Value } else { $null }
                Error   = $errorMsg
            })
        }
    }
    return [pscustomobject]@{
        AllowSids   = $allow.ToArray()
        DenySids    = $deny.ToArray()
        Unresolved  = $unresolved.ToArray()
        Resolutions = $resolutions.ToArray()
    }
}

function Test-IdentityInAllowedGroups {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$UserSid,

        # User's group SIDs (typically WindowsIdentity.Groups). Allowed empty
        # because the user themselves may match an allow/deny entry directly.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Security.Principal.SecurityIdentifier[]]$GroupSids,

        # Output of Resolve-DashboardAllowedGroups: { AllowSids, DenySids, Unresolved }.
        [Parameter(Mandatory)]
        [pscustomobject]$AllowedGroups
    )
    # The user matches if their own SID matches OR any of their group SIDs match.
    $userAndGroups = @($UserSid) + $GroupSids

    foreach ($denySid in $AllowedGroups.DenySids) {
        if ($userAndGroups -contains $denySid) {
            return [pscustomobject]@{
                Authorized = $false; Reason = 'group-denied'
                MatchedSid = $denySid
            }
        }
    }

    if ($AllowedGroups.AllowSids.Count -eq 0) {
        return [pscustomobject]@{
            Authorized = $true; Reason = 'no-allow-list'
            MatchedSid = $null
        }
    }

    foreach ($allowSid in $AllowedGroups.AllowSids) {
        if ($userAndGroups -contains $allowSid) {
            return [pscustomobject]@{
                Authorized = $true; Reason = 'group-allowed'
                MatchedSid = $allowSid
            }
        }
    }

    return [pscustomobject]@{
        Authorized = $false; Reason = 'not-in-allow-list'
        MatchedSid = $null
    }
}

function Test-DashboardAuth {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Untyped so Pester can pass a PSObject duck-type stub. At runtime
        # the production caller always passes a [System.Net.HttpListenerContext].
        # We access .Request.Url.LocalPath, .Request.Headers, .Request.QueryString,
        # and (for ADIntegrated) .User.Identity — all of which work on either a
        # real context or a stub with the same shape.
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [ValidateSet('None', 'ADIntegrated', 'Basic', 'Token')]
        [string]$Method,

        # Mode-specific inputs. Each is only meaningful for its own Method.
        [string]$Token,
        # Resolved allow/deny SID object from Resolve-DashboardAllowedGroups.
        # Optional so Basic/Token/None callers can omit it.
        [pscustomobject]$AllowedGroupSids,
        [string]$UsersFile
    )

    # /health is always anonymous so external monitoring works in every mode.
    # Favicon paths are anonymous so the browser can fetch the tab icon
    # without triggering a credential prompt or polluting the audit log.
    $p = $Context.Request.Url.LocalPath
    if ($p -in '/health', '/favicon.ico', '/favicon.svg') {
        return [pscustomobject]@{
            Authorized = $true; StatusCode = 200
            User = 'anonymous'; Reason = 'health-bypass'
        }
    }

    switch ($Method) {
        'None' {
            return [pscustomobject]@{
                Authorized = $true; StatusCode = 200
                User = 'anonymous'; Reason = 'auth-disabled'
            }
        }

        'Token' {
            # Accept token in Authorization: Bearer <token> header OR ?token= query string.
            # Header is checked first (more secure: not logged in URL).
            $provided = $null
            $authHeader = $Context.Request.Headers['Authorization']
            if ($authHeader -and $authHeader -match '^Bearer\s+(.+)$') {
                $provided = $matches[1]
            } elseif ($Context.Request.QueryString['token']) {
                $provided = $Context.Request.QueryString['token']
            }

            if (-not $provided) {
                return [pscustomobject]@{
                    Authorized = $false; StatusCode = 401
                    User = 'anonymous'; Reason = 'no-token'
                }
            }
            if (Test-ConstantTimeEqual -A $provided -B $Token) {
                return [pscustomobject]@{
                    Authorized = $true; StatusCode = 200
                    User = 'token-bearer'; Reason = 'token-matched'
                }
            }
            return [pscustomobject]@{
                Authorized = $false; StatusCode = 403
                User = 'anonymous'; Reason = 'token-mismatch'
            }
        }

        'Basic' {
            # HTTP Basic: Authorization: Basic base64(username:password). The
            # HttpListener stays in Anonymous mode and we parse the header
            # ourselves so /health stays anonymous and the response loop can
            # emit a 401 with WWW-Authenticate: Basic realm=... on first hit.
            $authHeader = $Context.Request.Headers['Authorization']
            if (-not $authHeader -or $authHeader -notmatch '^Basic\s+(.+)$') {
                return [pscustomobject]@{
                    Authorized = $false; StatusCode = 401
                    User = 'anonymous'; Reason = 'no-credentials'
                }
            }
            $decoded = $null
            try {
                $decoded = [System.Text.Encoding]::UTF8.GetString(
                    [Convert]::FromBase64String($matches[1]))
            } catch {
                return [pscustomobject]@{
                    Authorized = $false; StatusCode = 401
                    User = 'anonymous'; Reason = 'malformed-credentials'
                }
            }
            $colon = $decoded.IndexOf(':')
            if ($colon -lt 1) {
                return [pscustomobject]@{
                    Authorized = $false; StatusCode = 401
                    User = 'anonymous'; Reason = 'malformed-credentials'
                }
            }
            $providedUser = $decoded.Substring(0, $colon)
            $providedPwd  = $decoded.Substring($colon + 1)

            if (-not $UsersFile -or -not (Test-Path -LiteralPath $UsersFile)) {
                return [pscustomobject]@{
                    Authorized = $false; StatusCode = 500
                    User = $providedUser; Reason = 'users-file-missing'
                }
            }
            $users = Read-DashboardUsersFile -Path $UsersFile
            if (-not $users.ContainsKey($providedUser)) {
                return [pscustomobject]@{
                    Authorized = $false; StatusCode = 401
                    User = $providedUser; Reason = 'unknown-user'
                }
            }
            if (Test-DashboardPasswordHash -Password $providedPwd -StoredHash $users[$providedUser]) {
                return [pscustomobject]@{
                    Authorized = $true; StatusCode = 200
                    User = $providedUser; Reason = 'password-matched'
                }
            }
            return [pscustomobject]@{
                Authorized = $false; StatusCode = 401
                User = $providedUser; Reason = 'password-mismatch'
            }
        }

        'ADIntegrated' {
            # The HttpListener's AuthenticationSchemeSelectorDelegate handled
            # the Negotiate handshake; by the time we see the context the user
            # is either authenticated (context.User populated) or already 401'd
            # by the listener (we never receive that context). The explicit
            # null check below is defense-in-depth.
            if (-not $Context.User -or -not $Context.User.Identity -or
                -not $Context.User.Identity.IsAuthenticated) {
                return [pscustomobject]@{
                    Authorized = $false; StatusCode = 401
                    User = 'anonymous'; Reason = 'no-windows-identity'
                }
            }
            $userName = $Context.User.Identity.Name
            $userSid  = $Context.User.Identity.User
            $groupSids = @()
            if ($Context.User.Identity.Groups) {
                $groupSids = @($Context.User.Identity.Groups)
            }
            if (-not $AllowedGroupSids) {
                # Empty config = any authenticated user
                $AllowedGroupSids = [pscustomobject]@{
                    AllowSids  = @()
                    DenySids   = @()
                    Unresolved = @()
                }
            }
            $decision = Test-IdentityInAllowedGroups `
                -UserSid       $userSid `
                -GroupSids     $groupSids `
                -AllowedGroups $AllowedGroupSids
            if ($decision.Authorized) {
                return [pscustomobject]@{
                    Authorized = $true; StatusCode = 200
                    User = $userName; Reason = $decision.Reason
                }
            }
            return [pscustomobject]@{
                Authorized = $false; StatusCode = 403
                User = $userName; Reason = $decision.Reason
            }
        }
    }
}

# ===================================================================
# -AddBasicUser helper mode  (exits after completion)
#
# Appends a new entry to AuthBasicUsersFile. The file path comes from CLI
# parameter or conf/config.conf; we default to conf\dashboard.users when
# neither is set. The password is read as a SecureString so it never sits
# in the host's command history or process arg list.
# ===================================================================
if ($AddBasicUser) {
    Write-Host "`n=== Add Basic Auth User ===" -ForegroundColor Cyan
    Write-Host ''
    $usersPath = $AuthBasicUsersFile
    if (-not $usersPath) { $usersPath = Join-Path $ScriptDir 'conf\dashboard.users' }
    Write-Host "  Users file: $usersPath"
    Write-Host "  Username  : $AddBasicUser"
    try {
        $pwd1 = Read-Host -AsSecureString -Prompt '  Enter password'
        $pwd2 = Read-Host -AsSecureString -Prompt '  Confirm password'
        $b1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1)
        $b2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2)
        try {
            $p1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
            $p2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
            if ($p1 -ne $p2) { Write-Host '  ERROR: passwords do not match.' -ForegroundColor Red; exit 1 }
            if (-not $p1)    { Write-Host '  ERROR: password cannot be empty.' -ForegroundColor Red; exit 1 }
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
        }
        $written = Add-DashboardBasicUser -Path $usersPath -Username $AddBasicUser -Password $pwd1
        Write-Host "  Saved: $written" -ForegroundColor Green
        Write-Host "  Hint : ensure conf/config.conf sets AuthMethod = Basic and AuthBasicUsersFile = $written" -ForegroundColor DarkGray
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    exit 0
}

# ===================================================================
# Logging  (file-only; no console assumed when running as a task)
# ===================================================================
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogPath "DefenderDashboard_$(Get-Date -Format 'yyyyMMdd').log"

function Write-DashLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    # Mirror to console for interactive/debug runs
    $color = switch ($Level) {
        'INFO'    { 'Cyan'    }
        'WARN'    { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
    }
    Write-Host $line -ForegroundColor $color
}

# ===================================================================
# Startup Profiling  (v0.0.14)
#
# Lightweight phase timer for the dashboard's cold start path. Each
# call to Write-StartupPhase emits a structured key=value INFO line
# with the duration of the phase that just finished and the total
# elapsed time since Start-StartupTimer ran. The output is parseable
# by the same SIEM ingest that consumes event=auth_resolve and
# event=request_error, so phase profiles can be queried alongside
# the existing audit stream.
#
# Phases instrumented (see main-flow block at the bottom of the
# script): banner, auth_preflight, https_cert_resolve, target_computers,
# available_version, port_and_https_binding, primary_listener,
# redirect_listener, status_file, event_log, initial_fleet_refresh.
# A final event=startup_complete line carries the grand total.
# ===================================================================
$script:StartupSw         = $null
$script:LastPhaseMs       = 0
$script:StartupPhaseCount = 0

function Start-StartupTimer {
    $script:StartupSw         = [System.Diagnostics.Stopwatch]::StartNew()
    $script:LastPhaseMs       = 0
    $script:StartupPhaseCount = 0
}

function Write-StartupPhase {
    param([Parameter(Mandatory)][string]$Phase)
    if (-not $script:StartupSw) { return }
    $totalMs = [int]$script:StartupSw.Elapsed.TotalMilliseconds
    $deltaMs = $totalMs - $script:LastPhaseMs
    $script:LastPhaseMs = $totalMs
    $script:StartupPhaseCount++
    Write-DashLog ("event=startup_phase phase={0} duration_ms={1} elapsed_ms={2}" -f $Phase, $deltaMs, $totalMs) 'INFO'
}

function Write-StartupComplete {
    if (-not $script:StartupSw) { return }
    $totalMs = [int]$script:StartupSw.Elapsed.TotalMilliseconds
    Write-DashLog ("event=startup_complete total_ms={0} phase_count={1}" -f $totalMs, $script:StartupPhaseCount) 'SUCCESS'
}

# ===================================================================
# Target Resolution
# ===================================================================
function Resolve-TargetComputers {
    if ($ComputerName) {
        return $ComputerName | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim().ToUpper() }
    }
    # hosts.conf is skipped when -ADSearchBase is set so a cached snapshot
    # from a previous (possibly differently-scoped) run does not override the
    # operator's explicit AD scope.
    $hostsExists = Test-Path $HostsFile
    if (-not $ADSearchBase -and $hostsExists) {
        return Get-Content $HostsFile |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
            ForEach-Object { $_.Trim().ToUpper() }
    }
    if ($ADSearchBase -and $hostsExists) {
        Write-DashLog 'Ignoring hosts.conf because ADSearchBase is set; querying AD with that scope.' 'INFO'
    }
    if (-not $hostsExists) {
        Write-DashLog 'hosts.conf not found – attempting Active Directory auto-discovery...' 'WARN'
    }
    if ($ADCredential) {
        Write-DashLog "Using saved AD credential for LDAP bind: $($ADCredential.UserName)" 'INFO'
    }
    if ($ADSearchBase) {
        Write-DashLog "Restricting AD discovery to: $ADSearchBase" 'INFO'
    }
    try {
        $discovery = Get-DefenderComputers -SearchBase $ADSearchBase -ADCredential $ADCredential
        if (-not $discovery.UsedAdModule) {
            Write-DashLog 'ActiveDirectory PowerShell module is not installed; used ADSI fallback.' 'INFO'
        }
        if ($discovery.WasFiltered) {
            foreach ($s in $discovery.SearchBases) {
                if ($s.Resolved) {
                    Write-DashLog "  AD search base '$($s.DN)' -> $($s.Count) computer(s)" 'INFO'
                } else {
                    Write-DashLog "  AD search base '$($s.DN)' could not be resolved: $($s.Error)" 'WARN'
                }
            }
            $resolved = @($discovery.SearchBases | Where-Object Resolved).Count
            $total    = $discovery.SearchBases.Count
            if ($resolved -eq 0) {
                throw "All $total AD search base(s) failed to resolve. Check ADSearchBase syntax / AD reachability."
            }
            if ($resolved -lt $total) {
                Write-DashLog "Partial AD search-base resolution: $resolved of $total succeeded. Continuing with the resolved subset." 'WARN'
            }
        }
        if (-not $discovery.Computers -or $discovery.Computers.Count -eq 0) {
            throw 'AD discovery returned no computers.'
        }
        return $discovery.Computers
    } catch {
        $adErr = $_.Exception.Message
        Write-DashLog "AD auto-discovery failed: $adErr" 'ERROR'
        Write-DashLog 'Remediation options for the service identity:' 'ERROR'
        Write-DashLog '  - Save an AD credential once via:  .\Start-DefenderDashboard.ps1 -SaveADCredential' 'ERROR'
        Write-DashLog "  - Or provide a hosts.conf at:  $HostsFile" 'ERROR'
        Write-DashLog '  - Or grant the dashboard service identity AD read on the domain naming context.' 'ERROR'
        # exit (not throw): the WARN/ERROR lines above are the operator-facing
        # diagnostic; throw would dump the exception text on top of that.
        Write-DashLog "Cannot resolve target list: $adErr" 'ERROR'
        exit 1
    }
}

# ===================================================================
# Latest Available Version
# ===================================================================
function Get-LatestAvailableVersion {
    param([string]$Root)
    # Returns $null for any failure. Caller-side "no path configured"
    # is silent — the caller checks $SourceSharePath separately so the
    # message can include the parameter name. All other failures log
    # with the distinguishing reason here so the operator doesn't have
    # to guess between "path doesn't exist", "permission denied",
    # "share unreachable", and "share OK but layout doesn't match".
    if (-not $Root) { return $null }

    try {
        if (-not (Test-Path -LiteralPath $Root -ErrorAction Stop)) {
            Write-DashLog "Available version: SourceSharePath '$Root' is not reachable (path does not exist or service account lacks read access). Version currency check disabled." 'WARN'
            return $null
        }
    } catch {
        Write-DashLog "Available version: error accessing SourceSharePath '$Root' - $($_.Exception.Message). Version currency check disabled." 'ERROR'
        return $null
    }

    # Supports two layouts (v0.0.8 introduced the per-arch subfolder layout):
    #   Flat (legacy)   : <version>\mpam-fe.exe                  -> parent matches ^v\d+...
    #   Per-arch (new)  : <version>\<arch>\mpam-fe.exe           -> parent is x64/x86/arm64; grandparent is ^v\d+...
    try {
        $versions = Get-ChildItem -LiteralPath $Root -Recurse -Filter 'mpam-fe.exe' -ErrorAction Stop |
            Where-Object { $_.FullName -notmatch '(?i)[/\\]_?archive[/\\]' } |
            ForEach-Object {
                $parent      = $_.Directory.Name
                $grandparent = if ($_.Directory.Parent) { $_.Directory.Parent.Name } else { '' }
                if ($parent -match '^(?i)(x64|x86|arm64)$' -and $grandparent -match '^v(\d+\.\d+\.\d+\.\d+)$') {
                    [version]$Matches[1]
                } elseif ($parent -match '^v(\d+\.\d+\.\d+\.\d+)$') {
                    [version]$Matches[1]
                }
            }
    } catch {
        Write-DashLog "Available version: error enumerating SourceSharePath '$Root' - $($_.Exception.Message). Version currency check disabled." 'ERROR'
        return $null
    }

    $latest = $versions | Sort-Object -Descending | Select-Object -First 1
    if (-not $latest) {
        Write-DashLog "Available version: SourceSharePath '$Root' contains no 'mpam-fe.exe' matching the expected '<YYYYMMDD>\v#.#.#.#\[arch\]\mpam-fe.exe' structure. Version currency check disabled." 'WARN'
    }
    return $latest
}

# ===================================================================
# Per-Host Defender Query
# (defined at script scope so it can be captured for thread jobs)
# ===================================================================
function Get-DefenderStatus {
    param(
        [string]$Computer,
        [int]$TimeoutSeconds,
        [string]$AvailableVersionStr,
        [System.Management.Automation.PSCredential]$WinRmCredential,
        [bool]$DisableIPv6 = $true
    )

    $result = [pscustomobject]@{
        ComputerName              = $Computer
        IPv4Address               = ''
        Online                    = $false
        DefenderService           = 'Unknown'
        SignatureVersion          = ''
        AvailableVersion          = $AvailableVersionStr
        VersionStatus             = 'Unknown'
        RealTimeProtection        = 'Unknown'
        AntivirusEnabled          = 'Unknown'
        # Full toggle set surfaced in the /defender drill-down modal (v0.0.10).
        AmServiceEnabled          = 'Unknown'
        BehaviorMonitorEnabled    = 'Unknown'
        IoavProtectionEnabled     = 'Unknown'
        OnAccessProtectionEnabled = 'Unknown'
        LastQuickScan             = ''
        LastFullScan              = ''
        ThreatCount               = ''
        ThreatList                = @()
        HealthStatus              = ''
        HealthReason              = ''
        QueryDuration             = 0
        Error                     = ''
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Resolve IPv4 once, up front, regardless of reachability strategy —
        # the address surfaces in the dashboard row whether the host is
        # online, offline, or DNS-known-but-unreachable. The DisableIPv6
        # reachability path reuses this lookup to avoid a duplicate DNS hit.
        $ipv4 = $null
        try {
            $ipv4 = [System.Net.Dns]::GetHostAddresses($Computer) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                Select-Object -First 1
            if ($ipv4) { $result.IPv4Address = $ipv4.IPAddressToString }
        } catch {}

        # Reachability check.  When DisableIPv6 is set (LAN default), connect
        # directly to the IPv4 we already resolved — avoids the ~21s TCP
        # timeout that Test-NetConnection eats on IPv6 ULA addresses
        # advertised in DNS but not actually routed.
        $reachable = $false
        if ($DisableIPv6) {
            if ($ipv4) {
                try {
                    $client = [System.Net.Sockets.TcpClient]::new()
                    $task   = $client.ConnectAsync($ipv4, 5985)
                    $reachable = $task.Wait(3000) -and -not $task.IsFaulted -and $client.Connected
                    try { $client.Close() } catch {}
                } catch { $reachable = $false }
            }
        } else {
            $reachable = [bool](Test-NetConnection -ComputerName $Computer -Port 5985 `
                -InformationLevel Quiet -WarningAction SilentlyContinue)
        }
        if (-not $reachable) {
            $result.Error = 'WinRM not reachable'
            return $result
        }

        $sessionParams = @{ ComputerName = $Computer }
        if ($WinRmCredential) { $sessionParams.Credential = $WinRmCredential }
        $session = New-DefenderRemoteSession @sessionParams
        try {
            $data = Invoke-DefenderRemote -Session $session -ScriptBlock {
                $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                $mp  = $null
                try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
                # Per-threat detail for the row-click modal. Get-MpThreat is
                # the *catalog* of threat types ever seen — it doesn't reliably
                # populate InitialDetectionTime / Resources for long-quarantined
                # PUA items. Get-MpThreatDetection has the per-event timestamps
                # and resource paths, so we cross-reference both: ThreatID -> Name
                # from the catalog, plus the most recent detection event's time
                # and resources from MpThreatDetection. One row per distinct
                # ThreatID so ThreatCount matches the rendered grid.
                $threats = @()
                if ($mp) {
                    $catalog = @{}
                    foreach ($t in (Get-MpThreat -ErrorAction SilentlyContinue)) {
                        $catalog[[int64]$t.ThreatID] = [string]$t.ThreatName
                    }
                    $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
                    $threats = @($detections | Group-Object ThreatID | ForEach-Object {
                        $latest = $_.Group | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
                        $id     = [int64]$_.Name
                        [pscustomobject]@{
                            ThreatName           = if ($catalog.ContainsKey($id)) { $catalog[$id] } else { "ThreatID $id" }
                            ThreatID             = $id
                            InitialDetectionTime = $latest.InitialDetectionTime
                            Resources            = if ($latest.Resources) { [string]($latest.Resources -join '; ') } else { '' }
                        }
                    } | Sort-Object InitialDetectionTime -Descending)
                }
                [pscustomobject]@{
                    # Stringify the ServiceController.Status enum so the JSON
                    # path renders 'Running' rather than '[object Object]'.
                    SvcStatus            = if ($svc) { [string]$svc.Status } else { 'NotFound' }
                    SignatureVersion     = if ($mp) { $mp.AntivirusSignatureVersion }  else { $null }
                    RealTimeProtection   = if ($mp) { $mp.RealTimeProtectionEnabled } else { $null }
                    AMServiceEnabled     = if ($mp) { $mp.AMServiceEnabled }           else { $null }
                    AntivirusEnabled     = if ($mp) { $mp.AntivirusEnabled }          else { $null }
                    BehaviorMonitor      = if ($mp) { $mp.BehaviorMonitorEnabled }     else { $null }
                    IoavProtection       = if ($mp) { $mp.IoavProtectionEnabled }      else { $null }
                    OnAccessProtection   = if ($mp) { $mp.OnAccessProtectionEnabled }  else { $null }
                    LastQuickScan        = if ($mp) { $mp.QuickScanStartTime }        else { $null }
                    LastFullScan         = if ($mp) { $mp.FullScanStartTime }         else { $null }
                    ThreatCount          = $threats.Count
                    ThreatList           = $threats
                }
            }

            $result.Online                    = $true
            $result.DefenderService           = $data.SvcStatus
            $result.SignatureVersion          = $data.SignatureVersion
            $result.RealTimeProtection        = if ($null -ne $data.RealTimeProtection) { $data.RealTimeProtection.ToString() } else { 'Unknown' }
            $result.AntivirusEnabled          = if ($null -ne $data.AntivirusEnabled)   { $data.AntivirusEnabled.ToString() }   else { 'Unknown' }
            $result.AmServiceEnabled          = if ($null -ne $data.AMServiceEnabled)   { $data.AMServiceEnabled.ToString() }   else { 'Unknown' }
            $result.BehaviorMonitorEnabled    = if ($null -ne $data.BehaviorMonitor)    { $data.BehaviorMonitor.ToString() }    else { 'Unknown' }
            $result.IoavProtectionEnabled     = if ($null -ne $data.IoavProtection)     { $data.IoavProtection.ToString() }     else { 'Unknown' }
            $result.OnAccessProtectionEnabled = if ($null -ne $data.OnAccessProtection) { $data.OnAccessProtection.ToString() } else { 'Unknown' }
            $result.LastQuickScan             = if ($data.LastQuickScan) { $data.LastQuickScan.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
            $result.LastFullScan              = if ($data.LastFullScan)  { $data.LastFullScan.ToString('yyyy-MM-dd HH:mm') }  else { 'Never' }
            $result.ThreatCount               = if ($null -ne $data.ThreatCount) { $data.ThreatCount.ToString() } else { 'Unknown' }
            $result.ThreatList                = @($data.ThreatList)

            # Health classification — see lib/Get-DefenderHealthProbe.ps1.
            if ($null -ne $data.RealTimeProtection -and
                $null -ne $data.AMServiceEnabled  -and
                $null -ne $data.AntivirusEnabled  -and
                $null -ne $data.BehaviorMonitor   -and
                $null -ne $data.IoavProtection    -and
                $null -ne $data.OnAccessProtection) {
                $cls = Get-DefenderHealthClassification `
                    -RealTimeProtectionEnabled  ([bool]$data.RealTimeProtection) `
                    -AntimalwareServiceEnabled  ([bool]$data.AMServiceEnabled)   `
                    -AntivirusEnabled           ([bool]$data.AntivirusEnabled)   `
                    -BehaviorMonitorEnabled     ([bool]$data.BehaviorMonitor)    `
                    -IoavProtectionEnabled      ([bool]$data.IoavProtection)     `
                    -OnAccessProtectionEnabled  ([bool]$data.OnAccessProtection) `
                    -RecentThreatCount          ([int]($data.ThreatCount ?? 0))
                $result.HealthStatus = $cls.OverallStatus
                $result.HealthReason = if ($cls.StatusReason) { $cls.StatusReason } else { '' }
            }

            if ($result.SignatureVersion -and $AvailableVersionStr) {
                try {
                    # Three-way compare so hosts that received defs from
                    # another channel (cloud, manual, lingering MECM) — or
                    # a stale share — surface as 'Ahead' instead of being
                    # silently bucketed with 'Current'. Ahead is informational,
                    # not an error; the detail string is written to .Error so
                    # it shows in the GUI's Error/Detail column, the dashboard
                    # hostname tooltip, and the Host Details modal.
                    $cmp = ([version]$result.SignatureVersion).CompareTo([version]$AvailableVersionStr)
                    if     ($cmp -lt 0) { $result.VersionStatus = 'Outdated' }
                    elseif ($cmp -gt 0) {
                        $result.VersionStatus = 'Ahead'
                        $result.Error         = "Newer than share (available: v$AvailableVersionStr)"
                    }
                    else { $result.VersionStatus = 'Current' }
                } catch { $result.VersionStatus = 'Unknown' }
            } elseif ($result.SignatureVersion) {
                $result.VersionStatus = 'Unknown'
            }

        } finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
    } catch {
        $result.Error = ($_.Exception.Message -replace "`r`n", ' ').Trim()
    } finally {
        $sw.Stop()
        $result.QueryDuration = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
    return $result
}

# ===================================================================
# Parallel Refresh
# Returns a List of results; runs in background via Start-ThreadJob
# ===================================================================
function Invoke-FleetRefresh {
    param(
        [string[]]$Computers,
        [string]$AvailableVersionStr,
        [int]$Threads,
        [int]$TSeconds,
        [string]$FunctionDef,    # Get-DefenderStatus serialised as a string
        [System.Management.Automation.PSCredential]$WinRmCredential,
        [bool]$DisableIPv6 = $true,
        [string[]]$LibPaths      # Paths to lib/*.ps1 helpers — passed through
                                 # to child runspaces so wrapper functions and
                                 # the shared health classifier are available.
    )

    # Dot-source the wrappers in this runspace (Invoke-FleetRefresh runs inside
    # a Start-ThreadJob from Start-BackgroundRefresh, so the parent's lib
    # dot-source isn't visible here).
    foreach ($lib in $LibPaths) { if ($lib) { . $lib } }
    ${function:Get-DefenderStatus} = [scriptblock]::Create($FunctionDef)

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $Computers | ForEach-Object -Parallel {
            $comp = [string]$_
            # Each parallel runspace is also isolated; re-import the wrappers.
            foreach ($lib in $using:LibPaths) { if ($lib) { . $lib } }
            ${function:Get-DefenderStatus} = [scriptblock]::Create($using:FunctionDef)
            $cred = $using:WinRmCredential
            Get-DefenderStatus -Computer $comp `
                -TimeoutSeconds      $using:TSeconds `
                -AvailableVersionStr $using:AvailableVersionStr `
                -WinRmCredential     $cred `
                -DisableIPv6         $using:DisableIPv6
        } -ThrottleLimit $Threads | ForEach-Object { if ($_) { $results.Add($_) } }
    } else {
        foreach ($comp in $Computers) {
            $results.Add((Get-DefenderStatus -Computer $comp -TimeoutSeconds $TSeconds -AvailableVersionStr $AvailableVersionStr -WinRmCredential $WinRmCredential -DisableIPv6 $DisableIPv6))
        }
    }

    return $results
}

# ===================================================================
# HTML Page Builder
# ===================================================================
function Build-DashboardHtml {
    param(
        [object[]]$Data,
        [string]$AvailableVersionStr,
        [datetime]$AsOf,
        [bool]$IsRefreshing,
        [ValidateSet('Dark','Light')]
        [string]$Theme = 'Dark'
    )

    $themeAttr = if ($Theme -eq 'Light') { 'light' } else { 'dark' }

    $onlineCount  = @($Data | Where-Object Online).Count
    $offlineCount = $Data.Count - $onlineCount
    $outdated     = @($Data | Where-Object VersionStatus -eq 'Outdated').Count
    $rtOff        = @($Data | Where-Object { $_.RealTimeProtection -eq 'False' -and $_.Online }).Count

    # When the async initial collection has not completed yet, $AsOf is
    # DateTime.MinValue (year 0001). Subtracting that from "now" yields
    # ~-64 billion seconds, which overflows Int32 on the cast below and
    # throws a RuntimeException before any HTML is built. Treat the
    # empty-cache window as "next refresh due immediately" so the meta
    # refresh fires in 5s and re-fetches once the background work is in.
    if ($AsOf -eq [datetime]::MinValue) {
        $secsUntil = 0
    } else {
        $nextRefresh = $AsOf.AddSeconds($RefreshInterval)
        $secsUntil   = [math]::Max(0, [int]($nextRefresh - (Get-Date)).TotalSeconds)
    }
    # Meta-refresh fires this many seconds after page load.  Align it
    # with $secsUntil + 5 so the browser reloads ~5s after the countdown
    # reaches 0 — instead of the previous hardcoded $RefreshInterval
    # which could be wildly out of sync (page sat at 'Next refresh: 0s'
    # for up to 5 minutes before actually reloading).
    #
    # When a refresh is in-flight (Force Refresh, or auto-refresh that
    # kicked off a new collection), tighten the cadence to 5s so the
    # banner clears promptly once the job finishes. Without this, Force
    # Refresh clicked mid-cycle would leave the banner up for nearly the
    # full RefreshInterval (since secsUntil is computed from CachedAt,
    # which doesn't move until the refresh completes).
    $metaRefreshSecs = if ($IsRefreshing) {
        5
    } else {
        [math]::Max(5, $secsUntil + 5)
    }

    $rows = foreach ($r in $Data | Sort-Object ComputerName) {
        # Same priority order as Show-DefenderStatus:
        #   Offline   -> no comms
        #   Outdated  -> reachable but signature is behind
        #   else      -> defer to shared health classifier; fall back to legacy
        $status = if (-not $r.Online) { 'Offline' }
                  elseif ($r.VersionStatus -eq 'Outdated') { 'Outdated' }
                  elseif ($r.HealthStatus) { $r.HealthStatus }
                  elseif ($r.RealTimeProtection -eq 'False' -or $r.AntivirusEnabled -eq 'False') { 'Degraded' }
                  else { 'Healthy' }
        $badge  = switch ($status) {
            'Offline'         { '<span class="badge b-off">Offline</span>' }
            'Outdated'        { '<span class="badge b-out">Outdated</span>' }
            'Degraded'        { '<span class="badge b-deg">Degraded</span>' }
            'ThreatsDetected' { '<span class="badge b-thr">ThreatsDetected</span>' }
            default           { '<span class="badge b-ok">Healthy</span>' }
        }
        $tip = if ($r.Error) {
            " title=`"$($r.Error -replace '"','&quot;' -replace '<','&lt;' -replace '>','&gt;')`""
        } else { '' }

        # Data attributes drive client-side card-click filtering
        $isOnline   = if ($r.Online) { 'true' } else { 'false' }
        $isOutdated = if ($r.VersionStatus -eq 'Outdated') { 'true' } else { 'false' }
        $isRtOff    = if ($r.RealTimeProtection -eq 'False' -and $r.Online) { 'true' } else { 'false' }

        # data-host is the key the row-click handler uses to look up the
        # per-host record in the embedded JSON blob and populate the modal.
        "<tr class=`"hostrow`" data-host=`"$($r.ComputerName)`" data-online=`"$isOnline`" data-outdated=`"$isOutdated`" data-rtoff=`"$isRtOff`">
          <td$tip>$($r.ComputerName)</td>
          <td>$($r.IPv4Address)</td>
          <td>$badge</td>
          <td>$($r.SignatureVersion)</td>
          <td>$($r.VersionStatus)</td>
          <td>$($r.RealTimeProtection)</td>
          <td>$($r.AntivirusEnabled)</td>
          <td>$($r.LastQuickScan)</td>
          <td>$($r.ThreatCount)</td>
          <td>$($r.QueryDuration)s</td>
        </tr>"
    }

    $refreshingBanner = if ($IsRefreshing) {
        '<div class="banner">&#x21BB; Refresh in progress…</div>'
    } else { '' }

    # Embed per-host data as JSON so the row-click modal can populate without
    # an extra request. Compressed + sorted to keep the page payload small.
    # `</` is escaped to `<\/` to prevent a malicious threat name with the
    # literal text "</script>" from prematurely ending the script tag.
    $hostJsonBlob = @($Data | Sort-Object ComputerName | ForEach-Object {
        [ordered]@{
            computerName              = $_.ComputerName
            ipv4Address               = $_.IPv4Address
            online                    = [bool]$_.Online
            defenderService           = $_.DefenderService
            signatureVersion          = $_.SignatureVersion
            availableVersion          = $_.AvailableVersion
            versionStatus             = $_.VersionStatus
            realTimeProtection        = $_.RealTimeProtection
            antivirusEnabled          = $_.AntivirusEnabled
            amServiceEnabled          = $_.AmServiceEnabled
            behaviorMonitorEnabled    = $_.BehaviorMonitorEnabled
            ioavProtectionEnabled     = $_.IoavProtectionEnabled
            onAccessProtectionEnabled = $_.OnAccessProtectionEnabled
            lastQuickScan             = $_.LastQuickScan
            lastFullScan              = $_.LastFullScan
            threatCount               = $_.ThreatCount
            threats                   = @($_.ThreatList | ForEach-Object {
                [ordered]@{
                    name      = $_.ThreatName
                    id        = $_.ThreatID
                    detected  = if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm') } else { '' }
                    resources = $_.Resources
                }
            })
            healthStatus              = $_.HealthStatus
            healthReason              = $_.HealthReason
            queryDurationSec          = $_.QueryDuration
            error                     = $_.Error
        }
    }) | ConvertTo-Json -Compress -Depth 5
    # Make sure it's an array literal even for a single host.
    if ($Data.Count -eq 1) { $hostJsonBlob = '[' + $hostJsonBlob + ']' }
    $hostJsonBlob = $hostJsonBlob -replace '</','<\/'

    @"
<!DOCTYPE html>
<html lang="en" data-theme="$themeAttr">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="$metaRefreshSecs">
  <title>Microsoft Defender Antivirus &#8211; Fleet Status</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="shortcut icon" href="/favicon.ico">
  <script>
    // Early-load: apply per-browser theme preference (if any) BEFORE the
    // stylesheet renders, so we never flash the server-side default and
    // then snap to the user's choice.
    (function() {
      try {
        var t = localStorage.getItem('mdo-dashboard-theme');
        if (t === 'light' || t === 'dark') {
          document.documentElement.setAttribute('data-theme', t);
        }
      } catch(e) {}
    })();
  </script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    /* Dark is the implicit base.  data-theme="light" overrides below. */
    :root {
      --bg-page: #1e1e2e;
      --bg-elev: #313244;
      --bg-input: #45475a;
      --bg-input-hover: #585b70;
      --bg-row-hover: rgba(255,255,255,.04);
      --text-primary: #cdd6f4;
      --text-muted: #a6adc8;
      --text-faint: #6c7086;
      --accent: #cba6f7;
      --link: #89b4fa;
      --border: #45475a;
      --border-strong: #585b70;
      --th-bg: #45475a;
      --th-text: #cba6f7;
      /* Status colours — identical in both themes for visual continuity
         with the Forms GUI and HTML report. */
      --c-online-bg:   #107c10; --c-online-fg:   #ffffff;
      --c-offline-bg:  #4b5563; --c-offline-fg:  #ffffff;
      --c-outdated-bg: #f59e0b; --c-outdated-fg: #1e1e2e;
      --c-rtoff-bg:    #f9e2af; --c-rtoff-fg:    #1e1e2e;
      --c-degraded-bg: #b8860b; --c-degraded-fg: #ffffff;
      --c-threats-bg:  #d13438; --c-threats-fg:  #ffffff;
    }
    [data-theme="light"] {
      --bg-page: #f5f7fa;
      --bg-elev: #ffffff;
      --bg-input: #ffffff;
      --bg-input-hover: #f1f5f9;
      --bg-row-hover: rgba(0,120,212,.04);
      --text-primary: #333333;
      --text-muted: #888888;
      --text-faint: #aaaaaa;
      --accent: #0078d4;
      --link: #0078d4;
      --border: #e8e8e8;
      --border-strong: #d1d5db;
      --th-bg: #0078d4;
      --th-text: #ffffff;
    }

    body { font-family: "Segoe UI", Arial, sans-serif; background: var(--bg-page);
           color: var(--text-primary); min-height: 100vh; }

    .topbar { background: var(--bg-elev); padding: 14px 28px; display: flex;
              align-items: center; justify-content: space-between;
              border-bottom: 3px solid var(--accent); }
    .topbar h1 { font-size: 1.25em; color: var(--accent); font-weight: 700; }
    .topbar .meta { font-size: .82em; color: var(--text-muted); text-align: right;
                    line-height: 1.6; display: flex; align-items: center; gap: 14px; }
    .topbar .meta .meta-text { text-align: right; }
    .topbar .meta a { color: var(--link); text-decoration: none; }
    .topbar .meta a:hover { text-decoration: underline; }

    .theme-toggle { background: transparent; border: 1px solid var(--border-strong);
                    color: var(--text-primary); cursor: pointer; padding: 6px 10px;
                    border-radius: 6px; font-size: 1.1em; line-height: 1; }
    .theme-toggle:hover { background: var(--bg-input-hover); }

    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px;
             padding: 20px 28px 8px; }
    .stat { border-radius: 10px; padding: 14px 18px; cursor: pointer;
            border: 3px solid transparent; transition: filter .12s;
            user-select: none; }
    .stat:hover { filter: brightness(1.06); }
    .stat.active { filter: brightness(.78); box-shadow: inset 0 0 0 3px rgba(0,0,0,.35); }
    .stat .lbl { font-size: .78em; margin-bottom: 6px; text-transform: uppercase;
                 letter-spacing: .05em; font-weight: 700; }
    .stat .val { font-size: 2em; font-weight: 800; line-height: 1; }
    .st-online  { background: var(--c-online-bg);   color: var(--c-online-fg); }
    .st-offline { background: var(--c-offline-bg);  color: var(--c-offline-fg); }
    .st-out     { background: var(--c-outdated-bg); color: var(--c-outdated-fg); }
    .st-rt      { background: var(--c-rtoff-bg);    color: var(--c-rtoff-fg); }

    .legend { display: inline-flex; flex-wrap: wrap; gap: 14px; align-items: center;
              margin-left: 10px; font-size: .78em; color: var(--text-muted); }
    .legend .lgnd-label { font-weight: 600; color: var(--text-primary); }
    .legend .lgnd-chip  { display: inline-flex; align-items: center; gap: 6px; }
    .legend .lgnd-dot   { display: inline-block; width: 10px; height: 10px;
                          border-radius: 50%; border: 1px solid rgba(0,0,0,0.08); }

    .toolbar { padding: 12px 28px; display: flex; align-items: center; gap: 10px; }
    .toolbar input { background: var(--bg-input); border: 1px solid var(--border-strong);
                     color: var(--text-primary); padding: 7px 12px; border-radius: 6px;
                     font-size: .88em; width: 240px; }
    .toolbar input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
    .toolbar a.btn { background: var(--accent); color: #ffffff; padding: 7px 16px;
                     border-radius: 6px; text-decoration: none; font-size: .85em;
                     border: 1px solid var(--accent); font-weight: 600; }
    .toolbar a.btn:hover { filter: brightness(1.08); }
    .toolbar .clear-filter { color: var(--link); font-size: .82em; text-decoration: none;
                             margin-left: auto; display: none; }
    .toolbar .clear-filter.visible { display: inline-block; }
    .toolbar .clear-filter:hover { text-decoration: underline; }

    .banner { background: var(--c-outdated-bg); color: var(--c-outdated-fg);
              text-align: center; padding: 6px; font-size: .85em;
              margin: 0 28px 8px; border-radius: 6px; font-weight: 600; }

    .wrap { padding: 0 28px 32px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; background: var(--bg-elev);
            border-radius: 10px; overflow: hidden; }
    th { background: var(--th-bg); color: var(--th-text); padding: 11px 14px;
         text-align: left; font-size: .82em; font-weight: 700; cursor: pointer;
         user-select: none; white-space: nowrap; }
    th:hover { filter: brightness(.92); }
    td { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: .88em; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: var(--bg-row-hover); }

    .badge { display: inline-block; padding: 3px 12px; border-radius: 12px;
             font-size: .78em; font-weight: 700; }
    .b-ok  { background: var(--c-online-bg);   color: var(--c-online-fg); }
    .b-off { background: var(--c-offline-bg);  color: var(--c-offline-fg); }
    .b-out { background: var(--c-outdated-bg); color: var(--c-outdated-fg); }
    .b-deg { background: var(--c-degraded-bg); color: var(--c-degraded-fg); }
    .b-thr { background: var(--c-threats-bg);  color: var(--c-threats-fg); }
    /* Hostrow click affordance — pointer cursor, hover highlight */
    tr.hostrow { cursor: pointer; }

    /* Host Details modal — vanilla CSS overlay */
    .mdo-modal-backdrop {
      position: fixed; inset: 0; background: rgba(0,0,0,.55);
      display: none; align-items: flex-start; justify-content: center;
      z-index: 1000; padding: 40px 16px; overflow-y: auto;
    }
    .mdo-modal-backdrop.show { display: flex; }
    .mdo-modal {
      background: var(--bg-elev); color: var(--text-primary);
      border-radius: 10px; box-shadow: 0 20px 60px rgba(0,0,0,.5);
      max-width: 800px; width: 100%; padding: 24px 28px;
      border: 1px solid var(--border);
    }
    .mdo-modal h2 {
      margin: 0 0 4px 0; font-size: 1.4em; color: var(--text-primary);
    }
    .mdo-modal .mdo-sub {
      color: var(--text-muted); font-size: .9em; margin-bottom: 18px;
    }
    .mdo-modal h3 {
      margin: 18px 0 8px 0; font-size: .85em; text-transform: uppercase;
      color: var(--accent); letter-spacing: .04em; border-bottom: 1px solid var(--border);
      padding-bottom: 4px;
    }
    .mdo-kv { display: grid; grid-template-columns: 220px 1fr; gap: 4px 12px; font-size: .9em; }
    .mdo-kv .k { color: var(--text-muted); }
    .mdo-kv .v { color: var(--text-primary); word-break: break-word; }
    /* Use the same green/red as the Healthy/ThreatsDetected status badge
       backgrounds so the bool values feel like part of the same palette
       instead of a separate, brighter accent layer. */
    .mdo-kv .v.bool-true  { color: var(--c-online-bg);  font-weight: 600; }
    .mdo-kv .v.bool-false { color: var(--c-threats-bg); font-weight: 600; }
    .mdo-threats {
      width: 100%; margin-top: 8px; border-collapse: collapse;
      background: var(--bg-page); border-radius: 6px; overflow: hidden;
      /* Fixed table layout + explicit column widths so a long Resource
         string can't expand the cell beyond the modal's content area. */
      table-layout: fixed;
    }
    .mdo-threats th, .mdo-threats td {
      padding: 6px 10px; text-align: left; font-size: .85em;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      word-break: break-word;
      overflow-wrap: anywhere;
    }
    .mdo-threats th:nth-child(1), .mdo-threats td:nth-child(1) { width: 28%; }
    .mdo-threats th:nth-child(2), .mdo-threats td:nth-child(2) { width: 16%; white-space: nowrap; }
    .mdo-threats th:nth-child(3), .mdo-threats td:nth-child(3) { width: 56%; }
    /* Cap really-long Resource cells with internal scroll instead of letting
       one threat row balloon the modal vertically. Inner div is required
       because <td> ignores max-height. */
    .mdo-threats .r-wrap {
      max-height: 8em;
      overflow-y: auto;
      word-break: break-word;
      overflow-wrap: anywhere;
    }
    .mdo-threats th { background: var(--th-bg); color: var(--th-text); }
    .mdo-threats tr:last-child td { border-bottom: none; }
    .mdo-modal .mdo-err {
      /* Text uses --text-primary so it's readable on both themes; the red
         border + tinted background carry the "this is an error/detail"
         semantic. Previously the salmon-on-pink combo was unreadable in
         light mode. */
      background: rgba(209,52,56,.15); border: 1px solid #d13438;
      color: var(--text-primary); padding: 10px 12px; border-radius: 6px; font-size: .9em;
    }
    .mdo-modal-footer {
      display: flex; justify-content: flex-end; margin-top: 20px;
      padding-top: 14px; border-top: 1px solid var(--border);
    }
    .mdo-btn {
      background: var(--accent); color: #1e1e2e; border: none;
      padding: 8px 22px; border-radius: 6px; font-weight: 600;
      cursor: pointer; font-size: .95em;
    }
    .mdo-btn:hover { opacity: .9; }
    .mdo-modal .mdo-pill {
      display: inline-block; padding: 3px 12px; border-radius: 12px;
      font-size: .9em; font-weight: 600;
    }
    .mdo-pill.p-ok  { background: var(--c-online-bg);   color: var(--c-online-fg); }
    .mdo-pill.p-off { background: var(--c-offline-bg);  color: var(--c-offline-fg); }
    .mdo-pill.p-out { background: var(--c-outdated-bg); color: var(--c-outdated-fg); }
    .mdo-pill.p-deg { background: var(--c-degraded-bg); color: var(--c-degraded-fg); }
    .mdo-pill.p-thr { background: var(--c-threats-bg);  color: var(--c-threats-fg); }

    .footer { text-align: center; padding: 16px 28px; font-size: .78em;
              color: var(--text-faint); border-top: 1px solid var(--border); }
  </style>
</head>
<body>
  <div class="topbar">
    <h1><svg viewBox="0 0 24 24" width="0.9em" height="0.9em" style="vertical-align:-0.12em" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.6 8 11 4.6-1.4 8-6 8-11V5l-8-3z" fill="currentColor"/><path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg> Microsoft Defender Antivirus &#8211; Fleet Status</h1>
    <div class="meta">
      <div class="meta-text">
        Available: <strong>$(if ($AvailableVersionStr) { "v$AvailableVersionStr" } else { 'N/A' })</strong><br>
        Last data: <strong>$(if ($AsOf -eq [datetime]::MinValue) { '(collecting…)' } else { $AsOf.ToString('yyyy-MM-dd HH:mm:ss') })</strong> &nbsp;|&nbsp;
        Next refresh in: <strong id="countdown">$secsUntil</strong>s &nbsp;|&nbsp;
        <a href="/refresh">Force Refresh</a> &nbsp;|&nbsp;
        <a href="/status" target="_blank">JSON</a>
      </div>
      <button type="button" class="theme-toggle" id="themeToggle"
              onclick="toggleTheme()" title="Switch theme">&#9728;</button>
    </div>
  </div>

  <div class="stats">
    <div class="stat st-online"  data-card="online"   onclick="filterByCard('online')">
      <div class="lbl">Online</div><div class="val">$onlineCount</div></div>
    <div class="stat st-offline" data-card="offline"  onclick="filterByCard('offline')">
      <div class="lbl">Offline</div><div class="val">$offlineCount</div></div>
    <div class="stat st-out"     data-card="outdated" onclick="filterByCard('outdated')">
      <div class="lbl">Outdated</div><div class="val">$outdated</div></div>
    <div class="stat st-rt"      data-card="rtoff"    onclick="filterByCard('rtoff')">
      <div class="lbl">RT Prot Off</div><div class="val">$rtOff</div></div>
  </div>

  <div class="toolbar">
    <input type="text" id="filter" placeholder="Filter by computer name…" oninput="applyFilter()">
    <a href="/refresh" class="btn">&#x21BB; Refresh Now</a>
    <span class="legend">
      <span class="lgnd-label">Status:</span>
      <span class="lgnd-chip"><i class="lgnd-dot" style="background:var(--c-online-bg)"></i>Healthy</span>
      <span class="lgnd-chip"><i class="lgnd-dot" style="background:var(--c-outdated-bg)"></i>Outdated</span>
      <span class="lgnd-chip"><i class="lgnd-dot" style="background:var(--c-threats-bg)"></i>ThreatsDetected</span>
      <span class="lgnd-chip"><i class="lgnd-dot" style="background:var(--c-degraded-bg)"></i>Degraded</span>
      <span class="lgnd-chip"><i class="lgnd-dot" style="background:var(--c-offline-bg)"></i>Offline</span>
    </span>
    <a href="#" class="clear-filter" id="clearFilter"
       onclick="clearAllFilters(); return false;">Clear filters</a>
  </div>

  $refreshingBanner

  <div class="wrap">
    <table id="tbl">
      <thead><tr>
        <th onclick="sort(0)">Computer &#9651;</th>
        <th onclick="sort(1)">IPv4</th>
        <th onclick="sort(2)">Status</th>
        <th onclick="sort(3)">Installed Version</th>
        <th onclick="sort(4)">Currency</th>
        <th onclick="sort(5)">RT Protection</th>
        <th onclick="sort(6)">AV Enabled</th>
        <th onclick="sort(7)">Last Quick Scan</th>
        <th onclick="sort(8)">Threats</th>
        <th onclick="sort(9)">Query Time</th>
      </tr></thead>
      <tbody>
        $($rows -join "`n        ")
      </tbody>
    </table>
  </div>

  <div class="footer">
    Start-DefenderDashboard.ps1 v$ScriptVersion &nbsp;|&nbsp;
    $($Data.Count) computers &nbsp;|&nbsp; $onlineCount online &nbsp;|&nbsp; $offlineCount offline
  </div>

  <!-- Host Details modal (hidden until a row is clicked) -->
  <div class="mdo-modal-backdrop" id="mdoModal" onclick="if(event.target===this)closeHostModal()">
    <div class="mdo-modal" role="dialog" aria-modal="true" aria-labelledby="mdoTitle">
      <h2 id="mdoTitle">—</h2>
      <div class="mdo-sub" id="mdoSub">—</div>
      <div id="mdoBody"></div>
      <div class="mdo-modal-footer">
        <button class="mdo-btn" onclick="closeHostModal()">Close</button>
      </div>
    </div>
  </div>

  <script id="mdo-hosts-json" type="application/json">$hostJsonBlob</script>
  <script>
    // Theme handling.  The <head> early-load script already applied the
    // localStorage preference (if any), so here we just sync the button
    // icon and provide the toggle action.
    function syncThemeButton() {
      var t = document.documentElement.getAttribute('data-theme') || 'dark';
      var btn = document.getElementById('themeToggle');
      if (!btn) return;
      // Sun (&#9728;) = currently dark, click for light
      // Moon (&#127769;) = currently light, click for dark
      btn.innerHTML = t === 'light' ? '&#127769;' : '&#9728;';
      btn.title     = t === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
    }
    function toggleTheme() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next    = current === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('mdo-dashboard-theme', next); } catch(e) {}
      syncThemeButton();
    }
    syncThemeButton();

    // Card-click filtering — same behaviour as the HTML report.
    var activeCard = null;
    function filterByCard(key) {
      activeCard = (activeCard === key) ? null : key;
      var cards = document.querySelectorAll('.stat');
      for (var i = 0; i < cards.length; i++) {
        if (cards[i].dataset.card === activeCard) cards[i].classList.add('active');
        else cards[i].classList.remove('active');
      }
      applyFilter();
    }
    function clearAllFilters() {
      activeCard = null;
      var cards = document.querySelectorAll('.stat');
      for (var i = 0; i < cards.length; i++) cards[i].classList.remove('active');
      document.getElementById('filter').value = '';
      applyFilter();
    }
    function updateClearVisibility() {
      var has = (activeCard !== null) || (document.getElementById('filter').value.length > 0);
      var cf  = document.getElementById('clearFilter');
      if (cf) cf.classList.toggle('visible', has);
    }

    // Combined text-filter + card-filter applied to every row
    function applyFilter() {
      var q = document.getElementById('filter').value.toLowerCase();
      var rows = document.getElementById('tbl').tBodies[0].rows;
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var name = row.cells[0] ? row.cells[0].innerText.toLowerCase() : '';
        var nameMatch = name.indexOf(q) !== -1;
        var cardMatch = true;
        if      (activeCard === 'online')   cardMatch = row.dataset.online   === 'true';
        else if (activeCard === 'offline')  cardMatch = row.dataset.online   === 'false';
        else if (activeCard === 'outdated') cardMatch = row.dataset.outdated === 'true';
        else if (activeCard === 'rtoff')    cardMatch = row.dataset.rtoff    === 'true';
        row.style.display = (nameMatch && cardMatch) ? '' : 'none';
      }
      updateClearVisibility();
    }

    // Countdown timer
    var secs = $secsUntil;
    setInterval(function() {
      if (secs > 0) secs--;
      var el = document.getElementById('countdown');
      if (el) el.textContent = secs;
    }, 1000);

    // Sort
    var sortDir = {};
    function sort(col) {
      var tb   = document.getElementById('tbl').tBodies[0];
      var rows = Array.from(tb.rows);
      var asc  = sortDir[col] = !sortDir[col];
      rows.sort(function(a, b) {
        var av = a.cells[col] ? a.cells[col].innerText : '';
        var bv = b.cells[col] ? b.cells[col].innerText : '';
        return asc ? av.localeCompare(bv, undefined, {numeric:true})
                   : bv.localeCompare(av, undefined, {numeric:true});
      });
      rows.forEach(function(r) { tb.appendChild(r); });
    }

    // ----- Host Details modal -----------------------------------------
    // Embedded JSON drives the modal contents — no extra HTTP round-trip
    // is needed when a row is clicked. Schema mirrors /status's per-host
    // shape so the same modal could be ported to a JSON-only consumer.
    var MDO_HOSTS = (function() {
      try {
        var el = document.getElementById('mdo-hosts-json');
        return el ? JSON.parse(el.textContent) : [];
      } catch (e) { return []; }
    })();
    var MDO_BY_NAME = (function() {
      var m = {};
      for (var i = 0; i < MDO_HOSTS.length; i++) m[MDO_HOSTS[i].computerName] = MDO_HOSTS[i];
      return m;
    })();

    function esc(s) {
      if (s === null || s === undefined) return '';
      return String(s).replace(/[&<>"']/g, function(c) {
        return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
      });
    }
    function boolClass(v) {
      if (v === 'True')  return 'bool-true';
      if (v === 'False') return 'bool-false';
      return '';
    }
    function pillClass(s) {
      switch (s) {
        case 'Healthy':         return 'p-ok';
        case 'Offline':         return 'p-off';
        case 'Outdated':        return 'p-out';
        case 'Degraded':        return 'p-deg';
        case 'ThreatsDetected': return 'p-thr';
        default:                return 'p-off';
      }
    }
    function effectiveStatus(h) {
      if (!h.online)                       return 'Offline';
      if (h.versionStatus === 'Outdated')  return 'Outdated';
      if (h.healthStatus)                  return h.healthStatus;
      if (h.realTimeProtection === 'False' || h.antivirusEnabled === 'False') return 'Degraded';
      return 'Healthy';
    }
    function kv(k, v, cls) {
      cls = cls || '';
      return '<div class="k">' + esc(k) + ' :</div><div class="v ' + cls + '">' + esc(v || '—') + '</div>';
    }

    function renderHostModal(h) {
      var status = effectiveStatus(h);
      var pill   = '<span class="mdo-pill ' + pillClass(status) + '">' + esc(status) + '</span>';

      var threatRows = '';
      if (h.threats && h.threats.length > 0) {
        for (var i = 0; i < h.threats.length; i++) {
          var t = h.threats[i];
          threatRows += '<tr><td>' + esc(t.name) + '</td><td>' + esc(t.detected) + '</td><td><div class="r-wrap">' + esc(t.resources) + '</div></td></tr>';
        }
      }
      var threatBlock = h.threats && h.threats.length > 0
        ? '<table class="mdo-threats"><thead><tr><th>Threat</th><th>Detected</th><th>Resource</th></tr></thead><tbody>' + threatRows + '</tbody></table>'
        : '<div class="mdo-kv">' + kv('No threats reported', '') + '</div>';

      var errBlock = h.error
        ? '<h3>Error / Detail</h3><div class="mdo-err">' + esc(h.error) + '</div>'
        : '';

      return ''
        + '<h3>Identity</h3>'
        + '<div class="mdo-kv">'
        +   kv('Computer',       h.computerName)
        +   kv('IPv4 address',   (h.ipv4Address || '—'))
        +   kv('Online',         h.online ? 'Yes' : 'No', h.online ? 'bool-true' : 'bool-false')
        +   kv('Query duration', (h.queryDurationSec != null ? h.queryDurationSec + 's' : '—'))
        + '</div>'
        + '<h3>Health Classification</h3>'
        + '<div class="mdo-kv">'
        +   '<div class="k">Status :</div><div class="v">' + pill + '</div>'
        +   kv('Reason', (h.healthReason || '—'))
        + '</div>'
        + '<h3>Defender State</h3>'
        + '<div class="mdo-kv">'
        +   kv('WinDefend service',     h.defenderService)
        +   kv('Signature version',     h.signatureVersion + (h.versionStatus ? ' (' + h.versionStatus + ')' : ''))
        +   kv('Available version',     h.availableVersion)
        +   kv('Real-time protection',  h.realTimeProtection,        boolClass(h.realTimeProtection))
        +   kv('Antimalware service',   h.amServiceEnabled,          boolClass(h.amServiceEnabled))
        +   kv('Antivirus engine',      h.antivirusEnabled,          boolClass(h.antivirusEnabled))
        +   kv('Behavior monitor',      h.behaviorMonitorEnabled,    boolClass(h.behaviorMonitorEnabled))
        +   kv('IOAV protection',       h.ioavProtectionEnabled,     boolClass(h.ioavProtectionEnabled))
        +   kv('On-access protection',  h.onAccessProtectionEnabled, boolClass(h.onAccessProtectionEnabled))
        + '</div>'
        + '<h3>Scans</h3>'
        + '<div class="mdo-kv">'
        +   kv('Last quick scan', h.lastQuickScan)
        +   kv('Last full scan',  h.lastFullScan)
        + '</div>'
        + '<h3>Threats (' + (h.threats ? h.threats.length : 0) + ')</h3>'
        + threatBlock
        + errBlock;
    }

    function openHostModal(name) {
      var h = MDO_BY_NAME[name];
      if (!h) return;
      document.getElementById('mdoTitle').textContent = h.computerName;
      document.getElementById('mdoSub').textContent   = 'Last refreshed ' + (h.queryDurationSec || 0) + 's';
      document.getElementById('mdoBody').innerHTML    = renderHostModal(h);
      document.getElementById('mdoModal').classList.add('show');
    }
    function closeHostModal() {
      document.getElementById('mdoModal').classList.remove('show');
    }
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') closeHostModal();
    });
    // Delegate row clicks (avoids re-binding after DOM mutations from sort).
    var tbl = document.getElementById('tbl');
    if (tbl) {
      tbl.tBodies[0].addEventListener('click', function(e) {
        var tr = e.target.closest('tr.hostrow');
        if (tr && tr.dataset.host) openHostModal(tr.dataset.host);
      });
    }
  </script>
</body>
</html>
"@
}

# ===================================================================
# JSON Serialiser  (for /status endpoint)
# ===================================================================
function ConvertTo-DashboardJson {
    param(
        [object[]]$Data,
        [datetime]$AsOf,
        [string]$AvailableVersionStr,
        [bool]$IsRefreshing = $false
    )
    # When the async initial-collection has not completed yet, AsOf is
    # DateTime.MinValue. Serialise that as null so consumers checking
    # time-since don't see year-0001. The isRefreshing flag tells them
    # to retry instead of alerting on the empty totalComputers count.
    $generated = if ($AsOf -eq [datetime]::MinValue) { $null } else { $AsOf.ToString('o') }
    $payload = [ordered]@{
        generated        = $generated
        isRefreshing     = $IsRefreshing
        availableVersion = $AvailableVersionStr
        totalComputers   = $Data.Count
        onlineCount      = @($Data | Where-Object Online).Count
        offlineCount     = @($Data | Where-Object { -not $_.Online }).Count
        outdatedCount    = @($Data | Where-Object VersionStatus -eq 'Outdated').Count
        computers        = @($Data | Sort-Object ComputerName | ForEach-Object {
            [ordered]@{
                computerName              = $_.ComputerName
                ipv4Address               = $_.IPv4Address
                online                    = $_.Online
                defenderService           = $_.DefenderService
                signatureVersion          = $_.SignatureVersion
                availableVersion          = $_.AvailableVersion
                versionStatus             = $_.VersionStatus
                realTimeProtection        = $_.RealTimeProtection
                antivirusEnabled          = $_.AntivirusEnabled
                amServiceEnabled          = $_.AmServiceEnabled
                behaviorMonitorEnabled    = $_.BehaviorMonitorEnabled
                ioavProtectionEnabled     = $_.IoavProtectionEnabled
                onAccessProtectionEnabled = $_.OnAccessProtectionEnabled
                lastQuickScan             = $_.LastQuickScan
                lastFullScan              = $_.LastFullScan
                threatCount               = $_.ThreatCount
                threats                   = @($_.ThreatList)
                healthStatus              = $_.HealthStatus
                healthReason              = $_.HealthReason
                queryDurationSec          = $_.QueryDuration
                error                     = $_.Error
            }
        })
    }
    return $payload | ConvertTo-Json -Depth 5
}

# ===================================================================
# HTTP Response Helper
# ===================================================================
# Defender shield favicon — embedded SVG so the dashboard tab shows the
# project icon instead of the browser's default globe glyph. Single source
# of truth: referenced by the request handler (for /favicon.ico and
# /favicon.svg) and indirectly by the HTML head <link rel="icon"> tag.
# Designed at 24x24 viewport; renders cleanly at any tab-favicon size.
# Color is the same Fluent blue (#0078d4) used elsewhere in the UI.
$script:FaviconSvg = @'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5 3.4 9.6 8 11 4.6-1.4 8-6 8-11V5l-8-3z" fill="#0078d4"/><path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>
'@

function Send-HttpResponse {
    param(
        [System.Net.HttpListenerContext]$Context,
        [string]$Body,
        [string]$ContentType = 'text/html; charset=utf-8',
        [int]$StatusCode = 200
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Context.Response.StatusCode      = $StatusCode
    $Context.Response.ContentType     = $ContentType
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.AddHeader('X-Powered-By', "DefenderDashboard/$ScriptVersion")
    try {
        $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } finally {
        $Context.Response.OutputStream.Close()
    }
}

function Start-BackgroundRefresh {
    if ($script:IsRefreshing) { return }
    $script:IsRefreshing = $true
    Write-DashLog "Starting background refresh ($($TargetComputers.Count) computers)…" 'INFO'

    $script:RefreshJob = Start-ThreadJob -ScriptBlock ${function:Invoke-FleetRefresh} `
        -ArgumentList $TargetComputers, $AvailableVersionStr, $ParallelThreads, $TimeoutSeconds, $FunctionDef, $Credential, $DisableIPv6, @($LibInvokeDefenderRemote, $LibGetDefenderHealthProbe)
}

function Receive-RefreshIfDone {
    if (-not $script:RefreshJob) { return }
    if ($script:RefreshJob.State -notin 'Running','NotStarted') {
        $newData = Receive-Job $script:RefreshJob -ErrorAction SilentlyContinue
        Remove-Job $script:RefreshJob -Force
        $script:RefreshJob   = $null
        $script:IsRefreshing = $false

        if ($newData) {
            $script:CachedResults = if ($newData -is [array]) { [System.Collections.Generic.List[pscustomobject]]$newData } else { $newData }
            $script:CachedAt      = Get-Date
            $onlineCount  = @($script:CachedResults | Where-Object Online).Count
            $outdatedCount = @($script:CachedResults | Where-Object VersionStatus -eq 'Outdated').Count
            Write-DashLog "Refresh complete: $($script:CachedResults.Count) computers | $onlineCount online | $outdatedCount outdated" 'SUCCESS'
        } else {
            Write-DashLog 'Refresh job returned no data.' 'WARN'
        }
    }
}

# ===================================================================
# Main-flow guard
#
# When this script is dot-sourced (Pester or interactive testing of
# individual functions), return here so the banner and HTTP listener
# below do not run.  Direct invocation continues normally.
# ===================================================================
if ($MyInvocation.InvocationName -eq '.') { return }

# ===================================================================
# Startup
# ===================================================================
Start-StartupTimer
Write-DashLog "=== Defender Dashboard v$ScriptVersion starting ===" 'SUCCESS'
Write-DashLog "Port            : $Port"
Write-DashLog "Refresh interval: ${RefreshInterval}s"
Write-DashLog "Parallel threads: $ParallelThreads"
Write-DashLog "Default theme   : $DashboardTheme"
Write-DashLog "HTTPS           : $(if ($UseHttps) { "enabled (cert $CertificateThumbprint)" } else { 'disabled' })"
Write-DashLog "Auth            : $AuthMethod"
Write-DashLog "Log file        : $LogFile"
Write-DashLog "WinRM Auth      : $(if ($Credential) { $Credential.UserName } else { "caller context ($env:USERDOMAIN\$env:USERNAME)" })"
Write-DashLog "Source share    : $(if ($SourceSharePath) { $SourceSharePath } else { '(none configured)' })"
Write-StartupPhase 'banner'

# ===================================================================
# Authentication validation (early — fail fast for misconfigurations).
# Runs before HTTPS cert resolution so an auth-config problem surfaces
# in its own right instead of being masked by an unrelated cert error.
# ===================================================================
# Default to an empty allow/deny set so Basic/Token/None code paths can
# still pass $script:AdGroupResolution into Test-DashboardAuth.
$script:AdGroupResolution = [pscustomobject]@{
    AllowSids  = @()
    DenySids   = @()
    Unresolved = @()
}
switch ($AuthMethod) {
    'Basic' {
        if (-not $UseHttps) {
            Write-DashLog "AuthMethod=Basic over plain HTTP would send credentials in cleartext on every request. Enable UseHttps=true in config.conf, or pick a different AuthMethod." 'ERROR'
            exit 1
        }
        if (-not $AuthBasicUsersFile -or -not (Test-Path -LiteralPath $AuthBasicUsersFile)) {
            Write-DashLog "AuthMethod=Basic but AuthBasicUsersFile is missing or not found: $AuthBasicUsersFile" 'ERROR'
            Write-DashLog "Create users via:  .\Start-DefenderDashboard.ps1 -AddBasicUser <username>" 'ERROR'
            exit 1
        }
        $userCount = (Read-DashboardUsersFile -Path $AuthBasicUsersFile).Count
        if ($userCount -eq 0) {
            Write-DashLog "AuthMethod=Basic but AuthBasicUsersFile contains no users: $AuthBasicUsersFile" 'ERROR'
            Write-DashLog "Add at least one user via:  .\Start-DefenderDashboard.ps1 -AddBasicUser <username>" 'ERROR'
            exit 1
        }
        Write-DashLog "Basic auth: $userCount user(s) loaded from $AuthBasicUsersFile" 'INFO'
    }
    'Token' {
        if (-not $AuthToken) {
            $tokenFile = Join-Path $ScriptDir 'conf\dashboard.token'
            if (Test-Path -LiteralPath $tokenFile) {
                $AuthToken = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
                Write-DashLog "Loaded existing dashboard token from $tokenFile" 'INFO'
            } else {
                $AuthToken = New-RandomToken -ByteLength 32
                try {
                    $AuthToken | Out-File -LiteralPath $tokenFile -Encoding ASCII -NoNewline
                    # Tighten ACL: disable inheritance, allow only the current
                    # identity (which is the scheduled-task service account
                    # when run as a service). Falls back to file-system default
                    # if any of these calls fail.
                    try {
                        $acl = Get-Acl -LiteralPath $tokenFile
                        $acl.SetAccessRuleProtection($true, $false)
                        # Remove all inherited / pre-existing rules
                        @($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
                        $identity = "$env:USERDOMAIN\$env:USERNAME"
                        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                            $identity, 'FullControl', 'Allow')
                        $acl.AddAccessRule($rule)
                        Set-Acl -LiteralPath $tokenFile -AclObject $acl
                    } catch {
                        Write-DashLog "Could not tighten ACL on $tokenFile : $($_.Exception.Message). Falling back to default file permissions." 'WARN'
                    }
                    Write-DashLog "Generated new dashboard token and wrote to $tokenFile (restricted to $env:USERDOMAIN\$env:USERNAME)" 'SUCCESS'
                } catch {
                    Write-DashLog "Could not write token file $tokenFile : $($_.Exception.Message). Using in-memory token only (will regenerate on restart)." 'WARN'
                }
            }
        }
    }
    'ADIntegrated' {
        # Informational: NTLM still works for local-machine accounts on
        # workgroup hosts, so this is a warn-don't-block check.
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if (-not $cs.PartOfDomain) {
                Write-DashLog "AuthMethod=ADIntegrated on a non-domain-joined host. Only local-machine accounts can authenticate (e.g. AuthAllowedGroups = 'BUILTIN\Administrators')." 'WARN'
            }
        } catch {
            Write-DashLog "Could not determine domain membership ($($_.Exception.Message)). ADIntegrated may not work as expected." 'WARN'
        }
        # Resolve allow-list to SIDs once at startup. Per-request membership
        # checks then avoid any AD round-trip.
        $script:AdGroupResolution = Resolve-DashboardAllowedGroups -AllowList $AuthAllowedGroups

        # Per-entry structured log (key=value) so operators can see exactly
        # which input resolved to which DOMAIN\Group + SID — and which entries
        # failed. v0.0.12 only logged a count, which made AuthAllowedGroups
        # format mistakes (unqualified 'Helpdesk' vs 'WGSDAC\Helpdesk') hard
        # to diagnose remotely.
        foreach ($r in $script:AdGroupResolution.Resolutions) {
            $type = if ($r.IsDeny) { 'deny' } else { 'allow' }
            if ($r.Status -eq 'ok') {
                Write-DashLog ("event=auth_resolve input='{0}' type={1} status=ok account='{2}' sid={3}" -f $r.Input, $type, $r.Account, $r.Sid) 'INFO'
            } else {
                $errClean = ($r.Error -replace "'", "''" -replace "[\r\n]+", ' ').Trim()
                Write-DashLog ("event=auth_resolve input='{0}' type={1} status=unresolved error='{2}'" -f $r.Input, $type, $errClean) 'WARN'
            }
        }

        if ($script:AdGroupResolution.AllowSids.Count -eq 0 -and
            $script:AdGroupResolution.DenySids.Count  -eq 0) {
            Write-DashLog ("event=auth_summary allow_count=0 deny_count=0 unresolved={0} effect=any-authenticated-user-permitted" -f $script:AdGroupResolution.Unresolved.Count) 'INFO'
        } else {
            Write-DashLog ("event=auth_summary allow_count={0} deny_count={1} unresolved={2}" -f $script:AdGroupResolution.AllowSids.Count, $script:AdGroupResolution.DenySids.Count, $script:AdGroupResolution.Unresolved.Count) 'INFO'
        }
    }
    'None' {
        Write-DashLog "AuthMethod=None — dashboard is unauthenticated. Anyone with network access to port $Port can view fleet status. Set AuthMethod in conf/config.conf to close this." 'WARN'
    }
}
Write-StartupPhase 'auth_preflight'

# ===================================================================
# HTTPS validation (after auth so auth errors surface first).
# Resolves the cert thumbprint, warns on imminent expiry, and emits
# EventId 103 if the event source is registered.
# ===================================================================
$dashboardCert = $null
if ($UseHttps) {
    try {
        $dashboardCert = Resolve-DashboardCertificate -Thumbprint $CertificateThumbprint
        Write-DashLog "Certificate    : $($dashboardCert.Subject)" 'INFO'
        Write-DashLog "Cert expires   : $($dashboardCert.NotAfter.ToString('yyyy-MM-dd')) ($($dashboardCert.DaysUntilExpiry) day(s) from now)" 'INFO'
    } catch {
        Write-DashLog $_.Exception.Message 'ERROR'
        exit 1
    }
    if ($dashboardCert.DaysUntilExpiry -lt 30) {
        $expiryMsg = "Dashboard TLS certificate $($dashboardCert.Thumbprint) expires in $($dashboardCert.DaysUntilExpiry) day(s) (on $($dashboardCert.NotAfter.ToString('yyyy-MM-dd'))). " +
                     "Re-run Install-DefenderDashboard.ps1 -RenewCertificate to regenerate, or replace with a PKI-issued cert."
        Write-DashLog $expiryMsg 'WARN'
        try {
            if ([System.Diagnostics.EventLog]::SourceExists('Manage-DefenderOffline')) {
                Write-EventLog -LogName Application -Source 'Manage-DefenderOffline' `
                    -EventId 103 -EntryType Warning -Message $expiryMsg
                Write-DashLog 'Warning written to Windows Event Log (EventId 103).' 'WARN'
            }
        } catch {
            Write-DashLog "Could not write EventId 103 to Windows Event Log: $($_.Exception.Message)" 'WARN'
        }
    }
}
Write-StartupPhase 'https_cert_resolve'

$TargetComputers = @(Resolve-TargetComputers)
if ($ExcludeList.Count -gt 0) {
    $excluded = @($TargetComputers | Where-Object { $ExcludeList -contains $_ })
    if ($excluded.Count -gt 0) {
        Write-DashLog "Excluding $($excluded.Count) computer(s) per config.conf ExcludeComputers: $($excluded -join ', ')" 'WARN'
    }
    $TargetComputers = @($TargetComputers | Where-Object { $ExcludeList -notcontains $_ })
}
if ($TargetComputers.Count -eq 0) {
    Write-DashLog 'No target computers found. Exiting.' 'ERROR'
    exit 1
}
Write-DashLog "Target computers: $($TargetComputers.Count)" 'SUCCESS'
Write-StartupPhase 'target_computers'

$AvailableVersion    = Get-LatestAvailableVersion -Root $SourceSharePath
$AvailableVersionStr = if ($AvailableVersion) { $AvailableVersion.ToString() } else { '' }
if ($AvailableVersionStr) {
    Write-DashLog "Available version: v$AvailableVersionStr" 'SUCCESS'
} elseif (-not $SourceSharePath) {
    # Only log the "no path configured" branch here. All other failure
    # branches (path unreachable, permission denied, layout mismatch)
    # log their distinct reason from inside Get-LatestAvailableVersion
    # itself so the operator sees the actual cause.
    Write-DashLog 'Available version: SourceSharePath is not configured in conf/config.conf; version currency check disabled.' 'WARN'
}
Write-StartupPhase 'available_version'

# Resolve port. HTTPS does NOT use fallback because netsh sslcert binds the
# cert to a specific ipport — if the dashboard fell back to a different port,
# the cert wouldn't be bound there and the listener would fail to start.
# HTTP mode keeps the existing fallback behavior.
if ($UseHttps) {
    if (-not (Test-PortFree $Port)) {
        Write-DashLog "Port $Port is in use and HTTPS does not support fallback (the TLS certificate is bound to a specific port via netsh)." 'ERROR'
        Write-DashLog "Stop the conflicting process or change Port in config.conf, then re-run the installer with -RenewCertificate to rebind." 'ERROR'
        exit 1
    }

    # HTTPS pre-flight: confirm the cert is bound to the listener port via
    # netsh sslcert. Without a binding, HttpListener.Start() succeeds but
    # every TLS handshake fails — the browser sees a "Secure Connection
    # Failed" with no signal in the dashboard log to point the way.
    $bindingCheck = Test-HttpsCertBinding -Port $Port -ExpectedThumbprint $CertificateThumbprint
    if (-not $bindingCheck.IsBound) {
        Write-DashLog "HTTPS pre-flight FAILED: $($bindingCheck.Reason)" 'ERROR'
        Write-DashLog "TLS handshake would fail at first request. Bind the cert with:" 'ERROR'
        Write-DashLog "  netsh http add sslcert ipport=0.0.0.0:$Port certhash=$CertificateThumbprint appid='{12345678-DB90-4B66-8B01-88F7AF2A1234}'" 'ERROR'
        Write-DashLog "Or re-run the installer to bind automatically:" 'ERROR'
        Write-DashLog "  .\Install-DefenderDashboard.ps1 -UseHttps" 'ERROR'
        exit 1
    }
    Write-DashLog "HTTPS pre-flight: $($bindingCheck.Reason)" 'SUCCESS'

    $portResult = [pscustomobject]@{ Port = $Port; IsFallback = $false; PrimaryPort = $Port }
} else {
    $portResult = Find-AvailablePort -Primary $Port -Fallback $FallbackPort
    if ($portResult.IsFallback) {
        Write-DashLog "Port $($portResult.PrimaryPort) is in use. Binding to fallback port $($portResult.Port) instead." 'WARN'
    }
    $Port = $portResult.Port
}
Write-StartupPhase 'port_and_https_binding'

# Start primary listener (HTTP or HTTPS depending on -UseHttps)
$scheme   = if ($UseHttps) { 'https' } else { 'http' }
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("${scheme}://+:$Port/")

# For ADIntegrated, let HttpListener handle the multi-roundtrip Negotiate
# protocol (we can't reproduce NTLM/Kerberos ourselves). The selector
# delegate is consulted per request so /health stays anonymous.
#
# We use an Add-Type C# static method (not a PowerShell scriptblock) as
# the delegate target because HttpListener invokes the selector from a
# thread-pool thread that has no PowerShell Runspace — a scriptblock
# bound there throws "no Runspace available", which HttpListener surfaces
# to the caller as HTTP 500 before any of our user-space code runs.
if ($AuthMethod -eq 'ADIntegrated') {
    if (-not ('DashboardAuthSelector' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Net;
public static class DashboardAuthSelector {
    public static AuthenticationSchemes Decide(HttpListenerRequest req) {
        if (req != null && req.Url != null) {
            string path = req.Url.LocalPath;
            if (path == "/health" || path == "/favicon.ico" || path == "/favicon.svg") {
                return AuthenticationSchemes.Anonymous;
            }
        }
        return AuthenticationSchemes.Negotiate;
    }
}
'@
    }
    $listener.AuthenticationSchemeSelectorDelegate = [System.Delegate]::CreateDelegate(
        [System.Net.AuthenticationSchemeSelector],
        [DashboardAuthSelector],
        'Decide')
    Write-DashLog 'HttpListener configured for Negotiate authentication (anonymous for /health).' 'INFO'
}

try {
    $listener.Start()
} catch {
    Write-DashLog "Failed to bind to port $Port (${scheme}): $($_.Exception.Message)" 'ERROR'
    if ($UseHttps) {
        Write-DashLog "For HTTPS, the cert must also be bound to the port via:  netsh http add sslcert ipport=0.0.0.0:$Port certhash=$($dashboardCert.Thumbprint) appid={GUID}" 'ERROR'
        Write-DashLog 'The installer (Install-DefenderDashboard.ps1 -UseHttps) handles this binding automatically.' 'ERROR'
    } else {
        Write-DashLog 'Ensure no other process owns this port and that the account has permission to register HTTP prefixes.' 'ERROR'
    }
    exit 1
}
Write-DashLog "$($scheme.ToUpper()) listener started on ${scheme}://+:$Port/" 'SUCCESS'
Write-DashLog "Browse to: ${scheme}://localhost:$Port/defender" 'INFO'
Write-StartupPhase 'primary_listener'

# Optional HTTP-to-HTTPS redirect listener. Spun up in a thread job so it
# runs alongside the main listener; cleaned up in the main finally block.
$redirectListener = $null
$redirectJob      = $null
if ($UseHttps -and $RedirectHttpToHttps) {
    if ($RedirectHttpPort -eq $Port) {
        Write-DashLog "RedirectHttpPort ($RedirectHttpPort) collides with HTTPS Port ($Port). Skipping HTTP redirect listener." 'WARN'
    } else {
        try {
            $redirectListener = [System.Net.HttpListener]::new()
            $redirectListener.Prefixes.Add("http://+:$RedirectHttpPort/")
            $redirectListener.Start()
            $redirectJob = Start-ThreadJob -Name 'HttpsRedirect' -ScriptBlock {
                param($listener, $httpsPort)
                while ($listener.IsListening) {
                    try {
                        $ctx = $listener.GetContext()
                    } catch {
                        break  # listener stopped during shutdown
                    }
                    try {
                        $httpsUrl = "https://$($ctx.Request.Url.Host):$httpsPort$($ctx.Request.Url.PathAndQuery)"
                        $ctx.Response.StatusCode      = 301
                        $ctx.Response.RedirectLocation = $httpsUrl
                    } catch {} finally {
                        try { $ctx.Response.Close() } catch {}
                    }
                }
            } -ArgumentList $redirectListener, $Port
            Write-DashLog "HTTP redirect listener started on http://+:$RedirectHttpPort/ (301 -> https://+:$Port/)" 'SUCCESS'
        } catch {
            $errMsg = $_.Exception.Message
            Write-DashLog "Could not start HTTP redirect listener on port $RedirectHttpPort : $errMsg" 'WARN'

            # When the failure is a URL-ACL reservation conflict (HttpListener's
            # most common bind failure), enumerate every URL-ACL on the same
            # port and surface the holding prefix + owner so the operator
            # doesn't have to dig. HttpListener detects conflicts by port,
            # not by exact prefix, so we report any reservation whose URL
            # targets the requested port — including different wildcards
            # (+ vs *), different hostnames, or different path prefixes.
            if ($errMsg -match 'conflicts with an existing registration') {
                $collision = Test-UrlAclCollision -Port $RedirectHttpPort -Scheme 'http'
                if ($collision.HasCollision) {
                    Write-DashLog "  URL-ACL collision: $($collision.Reservations.Count) reservation(s) found on port $RedirectHttpPort -" 'WARN'
                    foreach ($r in $collision.Reservations) {
                        $ownerList = if ($r.Owners.Count -gt 0) { $r.Owners -join ', ' } else { '(no explicit User; SDDL-only)' }
                        Write-DashLog "    - $($r.Url)  [held by: $ownerList]" 'WARN'
                    }
                    Write-DashLog "  To free the reservation(s) so the redirect listener can bind, run as Administrator:" 'WARN'
                    foreach ($r in $collision.Reservations) {
                        Write-DashLog "    netsh http delete urlacl url=$($r.Url)" 'WARN'
                    }
                    Write-DashLog "  Or pick a different port via 'RedirectHttpPort' in conf\config.conf." 'WARN'
                } else {
                    Write-DashLog "  URL-ACL diagnostic found no reservations on port $RedirectHttpPort. The conflict is likely another process binding the port directly (run 'Get-NetTCPConnection -LocalPort $RedirectHttpPort -State Listen' to identify it) or a stale HttpListener from this same process." 'WARN'
                }
            }

            $redirectListener = $null
            $redirectJob      = $null
        }
    }
}
Write-StartupPhase 'redirect_listener'

# Write runtime status file so the installer and administrators can
# discover the actual bound port without reading through the log.
$statusFile = Join-Path $ScriptDir 'conf\dashboard.status'
$statusLines = @(
    "# Manage-DefenderOffline Dashboard – Runtime Status"
    "# Written by Start-DefenderDashboard.ps1 at each startup."
    "# Read this file to discover the port the service is currently using."
    "Port=$Port"
    "PrimaryPort=$($portResult.PrimaryPort)"
    "IsFallback=$($portResult.IsFallback)"
    "StartTime=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "ProcessId=$PID"
    "Hostname=$env:COMPUTERNAME"
)
try {
    $statusLines | Out-File -FilePath $statusFile -Encoding UTF8 -Force
    Write-DashLog "Status file written: $statusFile" 'INFO'
} catch {
    Write-DashLog "Could not write status file ($statusFile): $($_.Exception.Message)" 'WARN'
}
Write-StartupPhase 'status_file'

# Write to Windows Event Log if the source has been registered by the installer.
# EventId 100 = normal start on primary port
# EventId 101 = started on fallback port  (Warning — admin action may be needed)
# EventId 102 = service stopped
$evtSource = 'Manage-DefenderOffline'
try {
    if ([System.Diagnostics.EventLog]::SourceExists($evtSource)) {
        if ($portResult.IsFallback) {
            $evtMsg = "Defender Dashboard started on FALLBACK port $Port. " +
                      "Primary port $($portResult.PrimaryPort) was already in use. " +
                      "Update firewall rules, bookmarks, and monitoring tools to use port $Port."
            Write-EventLog -LogName Application -Source $evtSource -EventId 101 `
                -EntryType Warning -Message $evtMsg
            Write-DashLog "Warning written to Windows Event Log (EventId 101)." 'WARN'
        } else {
            Write-EventLog -LogName Application -Source $evtSource -EventId 100 `
                -EntryType Information `
                -Message "Defender Dashboard started on port $Port."
        }
    }
} catch {
    Write-DashLog "Could not write to Windows Event Log: $($_.Exception.Message)" 'WARN'
}
Write-StartupPhase 'event_log'

# ===================================================================
# State
# ===================================================================
$script:CachedResults  = [System.Collections.Generic.List[pscustomobject]]::new()
$script:CachedAt       = [datetime]::MinValue
$script:IsRefreshing   = $false
$script:RefreshJob     = $null
$FunctionDef           = ${function:Get-DefenderStatus}.ToString()

# Kick off the initial fleet collection asynchronously so the listener
# accepts requests immediately. First visitors before the refresh
# completes see an empty cache; Build-DashboardHtml renders the
# IsRefreshing banner ("Refreshing…") on /defender, and /status JSON
# returns the empty results with the same flag. The main loop's
# Receive-RefreshIfDone picks up the result and swaps the cache in
# without operator action.
#
# Pre-v0.0.14 this was a synchronous Invoke-FleetRefresh that blocked
# startup for ~14s on a healthy fleet; longer when offline hosts pushed
# WinRM probes to TimeoutSeconds. The async kickoff drops cold startup
# to ~6-7s end-to-end so the installer's status-file wait succeeds
# comfortably and operators don't stare at a hung browser tab.
Write-DashLog 'Kicking off initial fleet collection asynchronously…' 'INFO'
Start-BackgroundRefresh
Write-StartupPhase 'initial_fleet_refresh'
Write-StartupComplete

# ===================================================================
# Main Loop
# ===================================================================
Write-DashLog 'Entering main request loop. Press Ctrl+C to stop.' 'INFO'

# HttpListener has no Pending() method (that's a TcpListener idiom).
# Equivalent: start an async GetContext, wait up to 500 ms for a
# request, then loop around to do background work if nothing arrived.
# The IAsyncResult is held across loop iterations so we don't leak an
# async operation every time we time out.
$pendingCtx = $null

try {
    while ($listener.IsListening) {

        # Check if background refresh has completed
        Receive-RefreshIfDone

        # Kick off a new refresh if the interval has elapsed and we're not already refreshing
        if (-not $script:IsRefreshing -and
            ($script:CachedAt -eq [datetime]::MinValue -or
             ([datetime]::Now - $script:CachedAt).TotalSeconds -ge $RefreshInterval)) {
            Start-BackgroundRefresh
        }

        # Non-blocking HTTP request check (500 ms quantum so the loop
        # can service background-refresh work even when idle).
        if ($null -eq $pendingCtx) {
            $pendingCtx = $listener.BeginGetContext($null, $null)
        }
        if (-not $pendingCtx.AsyncWaitHandle.WaitOne(500)) { continue }

        # listener may have been stopped between WaitOne returning and now
        if (-not $listener.IsListening) { break }

        # Per-request try/catch: every action between EndGetContext and the
        # end of the switch can throw (NTLM token validation issues,
        # malformed requests, abandoned connections, HTML/JSON build errors,
        # stream-write failures on clients that disconnect mid-response).
        # Before v0.0.13 these bubbled to the outer finally and shut the
        # dashboard down with exit code 0 — symptoms looked like clean
        # graceful exits with no log trail. Now we log the exception with
        # structured fields, send a best-effort 500 response, and continue.
        $context = $null
        try {
            $context    = $listener.EndGetContext($pendingCtx)
            $pendingCtx = $null
            $path       = $context.Request.Url.AbsolutePath.TrimEnd('/')

        # ----- Authorization check (before any work) -----
        $authResult = Test-DashboardAuth `
            -Context           $context `
            -Method            $AuthMethod `
            -Token             $AuthToken `
            -AllowedGroupSids  $script:AdGroupResolution `
            -UsersFile         $AuthBasicUsersFile

        # Audit fields. Source IP is captured per-request from the HttpListener
        # context; user identity comes from Test-DashboardAuth (already populated
        # for all modes — username for Basic, 'token-bearer' for Token, the
        # WindowsIdentity Name for ADIntegrated, 'anonymous' for None).
        $auditUser = if ($authResult.User) { $authResult.User } else { 'anonymous' }
        $auditFrom = 'unknown'
        try {
            if ($context.Request.RemoteEndPoint) {
                $auditFrom = $context.Request.RemoteEndPoint.Address.ToString()
            }
        } catch {}

        if (-not $authResult.Authorized) {
            $context.Response.StatusCode = $authResult.StatusCode
            if ($authResult.StatusCode -eq 401 -and $AuthMethod -eq 'Basic') {
                $context.Response.Headers.Add('WWW-Authenticate', 'Basic realm="Defender Dashboard"')
            }
            try { $context.Response.OutputStream.Close() } catch {}
            try { $context.Response.Close() } catch {}
            # WARN so audit reviewers / SIEM filters can isolate denials at level.
            Write-DashLog ("event=auth_denied path={0} user='{1}' src={2} reason={3} status={4} method={5}" -f $path, $auditUser, $auditFrom, $authResult.Reason, $authResult.StatusCode, $AuthMethod) 'WARN'

            # For ADIntegrated denials, emit a separate INFO line with the user's
            # SIDs vs the configured allow/deny SIDs so the operator can see
            # exactly why authorization failed. Only fires when we have a real
            # Windows identity to inspect (avoids noise on /health bypasses and
            # pre-auth 401s).
            if ($AuthMethod -eq 'ADIntegrated' -and
                $authResult.Reason -in 'not-in-allow-list','group-denied' -and
                $context.User -and $context.User.Identity -and $context.User.Identity.IsAuthenticated) {
                $userSidStr = if ($context.User.Identity.User) { $context.User.Identity.User.Value } else { 'none' }
                $userGroupSids = @()
                if ($context.User.Identity.Groups) {
                    $userGroupSids = @($context.User.Identity.Groups | ForEach-Object { $_.Value })
                }
                $allowSids = @($script:AdGroupResolution.AllowSids | ForEach-Object { $_.Value })
                $denySids  = @($script:AdGroupResolution.DenySids  | ForEach-Object { $_.Value })
                Write-DashLog ("event=auth_denied_detail user='{0}' user_sid={1} user_group_sids=[{2}] allow_sids=[{3}] deny_sids=[{4}]" -f `
                    $auditUser, $userSidStr, ($userGroupSids -join ','), ($allowSids -join ','), ($denySids -join ',')) 'INFO'
            }
            continue
        }

        # Successful auth for human-facing paths: log who accessed what, from
        # where (NIST 800-53 AU-2 / STIG AC-7 auditable events). /health,
        # /status and /favicon.* are excluded because they're polled by
        # monitors / auto-refresh / browser tab-icon fetches, which would
        # flood the log without adding audit value.
        if ($path -notin '/health', '/status', '/favicon.ico', '/favicon.svg' -and $authResult.Reason -ne 'health-bypass') {
            Write-DashLog ("event=auth_allowed path={0} user='{1}' src={2} reason={3} method={4}" -f $path, $auditUser, $auditFrom, $authResult.Reason, $AuthMethod) 'INFO'
        }

        switch ($path) {
            '/defender' {
                $html = Build-DashboardHtml `
                    -Data               $script:CachedResults `
                    -AvailableVersionStr $AvailableVersionStr `
                    -AsOf               $script:CachedAt `
                    -IsRefreshing       $script:IsRefreshing `
                    -Theme              $DashboardTheme
                Send-HttpResponse -Context $context -Body $html
            }

            '/status' {
                $json = ConvertTo-DashboardJson `
                    -Data               $script:CachedResults `
                    -AsOf               $script:CachedAt `
                    -AvailableVersionStr $AvailableVersionStr `
                    -IsRefreshing       $script:IsRefreshing
                Send-HttpResponse -Context $context -Body $json -ContentType 'application/json; charset=utf-8'
            }

            '/health' {
                Send-HttpResponse -Context $context -Body 'OK' -ContentType 'text/plain; charset=utf-8'
            }

            { $_ -in '/favicon.ico', '/favicon.svg' } {
                Send-HttpResponse -Context $context -Body $script:FaviconSvg -ContentType 'image/svg+xml; charset=utf-8'
            }

            '/refresh' {
                # Force an immediate refresh; redirect back to dashboard.
                # Use a relative URL so the browser resolves it against the
                # same scheme/host/port it just hit. The previous hardcoded
                # "http://" prefix broke HTTPS deployments: the redirect
                # pointed at http://<host>:<https-port>/defender, the browser
                # opened a plain-HTTP connection to the HTTPS listener, the
                # malformed TLS handshake dropped the connection, and the
                # operator saw ERR_CONNECTION_RESET in the browser.
                if (-not $script:IsRefreshing) { Start-BackgroundRefresh }
                $context.Response.Redirect('/defender')
                $context.Response.OutputStream.Close()
            }

            '/' {
                $context.Response.Redirect('/defender')
                $context.Response.OutputStream.Close()
            }

            default {
                Send-HttpResponse -Context $context -Body '<html><body>404 Not Found</body></html>' -StatusCode 404
                Write-DashLog "404: $path" 'WARN'
            }
        }
        } catch {
            # Reset $pendingCtx so the next iteration starts a fresh
            # BeginGetContext — the failed EndGetContext consumed the
            # prior IAsyncResult (or the failure happened past it).
            $pendingCtx = $null

            $exType = $_.Exception.GetType().FullName
            $exMsg  = ($_.Exception.Message -replace "'", "''" -replace "[\r\n]+", ' ').Trim()
            $errPath = '(unknown)'
            $errSrc  = 'unknown'
            try {
                if ($context -and $context.Request) {
                    if ($context.Request.Url) {
                        $errPath = $context.Request.Url.AbsolutePath
                    }
                    if ($context.Request.RemoteEndPoint) {
                        $errSrc = $context.Request.RemoteEndPoint.Address.ToString()
                    }
                }
            } catch {}
            Write-DashLog ("event=request_error path={0} src={1} exception={2} message='{3}'" -f $errPath, $errSrc, $exType, $exMsg) 'ERROR'

            # Best-effort 500 response. If the connection is already gone
            # (e.g. client timed out and abandoned), these throw and we
            # silently ignore — the whole point of this catch is keeping
            # the listener alive, not adding a SECOND exception that
            # crashes us.
            if ($context) {
                try {
                    $context.Response.StatusCode = 500
                    $context.Response.Headers['Content-Type'] = 'text/plain; charset=utf-8'
                    $errBody = [System.Text.Encoding]::UTF8.GetBytes(
                        '500 Internal Server Error. See dashboard log for details (search for event=request_error).')
                    $context.Response.OutputStream.Write($errBody, 0, $errBody.Length)
                } catch {}
                try { $context.Response.OutputStream.Close() } catch {}
                try { $context.Response.Close() } catch {}
            }
        }
    }
} finally {
    Write-DashLog 'Stopping listener…' 'WARN'
    $listener.Stop()
    $listener.Close()
    if ($redirectListener) {
        try { $redirectListener.Stop()  } catch {}
        try { $redirectListener.Close() } catch {}
    }
    if ($redirectJob) {
        Stop-Job   $redirectJob -ErrorAction SilentlyContinue
        Remove-Job $redirectJob -Force -ErrorAction SilentlyContinue
    }
    if ($script:RefreshJob) {
        Stop-Job $script:RefreshJob -Force -ErrorAction SilentlyContinue
        Remove-Job $script:RefreshJob -Force -ErrorAction SilentlyContinue
    }
    Write-DashLog 'Dashboard stopped.' 'WARN'
    try {
        if ([System.Diagnostics.EventLog]::SourceExists('Manage-DefenderOffline')) {
            Write-EventLog -LogName Application -Source 'Manage-DefenderOffline' -EventId 102 `
                -EntryType Information -Message "Defender Dashboard stopped (port $Port)."
        }
    } catch {}

    # Clear the status file so stale port info is not left behind
    try {
        $statusFile = Join-Path $ScriptDir 'conf\dashboard.status'
        if (Test-Path $statusFile) { Remove-Item $statusFile -Force -ErrorAction SilentlyContinue }
    } catch {}
}

# Explicit success exit (only reached on clean shutdown via Ctrl+C or
# listener stop) so $LASTEXITCODE is reliably 0 for scheduled-task
# wrappers and CI.
exit 0

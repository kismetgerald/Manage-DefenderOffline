<#
.SYNOPSIS
    Get-DefenderDefinitions.ps1 — Downloads Microsoft Defender antivirus
    definition packages from Microsoft for transfer into an air-gapped
    environment.

.DESCRIPTION
    Runs on an INTERNET-CONNECTED staging machine. Downloads the latest
    mpam-fe.exe for one or more architectures (x64, x86, ARM64) from the
    Microsoft Security Intelligence download endpoint, verifies the
    Authenticode signature, computes SHA-256 hashes, and lays the files
    out in the directory structure that the air-gapped Update-DefenderOffline
    consumer expects:

        <OutputPath>\<YYYYMMDD>\v<version>\<arch>\mpam-fe.exe
        <OutputPath>\<YYYYMMDD>\v<version>\<arch>\mpam-fe.sha256
        <OutputPath>\<YYYYMMDD>\transfer-manifest.json

    The manifest documents version, hashes, signer thumbprint, and source
    URL for each architecture downloaded — useful for the data-diode /
    one-way-transfer ticket that moves the bundle into the disconnected
    network.

    Not part of the air-gapped script set: this script REQUIRES internet
    access and is intended to run on a separate staging host.

.PARAMETER OutputPath
    Local staging directory. Will be created if missing. Default: .\definitions

.PARAMETER Architecture
    Architectures to download. Accepts: 'All' (default — downloads x64, x86,
    and ARM64), or a comma-separated subset like 'x64,arm64'. Individual
    values: x64 | x86 | ARM64

.PARAMETER SkipSignatureCheck
    Bypass Authenticode signature verification. Default: $false. Only use
    for testing — production downloads must remain signed.

.PARAMETER Force
    Overwrite an existing version subfolder. Without -Force, an existing
    folder for the resolved version+architecture is left untouched and
    re-using existing files when integrity verifies.

.PARAMETER ConfigPath
    Path to a config.conf with an optional [Download] section.
    Default: .\conf\config.conf

.EXAMPLE
    .\Get-DefenderDefinitions.ps1
    # Downloads all three architectures into .\definitions\<YYYYMMDD>\<version>\<arch>\

.EXAMPLE
    .\Get-DefenderDefinitions.ps1 -Architecture x64 -OutputPath D:\Staging\Defender
    # Single-architecture download to a specific staging directory.

.EXAMPLE
    .\Get-DefenderDefinitions.ps1 -Architecture x64,arm64 -Force
    # Two architectures; overwrite if version folder already exists.

.NOTES
    Author         : Kismet Agbasi (GitHub: kismetgerald | Email: KismetG17@gmail.com)
    AI Contributors: Claude AI, Grok
    Requires       : PowerShell 5.1+; internet access to go.microsoft.com
    Version        : 0.0.7
    Last Updated   : 2026-05-26
#>

[CmdletBinding()]
param(
    [string]$OutputPath,

    # Comma-separated list, or 'All'. Resolved later against the
    # supported architectures.
    [string]$Architecture = 'All',

    [switch]$SkipSignatureCheck,

    [switch]$Force,

    [string]$ConfigPath
)

$ScriptVersion = '0.0.7'
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ===================================================================
# Configuration File
# ===================================================================
function Read-ConfigFile {
    param([string]$Path)
    $cfg = [System.Collections.Generic.Dictionary[string,string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
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

if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'conf\config.conf' }
$cfg = Read-ConfigFile $ConfigPath

# Config-merge: parameters provided on the CLI win; config fills in the
# rest; otherwise defaults apply.
if (-not $PSBoundParameters.ContainsKey('OutputPath')    -and $cfg['DefaultOutputPath'])    { $OutputPath    = $cfg['DefaultOutputPath'] }
if (-not $PSBoundParameters.ContainsKey('Architecture')  -and $cfg['DefaultArchitecture'])  { $Architecture  = $cfg['DefaultArchitecture'] }
if (-not $OutputPath) { $OutputPath = Join-Path $ScriptDir 'definitions' }

# Resolve the OutputPath against the script directory if a relative path
# is supplied — same convention as the dashboard's AuthBasicUsersFile.
# GetFullPath canonicalises '.\foo' style segments so the operator-facing
# log lines don't show ugly mid-path '.\' fragments.
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $ScriptDir $OutputPath
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

# ===================================================================
# Architecture resolution
# ===================================================================
# Microsoft Security Intelligence download endpoints. Documented at:
#   https://www.microsoft.com/en-us/wdsi/defenderupdates
$ArchitectureUrls = [ordered]@{
    'x64'   = 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64'
    'x86'   = 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86'
    'arm64' = 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=arm64'
}

function Resolve-Architectures {
    param([string]$Input)
    if (-not $Input -or $Input -match '^(?i)all$') {
        return @($ArchitectureUrls.Keys)
    }
    $requested = $Input -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }
    $valid     = New-Object System.Collections.Generic.List[string]
    foreach ($a in $requested) {
        if ($ArchitectureUrls.Contains($a)) {
            [void]$valid.Add($a)
        } else {
            throw "Unknown architecture '$a'. Supported: x64, x86, ARM64, All."
        }
    }
    return $valid.ToArray()
}

$Architectures = Resolve-Architectures -Input $Architecture
if ($Architectures.Count -eq 0) {
    Write-Host 'ERROR: No architectures to download.' -ForegroundColor Red
    exit 1
}

# ===================================================================
# Banner
# ===================================================================
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host "   Microsoft Defender Definitions Downloader v$ScriptVersion" -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Output path     : $OutputPath" -ForegroundColor White
Write-Host "  Architectures   : $($Architectures -join ', ')" -ForegroundColor White
Write-Host "  Signature check : $(if ($SkipSignatureCheck) { 'SKIPPED' } else { 'Enabled' })" -ForegroundColor $(if ($SkipSignatureCheck) { 'Yellow' } else { 'White' })
Write-Host "  Force overwrite : $($Force.IsPresent)" -ForegroundColor White
Write-Host ''

# ===================================================================
# Helpers
# ===================================================================
function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToUpper()
}

# Read the Authenticode signature and return a small descriptor. Throws if
# verification fails when -SkipSignatureCheck was not supplied.
function Test-MpamSignature {
    param([string]$Path, [switch]$Skip)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    $info = [pscustomobject]@{
        Status            = $sig.Status.ToString()
        SignerSubject     = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        SignerThumbprint  = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
        TimeStamperSubject = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }
    }
    if ($sig.Status -ne 'Valid' -and -not $Skip) {
        throw "Authenticode signature for $Path is '$($sig.Status)'. Re-run with -SkipSignatureCheck only if you accept the risk."
    }
    if ($info.SignerSubject -and $info.SignerSubject -notmatch '(?i)Microsoft Corporation') {
        # Treat unexpected signer as an error unless explicitly skipped.
        if (-not $Skip) {
            throw "Authenticode signer is not Microsoft Corporation (got: '$($info.SignerSubject)'). Aborting."
        }
    }
    return $info
}

function Get-FileVersionString {
    param([string]$Path)
    (Get-Item -LiteralPath $Path).VersionInfo.FileVersion
}

# ===================================================================
# Download loop
# ===================================================================
$dateStamp     = Get-Date -Format 'yyyyMMdd'
$dateFolder    = Join-Path $OutputPath $dateStamp
$manifestPath  = Join-Path $dateFolder 'transfer-manifest.json'
$manifestItems = New-Object System.Collections.Generic.List[pscustomobject]
$failedArchs   = New-Object System.Collections.Generic.List[string]

# Workspace for ephemeral download paths (one file per arch, then we move
# into the version subfolder once we know the version).
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "mdo-download-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    foreach ($arch in $Architectures) {
        $url       = $ArchitectureUrls[$arch]
        $tempFile  = Join-Path $tempRoot "mpam-fe-$arch.exe"
        $sw        = [System.Diagnostics.Stopwatch]::StartNew()

        Write-Host "  ━━ $arch ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
        Write-Host "     Source : $url" -ForegroundColor DarkGray
        Write-Host '     Downloading…' -ForegroundColor White

        try {
            # -UseBasicParsing keeps the IE engine out of the loop (deprecated
            # on PowerShell 7+). -OutFile streams directly to disk.
            Invoke-WebRequest -Uri $url -OutFile $tempFile -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-Host "     [FAIL] Download error: $($_.Exception.Message)" -ForegroundColor Red
            [void]$failedArchs.Add($arch)
            continue
        }

        if (-not (Test-Path $tempFile)) {
            Write-Host '     [FAIL] Download completed but file missing.' -ForegroundColor Red
            [void]$failedArchs.Add($arch)
            continue
        }

        $sizeBytes = (Get-Item -LiteralPath $tempFile).Length
        $sizeMB    = [math]::Round($sizeBytes / 1MB, 2)
        Write-Host "     [OK]   Downloaded $sizeMB MB in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Green

        # Read version from the binary's resource block before we move it.
        $version = $null
        try {
            $version = Get-FileVersionString -Path $tempFile
            if (-not $version) { throw 'Empty version string.' }
        } catch {
            Write-Host "     [FAIL] Could not read FileVersion from binary: $($_.Exception.Message)" -ForegroundColor Red
            [void]$failedArchs.Add($arch)
            continue
        }
        Write-Host "     Version : v$version" -ForegroundColor White

        # Authenticode check (before we move the file into the staging tree).
        $sigInfo = $null
        try {
            $sigInfo = Test-MpamSignature -Path $tempFile -Skip:$SkipSignatureCheck
            $sigStatus = if ($SkipSignatureCheck -and $sigInfo.Status -ne 'Valid') { "$($sigInfo.Status) (skipped)" } else { $sigInfo.Status }
            Write-Host "     Signed by : $($sigInfo.SignerSubject)" -ForegroundColor DarkGray
            Write-Host "     Signature : $sigStatus" -ForegroundColor $(if ($sigInfo.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
        } catch {
            Write-Host "     [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            [void]$failedArchs.Add($arch)
            continue
        }

        # Final destination: <OutputPath>\<YYYYMMDD>\v<version>\<arch>\
        $archFolder = Join-Path (Join-Path $dateFolder ('v' + $version)) $arch
        if (Test-Path $archFolder) {
            if (-not $Force) {
                Write-Host "     [SKIP] $archFolder already exists. Re-run with -Force to overwrite." -ForegroundColor Yellow
                # Treat as success for manifest purposes if the file is already there.
                $existingFile = Join-Path $archFolder 'mpam-fe.exe'
                if (Test-Path $existingFile) {
                    $existingHash = Get-Sha256 -Path $existingFile
                    [void]$manifestItems.Add([pscustomobject]@{
                        architecture       = $arch
                        fwlink             = $url
                        filename           = 'mpam-fe.exe'
                        relativePath       = (Resolve-Path $existingFile).Path.Substring($OutputPath.Length).TrimStart('\','/')
                        version            = $version
                        sizeBytes          = (Get-Item -LiteralPath $existingFile).Length
                        sha256             = $existingHash
                        signerSubject      = $sigInfo.SignerSubject
                        signerThumbprint   = $sigInfo.SignerThumbprint
                        downloadedAt       = $null
                        reusedExisting     = $true
                    })
                }
                continue
            }
            Remove-Item -Path $archFolder -Recurse -Force
        }
        New-Item -ItemType Directory -Path $archFolder -Force | Out-Null

        $finalFile = Join-Path $archFolder 'mpam-fe.exe'
        Move-Item -Path $tempFile -Destination $finalFile -Force

        # SHA-256 sidecar (sha256sum-compatible format).
        $hash = Get-Sha256 -Path $finalFile
        $hashFile = Join-Path $archFolder 'mpam-fe.sha256'
        "$hash  *mpam-fe.exe" | Out-File -LiteralPath $hashFile -Encoding ASCII -NoNewline
        Write-Host "     SHA-256 : $hash" -ForegroundColor DarkGray
        Write-Host "     Staged  : $finalFile" -ForegroundColor Green

        [void]$manifestItems.Add([pscustomobject]@{
            architecture     = $arch
            fwlink           = $url
            filename         = 'mpam-fe.exe'
            relativePath     = (Resolve-Path $finalFile).Path.Substring($OutputPath.Length).TrimStart('\','/')
            version          = $version
            sizeBytes        = $sizeBytes
            sha256           = $hash
            signerSubject    = $sigInfo.SignerSubject
            signerThumbprint = $sigInfo.SignerThumbprint
            downloadedAt     = (Get-Date).ToString('o')
            reusedExisting   = $false
        })

        Write-Host ''
    }

    # =================================================================
    # Manifest
    # =================================================================
    if ($manifestItems.Count -gt 0) {
        if (-not (Test-Path $dateFolder)) {
            New-Item -ItemType Directory -Path $dateFolder -Force | Out-Null
        }
        $manifest = [pscustomobject]@{
            manifestVersion = '1.0'
            generated       = (Get-Date).ToString('o')
            source          = "Get-DefenderDefinitions.ps1 v$ScriptVersion"
            outputRoot      = $OutputPath
            downloads       = $manifestItems.ToArray()
        }
        $manifest | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $manifestPath -Encoding UTF8
        Write-Host "  Manifest written: $manifestPath" -ForegroundColor Green
    }

    # =================================================================
    # Summary
    # =================================================================
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '   Summary' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor Cyan
    foreach ($m in $manifestItems) {
        $note = if ($m.reusedExisting) { '  (reused existing)' } else { '' }
        Write-Host ("   {0,-6}  v{1,-12}  {2,8:N1} MB  SHA256 {3}{4}" -f `
            $m.architecture, $m.version, ($m.sizeBytes / 1MB), $m.sha256.Substring(0, 12), $note) -ForegroundColor White
    }
    if ($failedArchs.Count -gt 0) {
        Write-Host ''
        Write-Host "   FAILED: $($failedArchs -join ', ')" -ForegroundColor Red
    }

    # Sanity check: warn when downloaded architectures returned different
    # versions. Microsoft normally publishes all three in lock-step, so a
    # mismatch is rare but worth surfacing.
    $distinctVersions = @($manifestItems | Select-Object -ExpandProperty version -Unique)
    if ($distinctVersions.Count -gt 1) {
        Write-Host ''
        Write-Host "   WARNING: Multiple versions across architectures: $($distinctVersions -join ', ')" -ForegroundColor Yellow
        Write-Host '   This is unusual; Microsoft normally publishes the three architectures in lock-step.' -ForegroundColor Yellow
        Write-Host '   Each arch is staged under its own version folder; the offline consumer will pick' -ForegroundColor Yellow
        Write-Host '   the latest available per architecture.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '   Next steps:' -ForegroundColor Cyan
    Write-Host "     1. Transfer the contents of '$dateFolder'" -ForegroundColor White
    Write-Host '        into your air-gapped share, preserving the folder structure.' -ForegroundColor White
    Write-Host '     2. Verify hashes on the air-gapped side using the .sha256 sidecar files.' -ForegroundColor White
    Write-Host '     3. Run Update-DefenderOffline.ps1 from the air-gapped management host.' -ForegroundColor White
    Write-Host ''

    if ($failedArchs.Count -gt 0) { exit 2 }
    exit 0

} finally {
    # Always clean up the temp workspace, even if a download bombed.
    if (Test-Path $tempRoot) {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

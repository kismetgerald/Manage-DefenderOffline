<#
.SYNOPSIS
    Build-Release.ps1 — Package the current branch into a deployable zip.

.DESCRIPTION
    Uses "git archive" to export only the tracked files from HEAD of the
    current branch into a versioned zip.  The zip unpacks into a single
    sub-folder:  manage-defenderoffline-<version>-<shortsha>\

    This zip is the test/deployment artifact.  Copy it to the lab machine,
    extract, and run from the sub-folder.

.PARAMETER OutputPath
    Directory where the zip will be written.  Default: D:\tmp

.PARAMETER Open
    Open OutputPath in Explorer after building.

.EXAMPLE
    .\Build-Release.ps1
    .\Build-Release.ps1 -OutputPath C:\Builds -Open
#>
[CmdletBinding()]
param(
    [string]$OutputPath = 'D:\tmp',
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
$ScriptDir = $PSScriptRoot

# ── Gather build metadata ──────────────────────────────────────────────────
Push-Location $ScriptDir
try {
    $ShortSha  = git rev-parse --short HEAD 2>&1
    $Branch    = git rev-parse --abbrev-ref HEAD 2>&1
    $IsDirty   = (git status --porcelain 2>&1) -ne $null
} finally {
    Pop-Location
}

if ($LASTEXITCODE -ne 0) { throw 'Not inside a git repository or git is not on PATH.' }

# Pull version from the script header (e.g.  Version : 0.0.6)
$VersionLine = Get-Content (Join-Path $ScriptDir 'Update-DefenderOffline.ps1') |
    Select-String '^\s+Version\s+:\s+(\S+)' | Select-Object -First 1
$Version = if ($VersionLine) { $VersionLine.Matches[0].Groups[1].Value } else { 'unknown' }

$DirtyTag  = if ($IsDirty) { '-dirty' } else { '' }
$FolderName = "manage-defenderoffline-v${Version}-${ShortSha}${DirtyTag}"
$ZipName    = "${FolderName}.zip"

# ── Prepare output directory ───────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}
$ZipPath = Join-Path $OutputPath $ZipName

# ── Warn if uncommitted changes ────────────────────────────────────────────
if ($IsDirty) {
    Write-Warning "Working tree has uncommitted changes.  The zip will contain the COMMITTED state only (HEAD)."
    Write-Warning "Uncommitted edits will NOT be included.  Commit first if you need them in the release."
}

# ── Build zip via git archive ──────────────────────────────────────────────
# git archive exports tracked files only; gitignored and untracked files
# (hosts.conf, conf/dashboard.status, Config/*.xml) are never included.
# The --prefix argument puts everything inside a sub-folder in the zip.
Write-Host "Building release package..." -ForegroundColor Cyan
Write-Host "  Version : v$Version"
Write-Host "  Commit  : $ShortSha  ($Branch)"
Write-Host "  Output  : $ZipPath"
Write-Host ''

Push-Location $ScriptDir
try {
    git archive --format=zip --prefix="${FolderName}/" --output="$ZipPath" HEAD
    if ($LASTEXITCODE -ne 0) { throw "git archive failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}

$SizeKb = [math]::Round((Get-Item $ZipPath).Length / 1KB, 1)
Write-Host "Done.  $ZipName  ($SizeKb KB)" -ForegroundColor Green
Write-Host ''
Write-Host "Deploy steps:"
Write-Host "  1. Copy $ZipName to the lab machine"
Write-Host "  2. Expand-Archive -Path <zip> -DestinationPath C:\Temp"
Write-Host "  3. cd C:\Temp\$FolderName"
Write-Host "  4. Run the script you want to test"

if ($Open) { Start-Process $OutputPath }

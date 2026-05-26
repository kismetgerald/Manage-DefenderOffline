#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a release package for Manage-DefenderOffline.

.DESCRIPTION
    Creates a distributable ZIP archive (or a directly-staged folder) containing
    only the files an administrator needs to deploy and run the toolkit. Runtime
    artefacts (hosts.conf, dashboard.status, logs, reports, credentials) are
    excluded. The conf/config.conf template is included with all values blank so
    the admin can fill in their environment after extraction.

    The resulting package mirrors exactly what will be published on GitHub and
    what a deployer downloads. Use -Stage during test iterations to sync changes
    without the ZIP round-trip.

.PARAMETER OutputDir
    Directory where the ZIP file (or staged folder) will be created.
    Default: .\dist  (resolves to .dist\dist\ when run from the .dist folder)

.PARAMETER TestId
    Test-iteration identifier appended to the version number.
    Convention: lowercase letters a–z, then za, zb, zc, …
    Example: -TestId a  →  manage-defenderoffline-0.0.6a.zip

.PARAMETER NoVersion
    Omit the version number from the archive filename.
    Produces: manage-defenderoffline.zip

.PARAMETER Stage
    Copy files directly to OutputDir\manage-defenderoffline\ without creating a
    ZIP. Uses robocopy /MIR so only changed files are overwritten and files
    removed from the project are removed from the staging area. Ideal for rapid
    test iterations where ZIP extraction is an unnecessary step.

.PARAMETER Verify
    After staging or extracting the archive, parse every included .ps1 file and
    report any syntax errors before the build is declared successful.

.EXAMPLE
    .\release.ps1
    # Creates .\dist\manage-defenderoffline-0.0.6.zip

.EXAMPLE
    .\release.ps1 -TestId a
    # Creates .\dist\manage-defenderoffline-0.0.6a.zip

.EXAMPLE
    .\release.ps1 -Stage -TestId a
    # Syncs directly to .\dist\manage-defenderoffline\ (no ZIP)

.EXAMPLE
    .\release.ps1 -Stage -OutputDir C:\Temp\MDO-Test
    # Syncs to C:\Temp\MDO-Test\manage-defenderoffline\

.EXAMPLE
    .\release.ps1 -OutputDir C:\Temp\MDO-Releases -Verify
    # Creates ZIP and parses all included scripts for syntax errors
#>

param(
    [string]$OutputDir = ".\dist",
    [string]$TestId    = "",
    [switch]$NoVersion,
    [switch]$Stage,
    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$OutputDir   = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::Combine($ScriptDir, $OutputDir)
)

# ---------------------------------------------------------------------------
# Extract version from Update-DefenderOffline.ps1
# ---------------------------------------------------------------------------
$mainScript = Join-Path $ProjectRoot "Update-DefenderOffline.ps1"
if (-not (Test-Path $mainScript)) {
    Write-Error "Cannot find $mainScript — run this script from inside the .dist folder."
    exit 1
}

$versionLine = Select-String -Path $mainScript -Pattern '\$ScriptVersion\s*=\s*''([^'']+)'''
if (-not $versionLine) {
    Write-Error "Cannot extract `$ScriptVersion from $mainScript. Check the variable is present and single-quoted."
    exit 1
}
$version = $versionLine.Matches[0].Groups[1].Value
if ($TestId) { $version += $TestId }

$archiveStem = if ($NoVersion) { "manage-defenderoffline" } else { "manage-defenderoffline-$version" }
$archiveName = "$archiveStem.zip"
$stageFolderName = "manage-defenderoffline"

Write-Host ""
Write-Host "  Manage-DefenderOffline — Release Builder" -ForegroundColor Cyan
Write-Host "  Version : $version" -ForegroundColor White
Write-Host "  Mode    : $(if ($Stage) { 'Stage (no ZIP)' } else { 'ZIP' })" -ForegroundColor White
Write-Host "  Output  : $OutputDir" -ForegroundColor White
Write-Host ""

$buildSw = [System.Diagnostics.Stopwatch]::StartNew()

# ---------------------------------------------------------------------------
# Temporary staging directory
# ---------------------------------------------------------------------------
$dateStamp   = Get-Date -Format "yyyyMMddHHmmss"
$stagingDir  = Join-Path ([System.IO.Path]::GetTempPath()) "mdo-release-$dateStamp"
$stagingRoot = Join-Path $stagingDir $stageFolderName
New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null

# ---------------------------------------------------------------------------
# Manifest — files included in every release
# ---------------------------------------------------------------------------
$includeFiles = @(
    "Update-DefenderOffline.ps1",
    "Show-DefenderStatus.ps1",
    "Start-DefenderDashboard.ps1",
    "Install-DefenderDashboard.ps1",
    "Get-DefenderDefinitions.ps1",
    "README.md",
    "LICENSE.txt"
)

# Directories included in every release (with per-dir exclusion rules)
$includeDirs = [ordered]@{
    "conf" = @("dashboard.status")   # key = dir name, value = files to exclude
    "lib"  = @()                     # shared helper modules dot-sourced by scripts
}

# ---------------------------------------------------------------------------
# Copy files
# ---------------------------------------------------------------------------
foreach ($file in $includeFiles) {
    $src = Join-Path $ProjectRoot $file
    $sw  = [System.Diagnostics.Stopwatch]::StartNew()
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $stagingRoot $file) -Force
        $sw.Stop()
        Write-Host ("  + {0,-42} [{1:N2}s]" -f $file, $sw.Elapsed.TotalSeconds) -ForegroundColor Green
    } else {
        Write-Warning "  ! Not found, skipping: $file"
    }
}

# ---------------------------------------------------------------------------
# Copy directories (with exclusions applied)
# ---------------------------------------------------------------------------
foreach ($dirName in $includeDirs.Keys) {
    $src       = Join-Path $ProjectRoot $dirName
    $dst       = Join-Path $stagingRoot $dirName
    $excludes  = $includeDirs[$dirName]
    $sw        = [System.Diagnostics.Stopwatch]::StartNew()

    if (Test-Path $src) {
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        Get-ChildItem -Path $src -File | Where-Object { $_.Name -notin $excludes } | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination (Join-Path $dst $_.Name) -Force
        }
        $sw.Stop()
        $copied = @(Get-ChildItem -Path $dst -File).Count
        Write-Host ("  + {0,-42} [{1:N2}s]  ({2} files)" -f "$dirName/", $sw.Elapsed.TotalSeconds, $copied) -ForegroundColor Green
    } else {
        Write-Warning "  ! Directory not found, skipping: $dirName"
    }
}

$fileCount = (Get-ChildItem -Path $stagingRoot -Recurse -File).Count
Write-Host ("  * Staged {0} files total" -f $fileCount) -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Optional syntax verification
# ---------------------------------------------------------------------------
if ($Verify) {
    Write-Host ""
    Write-Host "  Verifying script syntax..." -ForegroundColor Cyan
    $failedScripts = @(
        Get-ChildItem -Path $stagingRoot -Recurse -Filter "*.ps1" | ForEach-Object {
            $tokens = $null; $parseErrors = $null
            $null   = [System.Management.Automation.Language.Parser]::ParseFile(
                $_.FullName, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -eq 0) {
                Write-Host ("  ✓ {0}" -f $_.Name) -ForegroundColor Green
            } else {
                Write-Host ("  ✗ {0}" -f $_.Name) -ForegroundColor Red
                $parseErrors | ForEach-Object {
                    Write-Host ("      Line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Red
                }
                $_.Name   # pipeline output collected into $failedScripts
            }
        }
    )
    if ($failedScripts.Count -gt 0) {
        Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Error "Syntax errors in: $($failedScripts -join ', ') — build aborted."
        exit 1
    }
    Write-Host "  All scripts OK" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Create output directory
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ---------------------------------------------------------------------------
# Deliver: Stage or ZIP
# ---------------------------------------------------------------------------
if ($Stage) {
    $sw          = [System.Diagnostics.Stopwatch]::StartNew()
    $stageTarget = Join-Path $OutputDir $stageFolderName
    $roboArgs    = @($stagingRoot, $stageTarget, "/MIR", "/NJH", "/NJS", "/NP", "/NDL", "/NFL")
    & robocopy @roboArgs | Out-Null
    $robocopyExit = $LASTEXITCODE
    if ($robocopyExit -gt 7) {
        Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Error "robocopy failed with exit code $robocopyExit"
        exit 1
    }
    $sw.Stop()

    Write-Host ""
    Write-Host "  Release staged:" -ForegroundColor Cyan
    Write-Host "  $stageTarget" -ForegroundColor White
    Write-Host ("  Files: {0} | Sync time: {1:N2}s" -f $fileCount, $sw.Elapsed.TotalSeconds) -ForegroundColor Gray
} else {
    $archivePath = Join-Path $OutputDir $archiveName
    if (Test-Path $archivePath) { Remove-Item $archivePath -Force }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "  Compressing..." -ForegroundColor DarkGray
    Compress-Archive -Path $stagingRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $sw.Stop()

    $item        = Get-Item $archivePath
    $archiveSize = "$([math]::Round($item.Length / 1KB, 1)) KB"

    Write-Host ""
    Write-Host "  Release package created:" -ForegroundColor Cyan
    Write-Host "  $archivePath" -ForegroundColor White
    Write-Host ("  Files: {0} | Size: {1} | Compress time: {2:N2}s" -f $fileCount, $archiveSize, $sw.Elapsed.TotalSeconds) -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Cleanup temp staging
# ---------------------------------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Remove-Item -Path $stagingDir -Recurse -Force
$sw.Stop()
Write-Host ("  * Temp staging cleaned up  [{0:N2}s]" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray

$buildSw.Stop()
Write-Host ""
Write-Host ("  Total build time: {0:N2}s" -f $buildSw.Elapsed.TotalSeconds) -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Next steps
# ---------------------------------------------------------------------------
if ($Stage) {
    $stageTarget = Join-Path $OutputDir $stageFolderName
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Edit conf\config.conf in the staging area with your environment values:"
    Write-Host "         notepad `"$stageTarget\conf\config.conf`"" -ForegroundColor Gray
    Write-Host "    2. Run scripts from the staging area as you would in production:"
    Write-Host "         cd `"$stageTarget`"" -ForegroundColor Gray
    Write-Host "         .\Update-DefenderOffline.ps1 -WhatIfMode" -ForegroundColor Gray
} else {
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Extract the archive to your staging location:"
    Write-Host "         Expand-Archive `"$archivePath`" -DestinationPath C:\Temp\MDO-Test\" -ForegroundColor Gray
    Write-Host "    2. Edit conf\config.conf with your environment values:"
    Write-Host "         notepad C:\Temp\MDO-Test\$stageFolderName\conf\config.conf" -ForegroundColor Gray
    Write-Host "    3. Run scripts from the extracted directory:"
    Write-Host "         cd C:\Temp\MDO-Test\$stageFolderName" -ForegroundColor Gray
    Write-Host "         .\Update-DefenderOffline.ps1 -WhatIfMode" -ForegroundColor Gray
}
Write-Host ""
exit 0

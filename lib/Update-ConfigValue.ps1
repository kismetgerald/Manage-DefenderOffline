<#
.SYNOPSIS
    Write a single key=value pair into conf/config.conf while preserving comments,
    blank lines, and section structure.

.DESCRIPTION
    The config parser (Read-ConfigFile in each script) is one-way — read-only. This
    helper is the symmetric write path, used by code that needs to persist a value
    back to config.conf (e.g. the installer writing CertificateThumbprint after
    generating a self-signed cert).

    Behavior:
      - If the key exists in the named section, its value is updated in place.
      - If the key exists in a different section, it is updated there (sections are
        organizational only — keys are globally unique in the parser's view).
      - If the key doesn't exist, it is appended to the named section (or to the end
        of the file if the section doesn't exist).
      - Comments, blank lines, and section headers are preserved exactly.
      - Values containing spaces or special chars are NOT auto-quoted; pass quoted
        values in -Value if you need them.

.PARAMETER Path
    Path to config.conf.

.PARAMETER Section
    Section to write the key into (e.g. 'Dashboard'). The bracketed header [Section]
    must already exist in the file for in-section append; otherwise the key is
    appended to the end of the file with a fresh section header.

.PARAMETER Key
    Key name (e.g. 'CertificateThumbprint'). Case-insensitive match against existing
    keys.

.PARAMETER Value
    Value to write. Whitespace is preserved as supplied.

.NOTES
    Dot-source from each script that needs it:
        . (Join-Path $PSScriptRoot 'lib\Update-ConfigValue.ps1')

    Future enhancement: a -Comment parameter that lets the caller attach a comment
    line above the new key when appending. Not needed for v0.0.7 use cases.
#>
function Update-ConfigValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Section,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }

    $lines        = Get-Content -LiteralPath $Path
    $newLines     = [System.Collections.Generic.List[string]]::new()
    $keyPattern   = "^\s*$([regex]::Escape($Key))\s*="
    $sectionPattern = "^\s*\[\s*$([regex]::Escape($Section))\s*\]\s*$"
    $anySectionPattern = "^\s*\[\s*[^\]]+\s*\]\s*$"

    $keyReplaced     = $false
    $inTargetSection = $false
    $sectionFound    = $false
    $lastTargetSectionIndex = -1

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        # Detect section transitions
        if ($line -match $anySectionPattern) {
            $inTargetSection = ($line -match $sectionPattern)
            if ($inTargetSection) {
                $sectionFound = $true
                $lastTargetSectionIndex = $newLines.Count  # remember position for append-if-not-found
            }
        }

        # Update an existing key (regardless of section — keys are globally unique)
        if (-not $keyReplaced -and $line -match $keyPattern) {
            $newLines.Add("$Key = $Value")
            $keyReplaced = $true
            continue
        }

        $newLines.Add($line)
    }

    if (-not $keyReplaced) {
        if ($sectionFound) {
            # Append after the last line of the target section (before the next section header)
            # Walk forward from $lastTargetSectionIndex to find the insertion point
            $insertAt = $newLines.Count
            for ($j = $lastTargetSectionIndex + 1; $j -lt $newLines.Count; $j++) {
                if ($newLines[$j] -match $anySectionPattern) {
                    $insertAt = $j
                    break
                }
            }
            # Trim trailing blank lines back into the section before inserting
            while ($insertAt -gt 0 -and [string]::IsNullOrWhiteSpace($newLines[$insertAt - 1])) {
                $insertAt--
            }
            $newLines.Insert($insertAt, "$Key = $Value")
        } else {
            # Section doesn't exist — append both
            if ($newLines.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($newLines[$newLines.Count - 1])) {
                $newLines.Add('')
            }
            $newLines.Add("[$Section]")
            $newLines.Add("$Key = $Value")
        }
    }

    if ($PSCmdlet.ShouldProcess($Path, "Update $Section/$Key = $Value")) {
        Set-Content -LiteralPath $Path -Value $newLines -Encoding UTF8
    }
}

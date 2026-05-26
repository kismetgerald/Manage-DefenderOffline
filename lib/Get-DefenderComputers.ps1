# ============================================================================
# Get-DefenderComputers.ps1
#
# Shared AD auto-discovery for the three discovery-aware scripts
# (Update-DefenderOffline, Show-DefenderStatus, Start-DefenderDashboard).
# Returns a structured result so each caller can log per-DN status in its
# own style and decide whether to persist the result (e.g. hosts.conf).
#
# Honors the v0.0.8 -ADSearchBase parameter:
#   - Empty / whitespace        -> whole-domain search (current behavior)
#   - Single DN                 -> single Get-ADComputer -SearchBase call
#   - Semicolon-separated list  -> per-DN search, union, deduplicate by Name
#
# Hybrid validation: each DN is attempted in turn. Unresolvable DNs are
# captured in the result; the caller decides whether to WARN and continue
# (some DNs resolved) or throw (zero DNs resolved).
# ============================================================================

function Get-DefenderComputers {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Semicolon-separated AD DNs. Commas are valid inside DNs so a comma
        # delimiter would be ambiguous. Empty = whole-domain search.
        [AllowEmptyString()]
        [string]$SearchBase = '',

        # Explicit AD bind credential. When supplied we use DirectoryEntry
        # with explicit creds for the ADSI fallback, and Get-ADComputer
        # -Credential for the RSAT path. Mirrors the v0.0.6 -ADCredential
        # pattern.
        [pscredential]$ADCredential
    )

    # Parse the search-base list. Empty input == one "whole-domain" entry.
    $bases = @()
    if ($SearchBase -and $SearchBase.Trim()) {
        $bases = @($SearchBase -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    $isFiltered = $bases.Count -gt 0
    if (-not $isFiltered) { $bases = @('') }   # sentinel for whole-domain pass

    $hasAdModule = [bool](Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue)
    if ($hasAdModule) {
        try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
            # If the module exists but fails to load, fall through to ADSI.
            $hasAdModule = $false
        }
    }

    $domain = $null
    try {
        $domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain
    } catch {
        # Some environments (sandboxes, locked-down CIs) can't query Win32_*.
        # ADSI binds without an explicit root will fail later; surface that
        # naturally rather than failing here.
    }

    $names      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $baseStatus = New-Object 'System.Collections.Generic.List[pscustomobject]'
    $ldapFilter = '(&(objectCategory=computer)(operatingSystem=*Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'

    foreach ($base in $bases) {
        $statusEntry = [pscustomobject]@{
            DN       = if ($base) { $base } else { '(whole domain)' }
            Resolved = $false
            Count    = 0
            Error    = $null
        }

        try {
            if ($hasAdModule) {
                $adParams = @{
                    Filter     = 'OperatingSystem -like "*Windows*" -and Enabled -eq $true'
                    Properties = 'Name'
                }
                if ($base)         { $adParams.SearchBase  = $base; $adParams.SearchScope = 'Subtree' }
                if ($ADCredential) { $adParams.Credential  = $ADCredential }
                $found = @(Get-ADComputer @adParams | Select-Object -ExpandProperty Name)
            } else {
                $rootUrl = if ($base) { "LDAP://$base" } else { "LDAP://$domain" }
                if ($ADCredential) {
                    $de = [System.DirectoryServices.DirectoryEntry]::new(
                        $rootUrl,
                        $ADCredential.UserName,
                        $ADCredential.GetNetworkCredential().Password)
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new($de)
                    $searcher.Filter = $ldapFilter
                } else {
                    $searcher = [adsisearcher]$ldapFilter
                    $searcher.SearchRoot = $rootUrl
                }
                $searcher.SearchScope = 'Subtree'
                $found = @($searcher.FindAll() | ForEach-Object { $_.Properties.name[0] })
                if ($ADCredential -and $de) { $de.Dispose() }
            }

            foreach ($n in $found) { if ($n) { [void]$names.Add($n) } }
            $statusEntry.Resolved = $true
            $statusEntry.Count    = $found.Count
        } catch {
            $statusEntry.Error = $_.Exception.Message
        }

        [void]$baseStatus.Add($statusEntry)
    }

    return [pscustomobject]@{
        Computers     = @($names | Sort-Object)
        SearchBases   = $baseStatus.ToArray()
        UsedAdModule  = $hasAdModule
        WasFiltered   = $isFiltered
    }
}

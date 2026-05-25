<#
.SYNOPSIS
    Single chokepoint for all WinRM remote execution in the Manage-DefenderOffline toolkit.
    Wraps Invoke-Command and New-PSSession with consistent timeout, credential, and
    authentication handling.

.DESCRIPTION
    Two functions exported:

      New-DefenderRemoteSession  - create a PSSession with the toolkit's standard options
                                   (timeout, retry semantics). Use this everywhere instead
                                   of calling New-PSSession directly.

      Invoke-DefenderRemote      - execute a scriptblock against either a -ComputerName
                                   (one-shot) or an existing -Session (reuse).

    The reason this layer exists: Pester tests mock these two functions to verify
    parameter values without making real network calls. Every WinRM-touching code path
    in the toolkit goes through here.

.NOTES
    Dot-source this file from each script that needs it:
        . (Join-Path $PSScriptRoot 'lib\Invoke-DefenderRemote.ps1')
#>


<#
.SYNOPSIS
    Create a PSSession with the toolkit's standard options.

.PARAMETER ComputerName
    Target endpoint hostname or IP.

.PARAMETER Credential
    PSCredential for the WinRM session. Omit to use the caller's context.

.PARAMETER TimeoutSeconds
    Applied to both OperationTimeout and OpenTimeout. Default 30.

.PARAMETER Authentication
    WinRM authentication mechanism. Default lets PowerShell choose (typically Kerberos
    on domain, Negotiate on workgroup).
#>
function New-DefenderRemoteSession {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [pscredential]$Credential,

        # Opt-in. If omitted, no -SessionOption is applied (system default timeouts).
        # If supplied, builds a SessionOption with OperationTimeout/OpenTimeout set to
        # this value (seconds) and a fixed 5s CancelTimeout.
        [ValidateRange(5, 600)]
        [int]$TimeoutSeconds,

        [ValidateSet('Default', 'Basic', 'Credssp', 'Digest', 'Kerberos', 'Negotiate', 'NegotiateWithImplicitCredential')]
        [string]$Authentication = 'Default'
    )

    $params = @{
        ComputerName = $ComputerName
        ErrorAction  = 'Stop'
    }
    if ($Credential)                   { $params.Credential     = $Credential }
    if ($Authentication -ne 'Default') { $params.Authentication = $Authentication }
    if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) {
        $params.SessionOption = New-PSSessionOption `
            -OperationTimeout ($TimeoutSeconds * 1000) `
            -OpenTimeout      ($TimeoutSeconds * 1000) `
            -CancelTimeout    5000
    }

    New-PSSession @params
}


<#
.SYNOPSIS
    Execute a scriptblock against a remote endpoint via WinRM.

.PARAMETER ComputerName
    Target endpoint hostname. One-shot mode: the wrapper creates and disposes the
    session for you. Use -Session instead when making multiple calls to the same host.

.PARAMETER Session
    Existing PSSession (typically from New-DefenderRemoteSession). The script is
    responsible for the session lifecycle. Use this for per-host loops that make
    multiple Invoke-Command calls against the same target.

.PARAMETER ScriptBlock
    Code to execute on the remote endpoint.

.PARAMETER Credential
    Only honored with -ComputerName. Ignored with -Session (session already has its creds).

.PARAMETER TimeoutSeconds
    Only honored with -ComputerName. Ignored with -Session.

.PARAMETER ArgumentList
    Positional arguments passed to the scriptblock.

.PARAMETER Authentication
    Only honored with -ComputerName. Ignored with -Session.
#>
function Invoke-DefenderRemote {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ComputerName')]
        [string]$ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [pscredential]$Credential,

        # Opt-in. Only honored with -ComputerName. If omitted, system default
        # timeouts apply.
        [ValidateRange(5, 600)]
        [int]$TimeoutSeconds,

        [object[]]$ArgumentList,

        [ValidateSet('Default', 'Basic', 'Credssp', 'Digest', 'Kerberos', 'Negotiate', 'NegotiateWithImplicitCredential')]
        [string]$Authentication = 'Default'
    )

    $params = @{
        ScriptBlock = $ScriptBlock
        ErrorAction = 'Stop'
    }
    if ($ArgumentList) { $params.ArgumentList = $ArgumentList }

    if ($PSCmdlet.ParameterSetName -eq 'Session') {
        $params.Session = $Session
    } else {
        $params.ComputerName = $ComputerName
        if ($Credential)                   { $params.Credential     = $Credential }
        if ($Authentication -ne 'Default') { $params.Authentication = $Authentication }
        if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) {
            $params.SessionOption = New-PSSessionOption `
                -OperationTimeout ($TimeoutSeconds * 1000) `
                -OpenTimeout      ($TimeoutSeconds * 1000) `
                -CancelTimeout    5000
        }
    }

    Invoke-Command @params
}

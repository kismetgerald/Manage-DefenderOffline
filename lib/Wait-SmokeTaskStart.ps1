<#
.SYNOPSIS
    Wait up to N seconds for a one-shot scheduled task to actually start
    running. Used by Install-ManageDefender.ps1's -RunNowWhatIf path.

.DESCRIPTION
    Register-ScheduledTask + Start-ScheduledTask are both fire-and-forget:
    they return success once the task is queued, not once Windows has
    actually started executing it. In the v0.0.19 lab pass we hit a case
    where Start-ScheduledTask returned cleanly but the smoke task never
    actually ran (suspected silent contention with another task running
    under the same identity, e.g. the just-started Dashboard task).

    The completion-poll loop in the installer can't tell the difference
    between "task is running and will finish soon" and "task was queued
    but never started" because both states leave LastRunTime stale and
    State != Running. So it would wait the full deadline (10 minutes)
    before timing out. Operators reading the screen typically gave up
    after ~1 minute, with no signal about what went wrong.

    This helper provides the missing signal: it polls Get-ScheduledTask /
    Get-ScheduledTaskInfo for up to -TimeoutSeconds, returning as soon as
    EITHER:
      - The task is currently in the Running state, OR
      - The task already finished (LastRunTime advanced past -StartedAfter)
        AND LastTaskResult is not 267009 ("task has not yet run").

    Returns a structured result so the caller can decide how to surface
    the outcome via its own logger.

.PARAMETER TaskName
    Scheduled task name (typically the one-shot smoke-test name).

.PARAMETER TaskPath
    Task Scheduler folder containing the task (e.g. '\Manage-DefenderOffline\').
    Must include the leading and trailing backslash that Task Scheduler expects.

.PARAMETER StartedAfter
    The wall-clock time recorded immediately before Start-ScheduledTask was
    called. The helper considers the task "started" if LastRunTime advances
    past this value.

.PARAMETER TimeoutSeconds
    Maximum wait, in seconds. Default 20s — enough to ride out any normal
    Task Scheduler dispatch delay while bailing quickly enough that the
    install doesn't appear hung.

.PARAMETER PollIntervalSeconds
    Polling cadence. Default 1s.

.OUTPUTS
    [pscustomobject] with properties:
      Started  [bool]   $true if Running or LastRunTime advanced; else $false
      Reason   [string] 'running' | 'finished-fast' | 'timeout'
      Task               (last Get-ScheduledTask result, or $null)
      Info               (last Get-ScheduledTaskInfo result, or $null)
      ElapsedSeconds [int] Wall-clock seconds actually waited

.EXAMPLE
    $smokeStart = Get-Date
    Start-ScheduledTask -TaskName $smoke -TaskPath '\X\'
    $r = Wait-SmokeTaskStart -TaskName $smoke -TaskPath '\X\' -StartedAfter $smokeStart
    if (-not $r.Started) {
        Write-Warn "Task did not start within $($r.ElapsedSeconds)s — skipping poll."
        return
    }
    # ...enter normal completion-poll loop...

.NOTES
    Dot-source from the installer:
        . (Join-Path $PSScriptRoot 'lib\Wait-SmokeTaskStart.ps1')

    Side-effect-free: no Write-* calls; caller decides how to log.
    Get-ScheduledTask / Get-ScheduledTaskInfo / Start-Sleep / Get-Date are
    mockable in Pester so the helper has unit-test coverage for the
    started, finished-fast, and timeout paths.
#>
function Wait-SmokeTaskStart {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$TaskName,
        [Parameter(Mandatory)] [string]$TaskPath,
        [Parameter(Mandatory)] [datetime]$StartedAfter,
        [int]$TimeoutSeconds      = 20,
        [int]$PollIntervalSeconds = 1
    )

    # 267009 (0x00041309) = SCHED_S_TASK_HAS_NOT_RUN. When LastTaskResult is
    # this sentinel, Task Scheduler is reporting "this task has never run",
    # not a real exit code from a prior invocation. Ignore it.
    $TASK_HAS_NOT_RUN = 267009

    $startWall = Get-Date
    $deadline  = $startWall.AddSeconds($TimeoutSeconds)
    $task      = $null
    $info      = $null

    do {
        Start-Sleep -Seconds $PollIntervalSeconds

        $task = Get-ScheduledTask     -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue

        if ($task -and $task.State -eq 'Running') {
            return [pscustomobject]@{
                Started        = $true
                Reason         = 'running'
                Task           = $task
                Info           = $info
                ElapsedSeconds = [int]((Get-Date) - $startWall).TotalSeconds
            }
        }

        if ($info -and $null -ne $info.LastRunTime `
                -and $info.LastRunTime -gt $StartedAfter `
                -and $info.LastTaskResult -ne $TASK_HAS_NOT_RUN) {
            return [pscustomobject]@{
                Started        = $true
                Reason         = 'finished-fast'
                Task           = $task
                Info           = $info
                ElapsedSeconds = [int]((Get-Date) - $startWall).TotalSeconds
            }
        }
    } while ((Get-Date) -lt $deadline)

    return [pscustomobject]@{
        Started        = $false
        Reason         = 'timeout'
        Task           = $task
        Info           = $info
        ElapsedSeconds = [int]((Get-Date) - $startWall).TotalSeconds
    }
}

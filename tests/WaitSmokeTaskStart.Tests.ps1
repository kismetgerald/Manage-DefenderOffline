#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Tests for lib/Wait-SmokeTaskStart.ps1 — the helper that distinguishes
"task is running / has run" from "Task Scheduler queued it but never
actually dispatched it."

Pester mocks Get-ScheduledTask, Get-ScheduledTaskInfo, and Start-Sleep
so we can synthesise each state without spinning up real scheduled
tasks. Tests run with short -TimeoutSeconds so the timeout path stays
fast.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'lib\Wait-SmokeTaskStart.ps1')

    # 267009 = SCHED_S_TASK_HAS_NOT_RUN. Reused in the assertions below.
    $script:TASK_HAS_NOT_RUN = 267009
}

Describe 'lib/Wait-SmokeTaskStart.ps1' {

    BeforeEach {
        # Shave real wall-clock from the tests. The helper uses Get-Date for
        # its own deadline tracking, so we can't mock Start-Sleep to literal
        # zero without breaking the deadline loop — but a tiny mocked sleep
        # keeps each polling iteration fast.
        Mock Start-Sleep { }
        $script:StartedAfter = (Get-Date).AddSeconds(-1)
    }

    Context 'Task is Running' {

        It 'returns Started=true / Reason=running when the task is observed Running' {
            Mock Get-ScheduledTask     { [pscustomobject]@{ State = 'Running' } }
            Mock Get-ScheduledTaskInfo { [pscustomobject]@{ LastRunTime = $null; LastTaskResult = $script:TASK_HAS_NOT_RUN } }

            $r = Wait-SmokeTaskStart -TaskName 'x' -TaskPath '\y\' -StartedAfter $script:StartedAfter -TimeoutSeconds 5

            $r.Started | Should -BeTrue
            $r.Reason  | Should -Be 'running'
        }
    }

    Context 'Task finished before we could observe Running' {

        It 'returns Started=true / Reason=finished-fast when LastRunTime advanced past StartedAfter' {
            $finishedTime = (Get-Date)   # later than $StartedAfter
            Mock Get-ScheduledTask     { [pscustomobject]@{ State = 'Ready' } }
            Mock Get-ScheduledTaskInfo { [pscustomobject]@{ LastRunTime = $finishedTime; LastTaskResult = 0 } }

            $r = Wait-SmokeTaskStart -TaskName 'x' -TaskPath '\y\' -StartedAfter $script:StartedAfter -TimeoutSeconds 5

            $r.Started | Should -BeTrue
            $r.Reason  | Should -Be 'finished-fast'
        }

        It 'does NOT treat LastTaskResult=267009 (TASK_HAS_NOT_RUN) as a finish, even with a fresh LastRunTime' {
            # Synthetic adversarial state: Task Scheduler reports LastRunTime
            # but LastTaskResult is the SCHED_S_TASK_HAS_NOT_RUN sentinel.
            # Treat as "never actually ran" -> keep polling until timeout.
            $bogusTime = (Get-Date)
            Mock Get-ScheduledTask     { [pscustomobject]@{ State = 'Ready' } }
            Mock Get-ScheduledTaskInfo { [pscustomobject]@{ LastRunTime = $bogusTime; LastTaskResult = $script:TASK_HAS_NOT_RUN } }

            $r = Wait-SmokeTaskStart -TaskName 'x' -TaskPath '\y\' -StartedAfter $script:StartedAfter `
                                     -TimeoutSeconds 2 -PollIntervalSeconds 1

            $r.Started | Should -BeFalse
            $r.Reason  | Should -Be 'timeout'
        }

        It 'does NOT treat a stale LastRunTime (older than StartedAfter) as a finish' {
            $staleTime = $script:StartedAfter.AddMinutes(-1)
            Mock Get-ScheduledTask     { [pscustomobject]@{ State = 'Ready' } }
            Mock Get-ScheduledTaskInfo { [pscustomobject]@{ LastRunTime = $staleTime; LastTaskResult = 0 } }

            $r = Wait-SmokeTaskStart -TaskName 'x' -TaskPath '\y\' -StartedAfter $script:StartedAfter `
                                     -TimeoutSeconds 2 -PollIntervalSeconds 1

            $r.Started | Should -BeFalse
            $r.Reason  | Should -Be 'timeout'
        }
    }

    Context 'Task never starts (the v0.0.19 hang scenario)' {

        It 'returns Started=false / Reason=timeout when neither Running nor a fresh LastRunTime is observed' {
            Mock Get-ScheduledTask     { [pscustomobject]@{ State = 'Ready' } }
            Mock Get-ScheduledTaskInfo { [pscustomobject]@{ LastRunTime = $null; LastTaskResult = $script:TASK_HAS_NOT_RUN } }

            $r = Wait-SmokeTaskStart -TaskName 'x' -TaskPath '\y\' -StartedAfter $script:StartedAfter `
                                     -TimeoutSeconds 2 -PollIntervalSeconds 1

            $r.Started        | Should -BeFalse
            $r.Reason         | Should -Be 'timeout'
            $r.ElapsedSeconds | Should -BeGreaterOrEqual 1
        }

        It 'still returns a structured result when Get-ScheduledTask returns nothing (task disappeared)' {
            Mock Get-ScheduledTask     { $null }
            Mock Get-ScheduledTaskInfo { $null }

            $r = Wait-SmokeTaskStart -TaskName 'x' -TaskPath '\y\' -StartedAfter $script:StartedAfter `
                                     -TimeoutSeconds 2 -PollIntervalSeconds 1

            $r.Started | Should -BeFalse
            $r.Reason  | Should -Be 'timeout'
            $r.Task    | Should -BeNullOrEmpty
            $r.Info    | Should -BeNullOrEmpty
        }
    }

    Context 'Late start (task starts after a brief queue delay)' {

        It 'observes Running on a later poll iteration' {
            $script:PollCount = 0
            Mock Get-ScheduledTask {
                $script:PollCount++
                if ($script:PollCount -ge 2) {
                    [pscustomobject]@{ State = 'Running' }
                } else {
                    [pscustomobject]@{ State = 'Ready' }
                }
            }
            Mock Get-ScheduledTaskInfo { [pscustomobject]@{ LastRunTime = $null; LastTaskResult = $script:TASK_HAS_NOT_RUN } }

            $r = Wait-SmokeTaskStart -TaskName 'x' -TaskPath '\y\' -StartedAfter $script:StartedAfter `
                                     -TimeoutSeconds 5 -PollIntervalSeconds 1

            $r.Started | Should -BeTrue
            $r.Reason  | Should -Be 'running'
        }
    }
}

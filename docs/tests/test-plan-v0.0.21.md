# Test Plan — v0.0.21 (Manage-DefenderOffline)

## Baseline

`main` at commit `9673041` (v0.0.21 release).
**Tag:** `v0.0.21`
**Test bundle:** `manage-defenderoffline-0.0.21.zip` (207 KB, 19 entries, attached to the GitHub pre-release at https://github.com/kismetgerald/Manage-DefenderOffline/releases/tag/v0.0.21).

## Purpose

v0.0.21 is a polish release: three queued startup items from the v0.0.14 phase-profiling work plus stale `.NOTES` block hygiene across the script set. No new components, no breaking config schema, no migration path needed. The scenarios below validate that the changes do what they say AND that nothing in the v0.0.20 happy path regressed.

Changes validated by this test plan:

| # | Change | File(s) |
|---|---|---|
| A | `.NOTES` Version / Last Updated blocks bumped from `0.0.6`/`0.0.9` → `0.0.21` in 4 scripts | `Update-DefenderOffline.ps1`, `Show-DefenderStatus.ps1`, `Start-DefenderDashboard.ps1`, `Get-DefenderDefinitions.ps1` |
| B | Pre-timer gap measurement — `event=startup_gap pwsh_load_and_parse_ms=N` emitted right after `Start-StartupTimer` | `Start-DefenderDashboard.ps1` |
| C | Async `Write-EventLog` at startup — EventId 100/101 dispatched via `Start-ThreadJob` | `Start-DefenderDashboard.ps1` |
| D | Per-entry resolution timing — `DurationMs` on `Resolve-DashboardAllowedGroups.Resolutions[]`; `event=auth_resolve` gains `duration_ms=<N>` | `Start-DefenderDashboard.ps1` |

### Key behaviors

1. **`startup_gap` is informational, not functional.** A missing or zero value doesn't break the dashboard — it just means `Get-Process -Id $PID` failed and the surrounding `try` swallowed the error.
2. **Async EventLog has a known trade-off.** If the dashboard process dies between `Start-ThreadJob` dispatch and the actual `Write-EventLog` call (~ms window), the EventId 100/101 won't post to Windows Event Log. The same start info is captured in the dashboard file log, so this is acceptable for a status event but worth noting if SIEM rules are built on the Windows Event Log entry.
3. **`duration_ms` on `auth_resolve` is ADIntegrated-mode only.** The event line is only emitted when `AuthMethod=ADIntegrated` and `AuthAllowedGroups` has at least one entry. Other auth modes don't run `Resolve-DashboardAllowedGroups` at startup.
4. **All four new signatures are additive.** Existing log parsers that key on event name will see new key/value pairs at the end of `auth_resolve` lines but no removed or renamed fields. Positional parsers would need to handle the extra key.

### Out of scope for v0.0.21 testing

- **gMSA paths.** Still field-untested per [`project_gmsa_untested.md`](../../../../../C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/project_gmsa_untested.md). All v0.0.21 scenarios target traditional `-ServiceAccount` + `-Credential`.
- **Downloader component.** Still reserved for a later release.
- **GUI feature changes.** Soft-frozen per [`feedback_gui_freeze.md`](../../../../../C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/feedback_gui_freeze.md). `Show-DefenderStatus.ps1` only got its `.NOTES` Version bumped — no behavior change.

---

## Environment

Same as v0.0.20:

- **Admin workstation (lab build host):** Windows 10/11, PowerShell 7+, network access to the test endpoint over WinRM 5985.
- **Test endpoint:** Windows 10/11 or Server 2016+, WinRM enabled, local admin via the traditional service account.
- **Service account:** Traditional domain account with local admin on the test endpoint.
- **Test workflow:** Extract `manage-defenderoffline-0.0.21.zip` to `C:\Temp\MDO-Testing\0.0.21` on the test endpoint and run from there. ([`feedback_testing_workflow.md`](../../../../../C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/feedback_testing_workflow.md))

## Setup

The bundle is extracted at `C:\Temp\MDO-Testing\manage-defenderoffline-0.0.21\`. All scenarios below assume this is the current working directory:

```powershell
Set-Location 'C:\Temp\MDO-Testing\manage-defenderoffline-0.0.21'

# Unblock the extracted files (Mark-of-the-Web from the ZIP download).
Get-ChildItem -Recurse -File | Unblock-File
```

Capture the v0.0.20 cold-start baseline before installing v0.0.21 (only matters if upgrading in place — fresh installs skip this):

```powershell
# Tail the most recent dashboard log on a v0.0.20.x install.
$logDir = 'C:\Logs\DefenderDashboard'
$lastLog = Get-ChildItem $logDir -Filter '*.log' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Select-String -Path $lastLog.FullName -Pattern 'event=startup_complete' | Select-Object -Last 1
# Record the total_ms number for comparison against v0.0.21
```

---

### v0.0.21a — Bundle baseline (file presence, version stamps, .NOTES hygiene)

**Purpose:** Read-only sanity checks against the shipped bundle before any install runs. Confirms that `$ScriptVersion` was bumped uniformly and the `.NOTES` `Version` / `Last Updated` blocks are now in sync.

**Setup:** Bundle extracted; no installer run yet.

**Steps:**

1. Confirm `$ScriptVersion = '0.0.21'` in all five scripts:

```powershell
Select-String -Path .\*.ps1 -Pattern "ScriptVersion\s*=\s*'0\.0\.21'"
# Expect 5 matches:
#   Get-DefenderDefinitions.ps1
#   Install-ManageDefender.ps1
#   Show-DefenderStatus.ps1
#   Start-DefenderDashboard.ps1
#   Update-DefenderOffline.ps1
```

2. Confirm `.NOTES` Version blocks were updated in the 4 scripts that had stale values:

```powershell
Select-String -Path .\*.ps1 -Pattern '^\s+Version\s+:\s+0\.0\.21'
# Expect 4 matches (Install-ManageDefender.ps1 has no Version line in its .NOTES — design choice).
```

3. Confirm `.NOTES` Last Updated dates were aligned:

```powershell
Select-String -Path .\*.ps1 -Pattern '^\s+Last Updated\s+:\s+2026-06-04'
# Expect 4 matches matching the v0.0.21 release date.
```

4. Confirm `Get-Help` surfaces the new version (spot-check one script):

```powershell
(Get-Help .\Start-DefenderDashboard.ps1 -Full).alertSet.alert[0].Text -split "`n" |
    Select-String 'Version|Last Updated'
# Expect:
#   Version        : 0.0.21
#   Last Updated   : 2026-06-04
```

5. Confirm the 3 new code paths exist in `Start-DefenderDashboard.ps1`:

```powershell
Select-String -Path .\Start-DefenderDashboard.ps1 -Pattern 'event=startup_gap|Start-ThreadJob|DurationMs\s*='
# Expect at least 3 matches covering the 3 code paths (B, C, D).
```

**Expected result:**

- [ ] `$ScriptVersion = '0.0.21'` in all five scripts
- [ ] `.NOTES Version : 0.0.21` in 4 scripts
- [ ] `.NOTES Last Updated : 2026-06-04` in 4 scripts
- [ ] `Get-Help` output shows the bumped Version
- [ ] All three new code paths (B/C/D) present in `Start-DefenderDashboard.ps1` source

**Result:** _Pending lab run._

---

### v0.0.21b — Dashboard cold start: startup_gap + async event_log + startup_complete delta

**Purpose:** This is the headline scenario. Validates all three runtime changes (B + C + D's underlying timer) by tailing a single dashboard cold-start log. Cold start = first restart after a reboot or after stopping the scheduled task long enough for caches to clear.

**Setup:** v0.0.21 installed on the test endpoint via `Install-ManageDefender.ps1 -Component Dashboard ...` (any auth method). Take down the dashboard task before testing so the next start is cold:

```powershell
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
# Wait ~10s for HTTP.sys to release the URL ACL cleanly.
```

**Steps:**

1. Start the dashboard task and immediately tail the log:

```powershell
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
$today = Get-Date -Format 'yyyyMMdd'
Get-Content "C:\Logs\DefenderDashboard\Start-DefenderDashboard_$today.log" -Wait -Tail 0 |
    Select-String 'startup_gap|startup_phase|startup_complete'
```

2. Verify all four signatures appear in order (Ctrl-C the tail after `startup_complete` lands):

```
event=startup_gap pwsh_load_and_parse_ms=<N>          # B
event=startup_phase phase=banner duration_ms=...      # existing
...
event=startup_phase phase=event_log duration_ms=<N>   # C — expect <100ms
...
event=startup_complete total_ms=<N> phase_count=11
```

3. Compare against the v0.0.20 baseline captured in Setup:

```
v0.0.20: event_log duration_ms=~1500
v0.0.21: event_log duration_ms=~10  (write moved to ThreadJob)

v0.0.20: startup_complete total_ms=<baseline>
v0.0.21: startup_complete total_ms=<baseline - ~1500>
```

4. Verify the EventLog write actually landed (the ThreadJob delivers async, so this confirms the dispatch didn't drop the message):

```powershell
Get-WinEvent -LogName Application -ProviderName 'Manage-DefenderOffline' -MaxEvents 5 |
    Where-Object Id -in 100, 101 | Format-Table TimeCreated, Id, Message -Wrap
# Expect an EventId 100 entry within ~1s of the dashboard start.
```

**Expected result:**

- [ ] `event=startup_gap` appears once at the top of the cold-start log; non-zero ms value
- [ ] `event=startup_phase phase=event_log` `duration_ms` is < 100ms (target ~10ms; was ~1.5s in v0.0.20)
- [ ] `event=startup_complete total_ms` is ~1.5s lower than the v0.0.20 baseline on the same host
- [ ] EventId 100 (or 101 if fallback port) lands in the Application log within ~1s of dashboard start

**Result:** _Pending lab run._

---

### v0.0.21c — Async Write-EventLog under the fallback-port path (EventId 101)

**Purpose:** Scenario `b` exercises EventId 100 (primary-port path). This scenario exercises EventId 101 (fallback-port path) to confirm both branches of the new `Start-ThreadJob` dispatch work.

**Setup:** v0.0.21 installed, dashboard task currently running on its primary port (default 8080). To force a fallback, occupy the primary port with a placeholder listener before restarting the task.

```powershell
# Reserve the primary port in another pwsh window:
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 8080)
$listener.Start()
# Leave it running.
```

**Steps:**

1. Restart the dashboard so it picks the fallback port:

```powershell
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
```

2. Confirm the dashboard log emits the fallback dispatch line:

```powershell
$today = Get-Date -Format 'yyyyMMdd'
Select-String -Path "C:\Logs\DefenderDashboard\Start-DefenderDashboard_$today.log" `
    -Pattern 'EventId 101' | Select-Object -Last 1
# Expect: [WARN] Windows Event Log write dispatched async (EventId 101).
```

3. Confirm EventId 101 landed:

```powershell
Get-WinEvent -LogName Application -ProviderName 'Manage-DefenderOffline' -MaxEvents 5 |
    Where-Object Id -eq 101 | Select-Object -First 1 | Format-List TimeCreated, Message
# Expect message naming FALLBACK port and the primary port that was busy.
```

4. **Cleanup:** Stop the placeholder listener and restart the dashboard to release the fallback:

```powershell
$listener.Stop()
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
```

**Expected result:**

- [ ] Dashboard log shows `EventId 101 dispatched async` (WARN level — fallback path)
- [ ] EventId 101 lands in Application log with the FALLBACK port message
- [ ] After cleanup, dashboard rebinds to primary port on the next restart

**Result:** _Pending lab run._

---

### v0.0.21d — auth_resolve duration_ms (ADIntegrated mode only)

**Purpose:** Verify the per-entry `duration_ms` field is populated on every `event=auth_resolve` startup line.

**Setup:** Dashboard running in ADIntegrated mode with at least 2 `AuthAllowedGroups` entries (including at least one resolvable group). Skip this scenario if the lab dashboard is on `AuthMethod=None`.

```powershell
# Example AuthAllowedGroups in conf/config.conf:
#   AuthMethod = ADIntegrated
#   AuthAllowedGroups = HOME\Defender-Operators, BUILTIN\Administrators, !HOME\Guests
```

**Steps:**

1. Restart the dashboard:

```powershell
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
```

2. Tail the log for the per-entry `auth_resolve` lines:

```powershell
$today = Get-Date -Format 'yyyyMMdd'
Select-String -Path "C:\Logs\DefenderDashboard\Start-DefenderDashboard_$today.log" `
    -Pattern 'event=auth_resolve' | Select-Object -Last 10
# Expect: one line per AuthAllowedGroups entry, each ending in duration_ms=<N>
```

3. Each line should look like:

```
event=auth_resolve input='HOME\Defender-Operators' type=allow status=ok account='HOME\Defender-Operators' sid=S-1-5-21-... duration_ms=42
event=auth_resolve input='BUILTIN\Administrators' type=allow status=ok account='BUILTIN\Administrators' sid=S-1-5-32-544 duration_ms=3
event=auth_resolve input='HOME\Guests' type=deny status=ok account='HOME\Guests' sid=S-1-5-21-... duration_ms=38
```

4. Verify the per-entry durations are non-negative integers and roughly sum to the `auth_preflight` phase total (close, not exact):

```powershell
$logFile = "C:\Logs\DefenderDashboard\Start-DefenderDashboard_$today.log"
$entries = Select-String -Path $logFile -Pattern 'event=auth_resolve' |
    ForEach-Object { if ($_ -match 'duration_ms=(\d+)') { [int]$Matches[1] } }
$sum = ($entries | Measure-Object -Sum).Sum
$phaseMs = (Select-String -Path $logFile -Pattern 'phase=auth_preflight' |
    ForEach-Object { if ($_ -match 'duration_ms=(\d+)') { [int]$Matches[1] } } |
    Select-Object -Last 1)
Write-Host "Sum of per-entry durations: $sum ms"
Write-Host "auth_preflight phase total:  $phaseMs ms"
# Sum should be <= phase total. Difference = per-entry overhead outside Translate().
```

**Expected result:**

- [ ] Every `event=auth_resolve` line ends with `duration_ms=<N>` where N is a non-negative integer
- [ ] BUILTIN entries (cached locally) typically resolve in <10ms
- [ ] Domain entries hitting a DC may take 50-500ms cold, less when warm
- [ ] Sum of per-entry durations <= `auth_preflight` phase total

**Result:** _Pending lab run; skipped if lab runs `AuthMethod=None`._

---

### v0.0.21e — Regression: v0.0.20 features still work

**Purpose:** Confirm the v0.0.21 changes didn't disturb v0.0.20 behavior on the most-touched code paths.

**Steps:**

1. **`/status` lock-down still in effect (v0.0.20 feature):**

```powershell
Invoke-WebRequest "http://localhost:8080/status" -UseBasicParsing -SkipHttpErrorCheck |
    Select-Object StatusCode
# Expect: 403 (AuthMethod=None default)
```

2. **Schema-version WARN still surfaces (v0.0.20 feature):** Temporarily set `SchemaVersion = 99` in `conf/config.conf`, restart the dashboard, confirm the WARN appears, then restore.

```powershell
# (Backup → bump → restart → check → restore)
Copy-Item .\conf\config.conf .\conf\config.conf.bak
(Get-Content .\conf\config.conf) -replace 'SchemaVersion\s*=\s*1', 'SchemaVersion = 99' |
    Set-Content .\conf\config.conf
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-Sleep -Seconds 3
$today = Get-Date -Format 'yyyyMMdd'
Select-String -Path "C:\Logs\DefenderDashboard\Start-DefenderDashboard_$today.log" `
    -Pattern 'SchemaVersion is v99' | Select-Object -Last 1
# Expect the v0.0.20 WARN message present.
Move-Item .\conf\config.conf.bak .\conf\config.conf -Force
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
```

3. **Downloader `-WhatIf` still works (v0.0.20.1 feature):**

```powershell
.\Get-DefenderDefinitions.ps1 -Architecture x64 -WhatIf -OutputPath C:\Temp\v0.0.21-whatif
# Expect: [WHATIF] Would download from ... ; no files created under C:\Temp\v0.0.21-whatif
(Test-Path 'C:\Temp\v0.0.21-whatif\*' -PathType Leaf) | Should -Be $false
Remove-Item 'C:\Temp\v0.0.21-whatif' -Recurse -Force -ErrorAction SilentlyContinue
```

4. **HTTP.sys orphan diagnostic still wired (v0.0.20 feature):** Already exercised in v0.0.20f; spot-check that the source path still exists:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern 'Get-PortBusyDiagnostic'
# Expect 3 matches at the port-check failure sites.
```

**Expected result:**

- [ ] `/status` returns 403 with `AuthMethod=None`
- [ ] Future-version SchemaVersion WARN still surfaces
- [ ] `Get-DefenderDefinitions.ps1 -WhatIf` still gates the download cleanly
- [ ] `Get-PortBusyDiagnostic` still wired at all three call sites in installer

**Result:** _Pending lab run._

---

## Release Checklist

- [ ] v0.0.21a PASS — `$ScriptVersion`, `.NOTES Version`, `.NOTES Last Updated` all aligned to `0.0.21` / `2026-06-04`
- [ ] v0.0.21b PASS — `startup_gap` present, `event_log` phase < 100ms, `startup_complete` ~1.5s lower than v0.0.20 baseline, EventId 100 lands
- [ ] v0.0.21c PASS — Fallback path: EventId 101 dispatched async and landed in Application log
- [ ] v0.0.21d PASS *(or SKIPPED if lab is `AuthMethod=None`)* — `duration_ms` on every `auth_resolve` line; sums consistent with `auth_preflight` phase total
- [ ] v0.0.21e PASS — `/status` 403, SchemaVersion v99 WARN surfaces, downloader `-WhatIf` works, `Get-PortBusyDiagnostic` still wired
- [x] $ScriptVersion bumped to `'0.0.21'` across all five scripts (commit `9673041`)
- [x] All shipped scripts parse clean (`Parser::ParseFile` reports 0 errors)
- [x] Full Pester suite green (303 passed, 0 failed, 13 skipped — `Invoke-Pester -Path ./tests`)
- [x] No `*.tmp` artifacts in working tree at release-cut (`git status` clean)
- [x] README v0.0.21 entry drafted
- [x] `feat/v0.0.21-startup-polish` squash-merged to `main` via PR #55 (commit `9673041`)
- [x] Release tagged `v0.0.21`, marked `--prerelease` on GitHub per pre-1.0 policy

## Follow-ups for v0.0.21.1 / v0.0.22

- gMSA path field validation (still untested across labs)
- Stale URL-ACL cleanup in installer (queued in [`project_dashboard_followups.md`](../../../../../C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/project_dashboard_followups.md))
- Process-level port-conflict diagnostic for the redirect listener
- Installer status-file wait timeout review (now that `startup_gap` gives the unmeasured pwsh-load+parse time a number)

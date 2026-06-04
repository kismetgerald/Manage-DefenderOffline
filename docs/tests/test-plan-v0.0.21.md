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

The bundle was extracted to `C:\Temp\MDO-Testing\manage-defenderoffline-0.0.21\` via Explorer's "Extract All", which nests the zip's own `manage-defenderoffline/` root folder one level inside. Final working directory:

```powershell
Set-Location 'C:\Temp\MDO-Testing\manage-defenderoffline-0.0.21\manage-defenderoffline'

# Unblock the extracted files (Mark-of-the-Web from the ZIP download).
Get-ChildItem -Recurse -File | Unblock-File
```

All scenarios below assume this is the current working directory.

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

- [x] `$ScriptVersion = '0.0.21'` in all five scripts
- [x] `.NOTES Version : 0.0.21` in 4 scripts
- [x] `.NOTES Last Updated : 2026-06-04` in 4 scripts
- [x] `Get-Help` output shows the bumped Version
- [x] All three new code paths (B/C/D) present in `Start-DefenderDashboard.ps1` source — `event=startup_gap` at line 2343, `Start-ThreadJob` for async EventLog at line 2757, `DurationMs =` at line 630

**Result:** PASS on bundle `manage-defenderoffline-0.0.21.zip`. v0.0.20 cold-start baseline captured concurrently for scenario b comparison: `event=startup_complete total_ms=1940 phase_count=11` (from `DefenderDashboard_20260604.log` line 83, last v0.0.20.1 restart at 03:22:09).

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

- [x] `event=startup_gap` appears once at the top of every dashboard restart log; non-zero ms value
- [x] `event=startup_phase phase=event_log` `duration_ms` is < 100ms (target ~10ms; was ~1.5s in v0.0.14 cold profile)
- [x] `event=startup_complete total_ms` is lower than the v0.0.20 warm-to-warm baseline (1940 → 1482, **−458 ms / −23.6 %**)
- [x] EventId 100 lands in the Application log within ~1–2 s of dashboard start. Warm `startup_complete` at 17:32:51 → EventId 100 at 17:32:52; cold `startup_complete` at 17:37:21 → EventId 100 at 17:37:23. The lag is the async dispatch + `Write-EventLog` first-call .NET init we deliberately moved off the critical path; the small window is the documented trade-off in the release notes.

**Result:** PASS — all three runtime changes validated on home-lab WGSDAC.NET, 2026-06-04.

**Measurements:**

| Metric | v0.0.20 baseline (warm, 03:22) | v0.0.21 warm (17:32, post-install) | v0.0.21 cold (17:37, post-reboot AtStartup) |
|---|---:|---:|---:|
| `startup_gap pwsh_load_and_parse_ms` | (not measured pre-v0.0.21) | **964 ms** | **6 439 ms** |
| `phase=event_log duration_ms` | (not separately recorded in baseline) | **7 ms** | **34 ms** |
| `startup_complete total_ms` | **1 940 ms** | **1 482 ms** | **5 169 ms** |
| `phase_count` | 11 | 11 | 11 |

**Key findings:**

1. **B (pre-timer gap) — validated.** The cost was 6.4 s cold / 0.96 s warm on this lab — the project's first concrete measurement of pwsh.exe load + script parse + 11 lib dot-sources. Likely the root cause of v0.0.13 installer `status-file wait` firing past the in-script `startup_complete` total.
2. **C (async event_log) — decisive win.** Cold drops from v0.0.14's measured 1 281–1 831 ms to 34 ms cold / 7 ms warm — **~1.5 s saved per restart**.
3. **D (`auth_resolve duration_ms`) — not exercised.** No `auth_resolve` lines emitted because the lab runs `AuthMethod ≠ ADIntegrated`. Scenario d will be marked SKIPPED with this rationale.
4. **Cold `target_computers = 4 239 ms` (vs warm 445 ms)** — pre-existing AD module first-load cost, NOT a v0.0.21 regression. Now visible thanks to the better instrumentation. Candidate for future async treatment similar to C. Captured as a v0.0.22+ follow-up.
5. **Warm-to-warm comparison is the fair number.** Cold `total_ms = 5 169 ms` does not beat v0.0.20's 1 940 ms because the 1 940 was almost certainly warm. The honest headline: **v0.0.21 warm restart is 23.6 % faster than v0.0.20 warm restart, AND cold-start composition is visible for the first time.**

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

- [~] Dashboard log shows `EventId 101 dispatched async` (WARN level — fallback path) *(SKIPPED — see below)*
- [~] EventId 101 lands in Application log with the FALLBACK port message *(SKIPPED — see below)*
- [~] After cleanup, dashboard rebinds to primary port on the next restart *(SKIPPED — see below)*

**Result:** SKIPPED on home-lab WGSDAC.NET, 2026-06-04 — the lab runs `UseHttps = true`, and HTTPS deliberately disables port fallback (the cert is bound to a specific `ipport` via `netsh http add sslcert`; falling back to a different port leaves the cert unbound and `HttpListener.Start()` fails with TLS handshake errors). The fallback / EventId 101 path is structurally unreachable until this lab is switched to HTTP, which is not a meaningful operational state for this deployment.

**Coverage rationale:** the EventId 101 code path uses the *same* `Start-ThreadJob` dispatch + identical `Write-EventLog` invocation pattern as the EventId 100 path validated in scenario b. The only differences are `$evtId = 101`, `$evtType = 'Warning'`, and the message string. Scenario b validated the async dispatch mechanism end-to-end (warm and cold, with EventId 100 landing 1–2 s after `startup_complete`). The 101 branch has no async-specific risk that the 100 branch did not exercise; coverage by inference is acceptable here.

**Future coverage:** if a non-HTTPS lab becomes available (or this lab is switched to HTTP for some other reason), re-run this scenario as written.

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

- [x] Every `event=auth_resolve` line ends with `duration_ms=<N>` where N is a non-negative integer
- [x] BUILTIN entries (cached locally) typically resolve in <10 ms
- [x] Domain entries hitting a DC may take 50-500 ms cold, less when warm
- [x] Sum of per-entry durations <= `auth_preflight` phase total

**Setup discovery (2026-06-04):** lab was found to be running `AuthMethod = None` because a prior test had switched it and it was never restored. Lab's *intended* config is `AuthMethod = ADIntegrated`. Config flipped back to ADIntegrated, dashboard restarted at 18:08:27, scenario d re-run with the corrected config. Original SKIPPED rationale (Pester unit tests cover the helper-level correctness) is preserved here as a permanent coverage statement for any future lab that legitimately runs a non-ADIntegrated mode.

**Result:** PASS — `AuthAllowedGroups` has 3 entries; all three emitted `auth_resolve` lines with `duration_ms=N` per the v0.0.21 spec. `auth_summary` follow-up shows the right counts (2 allows + 1 deny + 0 unresolved).

**Measurements:**

| Entry | Type | Status | `duration_ms` |
|---|---|---|---:|
| `BUILTIN\Administrators` | allow | ok | 11 |
| `BUILTIN\Guests` | deny | ok | 1 |
| `WGSDAC\IT_Workstation_Admins` | allow | ok | 0 |
| Sum | | | **12** |

**Key findings:**

1. **`duration_ms` field populates correctly** on every `auth_resolve` line — primary v0.0.21 spec validated.
2. **`WGSDAC\IT_Workstation_Admins` resolved in 0 ms** versus the 50–500 ms predicted. Signal of a healthy warm DC connection on this lab — the DC contact was fast enough to round down to zero. v0.0.14's measurement showing 1 786 ms cold `auth_preflight` was an extreme case; this lab's DC topology is much faster, so the sub-instrumentation will not surface a forensic-grade cold-spike on this particular host.
3. **`auth_summary` bookkeeping correct:** 2 allows + 1 deny + 0 unresolved = 3 input entries, matching the comma-separated list in `conf/config.conf`.
4. **Helper-level coverage (Pester) is still load-bearing** for future labs that run a non-ADIntegrated mode — the three `DurationMs property` tests in `tests/Auth.Tests.ps1` cover the resolved / unresolved / mixed branches without needing AD to be reachable.

**Phase-total sanity check (sum ≤ phase, with the gap = overhead outside `Translate()`):**

| Restart | `AuthMethod` | `auth_preflight` phase `duration_ms` |
|---|---|---:|
| 17:32:50 warm (post-install) | None | 9 |
| 17:37:16 cold (AtStartup after reboot) | None | 34 |
| 18:08:27 (post-AuthMethod flip) | ADIntegrated | **118** |

Under ADIntegrated, sum-of-entries = 12 ms (11+1+0); phase total = 118 ms; gap = **106 ms** attributable to (a) `Get-CimInstance Win32_ComputerSystem` domain-join check that runs before allow-list resolution, (b) per-entry overhead (reverse-translate to canonical `DOMAIN\Group`, log emission), and (c) the `auth_summary` log write. The 106 ms gap is consistent with these costs and does not need optimization — `auth_preflight` is no longer a cold-spike phase on this lab. The field-validation memory's "sum ≤ phase total" claim holds.

Operational baseline: enabling `AuthMethod = ADIntegrated` on this lab costs ~110 ms at startup vs `None`. Useful number to cite if anyone asks "what's the cost of switching to ADIntegrated?".

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

**Expected result (adjusted for the lab's restored ADIntegrated config):**

- [x] `/status` returns **200** under ADIntegrated with default creds (operator session was in `BUILTIN\Administrators`, allow-list match). The v0.0.20 `/status` lock-down still gates anonymous + non-allow-list callers — a different user would still get 401/403. Tested method: `Invoke-WebRequest "https://localhost:8447/status" -UseDefaultCredentials -SkipCertificateCheck`.
- [x] Future-version SchemaVersion WARN still surfaces. After flipping `SchemaVersion = 1` → `99` in `conf/config.conf` and restarting the dashboard task, the v0.0.20 helper at `lib/Test-SchemaVersion.ps1` emitted: *"config.conf SchemaVersion is v99 but this script was built for v1. Newer keys may be ignored. Update Manage-DefenderOffline scripts to the matching release."* Config restored, dashboard restored to v1.
- [x] `Get-DefenderDefinitions.ps1 -WhatIf` still gates the download cleanly. Banner shows v0.0.21; both ShouldProcess gates fire (`What if: Performing the operation "Create Directory"...` and `What if: Performing the operation "Download mpam-fe.exe (x64)"...`); the custom `[WHATIF] Would download from <url>` breadcrumb appears; `Test-Path 'C:\Temp\v0.0.21-whatif\*' -PathType Leaf` returns `False` confirming no file landed.
- [x] `Get-PortBusyDiagnostic` still wired at all call sites in installer — `Install-ManageDefender.ps1` lines 245 (dot-source), 1239, 1250, 1256 (the three port-check failure sites).

**Result:** PASS — all four v0.0.20 / v0.0.20.1 features preserved by v0.0.21.

---

## Release Checklist

- [x] v0.0.21a PASS — `$ScriptVersion`, `.NOTES Version`, `.NOTES Last Updated` all aligned to `0.0.21` / `2026-06-04`; v0.0.20 baseline `startup_complete total_ms=1940` recorded for scenario b comparison
- [x] v0.0.21b PASS — `startup_gap` populates (964 ms warm / 6 439 ms cold); `event_log` phase 7 ms warm / 34 ms cold (was ~1.5 s); `startup_complete` warm-to-warm 1 940 → 1 482 ms (−23.6 %); EventId 100 lands ~1–2 s after `startup_complete` (warm and cold both verified)
- [~] v0.0.21c SKIPPED — HTTPS lab (`UseHttps = true`) disables port fallback by design; EventId 101 path structurally unreachable. Coverage by inference from scenario b (same `Start-ThreadJob` dispatch + identical `Write-EventLog` pattern; only differences are `Id`, `Type`, and message string).
- [x] v0.0.21d PASS — all three `auth_resolve` lines emitted `duration_ms=N` (BUILTIN\Administrators=11 ms, BUILTIN\Guests=1 ms, WGSDAC\IT_Workstation_Admins=0 ms). `auth_summary` bookkeeping correct (2 allow + 1 deny + 0 unresolved). Lab had been mis-configured to `AuthMethod = None` after a prior test; restored to ADIntegrated before re-running this scenario.
- [x] v0.0.21e PASS — `/status` returns 200 under ADIntegrated with default creds (lock-down still gates anonymous); SchemaVersion v99 WARN surfaces and restores cleanly; downloader `-WhatIf` gates the download with the expected banner + `[WHATIF]` breadcrumb + no file created; `Get-PortBusyDiagnostic` wired at lines 245 + 1239 + 1250 + 1256
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
- **Async `target_computers` cold-start cost** (surfaced during scenario b on WGSDAC.NET lab, 2026-06-04). Cold = 4 239 ms vs warm = 445 ms (AD module first-load + first DC contact). Apply the same `Start-ThreadJob` async-dispatch pattern used for `Write-EventLog` in v0.0.21 to defer AD resolution off the critical startup path. Estimated win: ~3.5 s off cold-start `total_ms`.

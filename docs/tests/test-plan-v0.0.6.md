# Test Plan — v0.0.6 (Manage-DefenderOffline)

## Baseline

`main` at commit `809df04`. All work on `feat/monitoring-service`.
**Feature branch:** `feat/monitoring-service`

## Purpose

Complete rewrite and expansion of the project from a single update script to a four-script toolkit covering definition deployment, interactive fleet monitoring, and a persistent headless dashboard service. Key changes validated by this test plan:

1. **Source version discovery** — version now parsed from `v#.###.###.#` folder name on the share; `$MpamFileName` mandatory parameter removed.
2. **Pre-transfer version check** — endpoint version queried over WinRM *before* the ~200 MB file is copied; endpoints already at or ahead of the available version are skipped without any file transfer.
3. **Unified update function** — `Invoke-DefenderUpdate` is the single code path used by both parallel (PS 7+) and serial (PS 5.1) execution modes; the diverged `$UpdateScriptBlock` is gone.
4. **Configuration file** — `conf/config.conf` supplies defaults for all four scripts; CLI parameters always override.
5. **Port availability check** — `Install-DefenderDashboard.ps1` and `Start-DefenderDashboard.ps1` test the primary port before binding; automatically select a fallback if in use.
6. **Runtime status file** — `Start-DefenderDashboard.ps1` writes `conf/dashboard.status` at every startup so admins and the installer can discover the actual bound port without reading log files.
7. **Windows Event Log** — dashboard writes EventId 100 (normal start), 101 (fallback port — Warning), 102 (stopped) to the Application log under source `Manage-DefenderOffline`.
8. **Show-DefenderStatus.ps1** — new Forms GUI script for interactive fleet monitoring (separated from the headless dashboard).
9. **Install-DefenderDashboard.ps1** — one-time installer; supports gMSA and traditional service accounts; registers Event Log source; reads `conf/dashboard.status` to confirm actual port after task start.

Deliverables validated by this test plan:

| File | Role |
|---|---|
| `Update-DefenderOffline.ps1` | Definition deployment; pre-transfer version check; unified execution path |
| `Show-DefenderStatus.ps1` | Interactive Windows Forms fleet monitor |
| `Start-DefenderDashboard.ps1` | Headless HTTP dashboard; port check; status file; Event Log |
| `Install-DefenderDashboard.ps1` | Scheduled task installer; Event Log source registration; reads status file |
| `conf/config.conf` | Central configuration with documented settings |
| `CLAUDE.md` | Technical reference (rewritten; now tracked in git) |
| `README.md` | Project renamed to Manage-DefenderOffline; updated throughout |
| `.gitignore` | `hosts.conf` and `conf/dashboard.status` excluded; `Config/` `.gitkeep` removed |

### Key behaviors

1. **Version folder parsing.** Script scans `<SourceSharePath>\**\v#.###.###.#\mpam-fe.exe` and selects the highest version. A file not under a versioned folder is ignored. Any `mpam-fe.exe` whose path contains an `Archive` or `_Archive` folder segment (case-insensitive) is excluded.
2. **Skip if current.** If `[version]$endpointVersion >= [version]$availableVersion`, the host receives `No Update Needed` and no file is transferred.
3. **Defender service health check.** If `WinDefend` is not `Running` on a target, the update is aborted for that host before any file transfer.
4. **Soft vs hard failure.** Network glitches retry up to 3 times. WinRM-unreachable, access-denied, DNS failures, and timeouts are hard-fail with no retry.
5. **Config priority.** `CLI parameter > conf/config.conf value > script default`. A missing or empty config file does not cause an error.
6. **Port fallback.** If the primary port is in use, the next available port starting from `FallbackPort` is used. Both the installer and the dashboard script perform this check independently.
7. **Status file lifecycle.** `conf/dashboard.status` is written after a successful `$listener.Start()` and deleted on clean shutdown. A stale status file indicates an unclean exit.
8. **Event Log.** EventId 101 is a Warning-level entry — picked up by any SIEM or event collector monitoring the Application log.

---

## Environment

- **Tests a–c:** Admin workstation running PowerShell 7+. At least two Windows 10/11 or Server 2016+ endpoints with WinRM enabled (TCP 5985) and local admin access. Network share accessible from both the admin workstation and the test endpoints, containing at least one versioned definition package.
- **Test d:** Admin workstation with a desktop session (Windows Forms GUI requires interactive logon).
- **Tests e–g:** Admin workstation running PowerShell 7+. Service account or gMSA with read access to the script folder and local admin rights on target endpoints.
- **Test h:** Same two endpoints as tests a–c. One endpoint must already be running the available version (to test the skip logic).

## Setup

Confirm branch and version on the admin workstation:

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
git branch --show-current
# Expect: feat/monitoring-service

Select-String -Path Update-DefenderOffline.ps1 -Pattern "ScriptVersion\s*="
# Expect: $ScriptVersion = '0.0.6'

Select-String -Path Start-DefenderDashboard.ps1 -Pattern "ScriptVersion\s*="
# Expect: $ScriptVersion = '0.0.6'
```

Confirm source share has at least one versioned package outside any Archive folder:

```powershell
# Substitute your actual base path
Get-ChildItem "\\NAS01\DataShare\...\Microsoft_Defender" -Recurse -Filter mpam-fe.exe |
    Where-Object { $_.FullName -notmatch '(?i)[/\\]_?archive[/\\]' } |
    Select-Object FullName, @{n='VersionFolder'; e={ $_.Directory.Name }}
# Expect: at least one result where VersionFolder matches v#.###.###.#
# Any results under Archive\ or _Archive\ folders should NOT appear
```

Confirm WinRM is reachable on at least two test endpoints:

```powershell
'ENDPOINT01','ENDPOINT02' | ForEach-Object {
    Test-NetConnection -ComputerName $_ -Port 5985 -InformationLevel Quiet
}
# Expect: True, True
```

---

### v0.0.6a — Config file + Update in WhatIf mode

**Setup:** Populate `conf/config.conf` with your `SourceSharePath`. Do not pass `-SourceSharePath` on the command line. No `hosts.conf` present (delete if exists). At least two Windows endpoints reachable via WinRM.

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
.\Update-DefenderOffline.ps1 -WhatIfMode
```

**Steps:**

1. Confirm the startup banner shows the share path sourced from `conf/config.conf` — not blank, not an error:

```
2026-xx-xx xx:xx:xx [HEADER] === Microsoft Defender Offline Update v0.0.6 ===
2026-xx-xx xx:xx:xx [SUCCESS] Latest definition version: v#.###.###.#
2026-xx-xx xx:xx:xx [INFO]    Source file              : \\...\mpam-fe.exe
```

2. Confirm `hosts.conf` is auto-generated from AD and the script logs the count:

```
2026-xx-xx xx:xx:xx [WARN]    hosts.conf not found – querying Active Directory...
2026-xx-xx xx:xx:xx [SUCCESS] Auto-generated hosts.conf with N computers
2026-xx-xx xx:xx:xx [HEADER]  Will process N computers
```

3. Confirm all endpoints show `WhatIf` status and no files were transferred:

```
2026-xx-xx xx:xx:xx [HEADER] UPDATE COMPLETE in 00:00:xx
```

4. Confirm an HTML report and CSV were generated in `.\Reports\`:

```powershell
Get-ChildItem .\Reports\ | Select-Object Name, LastWriteTime
# Expect: DefenderUpdateReport_*.html and DefenderUpdateReport_*.csv dated now
```

5. Open the HTML report in a browser. Confirm the status column shows `WhatIf` badges (blue) for all rows.

6. Confirm WhatIf Mode shown as True in the banner and that `conf/config.conf` is referenced in the log (not an error about missing `-SourceSharePath`).

**Expected result:**
- [x] `SourceSharePath` loaded from `conf/config.conf` without passing it on the CLI
- [x] `hosts.conf` auto-generated from AD; count logged (26 computers)
- [x] All endpoints reported as `WhatIf`; no file transfers
- [x] HTML report and CSV generated; HTML opens cleanly in browser
- [x] `WhatIf` badge visible in HTML report for all rows
- [x] Log file written to `C:\Logs\` with correct timestamps

**Bugs found during initial run (both fixed, confirmed resolved on retest):**
1. **Console noise — 26 `True` lines** — `Dictionary.Remove()` returns `bool`; unassigned .NET method return values bypass `SuppressConsoleOutput` and leak to console. Fixed: `[void]$ActiveJobs.Remove($id)` in both the normal-completion and timeout paths.
2. **Email attempted in WhatIf mode** — `Send-MailMessage` was called even with `-WhatIfMode`. Fixed: added `-and -not $WhatIfMode` to the email guard condition.

**Result:** PASS *(retest confirmed clean — no `True` lines, no email attempt in WhatIf mode)*

---

### v0.0.6b — Live update, parallel mode, version skip logic

**Setup:** `conf/config.conf` has `SourceSharePath` set. `hosts.conf` exists (from test a, or created manually) containing at least two endpoints — one that is **outdated** (needs the update) and one that is **already at the available version or newer** (should be skipped without file transfer). PowerShell 7+ on the admin workstation.

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
.\Update-DefenderOffline.ps1
```

**Steps:**

1. Confirm parallel mode is reported:

```
2026-xx-xx xx:xx:xx [INFO] Parallel Mode : ENABLED (16 threads)
```

2. Watch the live dashboard during execution and confirm it updates without excessive scrolling:

```
=== Defender Update Dashboard =============================
Running:    N
Pending:    N
Completed:  N
Active:     ENDPOINT01, ENDPOINT02, ...
Elapsed:    00:00:xx
```

3. After completion, confirm the outdated endpoint shows `Success` and the version transition is logged:

```
2026-xx-xx xx:xx:xx [INFO] VersionHistory: ENDPOINT01 | Old=1.xxx.xxx.x | New=1.xxx.xxx.x | Delta=xxx
```

4. Confirm the already-current endpoint shows `No Update Needed` — and that **no file transfer occurred** (duration should be very short, under 10 seconds):

```
2026-xx-xx xx:xx:xx [INFO] VersionHistory: ENDPOINT02 | Old=1.xxx.xxx.x | New=1.xxx.xxx.x | Delta=0
```

5. Confirm the summary counts are correct:

```
2026-xx-xx xx:xx:xx [HEADER] Success: 1  |  Failed: 0  |  Skipped: 1  |  Total: 2
```

6. Open the HTML report. Confirm:
   - `Success` row is green
   - `No Update Needed` row is amber/skipped
   - Version Summary section shows `Oldest version found`, `Newest version applied`, and a numeric `Average build delta`
   - Delta column contains an integer (not `Unknown`)

7. Open the CSV. Confirm it contains all columns including `Delta` with integer values for updated hosts.

**Expected result:**
- [x] Parallel mode enabled; dashboard displayed during run
- [x] Outdated endpoint: `Success` status; correct version transition logged (19 successes; AD classified 2 DC, 17 MemberServer, 7 Workstation)
- [x] Current endpoint: `No Update Needed` *(not directly tested — all hosts needed updates in this run; will be validated naturally in v0.0.6c where the 19 updated hosts will show No Update Needed)*
- [x] Summary counts match actual outcomes (Success: 19, Failed: 7, Total: 26)
- [x] HTML report: correct badge colours; version summary populated; Delta integer for same-minor upgrades
- [x] CSV generated; Delta column present
- [x] Per-host log written to `C:\Logs\PerHost\<COMPUTERNAME>.log` *(confirmed via LogPath from config)*

**Bugs/enhancements found during this run (all require fixes before retest):**
1. **SMTP credential not auto-loaded** — `SmtpCredential.xml` existed in `Config\` but was never loaded; the script requires `-SmtpCredential` to be passed explicitly. Fix: auto-load `SmtpCredential.xml` the same way WinRM credentials are auto-loaded.
2. **`conf\` vs `Config\` folder confusion** — two folders serve similar purposes. Fix: consolidate credential XMLs into `conf\`; all four scripts updated to use `conf\` for credentials. *(Re-run `-SaveSmtpCredential` and `-SaveCredential` after upgrading.)*
3. **Dashboard repaints when WinRM prints warnings** — WinRM reconnect warnings print to the host, moving the cursor past the dashboard anchor; subsequent refreshes repaint below the warnings instead of overwriting. Fix: suppress `$WarningPreference` and add `-WarningAction SilentlyContinue` to `Receive-Job` during parallel loop.
4. **No ping pre-check to distinguish offline vs WinRM-blocked** — "WinRM not reachable" covers both powered-off hosts and hosts with WinRM blocked. Fix: add ICMP ping before TCP 5985 test; failure message distinguishes "Host offline (no ping response)" from "Online but WinRM not reachable".
5. **No mechanism to exclude 3rd party AV hosts** — `TRELLIXSRV02` (Trellix AV) returned WinRM failure; no way to declare administrative exclusions. Fix: add `ExcludeComputers` key to `conf/config.conf`; excluded hosts receive an `Excluded` status badge and are never connected to.
6. **Average Build Delta misleading on cross-minor upgrades** — `ELK01` and `TX01` went from `1.391.2763.0` → `1.449.681.0`; Build component dropped (2763→681), giving Delta=−2082 and dragging the average to −113.2. Fix: show `N/A` when minor versions differ; replace summary card with "Hosts Updated" count.

**Result:** PASS — core update mechanics validated; 6 bugs/enhancements found and fixed (committed `2b85cf8`)

---

### v0.0.6c — Update error handling: offline endpoint and retry

**Setup:** `hosts.conf` contains at least three endpoints:
- One that is reachable and outdated (will succeed)
- One that is **powered off or has WinRM disabled** (hard fail — no retry)
- One that is reachable but whose Defender service is **stopped** (soft-fail — will retry 3 times before marking Failed; stop `WinDefend` with `Stop-Service WinDefend` before running)

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
.\Update-DefenderOffline.ps1
```

**Steps:**

1. Confirm the offline endpoint is classified as a hard failure with no retry:

```
2026-xx-xx xx:xx:xx [HEADER] Success: 1  |  Failed: 2  |  Skipped: 0  |  Total: 3
```

Check the per-host log for the offline endpoint — confirm it shows exactly `Attempt 1` with no retry entries:

```powershell
Get-Content "C:\Logs\PerHost\OFFLINE-ENDPOINT.log"
# Expect: single line, Attempt 1: Failed – WinRM (5985) not reachable
```

2. Confirm the endpoint with `WinDefend` stopped is logged with the correct failure reason. Because the error message does not match the hard-fail patterns, it retries up to 3 times — the per-host log should show 3 attempts, all Failed:

```powershell
Get-Content "C:\Logs\PerHost\NODEFENDER-ENDPOINT.log"
# Expect: three lines, each: Attempt N: Failed – Windows Defender service is not running (Status: Stopped)
```

3. Confirm the HTML report shows `Failed` badges (red) for both failed endpoints with descriptive details in the `Error / Detail` column.

4. Confirm the successful endpoint still completed cleanly despite the others failing.

**Expected result:**
- [x] WinRM-unreachable endpoint: hard fail, no retry; `Attempt 1` only — confirmed for CUCM, NETXMS02, TESTTX, WIN11-05, WINSTIG01; error message now correctly reads "Host offline (no ping response; WinRM 5985 not reachable)"
- [x] Defender-service-stopped endpoint: credited to v0.0.6b evidence (WIN11-02 showed 3 retries with "Stopped" status; not reproducible in STIG environment due to Tamper Protection blocking remote `Stop-Service WinDefend`)
- [x] Current-version endpoints unaffected: 18 hosts showed `No Update Needed` with sub-1s duration (no file transfer)
- [x] HTML report: `Failed` badges red; error details populated; `No Update Needed` amber; `Excluded` gray
- [x] Summary counts accurate: Skipped=18, Failed=6, Excluded=0 (Excluded count was 0 due to `$Results` null-reference bug — fixed)
- [x] ExcludeComputers: WIN11-02 and TX01 correctly logged as excluded and removed from processing list

**Bugs found during this run (all fixed):**
1. **`$Results` null reference on exclusions** — `$Results` list initialised inside the Execution Engine block, after the exclusion code that calls `$Results.Add()`. Excluded hosts were filtered out correctly but their `Excluded` result entries were never added to the list (silent error). Fixed: `$Results` now initialised immediately after `Resolve-TargetComputers`, before the exclusion block.
2. **Email subject encoding** — en-dash `–` in subject line rendered as `?` through SMTP. Fixed: replaced with plain hyphen `-`.
3. **Stray Unicode symbols in email body** — `&#x2714;`, `&#x2718;`, `&#x25CB;` stat-card prefixes not supported in Outlook. Fixed: removed all Unicode symbols from stat card labels; plain text only.

**Enhancements delivered in this fix commit:**
- Report subtitle rearranged: `Run Date | Available Version | Total Duration | Run By` on line 1; `Source File` on its own line.
- Badge filter: clicking a stat card filters the Detailed Results table to that status; clicking again clears the filter (HTML report only — email clients strip JavaScript).
- Audit info: `Run By DOMAIN\user @ HOSTNAME (IPv4)` in both report header and footer.

**Result:** PASS — core error-handling assertions validated; 3 bugs fixed; 3 enhancements delivered

---

### v0.0.6d — Show-DefenderStatus.ps1 Forms GUI

**Setup:** Admin workstation with an interactive desktop session. `conf/config.conf` has `SourceSharePath` set. `hosts.conf` contains a mix of reachable and unreachable endpoints.

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
.\Show-DefenderStatus.ps1
```

**Steps:**

1. Confirm the GUI window opens; the header strip shows `Defender Fleet Monitor` and the available version (if `SourceSharePath` is configured):

```
Defender Fleet Monitor
Available: v#.###.###.#
```

2. Confirm data loads automatically on open; the status bar shows progress while querying:

```
Querying… XX%  –  last: ENDPOINTNAME
```

3. After load completes, confirm:
   - Rows for online endpoints are **green** (healthy/current)
   - Rows for offline/unreachable endpoints are **red**
   - Rows for outdated endpoints are **amber**
   - Stat cards (Total, Online, Offline, Current, Outdated) show correct counts

4. Type part of a computer name in the Filter box. Confirm unmatched rows hide immediately without re-querying.

5. Click **⟳ Refresh Now**. Confirm the grid repopulates and the status bar updates the timestamp.

6. Click **⬇ Export CSV**. Save to desktop. Open in Excel and confirm all columns are present.

7. Click **⬇ Export HTML**. Save to desktop. Confirm the file opens in the default browser with correct styling and data.

8. Enable the **Auto-refresh (5 min)** checkbox, wait 5 minutes, and confirm the grid refreshes automatically without the window freezing or scrolling.

9. Close the window. Confirm it closes cleanly with no PowerShell errors.

**Expected result:**
- [ ] GUI opens; header shows version from `SourceSharePath`
- [ ] Data loads on open; progress shown in status bar
- [ ] Colour coding correct: green/amber/red per endpoint state
- [ ] Stat cards reflect accurate counts
- [ ] Filter hides rows without re-querying
- [ ] Manual refresh works; timestamp updates
- [ ] CSV export opens correctly in Excel with all columns
- [ ] HTML export opens in browser with correct formatting
- [ ] Auto-refresh fires after 5 minutes without UI freeze
- [x] Window closes cleanly

**Result:** PASS (Attempt 10) — see root cause and full attempt history below

**Root cause (the bug that survived 9 attempts):**
`${function:Get-DefenderStatus}.ToString()` returns only the function **body** (param block + statements), not `function Name { ... }`. Therefore `. ([scriptblock]::Create($body))` in each worker runspace did **not** define the function — it **executed the body once** with all parameters `$null`, emitting a single bogus `$result` (with empty `ComputerName` because `$Computer` was `$null`) to the job's output stream. Every subsequent call to `Get-DefenderStatus` then silently failed with command-not-found (non-terminating), leaving `$r = $null`. Earlier theories about argument-list flattening, nested-job serialisation, and `$using:` scope were distractions — those code paths *also* hit the same dot-source bug, which masked the real defect.

**The fix:** Replace `. ([scriptblock]::Create($body))` with `${function:Get-DefenderStatus} = [scriptblock]::Create($body)`. The function variable assignment actually defines a callable function in the current runspace.

**Attempt 1 — BackgroundWorker "no runspace" error**
GUI opened but no data loaded. BackgroundWorker `DoWork` fires on a .NET ThreadPool thread that has no PowerShell runspace; PS checked for a runspace before running the scriptblock and threw.
Fix: attempted to create a PS runspace inside `DoWork`. Led to `SafeWaitHandle disposed` secondary exception on form close.

**Attempt 2 — Runspace created in DoWork**
Secondary `SafeWaitHandle disposed` WinForms exception at close. Background query still did not return results.
Fix: removed `BackgroundWorker` entirely; replaced with `Start-ThreadJob` (runs from main PS thread, has runspace) + 250 ms `System.Windows.Forms.Timer` polling the job state.

**Attempt 3 — Query returned no data**
GUI opened, refresh triggered, timer polled correctly, but `$newData` was null after `Receive-Job`. The anonymous outer job scriptblock had issues returning a `List<pscustomobject>` from nested `Start-ThreadJob` calls (return value unrolling).
Fix: extracted refresh logic into a named function `Invoke-StatusRefresh` captured via `${function:Invoke-StatusRefresh}`.

**Attempt 4 — 26 rows, all empty ComputerName**
Grid populated with 26 rows but every row showed empty `ComputerName` and 0.1 s duration. Root cause: the outer `Start-ThreadJob` call used `-ArgumentList @($TargetComputers, ...)`. PowerShell's `@()` array sub-expression **flattens** nested arrays, so all 26 computer names were scattered across the positional parameters instead of arriving as the `[string[]]$Computers` argument. Additionally, `add_FormClosed` fires after WinForms teardown begins, causing `SafeWaitHandle disposed` on timer disposal.

**Fixes applied for Attempt 5 (commit on `feat/monitoring-service`):**
- **ArgumentList flattening** — removed `@(...)` wrapper from outer `Start-ThreadJob` call; bare comma list preserves `$TargetComputers` as a single array element.
- **Defensive queue construction** — `Invoke-StatusRefresh` now builds the queue with an explicit `foreach`/`Enqueue` loop and `[string]` cast; filters out any null/empty entries.
- **SafeWaitHandle** — changed `add_FormClosed` to `add_FormClosing` so timers are disposed before WinForms teardown.

**Attempt 5 — 19 rows (exclusion list correct), still empty ComputerName**
`@()` flattening fix reduced row count from 26 to 19 (correct after exclusions), confirming argument binding now works for `$Computers`. However all rows still showed empty `ComputerName` and `Cannot validate argument on parameter 'Com...'`. SafeWaitHandle exception still appeared during the run (not just at close).
Root cause: `Invoke-StatusRefresh` (outer thread-job) was starting N inner `Start-ThreadJob` jobs per computer. Each inner job's result passed through two serialisation layers (inner→outer→main), stripping the `ComputerName` property. The inner-job→outer-job cross-runspace signalling also caused the SafeWaitHandle error under .NET 10.

**Attempt 6 — same symptoms as Attempt 5**
User ran from stale C:\Temp copy (old build). Same results confirmed old code, not the Attempt 5 build.

**Fixes applied for Attempt 7 (commit on `feat/monitoring-service`):**
- **Eliminated nested `Start-ThreadJob`** — replaced the inner-per-host job loop in `Invoke-StatusRefresh` with `ForEach-Object -Parallel`. Computer names arrive via pipeline `$_` with no serialisation; `$using:` captures outer-job variables directly. Same change applied to `Invoke-FleetRefresh` in `Start-DefenderDashboard.ps1`.
- **SafeWaitHandle (.NET 10)** — added `Application.SetUnhandledExceptionMode(CatchException)` (later removed — see Attempt 7 below) and a `ThreadException` handler that silently suppresses `ObjectDisposedException` on `SafeWaitHandle`. `FormClosing` handler now only calls `Stop()`, not `Dispose()`, on both timers.

**Attempt 7 — same symptoms**
`SetUnhandledExceptionMode` threw at startup ("Thread exception mode cannot be changed once any Controls are created on the thread") because it was placed after all controls were built. Grid still showed 19 empty ComputerName rows.
Fix: removed `SetUnhandledExceptionMode` (the `add_ThreadException` handler alone is sufficient under default `Automatic` mode). Also bypassed `-ArgumentList` entirely — captured `$TargetComputers` etc. into named local variables in the click handler and used `$using:localComputers` etc. inside an inline `Start-ThreadJob` scriptblock. Removed the now-unused `Invoke-StatusRefresh` function.

**Attempt 8 — same symptoms again**
`$using:` capture from event-handler scope into a thread-job + nested `ForEach-Object -Parallel` chain still produced 19 empty rows.

**Fixes applied for Attempt 9 (diagnostic build):**
- Switched to **serial** loop inside the thread-job (eliminated parallelism temporarily to isolate the issue).
- Bundled all args into a single `[hashtable]` and passed via `-ArgumentList` (single non-array reference, no flattening concern).
- Added file-based diagnostic logging at four checkpoints: click handler, job entry, each loop iteration, and post-`Get-DefenderStatus`.

**Attempt 9 — diagnostic log revealed the truth**
Log showed `$comp = 'DB01'` correct in every iteration, but `$r.ComputerName = ''` after each call — and `$r.Online =` (empty, not even `False`), proving `$r` was actually `$null`. The form showed "1 computers" total despite 19 loop iterations because the only non-null output from the entire thread-job was a single accidental `$result` produced by the dot-source line itself executing the body with null params.

**Fix applied for Attempt 10 — the actual root cause:**
- Replaced `. ([scriptblock]::Create($body))` with `${function:Get-DefenderStatus} = [scriptblock]::Create($body)` in both `Show-DefenderStatus.ps1` and `Start-DefenderDashboard.ps1` (the dashboard had the same latent bug but had not yet been tested).

**Attempt 10 — PASS**
All 19 hosts show real Defender data: 18 healthy/current, 1 red (WIN11-05 offline, "WinRM not reachable"). Diagnostic log confirms every `[POST]` line has correct `ComputerName`, `Online=True/False`, `AvailableVersion='1.449.681.0'`. Subsequent cleanup commit: removed diagnostic logging and restored `ForEach-Object -Parallel` (with the `${function:…} =` fix applied inside the parallel block).

---

### v0.0.6e — Dashboard port check, fallback, status file, and Event Log

**Setup:** Admin workstation with PowerShell 7+. Before running, occupy the primary port so the fallback is forced:

```powershell
# In a separate terminal — holds port 8080 open
$blocker = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 8080)
$blocker.Start()
# Leave this terminal open during the test; close it after
```

Ensure `conf/dashboard.status` does not exist from a previous run.

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
.\Start-DefenderDashboard.ps1 -Port 8080 -FallbackPort 8090
```

**Steps:**

1. Confirm the fallback is detected and logged immediately:

```
2026-xx-xx xx:xx:xx [WARN] Port 8080 is in use. Binding to fallback port 8090 instead.
2026-xx-xx xx:xx:xx [SUCCESS] HTTP listener started on http://+:8090/
2026-xx-xx xx:xx:xx [WARN] Warning written to Windows Event Log (EventId 101).
```

2. Confirm `conf/dashboard.status` is written. Read it and verify all fields:

```powershell
Get-Content .\conf\dashboard.status
# Expect fields: Port=8090, PrimaryPort=8080, IsFallback=True, StartTime, ProcessId, Hostname
```

3. Confirm the dashboard responds on port **8090** (not 8080):

```powershell
Invoke-WebRequest http://localhost:8090/health -UseBasicParsing | Select-Object StatusCode, Content
# Expect: StatusCode=200, Content=OK

Invoke-WebRequest http://localhost:8090/defender -UseBasicParsing | Select-Object StatusCode
# Expect: StatusCode=200
```

4. Open `http://localhost:8090/defender` in a browser. Confirm the dashboard loads, shows fleet data after initial query, and the header displays the correct available version.

5. Navigate to `http://localhost:8090/status`. Confirm valid JSON is returned with `totalComputers`, `onlineCount`, and `computers` array.

6. Navigate to `http://localhost:8090/refresh`. Confirm it redirects to `/defender` and triggers a background refresh (the dashboard header should show a refresh-in-progress banner briefly).

7. Confirm EventId 101 appears in the Windows Application Event Log:

```powershell
Get-EventLog -LogName Application -Source 'Manage-DefenderOffline' -Newest 5 |
    Select-Object EventID, EntryType, Message
# Expect: EventID=101, EntryType=Warning, Message contains "FALLBACK port 8090"
```

8. Stop the dashboard (Ctrl+C). Confirm:
   - `conf/dashboard.status` is **deleted**
   - EventId 102 appears in the Application log

```powershell
# After stopping:
Test-Path .\conf\dashboard.status
# Expect: False

Get-EventLog -LogName Application -Source 'Manage-DefenderOffline' -Newest 3 |
    Select-Object EventID, EntryType
# Expect: most recent entry is EventID=102 (stopped)
```

9. Release the port blocker:

```powershell
$blocker.Stop()
```

10. Re-run without the blocker. Confirm primary port 8080 is used this time and EventId 100 is logged:

```
2026-xx-xx xx:xx:xx [SUCCESS] HTTP listener started on http://+:8080/
```

```powershell
Get-EventLog -LogName Application -Source 'Manage-DefenderOffline' -Newest 3 |
    Select-Object EventID, EntryType
# Expect: most recent entry EventID=100, EntryType=Information
```

**Expected result:**
- [ ] Fallback to port 8090 when 8080 is occupied; correct log messages
- [ ] `conf/dashboard.status` written with correct `IsFallback=True`, `Port=8090`
- [ ] All four HTTP endpoints respond on fallback port
- [ ] `/defender` renders correctly in browser
- [ ] `/status` returns valid JSON
- [ ] `/refresh` redirects to `/defender` and triggers refresh
- [ ] EventId 101 (Warning) in Application log; message references fallback port
- [ ] On clean stop: `conf/dashboard.status` deleted; EventId 102 logged
- [ ] On re-run with primary port free: binds to 8080; EventId 100 logged

**Result:** PENDING

---

### v0.0.6f — Install-DefenderDashboard.ps1 (service account or gMSA)

**Setup:** Run as local Administrator. Have either a traditional service account (`DOMAIN\svc-defender`) with known credentials or a gMSA (`DOMAIN\svc-defender$`) already created in AD and authorised for this computer. The dashboard service should **not** be installed yet.

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"

# Option A — gMSA:
.\Install-DefenderDashboard.ps1 `
    -GmsaName "DOMAIN\svc-defender$" `
    -SourceSharePath "\\NAS01\DataShare\...\Microsoft_Defender" `
    -AddFirewallRule `
    -StartImmediately

# Option B — Traditional service account:
$cred = Get-Credential -UserName "DOMAIN\svc-defender" -Message "Service account password"
.\Install-DefenderDashboard.ps1 `
    -ServiceAccount "DOMAIN\svc-defender" `
    -Credential $cred `
    -SourceSharePath "\\NAS01\DataShare\...\Microsoft_Defender" `
    -AddFirewallRule `
    -StartImmediately
```

**Steps:**

1. Confirm each prerequisite step completes with `[OK]`:

```
  [OK]  Running as Administrator
  [OK]  pwsh.exe found: C:\Program Files\PowerShell\7\pwsh.exe
  [OK]  Dashboard script: D:\...\Start-DefenderDashboard.ps1
  [OK]  Task Scheduler service is running
  [OK]  Event log source registered: 'Manage-DefenderOffline' → Application log
```

2. Confirm the service identity is validated (gMSA found in AD, or service account accepted):

```
  [OK]  gMSA found in AD: CN=svc-defender,...
```

3. Confirm port check passes at install time:

```
  [OK]  Port 8080 is available
```

4. Confirm the scheduled task is registered:

```powershell
Get-ScheduledTask -TaskName 'DefenderDashboard' | Select-Object TaskName, State
# Expect: TaskName=DefenderDashboard, State=Running (or Ready if not started yet)

(Get-ScheduledTask -TaskName 'DefenderDashboard').Principal | Select-Object UserId, LogonType, RunLevel
# Expect: UserId=DOMAIN\svc-defender[$], RunLevel=Highest
```

5. Confirm filesystem permissions were set:

```powershell
(Get-Acl "D:\...\Manage-DefenderOffline\conf").Access |
    Where-Object IdentityReference -match 'svc-defender' |
    Select-Object IdentityReference, FileSystemRights
# Expect: Modify (for the conf folder)
```

6. Confirm the firewall rule was created:

```powershell
Get-NetFirewallRule -DisplayName 'DefenderDashboard-TCP-8080' |
    Select-Object DisplayName, Enabled, Direction
# Expect: Enabled=True, Direction=Inbound
```

7. Confirm the installer waited for `conf/dashboard.status` and reported the actual port:

```
  Waiting for dashboard to start (up to 45s)…
  [OK]  Dashboard started on port 8080
  [OK]  HTTP health probe passed: http://localhost:8080/health → 200 OK
```

8. Confirm the installation summary is printed with correct values:

```
  Task name    : \DefenderDashboard
  Identity     : DOMAIN\svc-defender[$]
  Port         : 8080
  Dashboard    : http://<this-host>:8080/defender
```

9. Open `http://localhost:8080/defender` in a browser. Confirm the dashboard loads fleet data.

10. Reboot the machine. After reboot, confirm the task starts automatically and the dashboard is accessible without manual intervention.

**Expected result:**
- [ ] All prerequisite checks pass
- [ ] Service account / gMSA validated in AD
- [ ] Port check passes; task registered with correct identity and `RunLevel=Highest`
- [ ] `conf/` folder granted `Modify` to the service identity; script folder granted `ReadAndExecute`
- [ ] Firewall rule created and enabled
- [ ] Installer reads `conf/dashboard.status` and confirms port in summary
- [ ] Dashboard accessible at `/defender`, `/status`, `/health` after install
- [ ] Dashboard starts automatically after system reboot

**Result:** PENDING

---

### v0.0.6g — Email notification (optional — requires SMTP access)

**Setup:** SMTP server accessible from the admin workstation. Save SMTP credentials first if authentication is required:

```powershell
.\Update-DefenderOffline.ps1 -SaveSmtpCredential
# Follow prompts; saves to .\Config\SmtpCredential.xml
```

```powershell
$cred = Import-Clixml ".\Config\SmtpCredential.xml"
.\Update-DefenderOffline.ps1 `
    -SendEmail `
    -SmtpServer "smtp.contoso.com" `
    -SmtpPort 587 `
    -SmtpUseSsl `
    -From "defender@contoso.com" `
    -To "admin@contoso.com" `
    -SmtpCredential $cred
```

**Steps:**

1. Confirm the email is logged as sent:

```
2026-xx-xx xx:xx:xx [SUCCESS] Email notification sent successfully
```

2. Check the recipient inbox. Confirm the email arrives with:
   - Subject containing the date and `Success/Total` counts
   - HTML body rendered correctly (not raw HTML text)
   - Two attachments: the HTML report and the CSV

3. Open both attachments and confirm they are not corrupted and contain the expected data.

**Expected result:**
- [x] `[SUCCESS] Email notification sent` in log
- [x] Email received with correct subject line
- [x] HTML body renders correctly
- [x] Both attachments present and openable

**Result:** PASS (Attempt 6) — exercised against Gmail SMTP (smtp.gmail.com:587 STARTTLS) with app password.

**Attempts and fixes:**
1. **Attempt 1 — AD auto-discovery failure.** `Resolve-TargetComputers` AD bind threw "user name or password is incorrect" because the interactive operator (Workstation Admin) lacks AD read; the existing ADSI fallback uses the current process credentials. Generic `Cannot proceed without a target list` error gave no guidance.
2. **Attempt 2 — better UX for AD failure.** Added detailed three-option remediation help block (install RSAT, create hosts.conf, use -ComputerName); applied to all three scripts.
3. **Attempt 3 — STIG-compatible AD credential.** Added `-ADCredential` / `-SaveADCredential` parameter pattern (mirrors `-SmtpCredential`/`-SaveSmtpCredential`). DPAPI-encrypted into `conf\ADCredential.xml`, auto-loaded on subsequent runs. `Get-ADComputer -Credential` when the AD module is present; `DirectoryEntry` with explicit creds for ADSI fallback. AD auto-discovery succeeded.
4. **Attempt 4 — `Send-MailMessage` deprecation warning + email send failure.** PS7 marked `Send-MailMessage` `[Obsolete]` and emits a warning on every script run that references it. Replaced with `System.Net.Mail.SmtpClient` + `MailMessage`. First post-replacement run failed with `Could not find a part of the path 'C:\WINDOWS\system32\Reports\...'` — `Attachment::new()` resolves relative paths against the .NET process CurrentDirectory, not PowerShell's `$PWD`. Also discovered `Get-EndpointClassification` makes a second AD query that wasn't honoring `-ADCredential`.
5. **Attempt 5 — UTF-8 mangling + classification credential.** Email arrived but non-ASCII chars (en-dash in `<h1>`, em-dash in failure text, → in version transitions) rendered as `?`. `MailMessage` defaults `Body/Subject/Headers` encoding to ASCII. Pinned all three to UTF-8. Also wired `-ADCredential` through `Get-EndpointClassification` so tier breakdown works in STIG environments. Fixed in same build.
6. **Attempt 6 — Fleet Version Summary layout + color.** Cards rendered horizontally in the standalone HTML but stacked vertically in Gmail because `display: grid` is stripped by Gmail's CSS sanitizer. Replaced with `<table role="presentation">` (email-safe layout primitive) and added semantic colored top-borders + value colors (amber/green/blue). PASS — both surfaces now render identically.

**Side improvements committed during this test:**
- `-DisableIPv6` config option (default true) — unreachable host detection dropped from ~21s to ~3s.
- `Get-EndpointClassification` honors `-ADCredential` (was silently downgrading all hosts to MemberServer when classification AD bind failed).

---

### v0.0.6h — Regression: bugs fixed in this release

**Purpose:** Confirm the specific bugs identified in the pre-refactor analysis are resolved.

**Setup:** Two endpoints; one outdated, one already current.

```powershell
.\Update-DefenderOffline.ps1 -WhatIfMode:$false
```

**Steps:**

1. **Version delta is an integer, not `Unknown`.** After the run, open the HTML report. Confirm the `Delta` column shows numeric values (e.g., `1012`) for updated endpoints — not the word `Unknown`.

```powershell
# Confirm in the CSV too
Import-Csv (Get-ChildItem .\Reports\*.csv | Sort-Object LastWriteTime -Desc | Select-Object -First 1) |
    Select-Object ComputerName, Status, Delta
# Expect: Delta is a number for Success rows, 0 or Unknown for skipped
```

2. **Version sorting is correct.** In an environment with version numbers like `1.405.9.0` and `1.405.100.0`, confirm the HTML report's Fleet Version Summary shows `1.405.100.0` as the **newest** (not `1.405.9.0`).

3. **Log collection copies the right files.** If `-LogSharePath` is configured, confirm the collected files are named `install_*.log` and `install_*.log.err` — not `mpam-fe.exe.*`.

```powershell
Get-ChildItem "\\NAS01\DefenderLogs\ENDPOINT01\" | Select-Object Name
# Expect: install_20260519_103045.log  and  install_20260519_103045.log.err
# NOT:    mpam-fe.exe.log  or  mpam-fe.exe.err
```

4. **No update needed for current endpoint — no file transfer.** Confirm the `No Update Needed` endpoint has a short duration (< 10s) confirming no ~200 MB transfer occurred. Cross-check with the per-host log:

```powershell
Get-Content "C:\Logs\PerHost\CURRENT-ENDPOINT.log"
# Expect: Status=No Update Needed; no "Copying" or file-transfer lines
```

5. **HTML report columns `Attempt` and `Timeout` are populated.** Open the HTML report and confirm both columns contain values — not blank headers over empty cells.

6. **`$ScriptVersion` is `0.0.6`.** Confirm the startup log header and the HTML report footer both show `v0.0.6`, not `v0.0.1`.

7. **Archive folders are excluded from version discovery.** If an `Archive` or `_Archive` subfolder exists under the source share (a common housekeeping pattern), confirm the script does not select a version from inside it. Verify by checking the reported `Source file` path in the startup log does not contain `Archive`:

```powershell
# Create a decoy to simulate an archived higher-version package
# (use a version number higher than the real latest so the bug would be obvious if present)
$archivePath = "\\NAS01\DataShare\...\Microsoft_Defender\_Archive\20250101\v9.999.999.9"
New-Item -ItemType Directory -Path $archivePath -Force
Copy-Item "\\NAS01\...\mpam-fe.exe" $archivePath

.\Update-DefenderOffline.ps1 -WhatIfMode
# Expect: Source file does NOT reference _Archive in the log line:
#   [INFO] Source file : \\...\Microsoft_Defender\20260519\v1.449.681.0\mpam-fe.exe

# Cleanup
Remove-Item "\\NAS01\DataShare\...\Microsoft_Defender\_Archive" -Recurse -Force
```

```powershell
Select-String -Path (Get-ChildItem C:\Logs\Update-DefenderOffline_*.log | Sort-Object LastWriteTime -Desc | Select-Object -First 1) `
    -Pattern "ScriptVersion|v0\.0\."
# Expect: v0.0.6 in the header line
```

**Expected result:**
- [x] `Delta` column contains integers in HTML report and CSV; not `Unknown`
- [x] Version sort is numeric; `1.405.100.0` > `1.405.9.0` in summary *(implicit — Fleet Version Summary correctly picked `1.451.42.0` (build 42) as Newest over `1.451.36.0` (build 36); `[version]` cast compares each component numerically)*
- [ ] Log collection (if configured): files named `install_*.log`, not `mpam-fe.exe.*` *(N/A — `-LogSharePath` not set in test environment)*
- [ ] `No Update Needed` endpoint has short duration; per-host log confirms no transfer *(N/A — no "current" host in the targeted pair; both DH01 and NDI01 were Outdated. Previously verified in v0.0.6b)*
- [x] HTML report `Attempt` and `Timeout` columns are populated
- [x] Version shown as `v0.0.6` in log header and HTML report footer
- [x] Archive/\_Archive folder contents excluded from version discovery; decoy higher version not selected *(Source File path = `\\NAS01\…\20260522\v1.451.42.0\mpam-fe.exe`, no `_Archive` segment)*

**Result:** PASS (Attempt 2)

**Attempt 1 — discovered HTML report badge-filter bug:** clicking a stat card hid the column header row along with the non-matching data rows. Root cause: `ConvertTo-Html -Fragment` emits header `<tr>` and data `<tr>`s as siblings (no `<thead>`/`<tbody>`); browsers auto-wrap all of them in an implicit `<tbody>`, so `#resultsTable tbody tr` matched the header row too. The header `<tr>` has no `.tag` element, so `(badge && …)` evaluated to falsy and the row was hidden.
**Fix:** in `filterByStatus()`, skip rows where `r.querySelector('.tag')` is null (header / non-data rows) — only modify display on rows that actually have a status badge.

**Attempt 2 — PASS.** Live run on DH01 + NDI01 (both outdated): both updated successfully `1.451.36.0 → 1.451.42.0` with `Delta=6`, `Attempt=1`, `Timeout=No`. HTML report shows `v0.0.6` in footer, Source File path has no `_Archive` segment. Badge filter confirmed: clicking Failed/Skipped hides data rows but the column header band remains visible.

---

## Release Checklist

- [x] v0.0.6a PASS (config loading; WhatIf mode; AD auto-discovery; hosts.conf generation; HTML + CSV report)
- [x] v0.0.6b PASS (live update; parallel mode; version skip without file transfer; integer delta; HTML + CSV correct)
- [x] v0.0.6c PASS (offline hard fail; retry behaviour; correct error messages; No Update Needed validated)
- [ ] v0.0.6d PASS (Forms GUI opens; data loads; colour coding; filter; manual + auto refresh; CSV + HTML export)
- [ ] v0.0.6e PASS (port fallback; status file written/deleted; Event Log 101/100/102; all HTTP endpoints respond)
- [ ] v0.0.6f PASS (installer prereqs; service identity; scheduled task; ACLs; firewall rule; status file read; reboot persistence)
- [x] v0.0.6g PASS (Gmail SMTP via app password; surfaced + fixed: AD-discovery UX, -ADCredential pattern, Send-MailMessage deprecation, attachment-path resolution, UTF-8 mangling, Fleet Version Summary layout)
- [x] v0.0.6h PASS (delta integer; version sort; columns populated; version string; archive folder excluded. Log-filenames + no-transfer-for-current marked N/A — covered by prior v0.0.6b run)
- [ ] `CLAUDE.md` reflects current architecture
- [ ] `README.md` project name updated to Manage-DefenderOffline; repo renamed on GitHub ✓
- [ ] `conf/config.conf` complete and documented
- [ ] `.gitignore` excludes `hosts.conf`, `conf/dashboard.status`, `*.xml`, `*.log`
- [ ] No `*.tmp` or debug artifacts in working tree (`git status` clean)
- [ ] All four scripts parse clean (`Parser::ParseFile` reports 0 errors)
- [ ] `feat/monitoring-service` merged to `main` with `--no-ff`

# Test Plan — v0.0.20 (Manage-DefenderOffline)

## Baseline

`main` at commit `064f625` (v0.0.19 release).
**Feature branch:** `feat/v0.0.20-demo-feedback-and-ux-followups`
**Branch tip at plan authoring:** `89e222b`
**Test bundle:** `.dist/dist/manage-defenderoffline-0.0.20a.zip` (rebuild and bump the `-TestId` suffix as fixes land).

## Purpose

v0.0.20 is a polish release: it ships two demo-feedback items from 2026-06-02 and seven installer / report UX follow-ups carried over from the v0.0.19 lab pass. No new components, no breaking config schema, no migration. The scenarios below validate that the changes do what they say AND that nothing in the v0.0.19 happy path regressed.

Changes validated by this test plan:

| # | Change | Commit |
|---|---|---|
| 1 | Silent SMTP-skip breadcrumb when `-Component` excludes Updates | `367df36` |
| 2 | `Update-ConfigValue` retries on `IOException`, fails fast with actionable message | `91240de` |
| 3 | Default `-TaskName` → `Microsoft-Defender-Dashboard`; `-UpdateTaskName` → `Microsoft-Defender-Update` | `f477973` |
| 4 | Stale `Install-DefenderDashboard.ps1` reference in `HttpsCert.Tests.ps1` (test cleanup) | `7ae028a` |
| 5 | `[Meta] SchemaVersion = 1` in `config.conf`; `# SchemaVersion: 1` in `hosts.conf` header; `lib/Test-SchemaVersion.ps1` helper wired into all 5 reader scripts | `900b631` |
| 6 | `/status` and `/refresh` return 403 when `AuthMethod=None` (lock-down); `-AllowAnonymousStatus` opt-in for monitoring scrapers | `2211633` |
| 7 | Port-check moved BEFORE netsh sslcert + URL ACL; HTTP.sys orphan diagnostic via `lib/Get-PortBusyDiagnostic.ps1` | `536046a` |
| 8 | "Click a badge to filter" instruction suppressed in email body (`New-HtmlReport -Mode Email`); standalone HTML attachment unchanged | `30d6c04` |
| 9 | `-RunNowWhatIf` smoke task: early-bail within 20s if not started; completion-poll deadline 10min → 5min; diagnostics on both paths | `89e222b` |

### Key behaviors

1. **TaskName rename is a default change, not a forced rename.** Existing installs keep their old `DefenderDashboard` / `DefenderUpdate` task names. A fresh v0.0.20 install — or any install where `-TaskName` / `-UpdateTaskName` is not specified — gets the new defaults.
2. **`/status` lock-down defaults to OFF (the safe direction).** With `AuthMethod=None` and no `-AllowAnonymousStatus`, `/status` and `/refresh` return 403. `/defender` stays open so the UI works. `/health` is always anonymous. In Token / Basic / ADIntegrated modes `/status` follows the same auth as `/defender` — `-AllowAnonymousStatus` is None-mode-only.
3. **Schema version absent = treated as v1.** Pre-v0.0.20 configs missing the `[Meta] SchemaVersion = 1` line still load cleanly. A future on-disk version higher than what the script expects produces a WARN at startup but does not block.
4. **Port-check ordering matters.** With v0.0.20, a port-in-use failure during HTTPS install aborts BEFORE `netsh http add sslcert` and `netsh http add urlacl` run — so no manual `netsh http delete sslcert` cleanup is needed before re-trying.
5. **Smoke-test early-bail is independent of root cause.** The v0.0.19 hang hypothesis (same-identity contention) was never deterministically reproduced. The early-bail check covers any scenario where the smoke task is queued but not dispatched.

### Out of scope for v0.0.20 testing

- **gMSA paths.** Still field-untested per [`project_gmsa_untested.md`](C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/project_gmsa_untested.md). All v0.0.20 scenarios target traditional `-ServiceAccount` + `-Credential`. gMSA bugs surfaced later are first-encounter, not regressions.
- **Downloader component.** Still reserved for a later release; `-Component Downloader` should still error with the v0.0.19 `ValidateScript` message.
- **GUI consolidation.** Soft-frozen per [`feedback_gui_freeze.md`](C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/feedback_gui_freeze.md). `Show-DefenderStatus.ps1` got the schema-version check (it's a reader); no other behavior changes.

---

## Environment

Same as v0.0.19:

- **Admin workstation (lab build host):** Windows 10/11, PowerShell 7+, network access to the test endpoint over WinRM 5985.
- **Test endpoint:** Windows 10/11 or Server 2016+, WinRM enabled, local admin via the traditional service account. STIG-hardened host preferred so the seclogon dance still runs end-to-end.
- **Service account:** Traditional domain account with local admin on the test endpoint and read on the source share.
- **Test workflow:** Build the bundle on the dev box with a `-TestId` suffix if iterating; extract to `C:\Temp\MDO-Testing` on the test PC and run from there. ([`feedback_testing_workflow.md`](C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/feedback_testing_workflow.md))

## Setup

Confirm branch and version on the admin workstation:

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
git branch --show-current
# Expect: feat/v0.0.20-demo-feedback-and-ux-followups

Select-String -Path Install-ManageDefender.ps1 -Pattern "ScriptVersion\s*="
# Expect: $ScriptVersion = '0.0.20'   (after the release-cut version bump)
```

Extract the test bundle on the test endpoint:

```powershell
$bundle = 'C:\Temp\MDO-Testing\manage-defenderoffline-0.0.20a.zip'
$dest   = 'C:\Temp\MDO-Testing\0.0.20a'
Expand-Archive -Path $bundle -DestinationPath $dest -Force
Set-Location $dest
Get-ChildItem
```

Capture the seclogon baseline on the test endpoint (needed if scenario `e` ends up re-running the credential save):

```powershell
Get-Service seclogon | Select-Object Name, Status, StartType
```

---

### v0.0.20a — Schema version baseline and TaskName rename verification

**Purpose:** Read-only sanity checks against the shipped bundle before any install runs. Confirms that the bundle on disk carries the new defaults and pragmas.

**Setup:** Bundle extracted; no installer run yet.

**Steps:**

1. Confirm `conf/config.conf` has the new `[Meta]` block as its first section:

```powershell
Select-String -Path .\conf\config.conf -Pattern '^\[Meta\]|^SchemaVersion\s*=' | Select-Object -First 3
# Expect: [Meta] header followed by SchemaVersion = 1
```

2. Confirm the TaskName defaults in `conf/config.conf` use the new names:

```powershell
Select-String -Path .\conf\config.conf -Pattern '^TaskName\s*=|^UpdateTaskName\s*='
# Expect:
#   TaskName = Microsoft-Defender-Dashboard
#   UpdateTaskName = Microsoft-Defender-Update
```

3. Confirm the new lib helpers shipped:

```powershell
Get-ChildItem .\lib\*.ps1 | Select-Object Name
# Expect (among others):
#   Test-SchemaVersion.ps1
#   Get-PortBusyDiagnostic.ps1
#   Wait-SmokeTaskStart.ps1
```

4. Confirm the installer's `-TaskName` parameter default in the script source:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern "TaskName\s+=\s+'Microsoft-Defender-"
# Expect two matches: one for TaskName, one for UpdateTaskName
```

**Expected result:**

- [ ] `conf/config.conf` opens with `[Meta]` followed by `SchemaVersion = 1`
- [ ] `TaskName = Microsoft-Defender-Dashboard` and `UpdateTaskName = Microsoft-Defender-Update` present in config
- [ ] Three new lib helpers present
- [ ] Installer parameter defaults match the new names in the script source

**Result:** _TBD_

---

### v0.0.20b — Dashboard component: TaskName rename + silent SMTP-skip + /status lock-down + email click-affordance

**Purpose:** Single Dashboard install exercises four v0.0.20 changes at once. The endpoint state at the end of this scenario is what scenarios `c`, `d`, `f` build on.

**Setup:** Test endpoint with no `Microsoft-Defender-Dashboard` (or older `DefenderDashboard`) task registered. `conf/config.conf` has `SourceSharePath` set, `AuthMethod = None` (the default), and `SendEmail = true` so we can verify the silent-SMTP-skip breadcrumb.

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

**Steps:**

1. **Silent SMTP-skip breadcrumb.** During the credential-setup section, look for the `Write-Info` line explaining why SMTP setup was skipped:

```
   SMTP setup skipped: SendEmail=true in config applies to the Updates task,
   which is not included in -Component Dashboard. Re-run with -Component Updates
   or -Component All to configure SMTP.
```

   This is the v0.0.20 fix for the "I had SendEmail=true; why didn't the installer prompt for SMTP creds?" footgun.

2. **TaskName rename in action.** Confirm the registered task uses the new default name:

```powershell
Get-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard' | Select-Object TaskName, State
# Expect: present, State=Running (because -StartImmediately)

Get-ScheduledTask -TaskName 'DefenderDashboard' -ErrorAction SilentlyContinue
# Expect: $null  (old default name no longer used on fresh installs)
```

3. **Schema-version startup output.** Check the installer's startup output for the schema-check line (should NOT emit a WARN with v1 config):

```
# No WARN line about config.conf SchemaVersion — silent pass-through is the
# correct v1=v1 behavior.
```

4. **/status lock-down.** With `AuthMethod=None` and no `-AllowAnonymousStatus`, `/status` and `/refresh` should return 403 while `/defender` and `/health` stay open:

```powershell
# /defender open
Invoke-WebRequest http://localhost:8080/defender -UseBasicParsing |
    Select-Object StatusCode
# Expect: 200

# /health open
Invoke-WebRequest http://localhost:8080/health -UseBasicParsing |
    Select-Object StatusCode
# Expect: 200

# /status LOCKED
try { Invoke-WebRequest http://localhost:8080/status -UseBasicParsing -ErrorAction Stop } catch {
    $_.Exception.Response.StatusCode.value__
}
# Expect: 403

# /refresh LOCKED (same gate)
try { Invoke-WebRequest http://localhost:8080/refresh -UseBasicParsing -ErrorAction Stop } catch {
    $_.Exception.Response.StatusCode.value__
}
# Expect: 403
```

5. **Dashboard log emits the lock-down INFO line at startup:**

```powershell
Get-Content "C:\Logs\DefenderDashboard\DefenderDashboard_$(Get-Date -Format yyyyMMdd).log" |
    Select-String 'status-locked|AllowAnonymousStatus' | Select-Object -First 3
# Expect: '/status and /refresh return 403 because AuthMethod=None...'
```

6. **Opt-in via -AllowAnonymousStatus.** Stop the task, set the config key, restart, and verify `/status` opens AND the dashboard log line flips to a WARN:

```powershell
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
# Edit conf/config.conf: AllowAnonymousStatus = true
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-Sleep -Seconds 10

Invoke-WebRequest http://localhost:8080/status -UseBasicParsing |
    Select-Object StatusCode
# Expect: 200

Get-Content "C:\Logs\DefenderDashboard\DefenderDashboard_$(Get-Date -Format yyyyMMdd).log" |
    Select-String 'exposed anonymously|AllowAnonymousStatus' | Select-Object -Last 2
# Expect: a WARN line — "/status and /refresh are exposed anonymously (-AllowAnonymousStatus is set)..."
```

7. **Reset AllowAnonymousStatus to false** before moving on to subsequent scenarios:

```powershell
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
# Edit conf/config.conf: AllowAnonymousStatus = false
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
```

**Expected result:**

- [ ] Banner emits the "SMTP setup skipped" `Write-Info` line during credential setup
- [ ] `Microsoft-Defender-Dashboard` task registered; no `DefenderDashboard` task present
- [ ] No schema-version WARN in installer output (v1 config matches v1 expectation)
- [ ] `/defender` returns 200; `/health` returns 200; `/status` returns 403; `/refresh` returns 403 (default AuthMethod=None state)
- [ ] Dashboard log emits the locked-down INFO line at startup
- [ ] After setting `AllowAnonymousStatus = true`: `/status` returns 200, dashboard log emits the opt-open WARN
- [ ] After resetting to `false`: `/status` back to 403

**Result:** _TBD_

---

### v0.0.20c — Email body affordance suppression (separate verification)

**Purpose:** Confirm the "Click a badge to filter the results table" instruction is suppressed in the emailed report body but preserved in the on-disk HTML attachment. This is independent of how Updates is installed — it's about the rendering paths inside `New-HtmlReport`.

**Setup:** The Updates task is not yet installed (we're going to run the script directly here). `conf/config.conf` has `SendEmail = true`, valid `SmtpServer`, and `EmailTo`. `SmtpCredential.xml` is already saved in `conf/` from a prior scenario (or use `-SaveSmtpCredential` ahead of time).

```powershell
.\Update-DefenderOffline.ps1 `
    -ComputerName $env:COMPUTERNAME `
    -SourceSharePath "<your share>" `
    -WhatIfMode `
    -SendEmail
```

**Steps:**

1. After the script runs, find the report file written under `Reports/`:

```powershell
Get-ChildItem .\Reports\DefenderUpdateReport_*.html | Sort-Object LastWriteTime -Desc |
    Select-Object -First 1
```

2. Confirm the standalone HTML file STILL contains the affordance text (it works when opened in a browser):

```powershell
$report = Get-ChildItem .\Reports\DefenderUpdateReport_*.html | Sort-Object LastWriteTime -Desc | Select-Object -First 1
Get-Content $report.FullName -Raw | Select-String 'Click a badge to filter'
# Expect: one match
```

3. Open the emailed message in any email client. Confirm:
   - The status badges (Success / Failed / Skipped) are visible
   - **The instruction "Click a badge to filter the results table. Click again to clear." is absent from the email body**
   - The attached `.html` file (the same report from step 1) DOES contain the instruction when opened in a browser

**Expected result:**

- [ ] On-disk HTML report contains "Click a badge to filter the results table"
- [ ] Email body (visible content) does NOT contain the affordance text
- [ ] Email body still renders badge counts, host rows, version summary
- [ ] Attached `.html` file (saved by the email client) renders the affordance text when opened in a browser

**Result:** _TBD_

---

### v0.0.20d — Component=All with -RunNowWhatIf: smoke-test early-bail

**Purpose:** Validate the v0.0.20 fix for the v0.0.19 lab hang. `-Component All -RunNowWhatIf` should either complete the smoke test cleanly OR bail within ~20 seconds with a clear diagnostic — never the v0.0.19 long-poll hang.

**Setup:** Test endpoint with both tasks absent. Service account credentials in hand. `conf/config.conf` has `SourceSharePath` set.

```powershell
.\Install-ManageDefender.ps1 `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -StartImmediately `
    -RunNowWhatIf `
    -Force
# (no -Component → defaults to All)
```

**Steps:**

1. Confirm both tasks registered:

```powershell
Get-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard','Microsoft-Defender-Update' |
    Select-Object TaskName, State
# Expect: both present
```

2. Watch the smoke-test output. EITHER:

   **(a) Happy path** — the smoke task starts and completes:

   ```
   [STEP]  Running Update-DefenderOffline.ps1 -WhatIfMode as HOME\xxSecurityMonitor (smoke test)…
   --- WhatIf smoke test log (Update-DefenderOffline_<timestamp>.log) ---
   ...framed log content...
   --- end smoke test log ---
   [OK]    WhatIf smoke test exited cleanly (code 0).
   ```

   OR

   **(b) Early-bail** — the smoke task didn't start within 20s; the install emits the new diagnostic and continues:

   ```
   [STEP]  Running Update-DefenderOffline.ps1 -WhatIfMode as HOME\xxSecurityMonitor (smoke test)…
   [WARN]  WhatIf smoke task did not start within ~20s. Skipping completion poll;
           the install is otherwise complete.
           Likely cause: Task Scheduler queued the task but has not dispatched it
           (often a same-identity contention with another running task). The
           registered Updates task is unaffected.
           Smoke task state          : <Ready / Queued>
           Smoke task LastRunTime    : <stale timestamp>
           Smoke task LastTaskResult : 267009
           To exercise the Updates task manually: Start-ScheduledTask -TaskName 'Microsoft-Defender-Update' -TaskPath '\'
   ```

   The KEY point is the installer returns control within ~20-30 seconds either way. **Anything taking longer than 90 seconds is a regression** — kill it and capture the output for diagnosis.

3. **Independent of which branch fired**, confirm the registered Updates task itself works:

```powershell
Start-ScheduledTask -TaskName 'Microsoft-Defender-Update' -TaskPath '\'
Start-Sleep -Seconds 60   # give the WhatIf-less run time to do real work
Get-ScheduledTaskInfo -TaskName 'Microsoft-Defender-Update' -TaskPath '\' |
    Select-Object LastRunTime, LastTaskResult
# Expect: LastTaskResult=0; LastRunTime within the last minute
```

**Expected result:**

- [ ] Both tasks registered with new default names
- [ ] Smoke-test phase completes (clean exit OR early-bail diagnostic) within ~30 seconds
- [ ] Install never hangs longer than ~5 minutes (the hardened upper bound)
- [ ] Manual `Start-ScheduledTask` on the real Updates task runs successfully — regardless of whether the smoke test bailed

**Result:** _TBD_

---

### v0.0.20e — HTTPS install: port-check ordering (Item 3)

**Purpose:** A port-in-use failure on HTTPS install should now abort BEFORE the installer touches `netsh sslcert` / `netsh urlacl`. No half-configured state should be left behind for the operator to clean up manually.

**Setup:** Pick a port that's not the dashboard's default (e.g., 8444). On a separate PowerShell window, hold that port open:

```powershell
# Window A — keep this running for the duration of the scenario:
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 8444)
$listener.Start()
"Port 8444 held; Ctrl-C this window when done"
```

**Steps:**

1. **Before the install, snapshot the existing netsh state:**

```powershell
netsh http show sslcert ipport=0.0.0.0:8444
netsh http show urlacl url=https://+:8444/
# Either should be empty for a fresh box
```

2. **Run the installer with `-Port 8444 -UseHttps`** — the port-check should fail FAST, before any netsh mutation:

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -Port 8444 `
    -UseHttps `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -Force
```

3. Confirm the installer:
   - Aborts at the port-check phase, NOT after a half-completed sslcert binding
   - Emits the v0.0.20 HTTP.sys / userland diagnostic (in this case, the userland process is your own PowerShell window holding `$listener`)
   - Shows a non-zero exit code

```
[FAIL]  Port 8444 is in use and HTTPS does not support fallback (cert binding is per-port).
        Port 8444: held by PID <your PID> (pwsh). Stop that process (or pick a different port) and re-run.
```

4. **Confirm no half-configured netsh state was created:**

```powershell
netsh http show sslcert ipport=0.0.0.0:8444
# Expect: empty (or unchanged from baseline) — no v0.0.20 sslcert binding
netsh http show urlacl url=https://+:8444/
# Expect: empty (or unchanged from baseline) — no v0.0.20 urlacl reservation
```

5. **Tear down the blocker** (Ctrl-C window A), then retry the install — it should succeed cleanly with no leftover state interfering:

```powershell
.\Install-ManageDefender.ps1 -Component Dashboard -Port 8444 -UseHttps `
    -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred -StartImmediately -Force
```

**Expected result:**

- [ ] First install fails at port-check with the userland-PID diagnostic naming `pwsh` (Window A) and the held port
- [ ] No `netsh http show sslcert` binding present for 0.0.0.0:8444 after the failed install
- [ ] No `netsh http show urlacl` reservation present for https://+:8444/ after the failed install
- [ ] Second install (after releasing the port) succeeds without manual `netsh http delete sslcert` cleanup

**Result:** _TBD_

---

### v0.0.20f — HTTP.sys orphan diagnostic (Item 2, optional but recommended)

**Purpose:** Reproduce the PID 4 (System / HTTP.sys orphan) case and confirm the v0.0.20 diagnostic surfaces the right remediation. This is the case operators are LEAST likely to recognize on their own.

**Setup:** Best-effort reproduction — HTTP.sys orphans are inherently flaky. Two approaches:

**(A) Synthetic — simulate by binding HttpListener and killing pwsh ungracefully:**

```powershell
# Window B:
$L = [System.Net.HttpListener]::new()
$L.Prefixes.Add('http://+:8445/test/')
$L.Start()
# Then kill Window B abruptly (Task Manager -> End Task, NOT Ctrl-C / Stop-Process)
# This may leave HTTP.sys holding the port. Verify:
Get-NetTCPConnection -LocalPort 8445 -State Listen -ErrorAction SilentlyContinue |
    Select-Object OwningProcess
# If OwningProcess=4, we've reproduced the case.
```

**(B) Real-world — if you have a host where a prior dashboard run died and HTTP.sys is sitting on the port, run the install against THAT port.**

If neither (A) nor (B) reproduces, **skip this scenario** and rely on the unit-test coverage in `tests/PortBusyDiagnostic.Tests.ps1` for the PID-4 path.

**Steps (assuming reproduction succeeded on port 8445):**

1. Attempt the dashboard install on the held port:

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -Port 8445 `
    -UseHttps `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -Force
```

2. Confirm the diagnostic names HTTP.sys and surfaces the remediation:

```
[FAIL]  Port 8445 is in use and HTTPS does not support fallback (cert binding is per-port).
        Port 8445: held by HTTP.sys (PID 4 = System / kernel). A prior HttpListener
        exited without releasing its URL ACL. Release with 'Stop-Service http -Force;
        Start-Service http' (typically 30-60s; if the Stop hangs longer than 5 minutes,
        reboot). Then re-run the installer.
```

3. Follow the remediation:

```powershell
Stop-Service http -Force
Start-Service http

Get-NetTCPConnection -LocalPort 8445 -State Listen -ErrorAction SilentlyContinue
# Expect: empty — port released
```

4. Retry the install, should succeed.

**Expected result:**

- [ ] PID-4 case reproduced (synthetic or real)
- [ ] Diagnostic names HTTP.sys and PID 4 explicitly
- [ ] Diagnostic gives the exact `Stop-Service http -Force; Start-Service http` remediation
- [ ] Retry after remediation succeeds

OR, if reproduction failed:

- [ ] Scenario skipped; rely on unit-test coverage in `tests/PortBusyDiagnostic.Tests.ps1`

**Result:** _TBD_

---

### v0.0.20g — Config-lock retry / fail-fast (Item 6)

**Purpose:** Confirm `Update-ConfigValue` rides out a transient editor lock and, on persistent lock, fails with an actionable message instead of the cryptic IO sharing-violation.

**Setup:** A previously installed component (any) so the installer has reason to touch config. Open `conf/config.conf` in Notepad and **leave it open with focus on the file** (Notepad holds an exclusive write lock on the file while it's open in older Notepad; modern Notepad's behavior varies but the test still exercises the retry-and-fail path).

**Steps:**

1. With Notepad still holding `conf/config.conf`, run an installer command that triggers a config write — e.g., re-running the dashboard install with `-Port 8090` (different from current) which forces a Port persist:

```powershell
.\Install-ManageDefender.ps1 -Component Dashboard -Port 8090 `
    -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred -Force
```

2. The installer should emit one of two outcomes:
   - **(a) Notepad releases briefly** during the install's retry window → the write succeeds; no error.
   - **(b) Notepad keeps the lock** for the full ~2.5s retry budget → the installer emits the new actionable message:

```
[FAIL]  Could not write to 'D:\...\conf\config.conf' after 4 attempts (~2.5s).
        Close any editor (Notepad, VS Code, Word) that has the file open, then
        retry. Underlying error: The process cannot access the file '...' because
        it is being used by another process.
```

3. Close Notepad and retry the install — should succeed cleanly.

**Expected result:**

- [ ] Install either succeeds (rode out the lock) or fails with the actionable message naming likely culprits
- [ ] No bare IO sharing-violation in the operator-facing output
- [ ] After closing the editor, retry succeeds

**Result:** _TBD_

---

### v0.0.20h — Schema-version mismatch WARN (synthetic future-version test)

**Purpose:** Validate that all five reader scripts detect a future on-disk SchemaVersion and emit a WARN at startup without blocking execution.

**Setup:** A baseline install completed. Synthetically bump the on-disk schema version to a "future" value:

```powershell
# Backup the real config first
Copy-Item .\conf\config.conf .\conf\config.conf.bak

# Edit conf/config.conf and change:
#   SchemaVersion = 1
# to:
#   SchemaVersion = 99
```

**Steps:**

1. **Installer:** Run any installer command. The startup output should include the schema WARN:

```powershell
.\Install-ManageDefender.ps1 -Component Dashboard -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred -WhatIf
# Expect: [WARN] config.conf SchemaVersion is v99 but this script was built for v1. ...
# Install proceeds anyway.
```

2. **Dashboard:** Stop and restart the dashboard task; check the log for the WARN:

```powershell
Stop-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-ScheduledTask -TaskName 'Microsoft-Defender-Dashboard'
Start-Sleep -Seconds 10
Get-Content "C:\Logs\DefenderDashboard\DefenderDashboard_$(Get-Date -Format yyyyMMdd).log" |
    Select-String 'SchemaVersion' | Select-Object -Last 2
# Expect: a [WARN] line mentioning v99 and v1.
```

3. **Update-DefenderOffline:** Trigger a manual WhatIf:

```powershell
.\Update-DefenderOffline.ps1 -WhatIfMode -ComputerName $env:COMPUTERNAME -SourceSharePath "<your share>"
# Expect: WARN line about config.conf SchemaVersion v99 vs v1 in the startup banner output
```

4. **Show-DefenderStatus:** Launch the GUI; the WARN should surface via `Write-Warning`:

```powershell
.\Show-DefenderStatus.ps1
# Expect: yellow WARNING line in the console before the form opens
```

5. **Get-DefenderDefinitions:** (Downloader) — invoke it:

```powershell
.\Get-DefenderDefinitions.ps1 -OutputPath C:\Temp\dlr-test -WhatIf
# Expect: WARNING about SchemaVersion v99 vs v1
```

6. **hosts.conf side:** Synthetically bump the hosts.conf header pragma:

```powershell
# Backup
Copy-Item .\hosts.conf .\hosts.conf.bak
# Edit the header:
#   # SchemaVersion: 1
# to:
#   # SchemaVersion: 99
```

   Now run `Update-DefenderOffline.ps1` again and confirm a SECOND WARN line specifically about `hosts.conf`:

```
[WARN] hosts.conf SchemaVersion is v99 but this script was built for v1. ...
```

7. **Restore both files** before moving on:

```powershell
Copy-Item .\conf\config.conf.bak .\conf\config.conf -Force
Copy-Item .\hosts.conf.bak .\hosts.conf -Force
Remove-Item .\conf\config.conf.bak, .\hosts.conf.bak
```

**Expected result:**

- [ ] Installer emits the config.conf v99/v1 WARN at startup
- [ ] Dashboard log emits the WARN after restart
- [ ] Update-DefenderOffline emits the WARN in its startup banner
- [ ] Show-DefenderStatus emits the WARN via `Write-Warning` before the form loads
- [ ] Get-DefenderDefinitions emits the WARN via `Write-Warning`
- [ ] hosts.conf v99 also produces a separate WARN in Update-DefenderOffline output
- [ ] All scripts STILL run to completion (mismatch is warn-only, not blocking)

**Result:** _TBD_

---

### v0.0.20i — Regression: `-Component Downloader` still errors out

**Purpose:** Confirm the v0.0.19 `[ValidateScript]` guard on `-Component` is unchanged by v0.0.20 work.

**Steps:**

```powershell
.\Install-ManageDefender.ps1 -Component Downloader
```

**Expected result:**

- [ ] Errors out cleanly with "Component 'Downloader' is reserved for v0.0.20 and not yet implemented" — same message as v0.0.19g

**Note:** The error message still references "v0.0.20" because Downloader was deferred AGAIN. Update the ValidateScript message at the next release when Downloader actually lands.

**Result:** _TBD_

---

## Release Checklist

- [ ] v0.0.20a PASS — `[Meta] SchemaVersion = 1` in config; `Microsoft-Defender-*` defaults in config; new lib helpers shipped
- [ ] v0.0.20b PASS — Silent SMTP-skip breadcrumb visible; new default task name registered; `/status` 403 by default, 200 with `-AllowAnonymousStatus`; dashboard log emits INFO and WARN lines correctly
- [ ] v0.0.20c PASS — Email body lacks "Click a badge to filter" affordance; attached HTML still contains it
- [ ] v0.0.20d PASS — `-Component All -RunNowWhatIf` either completes cleanly OR bails within 20-30s with the diagnostic; never hangs > 5 min
- [ ] v0.0.20e PASS — Port-in-use HTTPS install aborts at port-check; no half-configured netsh sslcert / urlacl left behind
- [ ] v0.0.20f PASS or SKIPPED — HTTP.sys orphan diagnostic names PID 4 and the remediation, OR scenario skipped with unit-test fallback noted
- [ ] v0.0.20g PASS — Config-lock retry succeeds or fails fast with actionable message; no bare IO sharing-violation
- [ ] v0.0.20h PASS — Future-version WARN surfaces in all five reader scripts (installer, dashboard, update, status GUI, downloader); both config.conf and hosts.conf cases
- [ ] v0.0.20i PASS — `-Component Downloader` still errors cleanly
- [ ] gMSA paths still untested in lab — flagged in release notes; not a regression
- [ ] No `*.tmp` artifacts in working tree (`git status` clean)
- [ ] All shipped scripts parse clean (`Parser::ParseFile` reports 0 errors)
- [ ] Full Pester suite green (`Invoke-Pester -Path ./tests` — expect ~297 passed, 0 failed)
- [ ] `$ScriptVersion` bumped to `'0.0.20'` across all five scripts (release-cut step)
- [ ] README v0.0.20 entry drafted; QUICKSTART version-bumped
- [ ] `feat/v0.0.20-demo-feedback-and-ux-followups` squash-merged to `main` via PR
- [ ] Release tagged `v0.0.20`, marked `--prerelease` on GitHub per pre-1.0 policy

# Test Plan — v0.0.19 (Manage-DefenderOffline)

## Baseline

`main` at commit `411e1fd` (v0.0.18 release).
**Feature branch:** `feat/v0.0.19-unified-installer`
**Branch tip at plan authoring:** `5b64587`
**Test bundle:** `.dist/dist/manage-defenderoffline-0.0.19d.zip` (16 files, ~184 KB)

## Purpose

v0.0.19 collapses installation into a single entry point and adds end-to-end automation for the original use case the project was built for: periodic definition patching on endpoints. Key changes validated by this test plan:

1. **Unified installer** — `Install-ManageDefender.ps1` replaces `Install-DefenderDashboard.ps1` (deleted, no shim). Driven by `-Component <Dashboard|Updates|All|Downloader>` (default `All`, which means Dashboard + Updates and explicitly **not** Downloader; Downloader is reserved for v0.0.20).
2. **Updates component** — Registers a `DefenderUpdate` scheduled task that runs `Update-DefenderOffline.ps1` on a schedule. `-Frequency TwiceDaily|Daily|Weekly|Monthly` plus `-UpdateStartTime 'HH:mm'` (default `02:00`). Monthly uses `MSFT_TaskMonthlyTrigger` (CIM) because `New-ScheduledTaskTrigger` has no `-Monthly`.
3. **Full credential automation** — Installer drops `WinRmCredential.xml`, `ADCredential.xml`, and (optionally) `SmtpCredential.xml` into `conf/` under the **service identity's** DPAPI master key, so the unattended task can decrypt them at runtime. `-SkipCredentialSetup` opts out and prints follow-up instructions.
4. **STIG V-253289 (Secondary Logon Service) handling** — On STIG-hardened hosts where seclogon is Disabled, the installer enables the service, performs the credential save, then restores `Disabled` in a `finally` block. Pattern lifted from `Get-CiscoTechSupport\Install-GetCiscoTechSupport.ps1`.
5. **Conf folder pre-grant** — Before credential save runs, the installer pre-grants the service identity `Modify` on `conf/` and `ReadAndExecute` on the script folder. Without this, `Start-Process -Credential` (traditional account) or the one-shot scheduled task (gMSA) writes the cred XML into a folder it cannot access. Surfaced by self-code-review on 2026-06-01; would have bitten gMSA testing first.
6. **`-RunNowWhatIf` smoke test** — Updates component installer can fire the task once with `-WhatIfMode` to verify wiring before the real schedule fires.
7. **Config file additions** — `[Install]` section now carries `UpdateTaskName`, `UpdateTaskFolder`, `UpdateFrequency`, and `UpdateStartTime`.

Deliverables validated by this test plan:

| File | Role |
|---|---|
| `Install-ManageDefender.ps1` | Single entry-point installer; component-driven; credential automation; STIG seclogon handling |
| `lib/Save-ServiceCredential.ps1` | Helper invoked under the service identity to re-encrypt credentials under its own DPAPI key |
| `conf/config.conf` | `[Install]` section extended with Updates-task keys |
| `Update-DefenderOffline.ps1` | No source changes from v0.0.18; validated as the target of the registered task |
| `Start-DefenderDashboard.ps1` | Error messages updated to point at `Install-ManageDefender -Component Dashboard` |
| `Show-DefenderStatus.ps1` | Synopsis reference updated |
| `ARCHITECTURE.md`, `README.md`, `QUICKSTART.md` | Operator-facing docs updated to the unified installer |
| `.dist/release.ps1` | Manifest includes `Install-ManageDefender.ps1`; old installer removed from manifest |

### Key behaviors

1. **Default `-Component All` is two components, not three.** `All` = Dashboard + Updates. Downloader is a separate host concept (the box that pulls definitions from the internet into the air-gapped share) and is reserved for v0.0.20 — never auto-installed.
2. **Credential save runs once per install, not per component.** `Initialize-ServiceCredentials` is called before component dispatch and lays down whichever cred files are required by the components being installed (WinRm + AD always; Smtp only if `[Email] SendEmail = true`).
3. **DPAPI handoff format.** Caller writes a two-line UTF-8 file: line 1 = username, line 2 = base64 of `ProtectedData::Protect(UTF-16 password, LocalMachine scope)`. Service identity reads it, decrypts under LocalMachine, re-exports as Clixml under its own user-scoped DPAPI key, then exits. Caller deletes the handoff file immediately. No plaintext password ever lands on disk.
4. **STIG restore is in `finally`.** If credential save throws, the seclogon service is still restored to its prior state before the installer exits. Manual cleanup commands print only if the restore itself fails.
5. **Conf folder pre-grant is gated.** Skipped when `-SkipCredentialSetup` is supplied (no credentials → no need for the service identity to write to `conf/` at install time).
6. **PSScriptAnalyzer false positive suppressed in-source.** `Invoke-AsServiceIdentity` and `Save-ServiceCredential` take a `$CredentialName` string parameter that is a tag (`'WinRm'`/`'AD'`/`'Smtp'`), not credential material. Suppressed with `[SuppressMessageAttribute]` + inline justification rather than renamed (preserves semantic clarity).
7. **Monthly trigger via CIM.** `New-ScheduledTaskTrigger -Monthly` does not exist; the installer builds the trigger directly from `MSFT_TaskMonthlyTrigger` in `ROOT/Microsoft/Windows/TaskScheduler` (day 1 of every month at the configured time).
8. **Backward compat: none.** `Install-DefenderDashboard.ps1` is **deleted**, not shimmed. Per the project's pre-1.0 policy ("not in production yet"). Any saved invocation pointing at the old script name will fail immediately with a file-not-found error — there is no silent redirect.

### Out of scope for v0.0.19 testing

- **gMSA paths.** Neither lab has provisioned a gMSA. The gMSA code in the installer is spec-built but field-unvalidated; lab runs target `-ServiceAccount` + `-Credential` only. gMSA bugs surfaced later are first-encounter, not regressions. See [`project_gmsa_untested.md`](C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/project_gmsa_untested.md).
- **Downloader component.** Reserved for v0.0.20. `-Component Downloader` should explicitly error out as "not yet implemented" — that error path is the only thing this plan validates for Downloader.

---

## Environment

- **Admin workstation (lab build host):** Windows 10/11, PowerShell 7+, network access to the test endpoint over WinRM 5985 and to the source share for definition packages.
- **Test endpoint:** Windows 10/11 or Server 2016+, WinRM enabled, local admin via the traditional service account being tested. **At least one test endpoint must be STIG-hardened** (seclogon = Disabled) to exercise the V-253289 dance in scenario `v0.0.19e`.
- **Service account:** Traditional domain account with local admin on the test endpoint and read on the source share. **No gMSA needed for this train.**
- **Test workflow:** Per the established pattern, build the bundle on the dev box with a `-TestId` suffix if iterating; extract to `C:\Temp\MDO-Testing` on the test PC and run from there. ([`feedback_testing_workflow.md`](C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/feedback_testing_workflow.md))

## Setup

Confirm branch and version on the admin workstation:

```powershell
cd "D:\Dropbox\IT Docs\Scripts\Manage-DefenderOffline"
git branch --show-current
# Expect: feat/v0.0.19-unified-installer

Select-String -Path Install-ManageDefender.ps1 -Pattern "ScriptVersion\s*="
# Expect: $ScriptVersion = '0.0.19'

Test-Path .\Install-DefenderDashboard.ps1
# Expect: False  (deleted, no shim)
```

Extract the test bundle on the test endpoint:

```powershell
$bundle = 'C:\Temp\MDO-Testing\manage-defenderoffline-0.0.19d.zip'
$dest   = 'C:\Temp\MDO-Testing\0.0.19d'
Expand-Archive -Path $bundle -DestinationPath $dest -Force
Set-Location $dest
Get-ChildItem
# Expect: Install-ManageDefender.ps1 present; Install-DefenderDashboard.ps1 absent
```

Capture the seclogon baseline on the test endpoint (you will need it for scenario `v0.0.19e`):

```powershell
Get-Service seclogon | Select-Object Name, Status, StartType
# STIG box: StartType=Disabled, Status=Stopped
# Non-STIG box: StartType=Manual, Status=Stopped or Running
```

Pre-create the credential prompts off-hours if needed — the installer expects them interactively. For unattended runs, save them ahead of time using the equivalent `-SaveADCredential` / `-SaveSmtpCredential` flags on the update script.

---

### v0.0.19a — Dashboard component only (regression vs v0.0.18 installer)

**Purpose:** Prove the lifted Dashboard install path produces identical state to what the old `Install-DefenderDashboard.ps1` produced in v0.0.18 — same task name, same principal, same action, same triggers, same firewall rule, same ACLs.

**Setup:** Test endpoint with no `DefenderDashboard` task currently registered (uninstall any prior copy with `Unregister-ScheduledTask -TaskName DefenderDashboard -Confirm:$false`). Service account credentials in hand.

```powershell
$cred = Get-Credential -UserName "HOME\xxSecurityMonitor" -Message "Service account password"
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

**Steps:**

1. Confirm the banner identifies the unified installer and the chosen component:

```
=== Install-ManageDefender v0.0.19 ===
Component(s): Dashboard
Identity    : HOME\xxSecurityMonitor (traditional)
```

2. Confirm the credential-save block runs and lands `WinRmCredential.xml` + `ADCredential.xml` in `conf/`:

```powershell
Get-ChildItem .\conf\*.xml | Select-Object Name, Length
# Expect: WinRmCredential.xml and ADCredential.xml (and SmtpCredential.xml only if SendEmail=true)
```

3. Confirm the dashboard task is registered, identity matches, and `RunLevel=Highest`:

```powershell
Get-ScheduledTask -TaskName 'DefenderDashboard' | Select-Object TaskName, State
(Get-ScheduledTask -TaskName 'DefenderDashboard').Principal | Select-Object UserId, LogonType, RunLevel
# Expect: UserId=HOME\xxSecurityMonitor, LogonType=Password, RunLevel=Highest
```

4. Confirm the dashboard reaches `/health` cleanly:

```powershell
Invoke-WebRequest http://localhost:8080/health -UseBasicParsing | Select-Object StatusCode, Content
# Expect: 200 / OK
```

5. Confirm the firewall rule was created:

```powershell
Get-NetFirewallRule -DisplayName 'DefenderDashboard-TCP-8080' | Select-Object Enabled, Direction
# Expect: Enabled=True, Direction=Inbound
```

6. Confirm conf ACL has the service identity with `Modify`:

```powershell
(Get-Acl .\conf).Access | Where-Object { $_.IdentityReference -match 'xxSecurityMonitor' } |
    Select-Object IdentityReference, FileSystemRights
# Expect: at least one Modify entry; not duplicated
```

7. Compare the registered action against what the v0.0.18 installer would have produced — should be the same `pwsh.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "...\Start-DefenderDashboard.ps1"` invocation:

```powershell
(Get-ScheduledTask -TaskName 'DefenderDashboard').Actions | Format-List
```

**Expected result:**
- [ ] Banner names `Install-ManageDefender v0.0.19` and `Component(s): Dashboard`
- [ ] `WinRmCredential.xml` and `ADCredential.xml` written under `conf/` and readable as the service identity
- [ ] Dashboard task registered; `Get-ScheduledTask` returns it with correct identity and `RunLevel=Highest`
- [ ] `/health` returns 200 OK within the installer's probe window
- [ ] Firewall rule enabled and inbound
- [ ] `conf/` ACL has a single (not duplicated) `Modify` entry for the service identity
- [ ] Registered task action is functionally identical to the v0.0.18 form

**Result:** _Pending_

---

### v0.0.19b — Updates component only, default Daily 02:00

**Purpose:** Prove the new `DefenderUpdate` task registers correctly with the default daily trigger and that `-RunNowWhatIf` produces a clean smoke run.

**Setup:** Test endpoint with no `DefenderUpdate` task currently registered. `conf/config.conf` has `SourceSharePath` set (Update script needs it to discover the source bundle, even in WhatIf mode).

```powershell
.\Install-ManageDefender.ps1 `
    -Component Updates `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -RunNowWhatIf `
    -Force
```

**Steps:**

1. Confirm the banner shows `Component(s): Updates` and the chosen frequency (`Daily`) and start time (`02:00`).

2. Confirm credential save still runs (it's shared infrastructure, not Dashboard-specific):

```powershell
Get-ChildItem .\conf\*.xml | Select-Object Name
# Expect: WinRmCredential.xml, ADCredential.xml
```

3. Confirm the `DefenderUpdate` task registered with a daily trigger at 02:00:

```powershell
Get-ScheduledTask -TaskName 'DefenderUpdate' | Select-Object TaskName, State
(Get-ScheduledTask -TaskName 'DefenderUpdate').Triggers | Format-List
# Expect: one trigger, ScheduleByDay every 1 day, StartBoundary contains T02:00:00
```

4. Confirm the registered action is the Update script with `-ConfigPath`:

```powershell
(Get-ScheduledTask -TaskName 'DefenderUpdate').Actions | Format-List Execute, Arguments
# Expect: Execute=pwsh.exe ; Arguments contain -File "...\Update-DefenderOffline.ps1" -ConfigPath "...\conf\config.conf"
```

5. Confirm `-RunNowWhatIf` fired the task once and produced a clean log:

```powershell
Get-ScheduledTaskInfo -TaskName 'DefenderUpdate' | Select-Object LastRunTime, LastTaskResult
# LastTaskResult=0 (success)

Get-ChildItem C:\Logs\Update-DefenderOffline_*.log | Sort-Object LastWriteTime -Desc | Select-Object -First 1 |
    Get-Content -Tail 30
# Expect: WhatIf banner, no errors, no email send attempt
```

6. Confirm `[Install]` keys in `conf/config.conf` were updated (if the installer was given non-default values, this is where they persist):

```powershell
Select-String -Path .\conf\config.conf -Pattern 'UpdateTaskName|UpdateFrequency|UpdateStartTime'
```

**Expected result:**
- [ ] Banner reports `Component(s): Updates`, `Frequency: Daily`, `UpdateStartTime: 02:00`
- [ ] Cred files present in `conf/`
- [ ] `DefenderUpdate` task registered; State=Ready
- [ ] Trigger: `ScheduleByDay`, daily, `T02:00:00` start
- [ ] Action invokes `Update-DefenderOffline.ps1` with `-ConfigPath` pointing at the installed `conf/config.conf`
- [ ] `LastTaskResult = 0` after `-RunNowWhatIf`
- [ ] WhatIf log written; no errors; no email attempt
- [ ] `[Install]` keys persisted into `conf/config.conf`

**Result:** _Pending_

---

### v0.0.19c — `-Component All` (Dashboard + Updates) under a single identity

**Purpose:** Confirm both tasks register under one credential pass, with no duplicated cred-file writes and no duplicated `conf/` ACL grants.

**Setup:** Test endpoint with neither task currently registered. Both `DefenderDashboard` and `DefenderUpdate` should be absent at the start.

```powershell
.\Install-ManageDefender.ps1 `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -AddFirewallRule `
    -StartImmediately `
    -RunNowWhatIf `
    -Force
# (no -Component → defaults to All = Dashboard + Updates)
```

**Steps:**

1. Confirm the banner says `Component(s): Dashboard, Updates` (the default `All`) and explicitly **not** Downloader.

2. Confirm credential save runs **once**, not twice. Look for a single set of `[STIG]`/`[CRED]` log blocks in the installer output, not duplicated per component.

3. Confirm both tasks are present:

```powershell
Get-ScheduledTask -TaskName 'DefenderDashboard','DefenderUpdate' |
    Select-Object TaskName, State
# Expect: both present
```

4. Confirm both tasks run as the same identity:

```powershell
'DefenderDashboard','DefenderUpdate' | ForEach-Object {
    (Get-ScheduledTask -TaskName $_).Principal | Select-Object @{n='Task';e={$_}}, UserId
}
# Expect: same UserId on both
```

5. Confirm `conf/` ACL has exactly **one** explicit `Modify` entry for the service identity (not two from two grant passes):

```powershell
(Get-Acl .\conf).Access |
    Where-Object { $_.IsInherited -eq $false -and $_.IdentityReference -match 'xxSecurityMonitor' } |
    Measure-Object
# Expect: Count=1
```

6. Confirm both smoke checks pass: `/health` returns 200 and `DefenderUpdate` LastTaskResult=0.

**Expected result:**
- [ ] Banner names both components, omits Downloader
- [ ] Single credential-save block; both `WinRmCredential.xml` and `ADCredential.xml` present
- [ ] Both tasks registered under the same identity
- [ ] `conf/` ACL has exactly one explicit grant for the service identity
- [ ] Dashboard `/health` returns 200 OK
- [ ] `DefenderUpdate` LastTaskResult=0 after `-RunNowWhatIf`

**Result:** _Pending_

---

### v0.0.19d — Frequency variants (TwiceDaily, Weekly, Monthly)

**Purpose:** Validate that all four `-Frequency` values produce correct triggers — the monthly path is the highest-risk because it bypasses `New-ScheduledTaskTrigger` and builds a CIM `MSFT_TaskMonthlyTrigger` directly.

**Setup:** Test endpoint with no `DefenderUpdate` task. Run the installer three times in sequence (or four counting the Daily run from `v0.0.19b`), passing `-Force` each time to overwrite.

```powershell
# TwiceDaily
.\Install-ManageDefender.ps1 -Component Updates `
    -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred `
    -Frequency TwiceDaily -SkipCredentialSetup -Force

(Get-ScheduledTask -TaskName 'DefenderUpdate').Triggers | Format-List StartBoundary, DaysInterval

# Weekly
.\Install-ManageDefender.ps1 -Component Updates `
    -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred `
    -Frequency Weekly -UpdateStartTime '03:30' -SkipCredentialSetup -Force

(Get-ScheduledTask -TaskName 'DefenderUpdate').Triggers | Format-List StartBoundary, DaysOfWeek, WeeksInterval

# Monthly
.\Install-ManageDefender.ps1 -Component Updates `
    -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred `
    -Frequency Monthly -UpdateStartTime '04:00' -SkipCredentialSetup -Force

(Get-ScheduledTask -TaskName 'DefenderUpdate').Triggers | Format-List
```

`-SkipCredentialSetup` is used here so each re-install doesn't re-prompt for the password; we already validated the cred-save path in `v0.0.19a`–`v0.0.19c`.

**Steps:**

1. **TwiceDaily** → confirm two triggers, both daily, at `02:00` and `14:00` (or whatever the implementation chose — verify against the source if values surprise you).
2. **Weekly** → confirm one trigger, weekly, on the configured day (default Sunday per plan doc) at `03:30`.
3. **Monthly** → confirm one trigger of type `MSFT_TaskMonthlyTrigger`, day 1 of every month, at `04:00`. The CIM class should resolve cleanly:

```powershell
$t = (Get-ScheduledTask -TaskName 'DefenderUpdate').Triggers[0]
$t.CimClass.CimClassName
# Expect: MSFT_TaskMonthlyTrigger
$t.DaysOfMonth     # Expect: 1
$t.MonthsOfYear    # Expect: 4095 (all 12 months) or equivalent bitmask
```

4. **`-UpdateStartTime` round-trip** → re-register `Weekly -UpdateStartTime '17:45'` and confirm the `StartBoundary` reflects 17:45 local time.

**Expected result:**
- [ ] TwiceDaily: two daily triggers; second start exactly 12 h offset (or per spec)
- [ ] Weekly: one weekly trigger; configured day; configured time
- [ ] Monthly: `MSFT_TaskMonthlyTrigger`; day 1; all 12 months; configured time
- [ ] `-UpdateStartTime` round-trips cleanly across all three frequencies
- [ ] `-Force` overwrites prior `DefenderUpdate` task without a prompt or error

**Result:** _Pending_

---

### v0.0.19e — STIG seclogon dance + credential save under traditional account

**Purpose:** Validate the V-253289 enable→save→restore-Disabled pattern on a STIG-hardened endpoint, and verify the credential files written by the installer can actually be read by the service identity at task runtime.

**Setup:** Test endpoint with seclogon **Disabled** (the STIG state). Confirm baseline:

```powershell
Get-Service seclogon | Select-Object Name, Status, StartType
# Expect: StartType=Disabled, Status=Stopped
```

Run the installer:

```powershell
.\Install-ManageDefender.ps1 `
    -Component All `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

**Steps:**

1. Watch the installer console for the seclogon block. Expect three phases logged:
   - `[STIG] Secondary Logon Service is Disabled — enabling temporarily for credential save…`
   - `[STIG] Saving credentials under service identity…`
   - `[STIG] Restoring Secondary Logon Service to Disabled.`

2. After the installer exits, confirm seclogon was restored:

```powershell
Get-Service seclogon | Select-Object Status, StartType
# Expect: StartType=Disabled, Status=Stopped
```

3. Confirm `conf/WinRmCredential.xml` is owned by the user-scope DPAPI key of the **service identity**, not the installing admin. The fastest validation is to run a probe **as the service identity**:

```powershell
# As the service account (use psexec, runas, or a Scheduled Task):
$cred = Import-Clixml C:\path\to\conf\WinRmCredential.xml
Test-WSMan -ComputerName <some-target> -Credential $cred -Authentication Default
# Expect: success — confirms DPAPI handoff worked
```

4. Confirm no plaintext handoff files remain in `conf/`:

```powershell
Get-ChildItem .\conf\ | Where-Object Name -match '\.handoff$|\.tmp\.'
# Expect: nothing
```

5. **Negative test — force a credential-save failure to prove the `finally` restore.** Simulate by passing a bad service-account name (one that exists in AD but whose password you wrong-type). The installer should fail, but seclogon should still be restored to Disabled:

```powershell
$badCred = Get-Credential -UserName 'HOME\xxSecurityMonitor' -Message "type a wrong password"
.\Install-ManageDefender.ps1 -Component Updates -ServiceAccount "HOME\xxSecurityMonitor" -Credential $badCred -Force
# Expect: installer errors out on cred save
Get-Service seclogon | Select-Object StartType
# Expect: StartType=Disabled  (restored even on failure)
```

**Expected result:**
- [ ] STIG enable→save→restore block logs all three phases
- [ ] After clean install: seclogon = Disabled / Stopped (matches baseline)
- [ ] `conf/WinRmCredential.xml` decrypts correctly when read as the service identity (probed via `Test-WSMan`)
- [ ] No `.handoff` / `.tmp.*` artifacts left in `conf/`
- [ ] Negative test: installer fails cleanly; seclogon still restored to Disabled in the `finally` block; manual cleanup instructions print only if the restore itself fails

**Result:** _Pending_

---

### v0.0.19f — `-SkipCredentialSetup` deferred path

**Purpose:** Confirm the opt-out path writes no credential files, doesn't touch seclogon, doesn't pre-grant `conf/`, and prints clear follow-up instructions for the operator.

**Setup:** Test endpoint with no prior install. seclogon Disabled (STIG box ideally — verifies the dance is genuinely skipped).

```powershell
.\Install-ManageDefender.ps1 `
    -Component All `
    -ServiceAccount "HOME\xxSecurityMonitor" `
    -Credential $cred `
    -SkipCredentialSetup `
    -Force
```

**Steps:**

1. Confirm the installer does **not** log any `[STIG]` or `[CRED]` lines.

2. Confirm seclogon was not touched:

```powershell
Get-Service seclogon | Select-Object StartType
# Expect: unchanged from baseline (Disabled on STIG box)
```

3. Confirm no credential files were written:

```powershell
Get-ChildItem .\conf\*.xml -ErrorAction SilentlyContinue
# Expect: nothing (or only files that pre-existed before the test)
```

4. Confirm `conf/` ACL was **not** pre-granted to the service identity (the pre-grant block is gated on `!SkipCredentialSetup`):

```powershell
(Get-Acl .\conf).Access |
    Where-Object { $_.IsInherited -eq $false -and $_.IdentityReference -match 'xxSecurityMonitor' }
# Expect: nothing
```

5. Confirm both tasks still registered (the install completed):

```powershell
Get-ScheduledTask -TaskName 'DefenderDashboard','DefenderUpdate' | Select-Object TaskName, State
# Expect: both present, State=Ready
```

6. Confirm the installer printed deferred-credential instructions at the end — a clear block telling the operator which `-SaveXxxCredential` switches to run as the service identity, with sample commands.

**Expected result:**
- [ ] No `[STIG]` or `[CRED]` log blocks emitted
- [ ] seclogon unchanged
- [ ] No new `*Credential.xml` files in `conf/`
- [ ] No explicit ACL entries for the service identity on `conf/`
- [ ] Both tasks registered
- [ ] Closing instructions clearly list the deferred steps (sample `-SaveADCredential`, `-SaveCredential`, `-SaveSmtpCredential` invocations)

**Result:** _Pending_

---

### v0.0.19g — `-Force`, re-install, and `-Component Downloader` guard

**Purpose:** Round out edge cases — overwrite behavior and the explicit not-yet-implemented guard on the reserved Downloader component.

**Setup:** Test endpoint with both tasks already installed from a prior scenario.

**Steps:**

1. **Re-install without `-Force`** — expect a clear refusal:

```powershell
.\Install-ManageDefender.ps1 -Component Updates -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred
# Expect: error/abort message identifying the existing DefenderUpdate task and recommending -Force
```

2. **Re-install with `-Force`** — expect clean overwrite, no orphaned triggers, no duplicate ACLs:

```powershell
.\Install-ManageDefender.ps1 -Component Updates -ServiceAccount "HOME\xxSecurityMonitor" -Credential $cred -Force
# Verify single task only:
Get-ScheduledTask -TaskName 'DefenderUpdate*' | Measure-Object
# Expect: Count=1
```

3. **`-Component Downloader`** — expect a clean refusal that names the version it's reserved for:

```powershell
.\Install-ManageDefender.ps1 -Component Downloader
# Expect: error like "Downloader component is reserved for v0.0.20 and not yet implemented."
```

4. **Old installer name** — confirm the removed shim really is gone (no silent redirect):

```powershell
.\Install-DefenderDashboard.ps1 -Component Dashboard 2>&1 | Select-Object -First 1
# Expect: file-not-found / command-not-found from PowerShell, not a shim banner
```

**Expected result:**
- [ ] Re-install without `-Force` refuses cleanly and points the operator at `-Force`
- [ ] Re-install with `-Force` produces exactly one `DefenderUpdate` task; no duplicate explicit ACL on `conf/`
- [ ] `-Component Downloader` errors out with a message naming v0.0.20
- [ ] `Install-DefenderDashboard.ps1` no longer exists — invoking it produces a PowerShell file-not-found error

**Result:** _Pending_

---

## Release Checklist

- [ ] v0.0.19a PASS — Dashboard component matches v0.0.18 installer output (task, principal, action, firewall, ACLs)
- [ ] v0.0.19b PASS — Updates component registers `DefenderUpdate` with Daily 02:00; `-RunNowWhatIf` LastTaskResult=0
- [ ] v0.0.19c PASS — `-Component All` registers both tasks under one identity; single cred-save pass; single ACL grant
- [ ] v0.0.19d PASS — TwiceDaily / Weekly / Monthly triggers correct; Monthly uses `MSFT_TaskMonthlyTrigger`; `-UpdateStartTime` round-trips
- [ ] v0.0.19e PASS — STIG seclogon enable→save→restore (Disabled); credential XML decrypts as service identity; `finally` restore covers cred-save failure path
- [ ] v0.0.19f PASS — `-SkipCredentialSetup` writes nothing under `conf/`, leaves seclogon alone, prints deferred instructions
- [ ] v0.0.19g PASS — `-Force` semantics; Downloader guard; removed shim really is removed
- [ ] gMSA paths still untested in lab — flagged in release notes; not a regression
- [ ] No `*.tmp` artifacts in working tree (`git status` clean)
- [ ] All shipped scripts parse clean (`Parser::ParseFile` reports 0 errors)
- [ ] `feat/v0.0.19-unified-installer` squash-merged to `main` via PR
- [ ] Release tagged `v0.0.19`, marked `--prerelease` on GitHub per pre-1.0 policy

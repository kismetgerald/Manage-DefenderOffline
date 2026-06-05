# Test Plan — v0.0.23 (Manage-DefenderOffline)

## Baseline

`main` at commit `b688749` (v0.0.22 release).
**Feature branch:** `feat/v0.0.23-url-acl-cleanup`
**Test bundle:** to be built from the branch tip after this plan is approved.

## Purpose

v0.0.23 is a single-feature installer release: **`Install-ManageDefender.ps1` cleans up stale netsh URL-ACL and sslcert reservations from prior installer runs.** Closes the v0.0.12-vintage gap where switching the HTTPS port left behind reservations that quietly broke the HTTP→HTTPS redirect listener on the next install.

Changes validated by this test plan:

| # | Change | File(s) |
|---|---|---|
| A | New helper `lib/Get-StaleHttpReservations.ps1` — multi-binding sslcert parser + URL-ACL filter + sslcert filter + top-level orchestrator | new file |
| B | New `[switch]$PreserveStaleReservations` parameter; `.PARAMETER` help block | `Install-ManageDefender.ps1` |
| C | New `Invoke-StaleReservationCleanup` orchestration function | `Install-ManageDefender.ps1` |
| D | `Install-DashboardComponent` gains the new pass-through parameter; calls the cleanup right after `Write-Step "Configuring HTTPS…"` | `Install-ManageDefender.ps1` |
| E | New Pester suite `tests/StaleHttpReservations.Tests.ps1` — 17 tests across parser, two filters, orchestrator | new file |
| F | `$ScriptVersion = '0.0.23'` across all five scripts | 5 scripts |

### Key behaviors

1. **Identity matching is strictly scoped:**
   - URL-ACLs: SID comparison via `NTAccount.Translate(SecurityIdentifier)`. A reservation owned by an account that translates to the service identity's SID is "ours". Owners that don't translate (deleted accounts, foreign domains) are skipped — they don't disqualify the reservation, but they also don't match.
   - sslcert bindings: Application ID match (case-insensitive after whitespace removal). The installer creates bindings tagged with `$script:HttpsAppId = '{a3f9b1c2-d4e5-46f7-8901-234567890abc}'`; any binding using a different AppID is left alone.
2. **Shape matching for URL-ACLs:** only `<http|https>://+:<port>/` reservations are considered ours. Hostname-bound (`https://hostname:8081/`) and path-prefixed (`https://+:8443/path/`) reservations are left alone even if they share the service identity — they might be from a sister tool we don't manage.
3. **Active port preservation:** the active set is `{Port, RedirectHttpPort, FallbackPort}`. Reservations on any of those three ports are NEVER deleted, even if they're ours and stale-shaped.
4. **Confirmation UX:** when stale reservations are found, the installer lists them and prompts `Remove the stale reservation(s) listed above? [Y/N]`. `-Force` bypasses the prompt; `-PreserveStaleReservations` bypasses both the prompt and the discovery (skips everything).
5. **HTTPS-only path:** cleanup runs inside the `if ($UseHttps)` branch of `Install-DashboardComponent`. Pure HTTP installs see no behavior change.

### Out of scope for v0.0.23 testing

- **gMSA paths.** Cleanup code uses `NTAccount.Translate()` which works for gMSA (the trailing `$` translates correctly), but field validation on a gMSA install has never happened. Per [`project_gmsa_untested.md`](../../../../../C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/project_gmsa_untested.md). Out of scope here; **planned for the work-lab gMSA session same day as this release.**
- **HTTP-only installs.** Cleanup is gated by `$UseHttps`. Pure HTTP installs are unaffected by v0.0.23.

---

## Environment

Same as v0.0.22:

- **Admin workstation (lab build host):** Windows 10/11, PowerShell 7+.
- **Test endpoint:** Windows 10/11 or Server 2016+, WinRM enabled, traditional service account with local admin.
- **A v0.0.22 install on the test endpoint** with HTTPS bound to a specific port (e.g. 8444). The setup section creates a synthetic "stale" reservation on a different port to exercise the cleanup.
- **Test workflow:** Extract `manage-defenderoffline-0.0.23.zip` to `C:\Temp\MDO-Testing\manage-defenderoffline-0.0.23\manage-defenderoffline\` and run from there.

## Setup

```powershell
Set-Location 'C:\Temp\MDO-Testing\manage-defenderoffline-0.0.23\manage-defenderoffline'
Get-ChildItem -Recurse -File | Unblock-File

# Confirm the new helper shipped in the bundle
Test-Path .\lib\Get-StaleHttpReservations.ps1
# Expect: True

# Snapshot the current netsh reservation state so we have a clean before/after.
netsh http show urlacl   | Select-String 'Reserved URL|User' | Out-File .\.pre-v0.0.23-urlacl.txt
netsh http show sslcert  | Select-String 'IP:port|Application ID' | Out-File .\.pre-v0.0.23-sslcert.txt
```

---

### v0.0.23a — Bundle baseline (file presence, version stamps, new helper, new switch)

**Purpose:** Read-only sanity checks against the shipped bundle before any install runs.

**Steps:**

1. Confirm `$ScriptVersion = '0.0.23'` across all five scripts:

```powershell
Select-String -Path .\*.ps1 -Pattern "ScriptVersion\s*=\s*'0\.0\.23'"
# Expect 5 matches.
```

2. Confirm `lib/Get-StaleHttpReservations.ps1` exists and parses cleanly:

```powershell
$f = '.\lib\Get-StaleHttpReservations.ps1'
$tokens=$null; $err=$null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f).Path, [ref]$tokens, [ref]$err)
$err.Count   # Expect: 0
```

3. Confirm the new switch parameter is declared:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern '\[switch\]\$PreserveStaleReservations'
# Expect: 1 match.
```

4. Confirm the new orchestration functions are present:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern 'function (Invoke-StaleReservationCleanup)'
Select-String -Path .\lib\Get-StaleHttpReservations.ps1 -Pattern 'function (Get-NetshSslcertBindings|Get-StaleUrlAclReservations|Get-StaleSslcertBindings|Get-StaleHttpReservations)'
# Expect: 1 + 4 matches.
```

5. Confirm the comment-based help mentions the new switch:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern '\.PARAMETER PreserveStaleReservations'
# Expect: 1 match.
```

**Expected result:**

- [ ] `$ScriptVersion = '0.0.23'` in all five scripts
- [ ] `lib/Get-StaleHttpReservations.ps1` parses with 0 errors
- [ ] `[switch]$PreserveStaleReservations` declared
- [ ] 1 + 4 new functions present
- [ ] `.PARAMETER PreserveStaleReservations` block in help

**Result:** _Pending lab run._

---

### v0.0.23b — Synthesize a stale URL-ACL and verify cleanup

**Purpose:** This is the headline scenario. Synthesize an `https://+:8447/` URL-ACL owned by the service account (matching the v0.0.21 lab where the port temporarily landed on 8447 before being reverted), then run the installer with the current Port=8444. The installer should detect the 8447 reservation as stale, list it, prompt, and clean it up.

**Setup:**

```powershell
# Pre-condition: dashboard installed on port 8444. Confirm:
netsh http show sslcert ipport=0.0.0.0:8444 | Select-String 'Certificate Hash'
# Expect a Certificate Hash line.

# Synthesize a stale URL-ACL on port 8447 owned by the same service account.
netsh http add urlacl url=https://+:8447/ user='WGSDAC\xxSecurityMonitor'
# Expect: "URL reservation successfully added"

# Verify it's there
netsh http show urlacl url=https://+:8447/ | Select-String 'Reserved URL|User'
```

**Steps:**

1. Run the installer (NOT `-Force`, so the confirmation prompt fires):

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule
```

2. Watch for the new cleanup output in the **Configuring HTTPS…** section:

```
  Configuring HTTPS…
    [WARN] Found 1 stale netsh reservation(s) from prior installer runs:
           - URL-ACL  : https://+:8447/                          (owner SID matches WGSDAC\xxSecurityMonitor)

    [INFO] Active ports preserved: 8080, 8443, 8444. Reservations on these ports will be left alone.
    [INFO] -PreserveStaleReservations skips this cleanup entirely.
    Remove the stale reservation(s) listed above? [Y/N]
```

3. Answer **Y**. Expected next output:

```
    [OK]   Removed stale URL-ACL: https://+:8447/
    ...continue with cert / sslcert / URL-ACL grants for port 8444...
```

4. Confirm the 8447 URL-ACL is gone:

```powershell
netsh http show urlacl url=https://+:8447/
# Expect: "The system cannot find the file specified" or empty Reserved URL list
```

5. Confirm the dashboard is still working:

```powershell
Invoke-WebRequest "https://localhost:8444/health" -UseBasicParsing -SkipCertificateCheck |
    Select-Object StatusCode
# Expect: 200
```

**Expected result:**

- [ ] `[WARN] Found 1 stale netsh reservation(s)…` line surfaces
- [ ] The 8447 URL-ACL listed with the SID-match annotation
- [ ] `Active ports preserved: 8080, 8443, 8444…` line displayed
- [ ] Confirmation prompt fires (Y/N)
- [ ] After Y, `[OK] Removed stale URL-ACL: https://+:8447/` line
- [ ] `netsh http show urlacl url=https://+:8447/` no longer finds it
- [ ] Dashboard still serves HTTPS on 8444 (health probe 200)

**Result:** _Pending lab run._

---

### v0.0.23c — Synthesize a stale sslcert binding and verify cleanup

**Purpose:** Same idea as v0.0.23b but for the sslcert side. Synthesize a binding tagged with our AppID on port 9443, run the installer, verify cleanup.

**Setup:**

```powershell
# Get the current cert thumbprint from the live install.
$thumb = (Select-String -Path .\conf\config.conf -Pattern '^CertificateThumbprint\s*=\s*(\S+)').Matches.Groups[1].Value
$thumb
# Expect: a 40-char hex string

# Synthesize a stale sslcert binding on port 9443 with our AppID.
netsh http add sslcert ipport=0.0.0.0:9443 certhash=$thumb appid='{a3f9b1c2-d4e5-46f7-8901-234567890abc}'
# Expect: "SSL Certificate successfully added"

netsh http show sslcert ipport=0.0.0.0:9443
# Expect a binding with our AppID
```

**Steps:**

1. Run the installer (use `-Force` this time to skip the prompt and validate that path):

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -Force
```

2. Watch for the cleanup output. With `-Force`, no Y/N prompt fires; cleanup happens unconditionally:

```
  Configuring HTTPS…
    [WARN] Found 1 stale netsh reservation(s) from prior installer runs:
           - sslcert : ipport=0.0.0.0:9443             (AppID matches Manage-DefenderOffline; cert hash <hash>)

    [INFO] Active ports preserved: 8080, 8443, 8444. Reservations on these ports will be left alone.
    [INFO] -PreserveStaleReservations skips this cleanup entirely.
    [OK]   Removed stale sslcert binding: 0.0.0.0:9443
```

3. Confirm the binding is gone:

```powershell
netsh http show sslcert ipport=0.0.0.0:9443
# Expect: "The system cannot find the file specified"
```

**Expected result:**

- [ ] `[WARN] Found 1 stale netsh reservation(s)…` line
- [ ] sslcert listing shows port 9443 with AppID-match annotation
- [ ] **No Y/N prompt** (because `-Force` is set)
- [ ] `[OK] Removed stale sslcert binding: 0.0.0.0:9443`
- [ ] `netsh http show sslcert ipport=0.0.0.0:9443` no longer finds it

**Result:** _Pending lab run._

---

### v0.0.23d — `-PreserveStaleReservations` skips the whole pass

**Purpose:** Verify the operator opt-out leaves all reservations untouched.

**Setup:**

```powershell
# Synthesize a stale URL-ACL again.
netsh http add urlacl url=https://+:8447/ user='WGSDAC\xxSecurityMonitor'
```

**Steps:**

1. Run the installer with `-PreserveStaleReservations`:

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -Force `
    -PreserveStaleReservations
```

2. Watch for:

```
  Configuring HTTPS…
    [INFO] -PreserveStaleReservations set; skipping stale URL-ACL / sslcert cleanup.
    ...continue with cert / sslcert / URL-ACL grants...
```

3. Confirm the 8447 URL-ACL is **still there** (the opt-out worked):

```powershell
netsh http show urlacl url=https://+:8447/ | Select-String 'Reserved URL'
# Expect a Reserved URL line — NOT removed.
```

4. **Cleanup** for the next scenario:

```powershell
netsh http delete urlacl url=https://+:8447/
```

**Expected result:**

- [ ] `[INFO] -PreserveStaleReservations set; skipping stale URL-ACL / sslcert cleanup.` line
- [ ] No `[WARN] Found N stale netsh reservation(s)…` line
- [ ] No prompt
- [ ] Stale 8447 URL-ACL still present after install

**Result:** _Pending lab run._

---

### v0.0.23e — Operator answers N at the prompt: cleanup skipped, install continues

**Purpose:** Verify the cancellable path. Operator sees the listing and decides not to delete; install must continue cleanly anyway.

**Setup:**

```powershell
# Synthesize again.
netsh http add urlacl url=https://+:8447/ user='WGSDAC\xxSecurityMonitor'
```

**Steps:**

1. Run the installer WITHOUT `-Force`:

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule
```

2. At the `Remove the stale reservation(s)…` prompt, answer **N**.

3. Watch for:

```
    [WARN] Stale reservation cleanup cancelled by operator; proceeding with install.
    ...install continues; current-port sslcert / URL-ACL still get re-bound...
```

4. Verify the 8447 URL-ACL is still present (operator's choice respected):

```powershell
netsh http show urlacl url=https://+:8447/ | Select-String 'Reserved URL'
# Expect: still there
```

5. **Cleanup:**

```powershell
netsh http delete urlacl url=https://+:8447/
```

**Expected result:**

- [ ] `[WARN] Stale reservation cleanup cancelled by operator…` line on N answer
- [ ] Install continues to completion
- [ ] 8447 URL-ACL preserved
- [ ] Dashboard still serves HTTPS on 8444

**Result:** _Pending lab run._

---

### v0.0.23f — Sister-service reservation is NOT touched

**Purpose:** Synthesize a reservation owned by **someone else** (not the service account) on an inactive port. The cleanup must skip it — identity matching is the safety net.

**Setup:**

```powershell
# Synthesize a URL-ACL owned by BUILTIN\Administrators (not the service account)
# on an inactive port.
netsh http add urlacl url=https://+:9999/ user='BUILTIN\Administrators'

# Verify it's there with the BUILTIN owner
netsh http show urlacl url=https://+:9999/ | Select-String 'Reserved URL|User'
```

**Steps:**

1. Run the installer (use `-Force` for brevity):

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -Force
```

2. Watch the **Configuring HTTPS…** section:
   - **No** `[WARN] Found N stale netsh reservation(s)…` line (because the 9999 reservation isn't owned by our SID)
   - Cleanup line says: `No stale URL-ACL or sslcert reservations found for WGSDAC\xxSecurityMonitor outside active ports (…)`

3. Confirm the 9999 URL-ACL **still exists** (sister-service reservation untouched):

```powershell
netsh http show urlacl url=https://+:9999/ | Select-String 'User'
# Expect: still owned by BUILTIN\Administrators
```

4. **Cleanup:**

```powershell
netsh http delete urlacl url=https://+:9999/
```

**Expected result:**

- [ ] `[INFO] No stale URL-ACL or sslcert reservations found…` line
- [ ] 9999 URL-ACL still present after install
- [ ] No prompt
- [ ] No accidental cleanup of someone else's reservation

**Result:** _Pending lab run._

---

### v0.0.23g — HTTP-only install: cleanup does not run

**Purpose:** Regression check that the cleanup is properly gated by `$UseHttps`. Pure HTTP installs should be unaffected.

**Steps:**

```powershell
# Edit conf/config.conf temporarily: UseHttps = false.
Copy-Item .\conf\config.conf .\conf\config.conf.bak
(Get-Content .\conf\config.conf) -replace '^UseHttps\s*=\s*true', 'UseHttps = false' |
    Set-Content .\conf\config.conf

# Synthesize a stale URL-ACL to verify the cleanup doesn't fire.
netsh http add urlacl url=http://+:8447/ user='WGSDAC\xxSecurityMonitor'

.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -Force

# Confirm the stale URL-ACL is STILL there
netsh http show urlacl url=http://+:8447/ | Select-String 'Reserved URL'

# Restore
Move-Item .\conf\config.conf.bak .\conf\config.conf -Force
netsh http delete urlacl url=http://+:8447/
```

**Expected result:**

- [ ] No `[WARN] Found N stale netsh reservation(s)…` line in HTTP-only install
- [ ] No cleanup prompt
- [ ] No `[INFO] No stale URL-ACL or sslcert reservations…` line either (the function isn't called)
- [ ] Stale URL-ACL still present after install
- [ ] After restoring `UseHttps = true`, behavior reverts to scenarios b–f

**Result:** _Pending lab run._

---

## Release Checklist

- [ ] v0.0.23a PASS — Bundle baseline (versions / new helper / new switch / new functions / help block)
- [ ] v0.0.23b PASS — Stale URL-ACL detected, prompted, removed; dashboard healthy after
- [ ] v0.0.23c PASS — Stale sslcert detected (no prompt because `-Force`), removed
- [ ] v0.0.23d PASS — `-PreserveStaleReservations` skips the entire pass
- [ ] v0.0.23e PASS — Operator answers N: cleanup cancelled, install continues, dashboard still healthy
- [ ] v0.0.23f PASS — Sister-service reservation (different SID owner) untouched
- [ ] v0.0.23g PASS — HTTP-only install: cleanup gated off; stale URL-ACL untouched
- [x] $ScriptVersion bumped to `'0.0.23'` across all five scripts
- [x] All shipped scripts parse clean (`Parser::ParseFile` reports 0 errors)
- [x] Full Pester suite green (327 passed, 0 failed, 13 skipped — +17 from `tests/StaleHttpReservations.Tests.ps1`)
- [ ] No `*.tmp` artifacts in working tree (`git status` clean)
- [x] README v0.0.23 entry drafted
- [ ] `feat/v0.0.23-url-acl-cleanup` squash-merged to `main` via PR
- [ ] Release tagged `v0.0.23`, marked `--prerelease` on GitHub per pre-1.0 policy

## Follow-ups for v0.0.23.1 / v0.0.24

- **gMSA field validation** — same as v0.0.22's carry-forward. Operator visit to the work lab is planned for the same day this release ships; if it validates the cleanup against a gMSA install, the carry-forward note can be removed and the test plan amended.
- **Async `target_computers` cold-start cost** (from v0.0.21 scenario b finding). Cold = 4239 ms vs warm = 445 ms — apply the same `Start-ThreadJob` pattern used for `Write-EventLog` in v0.0.21.
- **Tier credential reuse** (Workstation/Server/DomainController XMLs) — operator-managed today; could be brought into v0.0.22's validation framework if there's demand.

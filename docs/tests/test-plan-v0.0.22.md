# Test Plan — v0.0.22 (Manage-DefenderOffline)

## Baseline

`main` at commit `18862d2` (v0.0.21 + v0.0.21 test-plan landed via PR #56).
**Feature branch:** `feat/v0.0.22-credential-reuse`
**Test bundle:** to be built from the branch tip after this plan is approved.

## Purpose

v0.0.22 is a single-feature release: **`Install-ManageDefender.ps1` reuses existing credential XMLs when they validate under the service identity's DPAPI**, eliminating the long-standing UX gap where every `-Force` re-install re-prompted for `WinRm`/`AD`/`SMTP` credentials even though valid encrypted copies already existed in `conf/`. User-prioritised after the v0.0.21 lab pass surfaced the friction during back-to-back installs.

Changes validated by this test plan:

| # | Change | File(s) |
|---|---|---|
| A | New helper `lib/Test-ServiceCredential.ps1` — runs in the service identity's context and `Import-Clixml`s an existing XML, exiting 0/1 | new file |
| B | New `[switch]$ForcePromptCredentials` parameter on `Install-ManageDefender.ps1`; comment-based help updated | `Install-ManageDefender.ps1` |
| C | New `Invoke-ValidationAsServiceIdentity` + `Test-ServiceCredential` orchestration functions (mirror of save side) | `Install-ManageDefender.ps1` |
| D | `Initialize-ServiceCredentials` restructured: seclogon dance pulled forward of the prompt phase; unified validation-first loop with precedence `pre-supplied → -ForcePromptCredentials → existing-XML-validates → prompt-and-save` | `Install-ManageDefender.ps1` |
| E | New Pester suite `tests/TestServiceCredential.Tests.ps1` covering the helper | new file |
| F | `$ScriptVersion = '0.0.22'` across all five scripts | 5 scripts |

### Key behaviors

1. **Precedence chain per credential slot, top wins:**
   1. **Pre-supplied** (`-WinRmCredential $cred` etc.) → use it, queue for save. Validation is skipped — operator's explicit choice wins.
   2. **`-ForcePromptCredentials`** → prompt for every slot, queue for save. Existing XMLs are overwritten.
   3. **Existing XML validates** → reuse silently, no save, no prompt. Operator sees a single `[OK]` per slot citing the XML's mtime.
   4. **XML absent or fails validation** → if it existed, emit a `WARN` explaining why (DPAPI failure → likely service-account change or corruption); prompt; queue for save.
2. **Seclogon dance now wraps both validation and save.** v0.0.21 enabled `seclogon` only for the save loop. v0.0.22 needs `seclogon` for validation too (the helper runs as the service identity via `Start-Process -Credential`), so the dance is pulled forward — the operator confirms once (when not `-Force`), and the same window covers both validation and save. **On STIG hosts the `Continue? [Y/N]` UX is unchanged.**
3. **Validation = decryption proof, not username comparison.** The helper succeeds iff `Import-Clixml` + `PSCredential.GetNetworkCredential().Password` round-trips cleanly under the service identity. DPAPI scoping does the identity binding for us — if the operator changes `-ServiceAccount` between runs, the old XML fails decryption and the operator is re-prompted. No explicit username check needed.
4. **The service-account password (`-Credential $cred`) still prompts every time.** That's not in scope — Task Scheduler stores the password in LSA secrets at task-registration time; there is no on-disk XML for it (and there can't be — that XML would itself need a password to decrypt, recursively). User explicitly OK'd this behavior in design discussion 2026-06-04.

### Out of scope for v0.0.22 testing

- **gMSA validation path.** Spec-built symmetrically (one-shot scheduled task running as the gMSA, mirroring `Invoke-AsServiceIdentity`'s gMSA branch). Field-untested per [`project_gmsa_untested.md`](../../../../../C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/project_gmsa_untested.md). Scenarios below all target traditional service accounts.
- **Tier credentials** (`WorkstationCredential.xml` / `ServerCredential.xml` / `DomainControllerCredential.xml`). Loaded by `Update-DefenderOffline.ps1` at runtime; not installer-managed today. v0.0.22 leaves them untouched.
- **GUI / dashboard runtime.** No changes in this release.

---

## Environment

Same as v0.0.21:

- **Admin workstation (lab build host):** Windows 10/11, PowerShell 7+.
- **Test endpoint:** Windows 10/11 or Server 2016+, WinRM enabled, traditional service account with local admin.
- **Existing v0.0.21 install** with valid `conf/WinRmCredential.xml`, `conf/ADCredential.xml`, `conf/SmtpCredential.xml` (the home-lab WGSDAC.NET install completed during v0.0.21 lab pass satisfies this).
- **Test workflow:** Extract `manage-defenderoffline-0.0.22.zip` over the existing `C:\Temp\MDO-Testing\manage-defenderoffline-0.0.21\manage-defenderoffline\` (or to a fresh sibling folder if you prefer cleaner isolation).

## Setup

```powershell
# Working directory matches v0.0.21 pattern.
Set-Location 'C:\Temp\MDO-Testing\manage-defenderoffline-0.0.22\manage-defenderoffline'
Get-ChildItem -Recurse -File | Unblock-File

# Confirm the new helper shipped in the bundle
Test-Path .\lib\Test-ServiceCredential.ps1
# Expect: True

# Capture cred-XML metadata for the reuse comparison in scenarios b + c.
Get-ChildItem .\conf\*Credential.xml | Select-Object Name, LastWriteTime, Length
```

---

### v0.0.22a — Bundle baseline (file presence, version stamps, new helper, new switch)

**Purpose:** Read-only sanity checks against the shipped bundle before any install runs. Confirms the new helper, the new switch parameter, and the new orchestration functions are all present in the source.

**Setup:** Bundle extracted; no installer run yet.

**Steps:**

1. Confirm `$ScriptVersion = '0.0.22'` across all five scripts:

```powershell
Select-String -Path .\*.ps1 -Pattern "ScriptVersion\s*=\s*'0\.0\.22'"
# Expect 5 matches.
```

2. Confirm `lib/Test-ServiceCredential.ps1` exists and parses cleanly:

```powershell
$f = '.\lib\Test-ServiceCredential.ps1'
Test-Path $f
$tokens=$null; $err=$null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f).Path, [ref]$tokens, [ref]$err)
$err.Count   # Expect: 0
```

3. Confirm the new switch parameter is declared in the installer:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern '\[switch\]\$ForcePromptCredentials'
# Expect: 1 match in the param() block.
```

4. Confirm the new orchestration functions are present:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern 'function (Test-ServiceCredential|Invoke-ValidationAsServiceIdentity|Get-CredentialTestHelperPath|Initialize-CredentialTestHelper)'
# Expect: 4 matches (one per function).
```

5. Confirm the comment-based help mentions the new switch:

```powershell
Select-String -Path .\Install-ManageDefender.ps1 -Pattern '\.PARAMETER ForcePromptCredentials'
# Expect: 1 match.
```

**Expected result:**

- [ ] `$ScriptVersion = '0.0.22'` in all five scripts
- [ ] `lib/Test-ServiceCredential.ps1` exists and parses
- [ ] `[switch]$ForcePromptCredentials` declared in param block
- [ ] 4 new orchestration functions present
- [ ] `.PARAMETER ForcePromptCredentials` block present in comment-based help

**Result:** _Pending lab run._

---

### v0.0.22b — Happy path: zero credential prompts when all XMLs validate

**Purpose:** This is the headline scenario. With valid `WinRmCredential.xml` / `ADCredential.xml` / `SmtpCredential.xml` already in `conf/` from the v0.0.21 install, a v0.0.22 install with `-Component All -Force` should produce **zero `Get-Credential` prompts** for WinRm/AD/SMTP. The service-account `-Credential $cred` still prompts (out of scope per design).

**Setup:** v0.0.21 install present on the endpoint, all three XMLs valid. SendEmail=true in `conf/config.conf` so the SMTP slot is part of the plan.

```powershell
$cred = Get-Credential `
    -UserName 'WGSDAC\xxSecurityMonitor' `
    -Message 'Password for the dashboard service account'

# Confirm SendEmail = true so SMTP is in the plan
Select-String -Path .\conf\config.conf -Pattern '^SendEmail\s*='
# Expect: SendEmail = true (or yes / 1)
```

**Steps:**

1. Run the installer. Watch the credential phase output carefully — there should be **NO Get-Credential dialog popups** for WinRm/AD/SMTP:

```powershell
.\Install-ManageDefender.ps1 `
    -Component All `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

2. Confirm the credential phase emitted the new reuse lines:

```
[STEP] Validating existing WinRm credential (WinRmCredential.xml)…
[OK]   WinRm credential: reusing existing XML (saved 2026-06-04 HH:MM). Set -ForcePromptCredentials to rotate.
[STEP] Validating existing AD credential (ADCredential.xml)…
[OK]   AD credential: reusing existing XML (saved 2026-06-04 HH:MM). Set -ForcePromptCredentials to rotate.
[STEP] Validating existing Smtp credential (SmtpCredential.xml)…
[OK]   Smtp credential: reusing existing XML (saved 2026-06-04 HH:MM). Set -ForcePromptCredentials to rotate.
[OK]   All needed credentials validated; No credential prompts needed (existing XMLs validated).
```

3. Confirm the XMLs were NOT rewritten (mtimes from setup should be unchanged):

```powershell
Get-ChildItem .\conf\*Credential.xml | Select-Object Name, LastWriteTime, Length
# Compare to the pre-install snapshot from Setup. Same LastWriteTime = success.
```

4. Confirm the dashboard task still starts cleanly with the reused creds:

```powershell
$today = Get-Date -Format 'yyyyMMdd'
$log = "C:\Logs\DefenderDashboard\DefenderDashboard_$today.log"
Get-Content $log -Tail 30 | Select-String 'startup_complete|auth_resolve'
# Expect: post-install startup_complete line with phase_count=11; auth_resolve lines if ADIntegrated.
```

**Expected result:**

- [ ] Zero `Get-Credential` dialogs for WinRm/AD/SMTP during the install
- [ ] Three `[OK] <Name> credential: reusing existing XML…` lines (one per slot)
- [ ] Final `All needed credentials validated; No credential prompts needed (existing XMLs validated).`
- [ ] All three XML mtimes unchanged after install
- [ ] Dashboard restarts cleanly under the reused creds

**Result:** _Pending lab run._

---

### v0.0.22c — `-ForcePromptCredentials`: prompts fire even when XMLs are valid

**Purpose:** Validate the rotation path. Operator wants to rotate credentials; explicit switch makes the prompts fire.

**Setup:** Same as v0.0.22b — valid XMLs in `conf/`.

**Steps:**

1. Run the installer with the new switch:

```powershell
.\Install-ManageDefender.ps1 `
    -Component All `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -StartImmediately `
    -Force `
    -ForcePromptCredentials
```

2. Three credential prompts should appear in sequence (WinRm → AD → SMTP). For each, supply the same values that were already saved (so the validation will pass next time). The installer output should include:

```
[INFO]  WinRm credential: -ForcePromptCredentials set; prompting for fresh value.
[INFO]  AD credential: -ForcePromptCredentials set; prompting for fresh value.
[INFO]  Smtp credential: -ForcePromptCredentials set; prompting for fresh value.
```

3. Confirm the XML mtimes advanced (saved fresh under DPAPI):

```powershell
Get-ChildItem .\conf\*Credential.xml | Select-Object Name, LastWriteTime
# LastWriteTime should be NOW, not the pre-install timestamps.
```

**Expected result:**

- [ ] Three `Get-Credential` prompts fire (WinRm, AD, SMTP)
- [ ] Three `[INFO] <Name> credential: -ForcePromptCredentials set; prompting for fresh value.` lines
- [ ] All three XML mtimes are within ~10 seconds of `Get-Date`
- [ ] Subsequent install without `-ForcePromptCredentials` (re-run scenario v0.0.22b) goes back to the zero-prompt path

**Result:** _Pending lab run._

---

### v0.0.22d — Identity-mismatch handling: WARN + re-prompt on DPAPI failure

**Purpose:** Validate the graceful-failure path. Simulate the "operator changed `-ServiceAccount` between installs" or "XML corrupted" scenario by tampering with one of the XMLs so validation fails.

**Setup:** Same v0.0.22 install. To synthesize a DPAPI failure cheaply, overwrite one of the XMLs with content that parses as Export-Clixml output but won't decrypt under the service identity. Easiest method: re-encrypt under the *operator's* DPAPI context (a different identity).

```powershell
# Backup the valid SmtpCredential.xml (we'll restore at the end).
Copy-Item .\conf\SmtpCredential.xml .\conf\SmtpCredential.xml.bak -Force

# Overwrite with an XML encrypted under the operator's DPAPI — NOT the
# service account's. This is what would happen if a previous Get-Credential
# | Export-Clixml run was done by the operator at the console instead of
# through Save-ServiceCredential.ps1.
$sec = ConvertTo-SecureString 'fake-test-pwd' -AsPlainText -Force
$bogusCred = [System.Management.Automation.PSCredential]::new('TESTDOMAIN\fake', $sec)
$bogusCred | Export-Clixml -Path .\conf\SmtpCredential.xml -Force
```

**Steps:**

1. Run an installer that includes the SMTP slot:

```powershell
.\Install-ManageDefender.ps1 `
    -Component All `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -Force
```

2. The credential phase should:
   - Reuse `WinRm` and `AD` (valid)
   - **WARN on `SmtpCredential.xml`** with a message like:
     ```
     [WARN]  Smtp credential: existing SmtpCredential.xml could not be decrypted as <IdentityLabel> (likely saved under a different identity or corrupted). Re-prompting and overwriting.
     ```
   - Prompt for the SMTP credential
   - Save under DPAPI (overwriting the tampered file)

3. Confirm the new XML decrypts cleanly by re-running scenario v0.0.22b (zero prompts expected this time):

```powershell
# Snapshot mtimes before
Get-ChildItem .\conf\*Credential.xml | Select-Object Name, LastWriteTime

# Re-install; expect zero prompts for WinRm/AD/Smtp
.\Install-ManageDefender.ps1 -Component All `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' -Credential $cred `
    -AddFirewallRule -Force
```

4. **Restore** if needed:

```powershell
Move-Item .\conf\SmtpCredential.xml.bak .\conf\SmtpCredential.xml -Force
```

**Expected result:**

- [ ] `WARN` line surfaces with the actionable phrasing
- [ ] WinRm + AD slots reused silently
- [ ] SMTP slot re-prompts and overwrites the tampered XML
- [ ] Subsequent install with no flags goes back to zero prompts
- [ ] No other credentials affected (WinRm and AD mtimes unchanged across both runs)

**Result:** _Pending lab run._

---

### v0.0.22e — `-SkipCredentialSetup` still defers entirely (regression)

**Purpose:** Confirm the v0.0.19 deferred-setup path is unchanged. `-SkipCredentialSetup` should still skip the whole credential phase — no validation attempts, no prompts, no XML touches — and print the deferred-instructions block.

**Steps:**

```powershell
.\Install-ManageDefender.ps1 `
    -Component All `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -Force `
    -SkipCredentialSetup
```

**Expected result:**

- [ ] The yellow `Credential setup deferred (-SkipCredentialSetup)` block prints
- [ ] No `[STEP] Validating existing…` lines
- [ ] No `Get-Credential` prompts
- [ ] All XML mtimes unchanged

**Result:** _Pending lab run._

---

### v0.0.22f — Pre-supplied `-WinRmCredential $cred` parameter wins over both XML reuse and `-ForcePromptCredentials`

**Purpose:** Validate the top-of-precedence rule. An operator who explicitly passes `-WinRmCredential` is asserting "use this one" — the installer should obey, regardless of what's on disk or whether `-ForcePromptCredentials` is set.

**Setup:**

```powershell
# Build a non-prompt PSCredential from an in-memory password.
$sec = ConvertTo-SecureString 'replacement-pwd' -AsPlainText -Force
$winRmReplacement = [System.Management.Automation.PSCredential]::new('WGSDAC\replacement-winrm', $sec)
```

**Steps (two sub-scenarios):**

1. **Without `-ForcePromptCredentials`** — pre-supplied still wins, no prompt for WinRm:

```powershell
.\Install-ManageDefender.ps1 -Component All `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' -Credential $cred `
    -WinRmCredential $winRmReplacement `
    -AddFirewallRule -Force
```

Expected: `[INFO] WinRm credential: using pre-supplied (-WinRmCredential parameter).` No WinRm prompt. AD and SMTP reuse from disk. `WinRmCredential.xml` mtime advances.

2. **With `-ForcePromptCredentials`** — pre-supplied still wins for WinRm (prompts fire for AD + SMTP):

```powershell
.\Install-ManageDefender.ps1 -Component All `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' -Credential $cred `
    -WinRmCredential $winRmReplacement `
    -AddFirewallRule -Force `
    -ForcePromptCredentials
```

Expected: Same `[INFO] WinRm credential: using pre-supplied…` line. AD + SMTP prompts fire (because `-ForcePromptCredentials` overrides reuse for slots without a pre-supplied value).

3. **Restore** the original WinRm credential after testing if needed (re-run scenario v0.0.22c with `-ForcePromptCredentials` and supply the real WinRm cred).

**Expected result:**

- [ ] Sub-step 1: zero prompts for WinRm; AD + SMTP reused; WinRm XML mtime advances
- [ ] Sub-step 2: zero prompts for WinRm; AD + SMTP prompts fire
- [ ] In both sub-steps, `[INFO] WinRm credential: using pre-supplied (-WinRmCredential parameter).` appears exactly once

**Result:** _Pending lab run._

---

### v0.0.22g — `-Component Dashboard` (no SMTP slot in plan) still validates the two it needs

**Purpose:** Confirm the plan-aware validation works for partial-component installs. `-Component Dashboard` needs only WinRm + AD; SMTP should be neither validated nor touched.

**Steps:**

```powershell
.\Install-ManageDefender.ps1 `
    -Component Dashboard `
    -ServiceAccount 'WGSDAC\xxSecurityMonitor' `
    -Credential     $cred `
    -AddFirewallRule `
    -Force
```

**Expected result:**

- [ ] Two `[STEP] Validating existing…` lines (WinRm, AD) — NOT three
- [ ] `SmtpCredential.xml` mtime unchanged
- [ ] No SMTP prompt
- [ ] The v0.0.20 "Silent SMTP-skip breadcrumb" still fires if SendEmail=true in config:
      `[INFO]  SMTP setup skipped: SendEmail=true in config applies to the Updates task…`

**Result:** _Pending lab run._

---

## Release Checklist

- [ ] v0.0.22a PASS — `$ScriptVersion`, new helper, new switch, new functions, help block all present in bundle
- [ ] v0.0.22b PASS — Headline scenario: zero credential prompts when valid XMLs exist
- [ ] v0.0.22c PASS — `-ForcePromptCredentials` forces prompts; mtimes advance
- [ ] v0.0.22d PASS — Identity mismatch: WARN + re-prompt; other slots untouched
- [ ] v0.0.22e PASS — `-SkipCredentialSetup` unchanged regression
- [ ] v0.0.22f PASS — Pre-supplied `-<Name>Credential` parameter wins (both sub-scenarios)
- [ ] v0.0.22g PASS — `-Component Dashboard` validates 2 slots, leaves SMTP alone
- [x] $ScriptVersion bumped to `'0.0.22'` across all five scripts
- [x] All shipped scripts parse clean (`Parser::ParseFile` reports 0 errors)
- [x] Full Pester suite green (310 passed, 0 failed, 13 skipped — `Invoke-Pester -Path ./tests` — +7 from `tests/TestServiceCredential.Tests.ps1`)
- [ ] No `*.tmp` artifacts in working tree (`git status` clean)
- [ ] README v0.0.22 entry drafted
- [ ] `feat/v0.0.22-credential-reuse` squash-merged to `main` via PR
- [ ] Release tagged `v0.0.22`, marked `--prerelease` on GitHub per pre-1.0 policy

## Follow-ups for v0.0.22.1 / v0.0.23

- gMSA path field validation — credential-reuse code is symmetric with the save side (one-shot scheduled task running as the gMSA), but the gMSA paths remain untested per [`project_gmsa_untested.md`](../../../../../C:/Users/kisme/.claude/projects/d--Dropbox-IT-Docs-Scripts-Manage-DefenderOffline/memory/project_gmsa_untested.md). When a gMSA lab becomes available, exercise scenarios v0.0.22b + v0.0.22d against it.
- Async `target_computers` cold-start cost (from v0.0.21 scenario b finding). Cold = 4239 ms vs warm = 445 ms — apply the same `Start-ThreadJob` pattern used for `Write-EventLog` in v0.0.21.
- Tier-credential reuse: `WorkstationCredential.xml` / `ServerCredential.xml` / `DomainControllerCredential.xml` are operator-managed today. Could be brought into the same validation-first reuse flow in a later release if there's demand.

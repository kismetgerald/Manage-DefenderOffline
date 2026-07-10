# Test Plan — v0.0.24 (Manage-DefenderOffline)

## Baseline

`main` at commit `b688749` (v0.0.22 release). **NOTE:** v0.0.23 is expected to land on `main` before v0.0.24 ships; when that happens this branch will be rebased and `$ScriptVersion` re-bumped. Test the branch tip as-is.
**Feature branch:** `feat/v0.0.24-clamav-consumer`
**Test bundle:** to be built from the branch tip after this plan is approved.
**Deploy-ClamAV counterpart:** contract per `.plans/02-v0.0.6-fleet-aggregate-plan.md` (D1 shipped as v0.0.6; D2 fleet aggregate publisher targets v0.0.7). This plan uses **local synthetic fixtures** to exercise every path without depending on a real Deploy-ClamAV mirror — the runtime interop test is a separate joint session with the ClamAV side when v0.0.7 ships.

## Purpose

v0.0.24 is a single-feature dashboard release: **`Start-DefenderDashboard.ps1` becomes an HTTP-native consumer of Deploy-ClamAV's fleet health contract**, rendering Linux/ClamAV rows alongside Windows/Defender rows in the same fleet grid, colour-coded with the same status column. Cross-project contract shape agreed 2026-07-08 (see `docs/plans/v0.0.24-clamav-consumer.md` v4).

Changes validated by this test plan:

| # | Change | File(s) |
|---|---|---|
| A | New library `lib/Get-ClamAVHealthProbe.ps1` — public probe + 5 helpers (staleness override, rank, merge, format, ProbeFailed row synthesizer) + `ConvertFrom-ClamAVHostDocument` | new file |
| B | New Pester suite `tests/ClamAVHealthProbe.Tests.ps1` — 52 tests covering shape detection, schema, staleness two-axis, escalate-only, threat count, installer_version, HTTP error paths | new file |
| C | New `[ClamAV]` section in `conf/config.conf` — 7 keys (Enabled + MirrorUrl + timeout + 4 staleness thresholds), all prefixed with `ClamAV` to avoid section-flat parser collisions | `conf/config.conf` |
| D | Config `SchemaVersion` bumped 1 → 2 (additive; older v0.0.19-v0.0.23 scripts soft-warn but continue reading) | `conf/config.conf` |
| E | 7 new CLI params + config parsing on `Start-DefenderDashboard.ps1`; guard that silently downgrades `Enabled = true` + empty `MirrorUrl` to disabled with a WARN | `Start-DefenderDashboard.ps1` |
| F | `Get-DefenderStatus` output gains `OSFamily = 'Windows'` field so grid/modal renderers can distinguish OS families consistently | `Start-DefenderDashboard.ps1` |
| G | `Invoke-FleetRefresh` gains 7 ClamAV parameters + inline `ConvertTo-DashboardRowFromClamAV` adapter; ClamAV pass runs serially after the parallel Defender pass and appends `.hosts[]` rows to the results list | `Start-DefenderDashboard.ps1` |
| H | `Start-BackgroundRefresh` threads new params + probe lib path through `Start-ThreadJob` | `Start-DefenderDashboard.ps1` |
| I | HTML template renders OS icon inline in the Computer cell (Windows 🪟, Linux 🐧), new `.b-pf` badge for `ProbeFailed`, updated legend, JS `renderHostModal` split into `renderWindowsModal` / `renderLinuxModal` with shared identity/classification blocks | `Start-DefenderDashboard.ps1` |
| J | Both JSON blobs (embedded `hostJsonBlob` for the modal + `/status` endpoint) surface `osFamily` + 12 `clamAv*` fields; Windows rows serialize the new fields as null | `Start-DefenderDashboard.ps1` |
| K | `$ScriptVersion = '0.0.24'` and expected config schema version bumped to `2` on `Start-DefenderDashboard.ps1`. Other four scripts remain at v0.0.22 for this branch — they'll bump when v0.0.23 merges | `Start-DefenderDashboard.ps1` |
| L | Startup log line `event=startup ... ClamAV consumer : enabled (URL) \| disabled` | `Start-DefenderDashboard.ps1` |

### Key behaviors

1. **Two consumer shapes, one code path.** The consumer auto-detects envelope vs single-host by presence of `kind: "fleet-status"` or a `hosts[]` array. This lets MDO v0.0.24 release against Deploy-ClamAV v0.0.6 (mirror-only visibility via `…/ClamAV/status.json`) *and* v0.0.7 (whole-fleet visibility via `…/ClamAV/fleet-status.json`) — operators change one config value on the switch, no MDO code change.

2. **Two-axis staleness, escalate-only.** For envelopes: aggregate axis first (`AggregateStaleSeconds` = 900 / `AggregateProbeFailedSeconds` = 1800 against envelope-level `generated_at`), then host axis (`HostStaleSeconds` = 1800 / `HostProbeFailedSeconds` = 3600 against each host's `generated_at`). Applied in order; a host whose underlying status is worse than an override wins keeps the worse status. Missing/unparseable `generated_at` counts as ProbeFailed.

3. **Independent schema versions on envelope + host axes.** Both are `schema_version: 1` today; either can bump alone in the future. Consumer validates each axis separately. Read `<= expected` → normal; `> expected` → soft warning surfaced on the row (`SchemaWarning` / `EnvelopeSchemaWarning` fields, both shown in the modal); missing/invalid → row is ProbeFailed.

4. **`recent_threat_count` is the count.** Deploy-ClamAV populates `status_reason` with a human string (e.g. `"3 threat(s) detected in the last 24h"`) but the number is already in the dedicated integer field. Consumer surfaces `RecentThreatCount` for tooltip/badge/sort/CSV. Do NOT regex the reason string for the count.

5. **`ProbeFailed` is a first-class status, not "offline for Linux".** ClamAV rows may show `ProbeFailed` for unreachable-during-aggregation hosts even when the mirror is up. The badge (`b-pf`) styles same as offline (both = "no live data") but the label reads `ProbeFailed` so operators know which side is broken. Windows rows never render `ProbeFailed` — they use `Offline`.

6. **Guard against half-configured opt-in.** `-ClamAVEnabled $true` with an empty `MirrorUrl` emits a WARN and silently downgrades to disabled — the dashboard never fills the grid with ProbeFailed rows because the operator forgot the URL.

7. **Two opt-in switches.** `[ClamAV].ClamAVEnabled = false` on this side AND `fleet_publish_enabled = false` on Deploy-ClamAV. Both must be flipped for envelope visibility. Single-host mode works without the Deploy-ClamAV publisher (v0.0.6 mirror publishes its own document by default).

### Out of scope for v0.0.24 testing

- **Interop with a real Deploy-ClamAV mirror.** This plan uses local synthetic fixtures served over pwsh HttpListener. Full interop is a joint session with the ClamAV side after their v0.0.7 ships. That session validates: mirror publishes valid envelope on its systemd timer, MDO consumes it, `--fresh` mode produces `host.generated_at ≈ envelope.generated_at`.
- **HTTPS + CA-trust.** MVP is HTTP-only (matches Deploy-ClamAV's on-trusted-segment posture). HTTPS + `[ClamAV].VerifyCert` + `[ClamAV].CaBundle` are Phase 2.
- **Per-host SSH fallback.** Phase 2, if mirror publish path proves unreliable in field use.
- **Multiple mirrors.** Phase 2. MVP polls one MirrorUrl.
- **gMSA validation of ClamAV consumer.** The probe runs in the dashboard's HTTP fetch path; the service identity affects `Invoke-RestMethod`'s outbound auth only if the mirror URL uses `https://` with client-cert auth (out of scope). Traditional service accounts and gMSAs are functionally identical for HTTP-only mirror consumption.

---

## Environment

- **Admin workstation (lab build host):** Windows 10/11, PowerShell 7+.
- **Test endpoint:** Windows 10/11 or Server 2016+, WinRM enabled, traditional service account with local admin, existing v0.0.22 or v0.0.23 install with a working dashboard (Windows-only fleet).
- **Loopback HTTP fixture server:** a small pwsh `HttpListener` on port 8000 serving JSON files from `test-fixtures/clamav/`. See Setup for the one-liner.
- **Anonymized hostnames.** All fixture JSONs use `linux-mirror`, `linux-client-01`, `linux-client-02`, `linux-client-03` (per `feedback-anonymize-lab-names`).

## Setup

```powershell
# Working directory
Set-Location 'C:\Temp\MDO-Testing\manage-defenderoffline-0.0.24\manage-defenderoffline'
Get-ChildItem -Recurse -File | Unblock-File

# Confirm the new library shipped
Test-Path .\lib\Get-ClamAVHealthProbe.ps1     # Expect: True
Test-Path .\tests\ClamAVHealthProbe.Tests.ps1 # Expect: True

# Confirm the [ClamAV] section is present in the shipped config
Select-String -Path .\conf\config.conf -Pattern '^\[ClamAV\]' -Quiet
# Expect: True
```

### Create the fixture directory + JSONs

Save each JSON in the "Scenarios" section below to `test-fixtures\clamav\<name>.json`. Filenames are called out per scenario. Create the folder first:

```powershell
New-Item -ItemType Directory -Path .\test-fixtures\clamav -Force | Out-Null
```

### Start the loopback HTTP fixture server

Save this to `test-fixtures\serve-fixtures.ps1`:

```powershell
# Serves .\test-fixtures\clamav\*.json at http://localhost:8000/<file>
# No admin required (localhost-only binding). Ctrl+C to stop.
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add('http://localhost:8000/')
$listener.Start()
Write-Host 'Serving http://localhost:8000/  (Ctrl+C to stop)'
try {
    while ($listener.IsListening) {
        $ctx  = $listener.GetContext()
        $name = $ctx.Request.Url.LocalPath.TrimStart('/')
        $file = Join-Path $PSScriptRoot ('clamav/' + $name)
        if (Test-Path -LiteralPath $file) {
            $bytes = [IO.File]::ReadAllBytes($file)
            $ctx.Response.ContentType = 'application/json'
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.StatusCode = 200
        } else {
            $ctx.Response.StatusCode = 404
        }
        $ctx.Response.Close()
    }
} finally {
    $listener.Stop()
}
```

Run in a **separate pwsh window**:

```powershell
pwsh -NoProfile -File .\test-fixtures\serve-fixtures.ps1
```

Verify it responds:

```powershell
Invoke-WebRequest http://localhost:8000/healthy-envelope.json -UseBasicParsing |
    Select-Object -ExpandProperty StatusCode   # 200 once you drop the fixture in
```

### Snapshot config for scenario switching

Scenarios flip `[ClamAV].ClamAVEnabled` and `[ClamAV].ClamAVMirrorUrl` between fixture files. Take a snapshot so you can revert cleanly:

```powershell
Copy-Item .\conf\config.conf .\conf\config.conf.pre-v0.0.24
```

Restore between scenarios if you like a clean slate:

```powershell
Copy-Item .\conf\config.conf.pre-v0.0.24 .\conf\config.conf -Force
```

---

## Scenarios

### v0.0.24a — Bundle baseline (file presence, version stamps, config section)

- [ ] PASS
- [ ] FAIL

**Purpose:** Read-only sanity checks against the shipped bundle before any dashboard restart.

**Steps:**

1. Confirm `$ScriptVersion = '0.0.24'` on the dashboard:

```powershell
Select-String -Path .\Start-DefenderDashboard.ps1 -Pattern "^\`$ScriptVersion\s*=\s*'0\.0\.24'"
# Expect exactly 1 match at approximately line 165.
```

2. Confirm the new lib parses cleanly:

```powershell
$errs = @()
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    '.\lib\Get-ClamAVHealthProbe.ps1', [ref]$null, [ref]$errs)
$errs.Count   # Expect: 0
```

3. Confirm Pester on the new probe passes:

```powershell
Invoke-Pester -Path .\tests\ClamAVHealthProbe.Tests.ps1 -Output Minimal
# Expect: Passed: 52, Failed: 0
```

4. Confirm `[ClamAV]` section is present with 7 keys:

```powershell
Select-String -Path .\conf\config.conf -Pattern '^Clam(AV)?(Enabled|MirrorUrl|RequestTimeoutSec|AggregateStale|AggregateProbeFailed|HostStale|HostProbeFailed)' |
    Measure-Object -Line   # Expect: Lines >= 7
```

5. Confirm config schema bumped to 2:

```powershell
Select-String -Path .\conf\config.conf -Pattern '^SchemaVersion\s*=\s*2' -Quiet
# Expect: True
```

---

### v0.0.24b — Headline (envelope mode) with a fresh, healthy mixed fleet

- [ ] PASS
- [ ] FAIL

**Purpose:** The single most important scenario. A fresh envelope with three healthy clients + one mirror renders correctly alongside the existing Windows rows.

**Fixture** `test-fixtures\clamav\healthy-envelope.json` — replace the four `generated_at` values with **timestamps within the last 60 seconds** (ISO-8601 with offset). A helper:

```powershell
$now = (Get-Date).ToUniversalTime().ToString('o')
"generated_at: $now"   # copy into the four spots below
```

```json
{
  "schema_version": 1,
  "product": "Deploy-ClamAV",
  "kind": "fleet-status",
  "installer_version": "0.0.7",
  "generated_at": "REPLACE-WITH-NOW-ISO8601",
  "host_count": 4,
  "hosts": [
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.7",
      "hostname": "linux-mirror", "role": "both",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "Healthy", "status_reason": null,
      "engine_version": "1.5.1",
      "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
      "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": true, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": true },
      "recent_threat_count": 0, "probe_error": null
    },
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.6",
      "hostname": "linux-client-01", "role": "client",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "Healthy", "status_reason": null,
      "engine_version": "1.5.1",
      "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
      "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": true, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": false },
      "recent_threat_count": 0, "probe_error": null
    },
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.6",
      "hostname": "linux-client-02", "role": "client",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "Healthy", "status_reason": null,
      "engine_version": "1.5.1",
      "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
      "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": true, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": false },
      "recent_threat_count": 0, "probe_error": null
    },
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.6",
      "hostname": "linux-client-03", "role": "client",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "Healthy", "status_reason": null,
      "engine_version": "1.5.1",
      "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
      "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": true, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": false },
      "recent_threat_count": 0, "probe_error": null
    }
  ]
}
```

**Setup:**

1. Serve the fixture (fixture server from Setup section running).
2. Edit `conf/config.conf` `[ClamAV]` section:

```
ClamAVEnabled  = true
ClamAVMirrorUrl = http://localhost:8000/healthy-envelope.json
```

3. Restart the Dashboard scheduled task (or run the script interactively).

**Verification:**

1. Startup log line shows opt-in state:

```powershell
Get-Content C:\Logs\DefenderDashboard\dashboard-*.log |
    Select-String 'ClamAV consumer' | Select-Object -Last 1
# Expect: "ClamAV consumer : enabled (http://localhost:8000/healthy-envelope.json)"
```

2. Wait one `RefreshInterval` cycle (default 300s) OR click `Force Refresh`.

3. Browse `http://<host>:<port>/defender`. Expect:
   - 4 new rows for `linux-mirror`, `linux-client-01`, `linux-client-02`, `linux-client-03`
   - Each Linux row has 🐧 icon before the hostname
   - All 4 badges show `Healthy` (green)
   - Windows rows retain 🪟 icon; their behavior is unchanged
   - Legend at top-right shows the new `ProbeFailed` chip

4. Click any Linux row. Modal shows sections in this order:
   - Identity, **Deploy-ClamAV** (Product / Role / Mode / Host installer / Publisher version for envelope), Health Classification, ClamAV state (Engine + Signature), Capabilities (✔/✖ checklist), Threats (0), no error, no schema warnings

5. Check `/status` JSON — 4 new entries with `"osFamily":"Linux"` and populated `clamAv*` fields.

---

### v0.0.24c — Single-host mode (Deploy-ClamAV v0.0.6 mirror publishing its own document)

- [ ] PASS
- [ ] FAIL

**Purpose:** The compatibility path with pre-v0.0.7 Deploy-ClamAV — the mirror publishes just its own status.

**Fixture** `test-fixtures\clamav\single-host.json` — replace `generated_at`:

```json
{
  "schema_version": 1,
  "product": "Deploy-ClamAV",
  "installer_version": "0.0.6",
  "hostname": "linux-mirror",
  "role": "both",
  "generated_at": "REPLACE-WITH-NOW-ISO8601",
  "overall_status": "Healthy",
  "status_reason": null,
  "engine_version": "1.5.1",
  "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
  "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": true, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": true },
  "recent_threat_count": 0,
  "probe_error": null
}
```

**Setup:** Change `ClamAVMirrorUrl = http://localhost:8000/single-host.json`. Force Refresh.

**Verification:**

1. `/defender` shows exactly one Linux row: `linux-mirror`, Healthy.
2. Modal → Deploy-ClamAV section shows `Mode: single-host` and empty (`—`) `Publisher version` field (no envelope-level `installer_version` in single-host mode).
3. `/status` JSON shows `"clamAvMode":"single-host"` on the row and `"clamAvPublisherVersion":null`.

---

### v0.0.24d — Shape auto-detection (envelope on one refresh, single-host on the next)

- [ ] PASS
- [ ] FAIL

**Purpose:** The consumer must handle a mid-flight URL swap between envelope and single-host without a restart.

**Steps:**

1. Start with `ClamAVMirrorUrl = http://localhost:8000/healthy-envelope.json`. Force Refresh. Confirm 4 Linux rows.
2. Change to `ClamAVMirrorUrl = http://localhost:8000/single-host.json`. **Do not restart the dashboard task** — the config change is picked up on the next refresh cycle only if the script re-reads config. If the change requires a restart, restart. Force Refresh.
3. Confirm 1 Linux row (`linux-mirror`), 3 Linux rows from step 1 are gone.
4. Change back to envelope URL. Force Refresh. Confirm 4 Linux rows again.

**Expected:** No exceptions in dashboard log; every refresh cleanly returns the correct row count.

---

### v0.0.24e — Envelope schema newer than expected (soft-warn, still renders)

- [ ] PASS
- [ ] FAIL

**Purpose:** Envelope-level `schema_version` bump is a compatibility signal, not a failure. Consumer surfaces a warning but keeps rendering.

**Fixture** `test-fixtures\clamav\envelope-schema-v2.json` — same shape as `healthy-envelope.json` but with the **top-level** `schema_version` = `2`. Inner `hosts[]` elements keep `schema_version: 1`.

**Verification:**

1. Force Refresh.
2. Dashboard log has a Write-Warning line:

```powershell
Get-Content C:\Logs\DefenderDashboard\dashboard-*.log |
    Select-String 'envelope schema v2 > expected v1'
```

3. `/defender` renders all 4 Linux rows normally.
4. Modal for any Linux row shows a **Schema warnings** section at the bottom with the envelope warning text.
5. `/status` JSON shows `"clamAvEnvelopeSchemaWarning":"envelope schema v2 > expected v1; parsing best-effort"` on every Linux row.

---

### v0.0.24f — Host doc schema newer than expected (per-host soft-warn)

- [ ] PASS
- [ ] FAIL

**Purpose:** Host-level `schema_version` bump on one element doesn't fail the whole envelope. Warning attaches to that host only.

**Fixture** `test-fixtures\clamav\host-schema-v2.json` — same as `healthy-envelope.json` but with `linux-client-02`'s inner `schema_version` set to `2`.

**Verification:**

1. Force Refresh.
2. Log shows exactly one Write-Warning for `linux-client-02`.
3. All 4 rows render Healthy.
4. Only `linux-client-02`'s modal shows a **Schema warnings** section (host-level).

---

### v0.0.24g — Aggregate stale (Degraded override)

- [ ] PASS
- [ ] FAIL

**Purpose:** Envelope `generated_at` older than 900s (`AggregateStaleSeconds` default) — all rows escalate to Degraded even if they were Healthy.

**Fixture** `test-fixtures\clamav\aggregate-stale.json` — same as `healthy-envelope.json` but with the **envelope-level** `generated_at` set to `1000 seconds ago` and inner host `generated_at`s **fresh (current now)**:

```powershell
$envAt  = (Get-Date).ToUniversalTime().AddSeconds(-1000).ToString('o')
$hostAt = (Get-Date).ToUniversalTime().ToString('o')
```

**Verification:**

1. Force Refresh.
2. All 4 Linux rows show `Degraded` badge (amber).
3. Each row's `StatusReason` (visible in tooltip on hover of the hostname / row-error attribute) reads `"fleet aggregate stale (16m old)"` (or whatever `Format-ClamAVAgeLabel` produces for the age).

---

### v0.0.24h — Aggregate very stale (ProbeFailed override)

- [ ] PASS
- [ ] FAIL

**Purpose:** Envelope older than 1800s (`AggregateProbeFailedSeconds` default) — all rows ProbeFailed.

**Fixture** `test-fixtures\clamav\aggregate-very-stale.json` — envelope `generated_at` = `2000 seconds ago`. Hosts fresh.

**Verification:**

1. All 4 rows show `ProbeFailed` badge.
2. `StatusReason` reads `"fleet aggregate too stale to trust (33m old)"`.

---

### v0.0.24i — Per-host stale (single host Degraded, others Healthy)

- [ ] PASS
- [ ] FAIL

**Purpose:** Envelope fresh but ONE host's `generated_at` > 1800s — only that host overrides to Degraded.

**Fixture** `test-fixtures\clamav\one-host-stale.json` — envelope fresh; `linux-client-01` has `generated_at` = `2000 seconds ago`; other hosts fresh.

**Verification:**

1. Only `linux-client-01` shows Degraded. Others show Healthy.
2. `linux-client-01`'s reason reads `"status document stale (33m old)"`.

---

### v0.0.24j — Per-host very stale (single host ProbeFailed)

- [ ] PASS
- [ ] FAIL

**Purpose:** Envelope fresh; ONE host's `generated_at` > 3600s (`HostProbeFailedSeconds` default).

**Fixture** `test-fixtures\clamav\one-host-very-stale.json` — envelope fresh; `linux-client-01` `generated_at` = `4000 seconds ago`.

**Verification:**

1. `linux-client-01` shows ProbeFailed. Others Healthy.
2. Reason: `"status document too stale to trust (Xm old)"`.

---

### v0.0.24k — Escalate-only (underlying ProbeFailed keeps its own reason)

- [ ] PASS
- [ ] FAIL

**Purpose:** A host that reports `overall_status: ProbeFailed` from Deploy-ClamAV's side (e.g. unreachable during aggregation) keeps THAT reason even if the aggregate is also stale. Staleness never de-escalates a real failure.

**Fixture** `test-fixtures\clamav\escalate-only.json` — envelope `generated_at` = `1000 seconds ago` (Degraded-range), one host (`linux-client-02`) has `overall_status: "ProbeFailed"` and `probe_error: "unreachable during aggregation"`, other hosts Healthy.

**Verification:**

1. `linux-client-02` shows `ProbeFailed`, StatusReason = `"unreachable during aggregation"` — NOT the aggregate-stale reason.
2. Other hosts show `Degraded` (aggregate-stale override applies to them).

---

### v0.0.24l — Mirror unreachable (single synthetic ProbeFailed row)

- [ ] PASS
- [ ] FAIL

**Purpose:** HTTP fetch fails entirely — probe emits one synthetic row so the operator sees the attempt.

**Setup:** Stop the fixture server (Ctrl+C in its window). Force Refresh.

**Verification:**

1. `/defender` shows a single new Linux row with `HostName = localhost` (or whatever `[uri].Host` extracts from the MirrorUrl).
2. Badge is `ProbeFailed`.
3. Modal shows an Error/Detail section with the underlying HTTP exception text.
4. Windows rows unaffected.

Restart the fixture server before proceeding.

---

### v0.0.24m — Malformed JSON (single synthetic ProbeFailed row)

- [ ] PASS
- [ ] FAIL

**Purpose:** Server responds 200 with invalid JSON — probe survives, emits one synthetic ProbeFailed row.

**Fixture** `test-fixtures\clamav\malformed.json` — literally the text `{ not-json`:

**Verification:**

1. Change `ClamAVMirrorUrl = http://localhost:8000/malformed.json`. Force Refresh.
2. One Linux row appears with `ProbeFailed`.
3. Error text mentions a JSON parse failure.
4. Windows rows unaffected.

---

### v0.0.24n — Empty envelope `hosts: []` (no Linux rows rendered)

- [ ] PASS
- [ ] FAIL

**Purpose:** Structurally valid envelope with no hosts — dashboard shows no new rows (not a synthetic ProbeFailed).

**Fixture** `test-fixtures\clamav\empty-envelope.json`:

```json
{
  "schema_version": 1,
  "product": "Deploy-ClamAV",
  "kind": "fleet-status",
  "installer_version": "0.0.7",
  "generated_at": "REPLACE-WITH-NOW-ISO8601",
  "host_count": 0,
  "hosts": []
}
```

**Verification:**

1. `/defender` row count === Windows fleet size. No Linux rows.
2. `/status` JSON `computers[]` count === Windows count.
3. Dashboard log records the refresh without warnings.

---

### v0.0.24o — Mixed status classes render correctly, unhealthy sorted first

- [ ] PASS
- [ ] FAIL

**Purpose:** Visual verification of the four badge states + platform icon + drill-down modal for each.

**Fixture** `test-fixtures\clamav\mixed-status.json`:

```json
{
  "schema_version": 1,
  "product": "Deploy-ClamAV",
  "kind": "fleet-status",
  "installer_version": "0.0.7",
  "generated_at": "REPLACE-WITH-NOW-ISO8601",
  "host_count": 4,
  "hosts": [
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.7",
      "hostname": "linux-mirror", "role": "both",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "Healthy", "status_reason": null,
      "engine_version": "1.5.1",
      "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
      "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": true, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": true },
      "recent_threat_count": 0, "probe_error": null
    },
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.6",
      "hostname": "linux-client-01", "role": "client",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "Degraded", "status_reason": "clamonacc inactive",
      "engine_version": "1.5.1",
      "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
      "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": false, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": false },
      "recent_threat_count": 0, "probe_error": null
    },
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.6",
      "hostname": "linux-client-02", "role": "client",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "ThreatsDetected", "status_reason": "3 threat(s) detected in the last 24h",
      "engine_version": "1.5.1",
      "signature": { "version": 28049, "build_time": "2026-07-09T06:24:34Z", "age_days": 0, "max_age_days": 7, "stale": false },
      "capabilities": { "clamd_active": true, "freshclam_active": true, "onaccess_active": true, "autoupgrade_timer_active": false, "selftest_passing": true, "mirror_active": false },
      "recent_threat_count": 3, "probe_error": null
    },
    {
      "schema_version": 1, "product": "Deploy-ClamAV", "installer_version": "0.0.6",
      "hostname": "linux-client-03", "role": "client",
      "generated_at": "REPLACE-WITH-NOW-ISO8601",
      "overall_status": "ProbeFailed", "status_reason": null,
      "engine_version": null,
      "signature": null,
      "capabilities": null,
      "recent_threat_count": 0, "probe_error": "unreachable during aggregation"
    }
  ]
}
```

**Verification:**

1. Four rows render in Sort-Object ComputerName order (the current sort — v0.0.24 doesn't change sort behavior).
2. Badges: `Healthy` green, `Degraded` amber, `ThreatsDetected` amber, `ProbeFailed` red.
3. `linux-client-02` modal → Threats section shows `Recent threat count : 3` and StatusReason `"3 threat(s) detected in the last 24h"`.
4. `linux-client-03` modal → Deploy-ClamAV section shows Mode envelope, Role client; Health Classification shows `ProbeFailed` pill + `unreachable during aggregation` reason.
5. Sort by Status column (click header): unhealthy rows float to top of the Linux subset.

---

### v0.0.24p — Opt-out (Enabled=false, no HTTP fetch attempted)

- [ ] PASS
- [ ] FAIL

**Purpose:** Turning off the consumer must produce zero HTTP calls — v0.0.23 behavior identical.

**Setup:**

1. Edit `conf/config.conf`: `ClamAVEnabled = false` (leave MirrorUrl set — irrelevant when disabled).
2. Restart the dashboard task.

**Verification:**

1. Startup log line: `ClamAV consumer : disabled`.
2. Force Refresh.
3. Fixture server access log (or a `netsh trace` if you're being thorough) shows NO requests to `localhost:8000` in the past refresh cycle.
4. `/defender` fleet count === Windows fleet count. No Linux rows.
5. `/status` payload has no `osFamily:"Linux"` entries.

---

## Cleanup

```powershell
# Restore config
Copy-Item .\conf\config.conf.pre-v0.0.24 .\conf\config.conf -Force

# Stop the fixture server (Ctrl+C in its window)

# Restart the dashboard task
```

---

## Results summary

| Scenario | PASS | FAIL | Notes |
|---|---|---|---|
| v0.0.24a — Bundle baseline               | [ ] | [ ] |  |
| v0.0.24b — Headline envelope             | [ ] | [ ] |  |
| v0.0.24c — Single-host mode              | [ ] | [ ] |  |
| v0.0.24d — Shape auto-detect             | [ ] | [ ] |  |
| v0.0.24e — Envelope schema newer         | [ ] | [ ] |  |
| v0.0.24f — Host schema newer             | [ ] | [ ] |  |
| v0.0.24g — Aggregate stale               | [ ] | [ ] |  |
| v0.0.24h — Aggregate very stale          | [ ] | [ ] |  |
| v0.0.24i — Per-host stale                | [ ] | [ ] |  |
| v0.0.24j — Per-host very stale           | [ ] | [ ] |  |
| v0.0.24k — Escalate-only                 | [ ] | [ ] |  |
| v0.0.24l — Mirror unreachable            | [ ] | [ ] |  |
| v0.0.24m — Malformed JSON                | [ ] | [ ] |  |
| v0.0.24n — Empty envelope                | [ ] | [ ] |  |
| v0.0.24o — Mixed status classes          | [ ] | [ ] |  |
| v0.0.24p — Opt-out                       | [ ] | [ ] |  |

Lab pass date: `YYYY-MM-DD` · Operator: `___` · Environment: `HOME lab` / `work lab`

---

## Post-pass follow-ups

- **Real Deploy-ClamAV interop.** Joint session with the ClamAV side once their v0.0.7 ships (D2 publisher + D3 contract addendum). Validates: mirror's `provision --status --publish` produces the exact envelope shape the consumer expects, `--fresh` mode is on by default, publish cadence is `*:0/5`.
- **Screenshot capture.** After PASS on v0.0.24b + v0.0.24o, capture the mixed-fleet dashboard shot on the anonymized lab for the MkDocs site (per `project-screenshot-capture-runbook`). This is the shot that makes multi-platform capability visible to project visitors.

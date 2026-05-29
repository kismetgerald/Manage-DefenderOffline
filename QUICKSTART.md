# Quick Start — Dashboard in under 10 minutes

Get the Defender fleet dashboard running and reachable from a remote workstation.
For full reference, see [README.md](README.md).

---

## What you'll have at the end

A browser-accessible HTTPS dashboard at `https://<host>:8444/defender` showing
per-host Defender health for every Windows endpoint discovered via AD (or a
`hosts.conf` subset you supply). Auto-refreshes every 5 minutes. Survives reboots.

---

## Prerequisites

**On the host that will run the dashboard:**
- Windows 10/11 or Windows Server 2016+
- **PowerShell 7+** ([download](https://github.com/PowerShell/PowerShell/releases))
- **Local Administrator** rights for the install
- A **service account** (or gMSA) that is a local administrator on every endpoint
  you want to monitor. The same account needs network access to those endpoints
  over **WinRM (TCP 5985)**.

**On each target endpoint** (one-time, do this first if not already done):
```powershell
Enable-PSRemoting -Force
```
…or do it at scale via GPO:
`Computer Configuration → Policies → Administrative Templates →
Windows Components → Windows Remote Management (WinRM) → WinRM Service →
Allow remote server management through WinRM`

---

## Step 1 — Download and extract (1 min)

In an **elevated PowerShell 7** window on the dashboard host:

```powershell
$Zip = "$env:TEMP\manage-defenderoffline-0.0.17.zip"

Invoke-WebRequest `
    -Uri 'https://github.com/kismetgerald/Manage-DefenderOffline/releases/download/v0.0.17/manage-defenderoffline-0.0.17.zip' `
    -OutFile $Zip

Expand-Archive -Path $Zip -DestinationPath 'C:\Tools' -Force
Set-Location 'C:\Tools\manage-defenderoffline'

# STIG-hardened systems: files extracted from a downloaded ZIP carry the
# Mark-of-the-Web (Zone.Identifier) ADS. PowerShell ExecutionPolicy will
# refuse to load them — even parameter tab-completion is blocked. Strip
# the marker on the whole bundle before running any script.
Get-ChildItem -Recurse -File | Unblock-File
```

---

## Step 2 — Configure (2 min)

Open `conf\config.conf` in Notepad and set, at minimum:

```ini
# [Common] section
SourceSharePath = \\NAS01\Share\_AVDefinitions\Microsoft_Defender

# [Dashboard] section
Port     = 8444
UseHttps = true
```

`SourceSharePath` enables the *Outdated* badge by comparing each endpoint's
signature version against the latest in the share. Skip it if you don't have
one yet — the dashboard still shows health pills, just without the currency
comparison.

Everything else in `config.conf` has sensible defaults. Tune later from the
[README](README.md#configuration).

---

## Step 3 — Install (2 min)

### Option A — Traditional service account

```powershell
$cred = Get-Credential `
    -UserName 'CONTOSO\svc-defender' `
    -Message 'Password for the dashboard service account'

.\Install-DefenderDashboard.ps1 `
    -ServiceAccount 'CONTOSO\svc-defender' `
    -Credential     $cred `
    -UseHttps `
    -Port           8444 `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

### Option B — gMSA (no password needed)

```powershell
.\Install-DefenderDashboard.ps1 `
    -GmsaName       'CONTOSO\svc-defender$' `
    -UseHttps `
    -Port           8444 `
    -AddFirewallRule `
    -StartImmediately `
    -Force
```

What the installer does (~30 seconds end-to-end):
- Generates a self-signed TLS cert (or reuses an existing one via `-CertificateThumbprint <thumb>`)
- Binds the cert to port 8444 via `netsh http add sslcert`
- Registers a scheduled task that runs the dashboard at system startup as the service identity
- Creates inbound Windows Firewall rules for TCP 8444 (Domain + Private profiles)
- Starts the task and probes `https://localhost:8444/health` for `200 OK`

---

## Step 4 — Verify (30 sec)

Browser test from the dashboard host:

```powershell
Start-Process 'https://localhost:8444/defender'
```

You should see the fleet grid with per-host pills:

| Pill | Meaning |
|---|---|
| **Healthy** (green) | All Defender protections on, no recent threats |
| **ThreatsDetected** (red) | One or more quarantined detections in the last 24h |
| **Degraded** (amber) | At least one protection toggle is off (e.g. RT disabled) |
| **Offline** (grey) | WinRM unreachable |
| **ProbeFailed** (grey) | WinRM reached but health probe threw |

If the page doesn't load, check the dashboard log:

```powershell
Get-Content "C:\Logs\DefenderDashboard\DefenderDashboard_$(Get-Date -Format yyyyMMdd).log" -Tail 30
```

Expected lines:
- `[SUCCESS] HTTPS pre-flight: Cert <thumb> is bound to 0.0.0.0:8444.`
- `[SUCCESS] HTTPS listener started on https://+:8444/`
- `[SUCCESS] Initial collection complete: N computers`

Common errors are self-diagnosing — if you see `[ERROR] HTTPS pre-flight FAILED`
or `[WARN] URL-ACL collision`, the log includes the exact `netsh` command to fix it.

### "Available: N/A" in the dashboard banner

If the dashboard loads but shows `Available: N/A` (or you don't see *Outdated*
pills despite stale endpoints), the dashboard couldn't enumerate
`SourceSharePath`. The log emits a distinct WARN/ERROR per cause: path not
configured, path unreachable, no `mpam-fe.exe` found, or permission denied.

For the permission case specifically: after granting share/dataset
permissions on the SMB server (TrueNAS, Windows file server, NAS appliance),
**restart the dashboard scheduled task** before retrying. SMB session caching
means the dashboard's in-flight session keeps using the old ACL evaluation —
the new grant won't take effect until the session expires (~10 min) or the
connection is recycled.

```powershell
Stop-ScheduledTask  -TaskName DefenderDashboard
Start-ScheduledTask -TaskName DefenderDashboard
```

---

## Step 4½ — Register service-account SPNs (for cross-host access)

**Skip this if you'll only browse the dashboard from the host that's running
it** — loopback uses local authentication and doesn't need Kerberos.

If you'll access the dashboard from a **different machine** with
`AuthMethod = ADIntegrated`, the service account must own the `HTTP/<host>`
Service Principal Name so the client can request a Kerberos service ticket.
Without it, browsers fail in confusing ways that don't reach the dashboard
log: Firefox returns 401 with no server entry, Edge prompts for credentials
then shows a blank page, and the server log captures a cryptic
`EndGetContext: successfully authenticated context` exception.

Run from a Domain Admin (or any account delegated "Write servicePrincipalName"
on the target service account):

```powershell
# Replace the hostnames + account with your values
setspn -S HTTP/util01                 CONTOSO\svc-defender
setspn -S HTTP/util01.contoso.local   CONTOSO\svc-defender
```

Use `-S` (not `-A`) — it checks for duplicates first. The computer account
(`UTIL01$`) sometimes holds `HOST/UTIL01` which can collide.

After registration, **purge cached tickets on each client** so the new SPN is
picked up on the next request:

```powershell
klist purge
```

Verify the SPNs landed:

```powershell
setspn -L CONTOSO\svc-defender
# Expected output includes:
#   HTTP/util01
#   HTTP/util01.contoso.local
```

### Service-account naming is not authoritative

Don't assume a service account's *name* reflects its *actual* AD group
membership. An account called `svc-defender-auditor` may not be in the
"Auditors" group — and the groups it *is* in determine which share/dataset
permissions actually apply. When troubleshooting unexplained access failures
(share permissions, SourceSharePath reachability, group-based allow-lists),
verify membership directly:

```powershell
Get-ADUser CONTOSO\svc-defender -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf
```

---

## Step 5 — Access from a remote workstation (1 min)

### Use the FQDN, not the IP

From any workstation on the same network, browse to:

```
https://<dashboard-fqdn>:8444/defender
```

**Use the FQDN form** (`dashboard.contoso.com`), not the IP (`10.0.0.50`). The auto-generated self-signed cert includes Subject Alternative Names for:
- Short hostname (`DASHBOARD`)
- FQDN (`DASHBOARD.contoso.com`)
- `localhost`
- The host's primary IPv4 (v0.0.13+)

Hitting by IP works *only* because v0.0.13+ auto-includes the primary IPv4 — but the FQDN form is what enables Kerberos auth (SPNs are hostname-based, not IP-based). On Edge and Chrome that's significant: Kerberos via FQDN works invisibly; NTLM-over-IP triggers a credential prompt.

If you need to access via an alias, CNAME, or load balancer VIP that isn't in the auto-included list, pass `-AdditionalSans` when running the installer:

```powershell
.\Install-DefenderDashboard.ps1 ... -AdditionalSans 'dashboard.contoso.com,my-alias,10.0.0.50' -RenewCertificate -Force
```

(`-RenewCertificate` is required when adding SANs to an existing install — otherwise the installer reuses the previously-generated cert and ignores the new SAN list.)

### Cert warnings on first access

**The browser will warn about an untrusted certificate** because self-signed certs aren't in any client's trusted root by default. Three options:

1. **Click through** (Advanced → Proceed) — fine for lab and pilot use.
2. **Install the cert on the client** (production-quality for self-signed deployments):
   ```powershell
   # On the dashboard host — export the public cert
   $cert = Get-Item 'Cert:\LocalMachine\My\<thumbprint>'
   Export-Certificate -Cert $cert -FilePath 'C:\Temp\dashboard-public.cer' -Type CERT

   # Copy the .cer file to each client workstation, then on each client (as Admin):
   Import-Certificate -FilePath '<path>\dashboard-public.cer' `
       -CertStoreLocation 'Cert:\LocalMachine\Root'
   ```
3. **Replace with a PKI-issued cert** (cleanest for production):
   ```powershell
   # On the dashboard host, after importing your PKI cert into Cert:\LocalMachine\My
   .\Install-DefenderDashboard.ps1 `
       -ServiceAccount         'CONTOSO\svc-defender' `
       -Credential             $cred `
       -UseHttps `
       -CertificateThumbprint  '<new-thumbprint>' `
       -Port                   8444 `
       -Force
   ```

### Browser auth quirks — Firefox specifically

Edge and Chrome auto-Negotiate against any URL matching their intranet-zone heuristics (RFC 1918, `.local`, domain-joined hostnames). **Firefox does not.**

If you get an immediate 401 with **no credential prompt** from Firefox, the browser declined to send a Kerberos/NTLM token. Configure it:

1. In Firefox, open `about:config` → *Accept the Risk*.
2. Search `network.negotiate-auth.trusted-uris` → set to your dashboard's domain (leading dot covers all hosts):
   ```
   .contoso.com
   ```
3. Search `network.automatic-ntlm-auth.trusted-uris` → set the same value.
4. Reload the dashboard.

For non-domain-joined workstations, Firefox/Edge/Chrome will all prompt for credentials (`DOMAIN\user` + password) instead of auto-Negotiating — that's normal and works fine.

### Cross-domain access from a non-domain-joined client

This works too — NTLM over HTTPS from a non-domain-joined workstation can authenticate against a domain-joined dashboard host. Expect:
- A "Not secure" cert warning (unless you imported the cert per option 2 above)
- A Windows Security credential prompt for `DOMAIN\user` + password
- Successful access after both are dismissed/entered

If the request appears to *hang*, the dashboard log is the source of truth. Check `C:\Logs\DefenderDashboard\DefenderDashboard_<date>.log` on the dashboard host: a healthy dashboard logs either `event=auth_allowed` (the request succeeded) or `event=auth_denied` / `event=request_error` (the request was rejected with explainable reason). A *silent* request — no log entry for your access attempt — usually means HTTP.sys rejected at the protocol layer; the cert-trust workaround above usually fixes it.

### Connectivity sanity check

If the page doesn't load at all from the remote workstation:

```powershell
Test-NetConnection -ComputerName <dashboard-fqdn> -Port 8444
# Expected: TcpTestSucceeded : True
```

If `False`, the dashboard host's firewall is blocking TCP 8444 on the network profile the remote workstation is connecting from. The installer enables **Domain + Private** profiles; if your network is on the **Public** profile, add it manually on the dashboard host:

```powershell
Set-NetFirewallRule -DisplayName 'DefenderDashboard-HTTPS-8444' -Profile Domain,Private,Public
```

---

## What's next

- **Lock down access** — the default `AuthMethod = None` allows anonymous
  access. Set `AuthMethod = ADIntegrated` in `conf\config.conf` plus
  `AuthAllowedGroups = Domain Admins,Helpdesk` to restrict to specific AD groups.
  See the [README authentication section](README.md#start-defenderdashboardps1-reference).
- **Deploy definition updates** — `Update-DefenderOffline.ps1` is the
  complementary script for pushing signature updates to the same fleet.
  Quick test: `.\Update-DefenderOffline.ps1 -WhatIfMode`. Full reference in the README.
- **Interactive monitor** — `Show-DefenderStatus.ps1` is a Windows Forms GUI
  variant of the same dashboard for desktop use (admin workstation).
- **Workgroup environments** — if your endpoints are not domain-joined, use
  a `hosts.conf` file instead of AD discovery. See
  [README → Workgroup deployments](README.md#workgroup-deployments).

---

## Common installer parameters reference

| Parameter | What it does | When to set |
|---|---|---|
| `-Port` | TCP port for HTTPS listener (default 8080) | Always specify; 8443 is often taken, 8444 is a safe pick |
| `-UseHttps` | Enable TLS | Recommended for any non-local use |
| `-CertificateThumbprint` | Reuse an existing cert from `Cert:\LocalMachine\My` | When you have a PKI-issued cert, or upgrading and want to keep the same cert |
| `-AdditionalSans` | Comma-separated extra Subject Alternative Names baked into a generated self-signed cert (DNS names + IPs) | When operators access via a CNAME, load-balancer VIP, alias, or extra IP. Pair with `-RenewCertificate` when adding to an existing install. |
| `-RenewCertificate` | Regenerate the cert (and rebind via `netsh sslcert`) even if a thumbprint is already set | When the existing cert's SAN coverage is wrong, or you just added `-AdditionalSans` to an existing install |
| `-AddFirewallRule` | Open inbound TCP `Port` on Domain + Private profiles | Almost always |
| `-StartImmediately` | Start the task right after registration + probe `/health` | Recommended — proves the install works |
| `-Force` | Overwrite an existing task with the same name | When re-installing or upgrading |
| `-SourceSharePath` | UNC path for the definitions share (also config-driven) | When you want the *Outdated* pill |
| `-ServiceAccount` + `-Credential` | Traditional account | One or the other — they're mutually exclusive |
| `-GmsaName` | Group Managed Service Account (ends with `$`) | Preferred — no password to rotate |

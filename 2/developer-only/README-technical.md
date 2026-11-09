> **Folder layout changed (parent-ready package).** Where this document says `agent/`, read `parent-package-template/program-DO-NOT-OPEN/`. The unit tests moved to `developer-only/tests/`. Parents no longer receive this project: use `1-MAKE-PARENT-PACKAGE.bat` and read `HOW-TO-SEND-TO-A-PARENT.txt`. The old `agent/config.json` contained a real device key and `agent/agent.log` contained browsing notices; both were removed.

# ParentGuard v5.11 — Windows endpoint + Firebase dashboard

ParentGuard has three parts: the hosted admin/parent dashboards (`web/`), a Windows endpoint agent (`agent/`), and Firestore security rules (`firestore.rules`). The endpoint agent runs on the managed Windows PC and polls its assigned device policy every 15 seconds.

## What this version implements

- Parent email/password accounts created by an authenticated administrator. The admin creates the account using a secondary Firebase Auth session so the admin is not signed out. The parent signs in at `parent.html` with the assigned email/password.
- Admin assigns a child device to a parent from the device card. Parents can only query devices assigned to their own Firebase UID.
- Per-device application process blocklists and allowlists. An allowed app takes precedence over a matching block.
- Common game/launcher block toggle, custom blocked game processes, and individually approved games.
- Website blocklist and allowlist. An allowed domain takes precedence over a matching blocked domain.
- Adult-content DNS filtering (Cloudflare Family DNS) and managed SafeSearch / YouTube Restricted Mode policies for Chrome and Edge.
- Screen-time limits, weekday/weekend limits, allowed hours, bedtime/wake schedule, lock-now and bonus time.
- Optional Windows Location API reporting. The dashboard shows a map link only when Windows returns actual coordinates.
- Device heartbeat, agent version, applied-policy timestamp, newly observed application-start events, app usage estimates and last-known-policy fallback.
- Website-issued lock/unlock commands have explicit priority over schedules and daily limits. Persistent unlock remains active until the dashboard locks again or resumes the normal schedule; timed unlock returns to schedule enforcement when it expires.
- The dashboard acknowledgement advances only after a successful policy fetch and application; failed syncs retain the last confirmed timestamp and expose the sync error.
- Screen-time extensions add minutes to the current day's limit.
- Admin can lock policy sections so parent controls for those sections are disabled.

## Admin setup and login (important)

The public landing page is `web/index.html`. It now has separate, visible links for **First-time admin setup**, **Admin sign in**, and **Parent sign in**. The administrator sign-in form is also rendered directly at `web/admin.html`; it does not depend on browser-generated element IDs.

For a new Firebase project:
1. Enable **Email/Password** and **Anonymous** under Firebase Authentication → Sign-in method.
2. Create the Cloud Firestore database.
3. From this project folder, deploy the rules and hosting site.
4. Open `https://YOUR_HOST/setup.html`, create the first Super Admin, then open `https://YOUR_HOST/admin.html` and sign in.
5. After successful setup, remove `web/setup.html` from the deployed source and redeploy hosting.

If the admin login says the account is not an administrator, check that the `admins/{AUTH_UID}` document exists in Firestore and that the rules below are deployed to the same Firebase project. If setup reports `permission-denied`, the rules were not deployed, the bootstrap document already exists, or setup is being attempted on a project that has already been initialized. Do not repeatedly create new administrator accounts.

## Deployment

1. In Firebase Console, enable **Email/Password** and **Anonymous** sign-in (anonymous sign-in is retained for legacy agent registration in this edition).
2. Create Firestore Database. Ensure the project ID and web API key in `web/firebase-config.js` and `agent/config.json` refer to the same Firebase project.
3. Deploy the site and rules from this folder using Firebase CLI:

   ```bash
   npm install -g firebase-tools
   firebase login
   firebase use parental-control-ffe24
   firebase deploy
   ```

4. If this is a fresh project, open `/setup.html` once to create the first administrator. Then delete `web/setup.html` from the deployed source and deploy again. Do not leave public admin bootstrap enabled after setup.
5. Sign in at `/admin.html`. Create each parent with a name, email and temporary password (minimum 8 characters). Share credentials securely and ask the parent to change the temporary password; the parent signs in at `/parent.html`.
6. Add a device, assign it to the correct parent, then use **Setup / credentials** to copy the device-specific `config.json` to the child's PC.
7. On the child's Windows 10/11 PC, create a **standard (non-administrator) Windows child account**. Copy the `agent/` folder there with its assigned `config.json`. Right-click `install.bat` and choose **Run as administrator**. The installer copies the agent into `C:\Program Files\ParentGuard`, restricts access to the device key file, and registers scheduled tasks. Keep that installed folder in place.
8. No Windows username assignment is required. ParentGuard automatically detects all interactive Windows accounts on the managed PC. Device lock and screen-time enforcement apply to every active user session on that PC.

## Important platform and safety limits

ParentGuard is not a full mobile-device-management (MDM) product and cannot guarantee complete device protection. This build targets Windows 10/11 only; it does not control Android or iOS devices.

- Application/game blocking is process-name based. A renamed executable, portable app, another Windows account, Safe Mode, or a user with local administrator rights may bypass it. Use a standard child account and keep administrator credentials private.
- The website hosts-file blocklist is domain based, not a full URL/path filter. It does not inspect HTTPS traffic, and VPNs, encrypted DNS/DoH, alternate browsers or network changes can bypass it. Cloudflare Family DNS and managed Chrome/Edge SafeSearch add layers but are not a complete web-content classifier. Firefox has no equivalent managed policy in this version.
- Windows Location Services must be enabled and permission granted. Location reporting is best-effort and may not work when Windows denies location access to a background SYSTEM task. No location is fabricated when the API fails.
- Screen-time measurement is an estimate based on process/session activity, not a hardware-level usage meter. A session restriction disconnects the configured child session; save work before applying a restriction.
- The endpoint agent is installed under `C:\Program Files\ParentGuard`; use the generated `uninstall.bat` there to remove its scheduled tasks and ParentGuard-managed filtering settings. The agent snapshots existing IPv4 DNS settings before applying the family DNS filter and restores that snapshot when the filter is disabled or the agent is uninstalled. The endpoint agent needs network access to Firebase. If the device is offline, it keeps the last downloaded policy and syncs again when connectivity returns. The supplied source-folder `uninstall.bat` delegates only to the installed ParentGuard uninstaller; it does not terminate unrelated Python processes or reset every network adapter.
- The agent reports successful policy application timestamps, but that acknowledgement does not prove that every browser, app, VPN or OS bypass has been defeated.

For stronger enforcement, deploy Windows Family Safety / Microsoft Intune or another supported MDM alongside ParentGuard, and use a managed child Windows account. A signed Windows service plus browser extensions/policies and a DNS filtering gateway would be required for stronger tamper resistance and deeper filtering.

## Testing

Run the included local policy tests from the `agent/` folder:

```bash
python -m unittest discover -s tests -v
python -m py_compile agent.py
```

These five tests validate domain normalisation, allowed-app precedence, blocked-game termination, and child-session scoping. They do not emulate Windows process termination, Windows Location permissions, Firebase rules deployment or a live child-device connection. Those require a real Windows test device and the configured Firebase project.

## Troubleshooting

- Agent status offline: confirm the device has internet access, `config.json` matches the device record, and `agent.log` has no Firebase authentication/rules errors.
- Policy not applied: check `policyAppliedAt`, agent version and `agent.log`; make sure the scheduled task `ParentGuardAgent` is running.
- App/game not blocked: confirm the actual process name in Task Manager and add the exact `.exe` name.
- Location unavailable: enable Windows Location Services and allow desktop-app location access. The dashboard will not display made-up coordinates.
- Parent cannot sign in: confirm the administrator created the parent account and the parent document exists at `parents/{parent-auth-uid}`.


## Admin login loop repair (v3.2)
The setup page now writes exactly `{uid}` to `meta/setup`, matching the deployed Firestore rule. The previous package wrote an extra `createdAt` field to this document; the rules rejected the atomic Firestore batch after Firebase Authentication had already created the user. As a result, `admins/{uid}` was missing, and `admin.html` correctly returned the user to the login screen. This setup page can recover that partial first-time setup by signing in with the same email/password and completing the bootstrap batch. Deploy the updated hosting files and rules to the same Firebase project.


## v3.1 changes (reliability, identity, verification)

**Agent (`agent/agent.py`)**
- Single-instance lock (Windows named mutex). The watchdog starts an agent only when none holds the lock, so duplicate agents can no longer pile up.
- `--check` mode: one-shot Firebase sign-in, device registration, policy read and status write. The installer uses it before creating any task.
- `health.json`: written after every successful sync. The installer polls it to confirm the *running* agent reached Firebase.
- Exponential backoff on repeated network/Firebase errors; `agent.log` rotates at ~500 KB.
- Reports device identity every 10 minutes: computer name, signed-in Windows user, Windows version/build, manufacturer, model, local IPs.
- When the parent enables location: also reports an **approximate, IP-based** city/region/country and public IP (looked up via ipwho.is, labelled approximate on the dashboard). Precise Windows location is still best-effort and is often unavailable to a SYSTEM task.

**Installer / uninstaller**
- `install.bat` checks source files, rejects the Microsoft Store Python stub, verifies Python 3.10+ and the `requests` import, runs the live connection test, creates the tasks, then waits up to 90 s for `health.json`. It prints INSTALLED AND VERIFIED only when the agent is running and has reported; otherwise it exits non-zero and shows the last log lines.
- `uninstall.bat` (copied to `C:\Program Files\ParentGuard`) stops/deletes both tasks, kills any agent process, restores hosts/DNS/browser policies, removes the Control Panel entry and folder, then checks each item and reports `UNINSTALL INCOMPLETE` if anything remains.

**Dashboard**
- Device card shows computer name, Windows user, OS, hardware, local IP, an alerts box (offline, restriction active, limit nearly reached, blocked-app attempts in 24 h) and approximate location.
- Admin can **Regenerate device key**; it also removes existing agent registrations so the old key and old agent stop working. Deleting a device now removes its agent registrations as well.

**Rotate the exposed key.** Any `deviceKey` that was shared outside the admin page must be replaced: Admin → device → *Regenerate device key*, copy the new config.json to the PC, re-run `install.bat`. `agent/config.json` in this package contains placeholders only.

**Not verified here:** the sandbox has no Windows and no Firebase access. Python logic and dashboard helpers were unit-tested; the batch scripts, scheduled tasks, SYSTEM-session behaviour and live Firebase writes must be tested on a real Windows PC.


## Windows client v4.0 - redeveloped installation and enforcement baseline

The Windows client is a primary component of this release, not an untouched legacy add-on. The v4 client now uses a persistent HTTPS session with an explicit product user-agent, validates all device credentials before startup, reports its enforcement mode and sync heartbeat, and detects interactive Windows sessions automatically and applies process/session controls to every interactive account on the managed device. Device-wide restrictions may also affect a parent or administrator using that same PC.

### Advanced installation

Run `agent\install.bat` as Administrator. The BAT launcher invokes the PowerShell installation wizard (`install.ps1`), which:

1. Verifies elevated privileges, 64-bit Windows 10/11 and supported 64-bit Python 3.10-3.12.
2. Validates the device-specific Firebase configuration and rejects placeholder credentials.
3. Creates a timestamped backup of an existing installation before updating it.
4. Installs pinned-major-version dependencies into the product folder and verifies imports.
5. Applies restrictive Windows ACLs to the installation and device credential file.
6. Performs a live Firebase authentication, registration, policy-read and status-write preflight before registering background tasks.
7. Creates a SYSTEM startup task with restart settings plus a periodic watchdog.
8. Registers the product in Windows Apps & Features and waits up to 120 seconds for a successful live Firebase heartbeat.
9. Writes a detailed transcript to `%TEMP%\MFamilySafetyGuard-install.log`.

The installer deliberately does not claim success merely because files were copied. A missing heartbeat is a failed installation and must be investigated before treating the device as protected. The installer currently requires Python 3.10-3.12 (64-bit) installed from python.org; it does not silently download or install an interpreter.

### Important enforcement boundary

The agent runs as a SYSTEM scheduled task and applies the product's configured policies, but this is not a signed Windows kernel driver or a Microsoft Intune MDM enrollment. A standard child account, protected administrator credentials, Windows security updates and supported family/MDM controls remain important. The website blocklist is host/DNS based and cannot inspect encrypted HTTPS paths. Windows Location reporting is permission-dependent and best-effort.

**Before enabling restrictions:** verify the managed PC is the intended device, because device-wide restrictions apply to every interactive user account on it. Test each restriction with a non-critical test account. The dashboard should show `agentMode: device-wide-enforcing`.

## v5.0.0 — Windows client and installer redevelopment

The Windows client and installer are now treated as core product components.

- `agent.py` reports product identity/version with device status, validates all Firebase/device fields before running, and atomically saves local state.
- `install.bat` requests elevation, validates the complete package and starts the PowerShell setup wizard.
- `install.ps1` can install a supported machine-wide Python 3.10–3.12 runtime through Windows Package Manager when available; otherwise it gives a clear prerequisite message. It rejects per-user Python because the background SYSTEM task must be able to access the interpreter.
- The installer validates device credentials, backs up an existing installation, installs dependencies in an isolated product folder, applies Windows ACLs, runs a Firebase preflight, registers SYSTEM startup/watchdog tasks, and waits for a fresh heartbeat.
- A failed upgrade attempts to remove the incomplete new installation and restore the previous backup.
- `requests` is pinned to a tested stable release instead of accepting any future 2.x version.

### Installation

1. In the Admin dashboard, generate/download a unique device configuration for the child device.
2. Replace `agent/config.json` with that device-specific file. Do not share it publicly or reuse it for another device.
3. Extract the entire ZIP archive to a local folder. Do not run the installer from inside the ZIP preview.
4. Right-click `agent/install.bat` and select **Run as administrator** (or double-click and approve the elevation prompt).
5. Wait for the explicit live Firebase heartbeat verification. A successful file copy alone is not success.
6. Confirm the device is ONLINE in the Admin dashboard. No Windows account assignment is needed; monitoring and controls automatically cover all interactive users on that PC.

### Important product boundary

This is a Windows user-mode endpoint agent. It is not a kernel driver, a signed Windows service, or Microsoft Intune MDM. It cannot guarantee resistance to a local administrator, Safe Mode, boot-media changes, VPNs, encrypted DNS, renamed applications, or all alternate user sessions. Website blocking uses the Windows hosts file and optional family DNS/SafeSearch policy; it is not HTTPS URL inspection. Process blocking is process-name based. Screen-time enforcement disconnects active user sessions; users may need to reconnect after an authorized unlock. Test every restriction using a non-critical standard child account before family deployment.

The install wizard's live Firebase check and local unit tests do not replace testing on a physical Windows 10/11 device. This environment cannot run Windows scheduled tasks, validate SYSTEM-session permissions, verify actual filtering, or confirm a live Firebase project. Do not describe the release as production-certified until those acceptance tests, Firebase rules review, code signing, and a clean-install/upgrade/uninstall test have passed.


## v4 activity and control notes
- The agent reports newly observed application processes across all interactive PC users in the recent activity feed and estimates usage from process/session activity. This is not a complete keystroke, screen recording, message, or browser-history monitor.
- Website blocking still uses the Windows HOSTS file and DNS filtering. These mechanisms block name resolution but cannot display a ParentGuard-branded browser interstitial. HTTPS certificate protection prevents safely replacing the browser's blocked-site error with a custom page using HOSTS alone. A managed browser extension or filtering proxy with appropriate certificate/policy deployment is a separate required component for that experience.
- Browser-level site visit/blocked-attempt logs are not claimed in this release; the dashboard shows the configured blocked-site list and policy application status.
- Temporary unlocks are time-bounded (30 minutes from the dashboard button) and bypass daily limits/allowed hours until expiry. The extension control adds the selected minutes to the day's allowance.


## Device-wide user detection (v5.4)

The Windows agent detects interactive Windows sessions directly. It no longer
requires a configured child Windows username and does not report "not signed in"
when a different account is using the PC. Screen-time accounting begins when any
unlocked interactive user session is active. Parent/admin lock commands disconnect
all active interactive user sessions on the managed PC; they do not sign users out
or delete their work. After an authorized unlock, users can reconnect or sign in.
App/game restrictions and activity reporting cover all interactive user sessions
on this installed device.


## Full-screen blockage notice (v5.5)

When a website, application, game, or screen-time action is blocked, the agent
publishes a notice for signed-in interactive Windows users. A separate per-user
desktop helper displays a full-screen @M Family Safety Guard notice with the
Mathcloud Tech Services WhatsApp, email, direct-call and website contact details.
The notice is acknowledged with the I UNDERSTAND button (or Escape/Enter). For
screen-time lock events, the SYSTEM agent gives the desktop helper a short
four-second display window before disconnecting active sessions.

## v5.6 additions: child requests, e-mail, save feedback

**Deploy order matters.** From the project folder run `firebase deploy` so the new `firestore.rules` (request, private/notify and settings rules) and the updated `web/` files go live. Then re-run `install.bat` as administrator on the child PC (it upgrades in place and keeps a backup).

**Pop-up requests.** When the agent blocks a site, an app, or locks the PC for screen time, the full-screen notice offers: Give me more time (15/30/60 min), Please allow this site / app, and Send a message, with an optional note. A time-limit lock now shows a 20-second countdown first (`NOTICE_GRACE` in `agent.py`) so the request can be sent before the session is disconnected. Once a session is disconnected the child cannot interact with the pop-up until a parent unlocks.

**Where requests go.** Notice window -> `C:\ProgramData\MFamilySafetyGuard\requests` -> the SYSTEM agent validates and rate-limits them (1 identical request per 2 minutes, 12 per hour) -> Firestore `devices/{id}/requests` -> Requests tab on the Admin and Parent dashboards (Approve / Decline) and an e-mail. Approving time unlocks the PC for that many minutes; approving a site or app adds it to the allowed list. The child sees the answer in a small pop-up.

**E-mail setup (Admin page > Request e-mail notifications).** Enter the administrator address(es) and your EmailJS Service ID, Template ID, Public Key and Private Key (template: To Email `{{to_email}}`, Subject `{{subject}}`, body `{{message}}`). Allow non-browser API calls in the EmailJS account security settings. Saving copies the settings plus each child's recipient list (administrator addresses + that child's parents' sign-in e-mails) to `devices/{id}/private/notify`, readable only by the administrator and that device's agent. EmailJS's free plan has a monthly send limit; each recipient counts as one e-mail. Failed sends are retried 5 times and the failure is shown on the request.

**Save feedback.** Every save/lock/approve button shows a spinner, then a green tick or the exact error; operations give up after 15 seconds with a clear message instead of spinning.

## v5.9.0 — real website blocking and real visited-sites history

**Why v5.8 missed sites.** It guessed from DNS traffic: sub-domains were not covered by the HOSTS file (it cannot do wildcards), an unknown adult site was only learned *after* its first successful lookup, and every background lookup (ads, CDNs, trackers) looked like a "visit". It could not tell what the child actually opened.

**What changed**
- `agent/dnsfilter.py` — a local DNS filter on `127.0.0.1:53` / `::1`. The agent points every network adapter at it. Every lookup is checked **before** it resolves: blocked domains, all their sub-domains, the category lists and the keyword rules are refused immediately (A/AAAA get `0.0.0.0`/`::`, other record types NXDOMAIN). Allowed names are forwarded to Cloudflare Family DNS (adult filter on) or the PC's original DNS. Allowed-site exceptions win over blocks. Firebase/EmailJS hosts can never be blocked, so a typo cannot lock the parent out. If the filter cannot start, or fails its self-test, Windows DNS is **not** redirected (and is restored if it was) and the agent falls back to HOSTS + family DNS; the dashboard says so.
- `agent/webhistory.py` — **Sites visited and the Live timeline now come from the browsers' own history** (Chrome, Edge, Brave, Vivaldi, Opera, Firefox, every Windows account). Only pages that were really opened are listed; sub-frames, ads, CDNs and `chrome://` pages are excluded. DNS lookups of allowed sites are kept only as *background* entries, hidden unless "Show background services" is ticked. First read imports the last 60 minutes, then only new visits.
- A visited site that matches the adult/gambling/proxy lists or keywords but is not blocked gets a red **“looks like adult site · not blocked”** tag with the Block button on the same row.
- If a blocked site opens anyway (browser cache, VPN, own DNS) the timeline shows **“Opened a blocked website that was NOT stopped”** and the child gets the notice. Failures are surfaced, not hidden.
- Hardening applied once per release (and removed on uninstall): Incognito/InPrivate/Guest/Tor off, “delete browsing history” off (Chrome/Edge/Brave), Firefox private browsing off, browser DNS prefetch off (so a link on a page cannot trigger a false “blocked attempt”), outbound DNS-over-TLS (port 853) blocked, Firefox DoH canary answered.
- **Notice window:** only one page can open now. The helper holds a per-session mutex (the installer's immediate start plus the logon task used to launch two copies, each showing the notice), repeat notices for the same site/app are suppressed (5 min / 2 min), and anything published while the window is open is covered by it. The window was redesigned as one centred card that fits 768-pixel screens without scrolling.
- **Dashboard:** the Sites visited tab has a *Web monitoring status* box that states plainly whether real-time blocking is on, which browser histories are being read, and whether private browsing is disabled.
- `agent/requirements.txt` was missing from the package, which made `install.bat` stop at its file check. It is included.

**Deploy:** re-run `agent\install.bat` as administrator on the child PC (it backs up and upgrades in place). The dashboard files are in `web/` (`firebase deploy`). Check `Admin → device → Sites visited → Web monitoring status`: it must show ✅ real-time blocking and ✅ the child's browser. `python agent.py --diagnose` on the PC prints the same facts and tests `pornhub.com` against the live rules.

**Honest limits.** Blocking works at the DNS level for names, not full URLs or HTTPS content. A VPN, a browser with its own hard-coded DNS, Tor Browser installed outside policy, a local administrator, Safe Mode or another device on the network can bypass it. Visited-site data comes from browser history, which the browser writes a few seconds to a minute after the page loads; browsers not listed above are not read. Everything here was verified with unit tests and rendered screenshots on Linux; **it has not been run on Windows or against your Firebase project**, so run the acceptance checklist below on the real PC.

**Acceptance checklist (on the child PC, standard account):** (1) dashboard shows real-time blocking ✅ and the browser ✅; (2) open a normal site, it appears under Sites visited within a minute; (3) turn on *Adult content* and open `pornhub.com`: browser cannot load it, one notice appears, a *Blocked website* entry appears; (4) add an unlisted test domain under *Always block*, save, reload within ~15 s: blocked incl. its sub-domains; (5) try Incognito: it should be unavailable; (6) unplug the agent (stop the task): Windows DNS must be restored within a minute by the watchdog or on uninstall.


## Updating an existing installation

Replace the hosted `web/` files and update the installed agent using the normal installer/update procedure for this project. Restart the ParentGuard agent service after updating it. A dashboard command cannot reach a device that is offline; when it reconnects, the agent fetches the latest Firestore policy and applies it. Check the dashboard's device status for the last confirmed policy time and any policy sync error.


## Dashboard update (web/ only — agent and Firestore rules unchanged)

- New design for every page (spruce green + amber, light/dark automatic, phone friendly).
- **Today so far** card on each child's Overview tab: pages visited, apps used, games played and blocked attempts. The counters cover 00:00 to 23:59 of the current day only, restart at midnight and never show earlier days. Anything the administrator hides from the parent is also left out of the parent's counts.
- **Read aloud** button (summary of the child's day) and **Hear greeting** button. They use the most natural voice the device offers (Microsoft Edge "Natural" voices are the most human); the viewer can pick another voice.
- Welcome greeting appears on `parent.html` only.
- Parents cannot use `admin.html` or `setup.html`: both show a "for administrators" screen to a signed-in parent, and no parent-facing page links to them. Open `admin.html` directly (bookmark it). Firestore rules remain the real protection.

## v5.11 - repair, stop protection and remote removal (no format needed)

Three admin-only buttons now appear on every child's card in `admin.html`. Parents cannot use them: the commands are written to fields (`command`, `protection`) that Firestore rules only let an administrator change, and the agent reports the result back through its existing `status` field, so **no rule changes are needed**.

| Button | What it does on the child PC | What it never touches |
|---|---|---|
| **Repair / refresh device** | Stops the local DNS filter and undoes ParentGuard's own network changes (DNS back to the saved/automatic setting, hosts block, browser policy values), proves internet still works, checks the program files and components (reinstalls components if missing), re-creates the agent / watchdog / notice scheduled tasks, clears stale notices and lock state, signs in to Firebase again, then restarts itself. The dashboard shows each step with a tick or cross. | Internet and Wi-Fi profiles, other programs, user files, firewall rules (except ParentGuard's own), other DNS settings, today's screen-time usage |
| **Stop protection / Resume protection** | Per device. Removes every ParentGuard setting and enforces and monitors nothing (no locks, no app or site blocking, no history or location). The agent keeps only its heartbeat so you can resume from the dashboard. | Other children's devices |
| **Remove from device** (type `REMOVE` to confirm) | Restores network settings, deletes the scheduled tasks, stops all ParentGuard processes, removes the Apps & Features entry, the install folder, all `M Family Safety Guard.backup-*` folders (they held a copy of the device key), `ProgramData` data, the firewall rule and hosts entries. A detached SYSTEM helper does the deletion, verifies it and reports `Completely removed and verified` (or lists what is left) to the dashboard, which then deletes the agent's registrations. | Python itself (other programs may use it), the child's Windows accounts and files |

Offline devices: a command stays queued and runs when the PC reconnects. A command that was issued before the current installation is ignored, so an old "remove" can never hit a fresh install. Each command runs once.

### Automatic self-healing (no button needed)
The watchdog (every minute) now also: re-creates missing scheduled tasks, and if the agent is not running while Windows still points at the dead local DNS filter, resets only those adapters to automatic DNS. The agent also resets any leftover loopback DNS at every start. The DNS snapshot can no longer remember `127.0.0.1`, which was a cause of "no internet until the PC is formatted".

### If the PC cannot reach the dashboard (local fallback)
Run `repair.bat` (copied to `C:\Program Files\M Family Safety Guard`) as administrator. Or, from an administrator prompt in that folder: `python agent.py --repair-now` (full repair) or `python agent.py --reset-network` (only gives internet back). `uninstall.bat` now also resets leftover loopback DNS and deletes backup folders.

### Not verified here
Written and unit-tested on Linux (command gating, once-only execution, removal-script scoping). PowerShell tasks, scheduled-task creation, the detached removal helper, DNS reset and the live Firestore round-trip must be tested on a real Windows 10/11 PC. Test **Repair** and **Stop/Resume** first, and **Remove** last, on a spare PC. A local administrator can still stop a SYSTEM task; this is not tamper-proof.

# DynAllow test ledger

What has been tested, on which build, by whom, and what it showed. The automated checks run on
every build; the cases below are the ones that need real machines, reboots, people or networks.

**How to use it**

1. Deploy a dev release ([README](README.md#deploy-a-dev-test-environment)) and fill in **Test bed** once.
2. Add a row to **Run log** (newest on top) with the build tag, e.g. `v3.1.0-dev.4`.
3. Work through the cases. Put the result in **Last result** as `PASS dev.4`, `FAIL dev.4 (#12)`,
   `BLOCKED (reason)` or `N/A`. Link an issue for every FAIL.
4. Case IDs never change meaning. Retire a case by striking it through; never reuse its ID.

The **CI** column says which automated check already covers part of a case, so manual time goes to
what automation can't reach. A CI pass never replaces the manual case.

## Test bed

| Role | Machine | Notes |
|---|---|---|
| Server | | Docker host, port, HTTPS proxy in front? |
| Windows agent (TPM) | | Windows version, TPM present |
| Windows agent (no TPM) | | e.g. VM without vTPM |
| Docker agent | | Proxmox LXC with nesting + keyctl |
| DNS account | | Cloudflare / PowerDNS zone used for tests |

## S: Server (Docker package)

| ID | Test | Expected | CI | Last result |
|---|---|---|---|---|
| S1 | Unpack the server tarball, `cp .env.example .env`, `docker compose up -d --build` | Healthy; admin password printed once in the logs | e2e, package smoke | — |
| S2 | First sign-in, change password, turn on 2FA | All three work; the next sign-in asks for a code | | — |
| S3 | Put HTTPS reverse proxy in front, set `DYNALLOW_TRUSTED_PROXIES`, `DYNALLOW_SECURE_COOKIES=1` | No plain-HTTP warning; agents show their real public IP, not "held" | | — |
| S4 | Settings → Email → Send a test email | Email arrives | UI (mock) | — |
| S5 | Add a DNS account, give a site a target | Record created with the site IP. Change the record at the provider: put back within the drift interval | UI (mock) | — |
| S6 | Stop an agent for 3+ intervals, then start it | OFFLINE email after 2 missed check-ins; RECOVERED email after | | — |
| S7 | `manage.php backup`, restore into a fresh folder, start it | Same sites; agents keep checking in | | — |
| S8 | Allowlist feed over HTTPS | Lists the site IPs; `X-IPF-Signature` present | portable (token scope only) | — |
| S9 | Restart the container, then reboot the host | Comes back healthy, data intact, no cron banner | e2e (restart) | — |
| S10 | Releases page fingerprint | Matches the release notes and `release-public.pem` | | — |

## W: Windows agent

| ID | Test | Expected | CI | Last result |
|---|---|---|---|---|
| W1 | Fresh install: `install --profile …json` (elevated) | Site green within 2 min; tray green; transferred profile deleted | smoke (no server) | — |
| W2 | Reboot, nobody signs in | Server shows check-ins after boot | | — |
| W3 | Two users signed in at once (RDP or user switching) | Each gets a tray icon; details and Check now work for both | | — |
| W4 | As a standard user | Can't open `ProgramData\IPFailoverAgent` (except `public`), can't stop the service; `status` works | smoke (ACLs) | — |
| W5 | Kill the service process in Task Manager | Service restarts on its own within about 30 s | | — |
| W6 | Machine with a TPM | Site page shows key storage **TPM** | | — |
| W7 | Machine without a TPM | Site page shows **DPAPI** | smoke (DPAPI) | — |
| W8 | 2.0 PowerShell install, then `DynAllow.Agent.exe install` with **no** profile | Same site and key, no re-enroll; old tasks and `Program Files\IPFailoverAgent` gone | smoke (folder, task, identity format) | — |
| W9 | Site page: prevent sleep on, then off, then stop the service | `powercfg /requests` lists DynAllow only while on and running | smoke (power API) | — |
| W10 | Site page: Rotate key | Stays green; key ID changes | portable | — |
| W11 | Block the server for 10+ min, then unblock | Missed-check-in alert, then recovery; queued log entries show on the site page | | — |
| W12 | Releases: upload `dynallow-update-test-windows-x64-*.json`, push to this agent | Agent reports the new version within one interval and stays green | portable (verify) | — |
| W13 | Upload an update-test bundle from a **different** dev build | Server refuses it; agents unchanged | e2e (Docker) | — |
| W14 | Site page: Decommission | Service disabled, identity removed, server shows the acknowledgment | e2e (Docker) | — |
| W15 | `uninstall`, then `install` with no profile | Same identity, no new profile needed | | — |
| W16 | Microsoft Defender or customer EDR present during install, run and update | No detection, or record what was flagged | | — |
| W17 | Footprint | Record EXE size, idle RAM, CPU over 1 h | | — |
| W18 | ARM64 PC | — | | BLOCKED (no ARM64 build in dev releases yet) |

## D: Docker agent

| ID | Test | Expected | CI | Last result |
|---|---|---|---|---|
| D1 | Generated installer in a Proxmox LXC | `docker ps` shows healthy; site green | e2e | — |
| D2 | Reboot the LXC | Container back and healthy | | — |
| D3 | 2.0 install in `/opt/ipfailover-agent`, run the new installer with `--upgrade` | Same identity; old folder and container gone | | — |
| D4 | Releases: upload `dynallow-update-test-docker-*.json`, push | Restarts onto the new version, healthy | e2e | — |
| D5 | Edit `data/current-release.json`, restart | Refuses to start (`VERIFICATION FAILED`); restoring the file brings it back | e2e | — |
| D6 | Delete `data/state.json`, restart | Fails closed (no silent re-enroll); `--reprovision` with a new installer recovers | portable | — |
| D7 | `docker stop` | Stops within a few seconds | | — |

## I: IP and allowlisting (real sites)

| ID | Test | Expected | CI | Last result |
|---|---|---|---|---|
| I1 | The site's public IP really changes (Starlink re-IP, or move the PC to another network) | Authoritative IP, DNS and feed follow within 2 intervals; email if enabled | | — |
| I2 | Agree mode, but the agent's traffic leaves by a different route (VPN on the PC) | IP **held**, alert after the mismatch delay | | — |
| I3 | FreePBX / firewall allowlist built from the DNS name or feed | Phones at the site register; a removed site is dropped | | — |

## Run log

| # | Date | Build | Bed | Tester | Scope | Result | Notes |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-16 | branch `ci-packaging-dev-deploy` (before the first dev release) | Linux sandbox with Docker | Claude | All local gates incl. `--docker` | PASS: 7/7 gates, Docker e2e 25/25, UI 29/29 | No Windows machine: Windows job and all manual cases not run. Packaged server smoke-tested from the tarball. |

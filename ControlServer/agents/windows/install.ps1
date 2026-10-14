#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the IP Failover agent on this PC.

.DESCRIPTION
    The control server's site page hands out this script with the agent and a
    ONE-TIME provisioning profile embedded. Right-click > Run with PowerShell.
    (A plain copy also works: put provisioning.json and the agent scripts in
    the same folder as this file.)

    What it does:
      * Program files -> C:\Program Files\IPFailoverAgent (users can read, not write)
      * Secrets       -> C:\ProgramData\IPFailoverAgent (SYSTEM + Administrators only)
      * Status/log    -> C:\ProgramData\IPFailoverAgent\public (users can read: the tray)
      * Task "IPFailoverAgent": SYSTEM, from boot, whether or not anyone signs in
      * Task "IPFailoverTray":  the status dot, for EVERY user who signs in
      * Removes the old "IPUpdater" version if it's here
      * Deletes the profile (and this installer, which contains it) after use

.PARAMETER Reprovision
    Replace an existing installation's identity with the one in this profile.
#>
[CmdletBinding()]
param([switch]$Reprovision, [string]$ProfilePath)

# IPF-EMBED-BEGIN
$Embedded = $null
# IPF-EMBED-END

$ErrorActionPreference = 'Stop'
function Say([string]$m, [string]$c = 'Gray') { Write-Host $m -ForegroundColor $c }
function Fail([string]$m) { Say "ERROR: $m" Red; Say 'Nothing was changed.' Red; Read-Host 'Press Enter to close' | Out-Null; exit 1 }

# ---- self-elevate (right-click > Run with PowerShell isn't elevated) ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $args2 = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($MyInvocation.MyCommand.Path)`"")
    if ($Reprovision) { $args2 += '-Reprovision' }
    if ($ProfilePath) { $args2 += @('-ProfilePath', "`"$ProfilePath`"") }
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList $args2 } catch { Fail 'Administrator rights are needed to install.' }
    exit 0
}

Say ''
Say '  IP Failover agent installer' Cyan
Say ''

# ---- prerequisites that ship with Windows; just make sure ----
$rel = 0
try { $rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release } catch { }
if ($rel -lt 460798) {
    Fail '.NET Framework 4.7 or newer is required (Windows 10 1709+ and Server 2019+ already have it). Install .NET Framework 4.8 from Windows Update, then run this again.'
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$prog = Join-Path $env:ProgramFiles 'IPFailoverAgent'
$data = Join-Path $env:ProgramData 'IPFailoverAgent'
$pub  = Join-Path $data 'public'
$scripts = 'run-agent.ps1', 'ip-agent.ps1', 'ip-agent-tray.ps1', 'uninstall.ps1'

# ---- collect files: embedded, or beside this script ----
$files = @{}
$profileSource = $null
if ($Embedded) {
    foreach ($k in $Embedded.Keys) { $files[$k] = [Convert]::FromBase64String($Embedded[$k]) }
} else {
    foreach ($s in $scripts) {
        $p = Join-Path $here $s
        if (-not (Test-Path $p)) { Fail "$s is missing next to the installer." }
        $files[$s] = [IO.File]::ReadAllBytes($p)
    }
    if (-not $ProfilePath) { $ProfilePath = Join-Path $here 'provisioning.json' }
    if (Test-Path $ProfilePath) { $files['provisioning.json'] = [IO.File]::ReadAllBytes($ProfilePath); $profileSource = $ProfilePath }
}
if (-not $files.ContainsKey('provisioning.json')) { Fail 'No provisioning profile. Download the installer from the site''s page on the control server.' }
try { $prof = [Text.Encoding]::UTF8.GetString($files['provisioning.json']) | ConvertFrom-Json } catch { Fail 'The provisioning profile is damaged.' }
if ($prof.format -ne 'ipfailover-provisioning') { Fail 'That file is not an IP Failover provisioning profile.' }
if ($prof.expires_at -and ([DateTimeOffset]::Parse($prof.expires_at) -lt [DateTimeOffset]::UtcNow)) {
    Fail "This profile expired on $($prof.expires_at). Download a new installer from the site's page."
}
foreach ($s in $scripts) {
    $tmp = [IO.Path]::GetTempFileName()
    [IO.File]::WriteAllBytes($tmp, $files[$s])
    $e = $null; $t = $null
    [void][Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$t, [ref]$e)
    Remove-Item -Force $tmp
    if ($e.Count) { Fail "$s is damaged (it does not parse)." }
}
Say "Site:    $($prof.site_name)  ($($prof.agent_uid))"
Say "Server:  $($prof.control_url)"

# ---- never silently re-point an enrolled agent ----
$state = Join-Path $data 'state.json'
if (Test-Path $state) {
    $st = Get-Content -Raw $state | ConvertFrom-Json
    if ($st.enrolled -and -not $Reprovision) {
        Fail "This PC is already set up as $($st.site_name) ($($st.agent_uid)). To replace that identity, run the installer again with -Reprovision."
    }
}

# ---- remove the old IPUpdater version (pre-2.0) ----
foreach ($t in 'IPUpdater', 'IPUpdaterTray') {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $t -Confirm:$false; Say "Removed old task $t" Yellow
    }
}
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -match 'ip-updater' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if ((Test-Path 'C:\IPUpdater\ip-updater.ps1')) {
    Remove-Item -Recurse -Force 'C:\IPUpdater' -ErrorAction SilentlyContinue; Say 'Removed old C:\IPUpdater folder (it held a DNS API token in plain text)' Yellow
}

# ---- stop a running copy ----
foreach ($t in 'IPFailoverAgent', 'IPFailoverTray') {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue }
}
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -match 'ip-agent|run-agent' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# ---- folders + permissions (by SID, so non-English Windows works) ----
foreach ($d in $prog, $data, $pub) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
# Secrets: SYSTEM + Administrators only, nothing inherited from ProgramData (which lets Users create files).
& icacls.exe $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /Q | Out-Null
# Status + log: also readable by every user, for the tray.
& icacls.exe $pub /grant '*S-1-5-32-545:(OI)(CI)RX' /T /Q | Out-Null
# Program files: same lockdown so no user can swap a script that SYSTEM runs.
& icacls.exe $prog /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /Q | Out-Null

if ($Reprovision) {
    foreach ($f in 'agent-key.json', 'master.key', 'state.json') {
        $p = Join-Path $data $f
        if (Test-Path $p) { $len = (Get-Item $p).Length; if ($len) { [IO.File]::WriteAllBytes($p, (New-Object byte[] $len)) }; Remove-Item -Force $p }
    }
    Say 'Old identity destroyed (re-provision).' Yellow
}

foreach ($s in $scripts) { [IO.File]::WriteAllBytes((Join-Path $prog $s), $files[$s]) }
[IO.File]::WriteAllBytes((Join-Path $data 'provisioning.json'), $files['provisioning.json'])
Say 'Files installed.'

# ---- scheduled tasks ----
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$act = New-ScheduledTaskAction -Execute $ps -WorkingDirectory $prog `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$prog\run-agent.ps1`""
$boot = New-ScheduledTaskTrigger -AtStartup
# A safety net: if the agent ever dies, this brings it back within 5 minutes.
$rep = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$sys = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'IPFailoverAgent' -Action $act -Trigger @($boot, $rep) -Settings $set -Principal $sys -Force `
    -Description 'IP Failover agent: reports this site''s public IP to the control server. Runs as SYSTEM from boot.' | Out-Null

$tact = New-ScheduledTaskAction -Execute $ps -WorkingDirectory $prog `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Sta -File `"$prog\ip-agent-tray.ps1`""
$users = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value
$tprin = New-ScheduledTaskPrincipal -GroupId $users -RunLevel Limited
$tset = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel
Register-ScheduledTask -TaskName 'IPFailoverTray' -Action $tact -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Settings $tset -Principal $tprin -Force `
    -Description 'IP Failover status dot for every user who signs in.' | Out-Null
Say 'Scheduled tasks created (agent from boot as SYSTEM; tray for every user).'

Start-ScheduledTask -TaskName 'IPFailoverAgent'
Start-ScheduledTask -TaskName 'IPFailoverTray' -ErrorAction SilentlyContinue

# ---- destroy the credential copies ----
function Remove-Credential([string]$p) {
    try { $len = (Get-Item -LiteralPath $p).Length; if ($len) { [IO.File]::WriteAllBytes($p, (New-Object byte[] $len)) }; Remove-Item -Force -LiteralPath $p } catch { Say "Could not delete $p - delete it by hand (it contains a one-time credential)." Yellow }
}
if ($profileSource) { Remove-Credential $profileSource }
if ($Embedded) { Remove-Credential $MyInvocation.MyCommand.Path; Say 'This installer contained a one-time credential and has deleted itself.' }

# ---- wait for the first check-in ----
Say ''
Say 'Waiting for the first check-in (up to 90 seconds)...'
$statusFile = Join-Path $pub 'status.json'
$deadline = (Get-Date).AddSeconds(90)
$s = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-Path $statusFile) {
        try { $s = Get-Content -Raw $statusFile | ConvertFrom-Json } catch { $s = $null }
        if ($s -and ($s.server_ok -or ($s.server_error -and $s.server_error -notmatch 'cannot reach'))) { break }
    }
}
Say ''
if ($s -and $s.server_ok) {
    Say "  INSTALLED. $($prof.site_name) is checking in." Green
    if ($s.ip.authoritative) { Say "  Verified public IP: $($s.ip.authoritative)" Green } else { Say '  Its IP will show as verified after the next check-in.' }
    Say '  Look for the dot next to the clock (green = all good).'
} elseif ($s) {
    Say "  Installed, but the server said: $($s.server_error)" Yellow
    Say "  Log: $pub\agent.log" Yellow
} else {
    Say '  Installed, but no answer from the server yet. Check that this PC can reach:' Yellow
    Say "    $($prof.control_url)" Yellow
    Say "  Log: $pub\agent.log" Yellow
}
Say ''
Read-Host 'Press Enter to close' | Out-Null

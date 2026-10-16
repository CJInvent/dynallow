#Requires -Version 7.4
#Requires -RunAsAdministrator
# Windows service smoke test. CLEAN, DISPOSABLE Windows machines only (CI runner or throwaway VM):
# it installs, restarts and purges the real DynAllowAgent service and its machine identity.
#   pwsh -File tests\windows-smoke.ps1 -Executable C:\path\DynAllow.Agent.exe
# On failure under GitHub Actions the reason is also written as an ::error annotation, because
# job logs are not always readable but annotations are.
param([Parameter(Mandatory)][string]$Executable)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path $Executable).Path
# The data folder keeps its pre-rename name on purpose: existing identities are reused in place.
$data = Join-Path $env:ProgramData 'IPFailoverAgent'
$legacyProgram = Join-Path $env:ProgramFiles 'IPFailoverAgent'
$passed = 0

function Fail([string]$message) {
    $detail = @()
    $detail += 'service: ' + ((sc.exe query DynAllowAgent 2>&1 | Out-String).Trim() -replace '\s+', ' ')
    if (Test-Path "$data/public/agent.log") { $detail += "agent.log (last 15):`n" + ((Get-Content "$data/public/agent.log" -Tail 15) -join "`n") }
    if (Test-Path "$data/public/status.json") { $detail += 'status.json: ' + (Get-Content -Raw "$data/public/status.json") }
    $text = "$message`n" + ($detail -join "`n")
    if ($env:GITHUB_ACTIONS) { Write-Output ('::error title=Windows smoke::' + ($text -replace '%', '%25' -replace "`r", '' -replace "`n", '%0A')) }
    throw $text
}
function Pass([string]$message) { $script:passed++; Write-Host "PASS: $message" }
function Run([string[]]$arguments) {
    $out = & $Executable @arguments 2>&1 | Out-String
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out.Trim() }
}
function WaitFor([scriptblock]$condition, [int]$seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    while ([DateTime]::UtcNow -lt $deadline) { if (& $condition) { return $true }; Start-Sleep -Milliseconds 500 }
    return $false
}

if ((Test-Path $data) -or (Get-Service DynAllowAgent -ErrorAction SilentlyContinue)) { Fail 'Use a disposable clean Windows machine; an existing agent or its data was found.' }

$env:DYNALLOW_DISPOSABLE_TEST = '1'
$r = Run @('windows-test')
Write-Host $r.Output
if ($r.Code -ne 0) { Fail "Platform tests (DPAPI, legacy identity migration, power request) failed:`n$($r.Output)" }
Pass 'platform tests: DPAPI, legacy identity migration, power request'

# Leftovers of the retired PowerShell agent that the installer must clean up.
New-Item -ItemType Directory -Force $legacyProgram | Out-Null
Set-Content (Join-Path $legacyProgram 'dynallow-agent.ps1') '# retired script that used to run as SYSTEM'
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
Register-ScheduledTask -TaskName 'IPFailoverAgent' -Action $action -User 'SYSTEM' -Force | Out-Null

$profilePath = Join-Path $env:TEMP ('dynallow-profile-' + [Guid]::NewGuid().ToString('N') + '.json')
$key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$p = $key.ExportParameters($false); $raw = [byte[]](@(4) + $p.Q.X + $p.Q.Y)
@{ format = 'dynallow-provisioning'; control_url = 'http://127.0.0.1:9'; server_key_id = 'test'; server_key = [Convert]::ToBase64String($raw)
   enroll_token = 'disposable-test-token'; agent_uid = 'agt_smoketest01'; site_name = 'Disposable smoke test' } | ConvertTo-Json | Set-Content $profilePath
try {
    $r = Run @('install', '--profile', $profilePath, '--no-tray')
    Write-Host $r.Output
    if ($r.Code -ne 0) { Fail "install failed:`n$($r.Output)" }
    Pass 'install succeeds'
    if (Test-Path $profilePath) { Fail 'installer left the transferred provisioning profile behind' }
    Pass 'installer deleted the transferred profile'
    if (Test-Path $legacyProgram) { Fail "installer left the retired agent's scripts in $legacyProgram" }
    if (Get-ScheduledTask -TaskName 'IPFailoverAgent' -ErrorAction SilentlyContinue) { Fail 'installer left the retired IPFailoverAgent scheduled task' }
    Pass 'retired PowerShell agent folder and task removed'

    if (-not (WaitFor { Test-Path "$data/startup.json" } 60)) { Fail 'service did not initialize within 60 seconds (no startup.json)' }
    Pass 'service initialized'
    if ((Test-Path "$data/provisioning.json") -or -not (Test-Path "$data/state.json")) { Fail 'service did not consume the provisioning profile into state.json' }
    Pass 'service consumed the provisioning profile'
    if ((Get-Service DynAllowAgent).Status -ne 'Running') { Fail 'service is not running' }
    if ((Get-CimInstance Win32_Service -Filter "Name='DynAllowAgent'").StartMode -ne 'Auto') { Fail 'service is not set to start at boot' }
    Pass 'service running, starts at boot'

    $users = 'BUILTIN\Users'
    if ((Get-Acl $data).Access | Where-Object { $_.IdentityReference.Value -eq $users }) { Fail 'standard users have access to the protected identity folder' }
    if (-not ((Get-Acl "$data/public").Access | Where-Object { $_.IdentityReference.Value -eq $users })) { Fail 'standard users cannot read the public status folder' }
    Pass 'identity folder closed to standard users; public status readable'

    if (-not (WaitFor { Test-Path "$data/public/status.json" } 60)) { Fail 'first check-in cycle never wrote status.json' }
    $r = Run @('status'); if ($r.Code -ne 0 -or $r.Output -notmatch 'agt_smoketest01') { Fail "status command failed:`n$($r.Output)" }
    Pass 'first cycle ran; status command reports the site'

    $before = (Get-Content "$data/public/agent.log").Count
    $r = Run @('check'); if ($r.Code -ne 0) { Fail "check-now could not signal the service:`n$($r.Output)" }
    if (-not (WaitFor { (Get-Content "$data/public/agent.log").Count -gt $before } 30)) { Fail 'check-now was signalled but the service ran no cycle' }
    Pass 'check-now wakes the service for an immediate cycle'

    $started = (Get-Item "$data/startup.json").LastWriteTimeUtc
    Restart-Service DynAllowAgent
    if (-not (WaitFor { (Test-Path "$data/startup.json") -and (Get-Item "$data/startup.json").LastWriteTimeUtc -gt $started } 60)) { Fail 'service did not re-initialize after a restart' }
    if ((Get-Service DynAllowAgent).Status -ne 'Running') { Fail 'service did not come back after a restart' }
    Pass 'service restarts cleanly'
} finally {
    $u = Run @('uninstall', '--purge')
    Write-Host $u.Output
    $key.Dispose()
    Remove-Item $profilePath -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:ProgramFiles 'DynAllow') -Recurse -Force -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'IPFailoverAgent' -Confirm:$false -ErrorAction SilentlyContinue
}
if (Get-Service DynAllowAgent -ErrorAction SilentlyContinue) { Fail 'uninstall left the service registered' }
if (Test-Path $data) { Fail 'uninstall --purge left the identity folder' }
Pass 'uninstall --purge removes service and identity'
Write-Host "ALL WINDOWS SMOKE TESTS PASSED ($passed)"

#Requires -Version 7.4
#Requires -RunAsAdministrator
param([Parameter(Mandatory)][string]$Executable)
$ErrorActionPreference='Stop'
$data=Join-Path $env:ProgramData 'IPFailoverAgent'
if ((Test-Path $data) -or (Get-Service DynAllowAgent -ErrorAction SilentlyContinue)) { throw 'Use a disposable clean Windows VM; existing agent/data detected.' }
$env:DYNALLOW_DISPOSABLE_TEST='1'
& $Executable windows-test
if ($LASTEXITCODE -ne 0) { throw 'Windows platform tests failed' }
$profile=Join-Path $env:TEMP ('dynallow-profile-'+[Guid]::NewGuid().ToString('N')+'.json')
$key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$p=$key.ExportParameters($false);$raw=[byte[]](@(4)+$p.Q.X+$p.Q.Y)
@{format='ipfailover-provisioning';control_url='http://127.0.0.1:9';server_key_id='test';server_key=[Convert]::ToBase64String($raw);enroll_token='disposable-test-token';agent_uid='agt_smoketest01';site_name='Disposable smoke test'} | ConvertTo-Json | Set-Content $profile
try {
    & $Executable install --profile $profile --no-tray
    if ($LASTEXITCODE -ne 0) { throw 'Install failed' }
    $deadline=[DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path "$data/startup.json") -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path "$data/startup.json")) { throw 'Service did not initialize' }
    if ((Get-Service DynAllowAgent).Status -ne 'Running') { throw 'Service not running' }
    & $Executable check
    if ($LASTEXITCODE -ne 0) { throw 'Check-now event failed' }
    Restart-Service DynAllowAgent
    if ((Get-Service DynAllowAgent).Status -ne 'Running') { throw 'Service did not restart' }
    Write-Host 'PASS: install, boot configuration, identity initialization, check-now event, restart'
} finally {
    & $Executable uninstall --purge
    $key.Dispose()
    Remove-Item $profile -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:ProgramFiles 'DynAllow') -Recurse -Force -ErrorAction SilentlyContinue
}

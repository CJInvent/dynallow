#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the IP Failover agent from this PC: scheduled tasks, tray icons,
    the TPM key, the identity key and all program/data folders.
    Then delete (or decommission) the site on the control server too.
#>
$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this as administrator (right-click > Run with PowerShell, or an admin PowerShell window).' -ForegroundColor Red; exit 1 }

$prog = Join-Path $env:ProgramFiles 'IPFailoverAgent'
$data = Join-Path $env:ProgramData 'IPFailoverAgent'

foreach ($t in 'IPFailoverAgent', 'IPFailoverTray') {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $t -Confirm:$false
        Write-Host "Removed scheduled task $t"
    }
}
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -match 'ip-agent|run-agent' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

try {
    $prov = New-Object Security.Cryptography.CngProvider 'Microsoft Platform Crypto Provider'
    if ([Security.Cryptography.CngKey]::Exists('IPFailoverAgentMasterKey', $prov, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
        [Security.Cryptography.CngKey]::Open('IPFailoverAgentMasterKey', $prov, [Security.Cryptography.CngKeyOpenOptions]::MachineKey).Delete()
        Write-Host 'Deleted the TPM key'
    }
} catch { }

foreach ($f in 'agent-key.json', 'master.key', 'state.json', 'provisioning.json') {
    $p = Join-Path $data $f
    if (Test-Path $p) {
        $len = (Get-Item $p).Length
        if ($len) { [IO.File]::WriteAllBytes($p, (New-Object byte[] $len)) }
        Remove-Item -Force $p
    }
}
foreach ($d in $data, $prog) { if (Test-Path $d) { Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue } }
Write-Host ''
Write-Host 'IP Failover agent removed. Tray icons already open disappear at the next sign-in.' -ForegroundColor Green
Write-Host 'Remember to delete (or decommission) this site on the control server.'

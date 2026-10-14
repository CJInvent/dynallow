#Requires -Version 5.1
<#
    Launcher for ip-agent.ps1, run by the "IPFailoverAgent" scheduled task as
    SYSTEM. Deliberately tiny and never self-updated, so a bad update can't
    take down the thing that restarts the agent.

    Exit codes from ip-agent.ps1:  10 = updated itself, restart now
                                   20 = decommissioned, stop for good
                                   anything else = restart after a pause
#>
$ErrorActionPreference = 'Continue'
$agent = Join-Path $PSScriptRoot 'ip-agent.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$pause = 30
while ($true) {
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $agent
    $code = $LASTEXITCODE
    if ($code -eq 20) { exit 0 }
    if ($code -eq 10) { $pause = 30; continue }
    Start-Sleep -Seconds $pause
    $pause = [Math]::Min(600, $pause * 2)   # crash loop: back off up to 10 minutes
}

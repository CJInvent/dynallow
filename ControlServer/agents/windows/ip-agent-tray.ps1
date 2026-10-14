#Requires -Version 5.1
<#
.SYNOPSIS
    Tray dot for the IP Failover agent, for every user who signs in.
      GREEN = checking in, IP verified, every DNS name up to date
      RED   = something is broken (server unreachable, DNS failing, IP held)
      GREY  = waiting, paused, not set up yet, or no recent status
    Right-click for details, "Check now" and the log.

    Reads C:\ProgramData\IPFailoverAgent\public\status.json (readable by all
    users; contains no secrets). Built-in WinForms only.
#>
[CmdletBinding()]
param([string]$DataDir = (Join-Path $env:ProgramData 'IPFailoverAgent'))
$ErrorActionPreference = 'Continue'

# One dot per logon session (Local\), so RDP / fast user switching each get theirs.
$mutex = New-Object Threading.Mutex($false, 'Local\IPFailoverTray')
try { $owned = $mutex.WaitOne(0, $false) } catch [Threading.AbandonedMutexException] { $owned = $true }
if (-not $owned) { exit 0 }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$StatusFile = Join-Path $DataDir 'public\status.json'
$LogFile    = Join-Path $DataDir 'public\agent.log'

function New-Dot([Drawing.Color]$c) {
    $bmp = New-Object Drawing.Bitmap 16, 16
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.FillEllipse((New-Object Drawing.SolidBrush $c), 2, 2, 12, 12)
    $g.DrawEllipse((New-Object Drawing.Pen ([Drawing.Color]::FromArgb(70, 0, 0, 0)), 1), 2, 2, 12, 12)
    $g.Dispose()
    $icon = [Drawing.Icon]::FromHandle($bmp.GetHicon())
    return $icon
}
$Icons = @{ green = (New-Dot ([Drawing.Color]::FromArgb(46, 170, 90))); red = (New-Dot ([Drawing.Color]::FromArgb(220, 60, 50))); grey = (New-Dot ([Drawing.Color]::FromArgb(150, 160, 165))) }

function Get-Ago([long]$ts) {
    if (-not $ts) { return 'never' }
    $s = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $ts
    if ($s -lt 90) { return "$s s ago" }
    if ($s -lt 5400) { return ('{0} min ago' -f [int]($s / 60)) }
    return ('{0:0.0} h ago' -f ($s / 3600))
}

# Returns @(color, tooltip, lines[])
function Get-View {
    if (-not (Test-Path $StatusFile)) { return @('grey', 'IP Failover - not set up yet', @('No status yet. Is the agent installed?')) }
    try { $s = Get-Content -Raw -LiteralPath $StatusFile | ConvertFrom-Json } catch { return @('grey', 'IP Failover - status unreadable', @('Status file could not be read.')) }
    $lines = New-Object Collections.ArrayList
    $site = if ($s.site) { $s.site } else { 'IP Failover' }
    if ($s.decommissioned) { return @('grey', "$site - decommissioned", @('This agent was decommissioned by the control server.')) }

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $interval = [Math]::Max(60, [int]$s.interval)
    $red = $false; $grey = $false
    $fresh = $s.updated_at -and ($now - [long]$s.updated_at) -lt (3 * $interval + 120)
    if (-not $fresh) { $grey = $true; [void]$lines.Add('Agent: NOT RUNNING (no status for ' + (Get-Ago ([long]$s.updated_at)) + ')') }

    if ($s.server_ok) {
        [void]$lines.Add('Control server: OK, checked in ' + (Get-Ago ([long]$s.last_success_at)))
    } elseif ($s.last_success_at) {
        if (($now - [long]$s.last_success_at) -gt (2 * $interval + 60)) { $red = $true }
        [void]$lines.Add('Control server: FAILING - ' + $s.server_error)
    } else {
        $grey = $true
        [void]$lines.Add('Control server: not reached yet - ' + $s.server_error)
    }
    if ($s.enabled -eq $false) { $grey = $true; [void]$lines.Add('Site is DISABLED on the control server') }

    if ($s.ip) {
        $ipl = 'Public IP: ' + $(if ($s.ip.authoritative) { $s.ip.authoritative } else { 'not verified yet' })
        if ($s.ip.source) { $ipl += " ($($s.ip.source))" }
        [void]$lines.Add($ipl)
        if ($s.ip.mismatch) { $red = $true; [void]$lines.Add('IP HELD: ' + $s.ip.detail) }
        if ($s.ip.pending -and $s.ip.trust_mode -eq 'manual') { $grey = $true; [void]$lines.Add("New IP $($s.ip.pending) waiting for approval") }
    }
    foreach ($t in @($s.targets)) {
        if (-not $t) { continue }
        switch ($t.state) { 'ok' { $w = 'OK' } 'fault' { $w = 'FAILING'; $red = $true } 'pending' { $w = 'updating'; $grey = $true } default { $w = $t.state } }
        [void]$lines.Add("DNS $($t.hostname): $w")
    }
    if (@($s.targets).Count -eq 0 -and $s.server_ok) { [void]$lines.Add('DNS: none (IP tracked only)') }
    $kp = @{ tpm = 'TPM'; dpapi = 'DPAPI (no TPM)'; plaintext = 'PLAINTEXT - no TPM or DPAPI' }[[string]$s.key_protector]
    if ($kp) { [void]$lines.Add("Key storage: $kp") }

    $color = 'green'
    if ($red) { $color = 'red' } elseif ($grey) { $color = 'grey' }
    $tip = "$site - " + @{ green = 'OK'; red = 'PROBLEM'; grey = 'waiting' }[$color]
    if ($s.ip -and $s.ip.authoritative) { $tip += " - $($s.ip.authoritative)" }
    if ($tip.Length -gt 63) { $tip = $tip.Substring(0, 63) }
    return @($color, $tip, $lines.ToArray())
}

$notify = New-Object Windows.Forms.NotifyIcon
$notify.Icon = $Icons.grey
$notify.Visible = $true
$menu = New-Object Windows.Forms.ContextMenuStrip
$notify.ContextMenuStrip = $menu
$script:last = ''

function Update-Tray {
    $v = Get-View
    $notify.Icon = $Icons[$v[0]]
    $notify.Text = $v[1]
    $menu.Items.Clear()
    $h = $menu.Items.Add('IP Failover'); $h.Enabled = $false; $h.Font = New-Object Drawing.Font($h.Font, [Drawing.FontStyle]::Bold)
    [void]$menu.Items.Add('-')
    foreach ($l in $v[2]) { $i = $menu.Items.Add($l); $i.Enabled = $false }
    [void]$menu.Items.Add('-')
    $now = $menu.Items.Add('Check now')
    $now.add_Click({
        try {
            $ev = [Threading.EventWaitHandle]::OpenExisting('Global\IPFailoverAgentCheckNow', [Security.AccessControl.EventWaitHandleRights]'Modify, Synchronize')
            [void]$ev.Set()
            $notify.ShowBalloonTip(3000, 'IP Failover', 'Checking in now. This dot updates in a few seconds.', 'Info')
        } catch {
            $notify.ShowBalloonTip(4000, 'IP Failover', 'The agent is not running, so it can''t check in right now.', 'Warning')
        }
    })
    $log = $menu.Items.Add('Open log')
    $log.add_Click({ if (Test-Path $LogFile) { Start-Process notepad.exe -ArgumentList "`"$LogFile`"" } })
    [void]$menu.Items.Add('-')
    $x = $menu.Items.Add('Hide this icon until next sign-in')
    $x.add_Click({ $notify.Visible = $false; [Windows.Forms.Application]::Exit() })

    if ($v[0] -eq 'red' -and $script:last -ne 'red' -and $script:last -ne '') {
        $notify.ShowBalloonTip(6000, 'IP Failover - problem', (($v[2] | Select-Object -First 3) -join "`n"), 'Error')
    }
    $script:last = $v[0]
}

Update-Tray
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 10000
$timer.add_Tick({ Update-Tray })
$timer.Start()
[Windows.Forms.Application]::Run()
$timer.Stop(); $notify.Dispose(); $mutex.ReleaseMutex()

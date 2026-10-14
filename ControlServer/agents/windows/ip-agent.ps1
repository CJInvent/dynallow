#Requires -Version 5.1
<#
.SYNOPSIS
    IP Failover agent for Windows. Runs as SYSTEM under run-agent.ps1.

.DESCRIPTION
    Deliberately small. It holds NO DNS credentials and talks to NO DNS
    provider. It proves who it is (P-256 signature), reports the address it
    sees, and follows the AUTHENTICATED answer from the control server. The
    server does the DNS work.

    Every request is encrypted to the server key pinned in the provisioning
    profile; every response is authenticated before it's obeyed. Plain HTTP
    is therefore safe; HTTPS is defense in depth.

    Key custody (same topology as NimbusBackupClient):
      random 256-bit DEK seals the identity private key (AES-256-CBC + HMAC-SHA256)
      DEK wrapped by: TPM (Platform Crypto Provider, RSA-2048 machine key,
      OAEP-SHA256, round-trip proven) -> DPAPI machine scope -> plaintext (loud)
      and re-wrapped under a stronger protector whenever one becomes available.

    Requirements: Windows PowerShell 5.1 + .NET Framework 4.7 or newer (all
    supported Windows 10/11/Server 2019+ have both built in).

.PARAMETER Once
    Run one check-in and exit (for testing).
#>
[CmdletBinding()]
param(
    [string]$DataDir = (Join-Path $env:ProgramData 'IPFailoverAgent'),
    [switch]$Once
)

$ErrorActionPreference = 'Stop'
$AGENT_VERSION = '2.0.0'

$script:OnWindows = $true
if (Test-Path variable:global:IsWindows) { $script:OnWindows = [bool]$global:IsWindows }

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
if ($script:OnWindows) { Add-Type -AssemblyName System.Security }

$PublicDir   = Join-Path $DataDir 'public'
$StatePath   = Join-Path $DataDir 'state.json'
$KeyPath     = Join-Path $DataDir 'agent-key.json'
$MasterPath  = Join-Path $DataDir 'master.key'
$ProfilePath = Join-Path $DataDir 'provisioning.json'
$StatusPath  = Join-Path $PublicDir 'status.json'
$LogPath     = Join-Path $PublicDir 'agent.log'
$InstallDir  = Split-Path -Parent $MyInvocation.MyCommand.Path

$TpmKeyName  = 'IPFailoverAgentMasterKey'
$EventName   = 'Global\IPFailoverAgentCheckNow'
$Utf8        = New-Object System.Text.UTF8Encoding($false)

# ============================================================================
# Small helpers
# ============================================================================

function Write-Log([string]$Level, [string]$Msg) {
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Msg
    Write-Host $line
    try {
        if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 1MB) {
            Move-Item -Force $LogPath "$LogPath.1"
        }
        [IO.File]::AppendAllText($LogPath, $line + "`r`n", $Utf8)
    } catch { }
}

function Get-Bytes([string]$s) { return $Utf8.GetBytes($s) }

function Join-Bytes {
    $ms = New-Object IO.MemoryStream
    foreach ($a in $args) {
        if ($null -eq $a) { continue }
        if ($a -is [string]) { $a = Get-Bytes $a }
        $ms.Write([byte[]]$a, 0, $a.Length)
    }
    return , $ms.ToArray()
}

function Get-RandomBytes([int]$n) {
    $b = New-Object byte[] $n
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($b)
    return , $b
}

function ConvertTo-Hex([byte[]]$b) { return (($b | ForEach-Object { $_.ToString('x2') }) -join '') }

function Get-Sha256([byte[]]$b) {
    $h = [Security.Cryptography.SHA256]::Create()
    return , $h.ComputeHash($b)
}

function Get-Hmac([byte[]]$key, [byte[]]$data) {
    $h = New-Object Security.Cryptography.HMACSHA256 (, $key)
    return , $h.ComputeHash($data)
}

function Test-BytesEqual([byte[]]$a, [byte[]]$b) {
    if ($null -eq $a -or $null -eq $b -or $a.Length -ne $b.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ($a[$i] -bxor $b[$i]) }
    return ($d -eq 0)
}

function Read-Json([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return ([IO.File]::ReadAllText($path, $Utf8) | ConvertFrom-Json) } catch { return $null }
}

# Write, flush, read back. A key that only exists in memory dies at the next reboot.
function Write-JsonVerified([string]$path, $obj) {
    $json = $obj | ConvertTo-Json -Depth 8
    $tmp = "$path.tmp"
    $fs = [IO.File]::Open($tmp, 'Create', 'Write', 'None')
    try { $bytes = Get-Bytes $json; $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    Move-Item -Force -LiteralPath $tmp -Destination $path
    if ([IO.File]::ReadAllText($path, $Utf8) -ne $json) { throw "$path did not read back what was written" }
}

function Remove-Securely([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    try {
        $len = (Get-Item -LiteralPath $path).Length
        if ($len -gt 0) {
            $fs = [IO.File]::Open($path, 'Open', 'Write', 'None')
            try { $z = New-Object byte[] $len; $fs.Write($z, 0, $len); $fs.Flush($true) } finally { $fs.Dispose() }
        }
    } catch { }
    try { Remove-Item -Force -LiteralPath $path } catch {
        Write-Log 'WARN' "could not delete $path - it may still contain a credential; delete it by hand"
    }
}

function Get-UnixTime { return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

# ============================================================================
# DEK protector chain (TPM -> DPAPI -> plaintext), with auto-upgrade
# ============================================================================

$ProtectorRank = @{ 'plaintext' = 0; 'dpapi' = 1; 'tpm' = 2 }

function Open-TpmKey([bool]$create) {
    $prov = New-Object Security.Cryptography.CngProvider 'Microsoft Platform Crypto Provider'
    $opt = [Security.Cryptography.CngKeyOpenOptions]::MachineKey
    if ([Security.Cryptography.CngKey]::Exists($TpmKeyName, $prov, $opt)) {
        return [Security.Cryptography.CngKey]::Open($TpmKeyName, $prov, $opt)
    }
    if (-not $create) { throw 'TPM key not present (TPM cleared or replaced?)' }
    $p = New-Object Security.Cryptography.CngKeyCreationParameters
    $p.Provider = $prov
    $p.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $p.Parameters.Add((New-Object Security.Cryptography.CngProperty('Length', [BitConverter]::GetBytes([int]2048), [Security.Cryptography.CngPropertyOptions]::None)))
    return [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $TpmKeyName, $p)
}

function Protect-WithTpm([byte[]]$dek) {
    $rsa = New-Object Security.Cryptography.RSACng (Open-TpmKey $true)
    return , $rsa.Encrypt($dek, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
}

function Unprotect-WithTpm([byte[]]$blob) {
    $rsa = New-Object Security.Cryptography.RSACng (Open-TpmKey $false)
    return , $rsa.Decrypt($blob, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
}

$DpapiEntropy = Get-Bytes 'IPFailoverAgent-DEK-v1'

function Protect-Dek([byte[]]$dek) {
    # TPM first, but only once a full protect -> unprotect round trip proves
    # it: a TPM that encrypts but can't decrypt would strand the key forever.
    if ($script:OnWindows) {
        try {
            $blob = Protect-WithTpm $dek
            $back = Unprotect-WithTpm $blob
            if (Test-BytesEqual $back $dek) { return @{ protector = 'tpm'; blob = $blob } }
            Write-Log 'WARN' 'TPM round-trip check failed - falling back to DPAPI'
        } catch { Write-Log 'INFO' "TPM protector unavailable ($($_.Exception.Message)) - trying DPAPI" }
        try {
            $blob = [Security.Cryptography.ProtectedData]::Protect($dek, $DpapiEntropy, 'LocalMachine')
            return @{ protector = 'dpapi'; blob = $blob }
        } catch { Write-Log 'WARN' "DPAPI unavailable ($($_.Exception.Message))" }
    }
    Write-Log 'WARN' 'WARNING: storing the master key with the PLAINTEXT protector - the identity key is only obfuscated'
    return @{ protector = 'plaintext'; blob = $dek }
}

function Get-Dek {
    if ($script:DekCache) { return , $script:DekCache }
    $mk = Read-Json $MasterPath
    if ($null -eq $mk) {
        $dek = Get-RandomBytes 32
        $w = Protect-Dek $dek
        Write-JsonVerified $MasterPath ([ordered]@{ protector = $w.protector; blob = [Convert]::ToBase64String($w.blob) })
        Write-Log 'INFO' "master key created under the $($w.protector) protector"
        $script:DekProtector = $w.protector
        $script:DekCache = $dek
        return , $dek
    }
    $blob = [Convert]::FromBase64String($mk.blob)
    switch ($mk.protector) {
        'tpm'       { $dek = Unprotect-WithTpm $blob }
        'dpapi'     { $dek = [Security.Cryptography.ProtectedData]::Unprotect($blob, $DpapiEntropy, 'LocalMachine') }
        'plaintext' { $dek = $blob }
        default     { throw "unknown master key protector '$($mk.protector)'" }
    }
    $script:DekProtector = $mk.protector
    # Upgrade the wrapping (never the DEK) if something stronger works now.
    if ($ProtectorRank[$mk.protector] -lt 2) {
        $w = Protect-Dek $dek
        if ($ProtectorRank[$w.protector] -gt $ProtectorRank[$mk.protector]) {
            try {
                Write-JsonVerified $MasterPath ([ordered]@{ protector = $w.protector; blob = [Convert]::ToBase64String($w.blob) })
                Write-Log 'INFO' "master key protector upgraded: $($mk.protector) -> $($w.protector)"
                $script:DekProtector = $w.protector
            } catch { Write-Log 'WARN' "protector upgrade not saved: $($_.Exception.Message)" }
        }
    }
    $script:DekCache = $dek
    return , $dek
}

function Protect-WithDek([byte[]]$plain) {
    $dek = Get-Dek
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = Get-Hmac $dek (Get-Bytes 'seal-enc'); $aes.IV = Get-RandomBytes 16
    $ct = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)
    $mac = Get-Hmac (Get-Hmac $dek (Get-Bytes 'seal-mac')) (Join-Bytes $aes.IV $ct)
    return 'sv1:' + [Convert]::ToBase64String((Join-Bytes $aes.IV $ct $mac))
}

function Unprotect-WithDek([string]$sealed) {
    # Fails LOUDLY. An identity key that silently comes back empty would make
    # the agent mint a new identity the server has never heard of.
    if (-not $sealed.StartsWith('sv1:')) { throw 'stored key has an unknown format' }
    $raw = [Convert]::FromBase64String($sealed.Substring(4))
    $dek = Get-Dek
    $iv = $raw[0..15]; $ct = $raw[16..($raw.Length - 33)]; $mac = $raw[($raw.Length - 32)..($raw.Length - 1)]
    $expect = Get-Hmac (Get-Hmac $dek (Get-Bytes 'seal-mac')) (Join-Bytes ([byte[]]$iv) ([byte[]]$ct))
    if (-not (Test-BytesEqual $expect ([byte[]]$mac))) { throw 'stored key failed its integrity check (wrong machine, or the file was altered)' }
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = Get-Hmac $dek (Get-Bytes 'seal-enc'); $aes.IV = [byte[]]$iv
    return , $aes.CreateDecryptor().TransformFinalBlock([byte[]]$ct, 0, $ct.Length)
}

# ============================================================================
# P-256 identity keys (two slots: active + pending rotation)
# ============================================================================

function New-P256Params([byte[]]$raw, [byte[]]$d) {
    $q = New-Object Security.Cryptography.ECPoint
    $q.X = [byte[]]$raw[1..32]; $q.Y = [byte[]]$raw[33..64]
    $p = New-Object Security.Cryptography.ECParameters
    $p.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $p.Q = $q
    if ($d) { $p.D = $d }
    return $p
}

function Get-RawPublic($params) { return , (Join-Bytes ([byte[]]@(4)) $params.Q.X $params.Q.Y) }

function New-KeyRecord {
    $ec = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $p = $ec.ExportParameters($true)
    $raw = Get-RawPublic $p
    return [ordered]@{
        key_id     = (ConvertTo-Hex (Get-Sha256 $raw)).Substring(0, 16)
        public     = [Convert]::ToBase64String($raw)
        protector  = $null   # filled after sealing, from what actually sealed it
        sealed     = (Protect-WithDek $p.D)
        created_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Get-Signer($rec) {
    $raw = [Convert]::FromBase64String($rec.public)
    $ec = [Security.Cryptography.ECDsa]::Create()
    $ec.ImportParameters((New-P256Params $raw (Unprotect-WithDek $rec.sealed)))
    return $ec
}

function Test-KeyPair($rec) {
    $probe = Get-RandomBytes 32
    $sig = (Get-Signer $rec).SignData($probe, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $pub = [Security.Cryptography.ECDsa]::Create()
    $pub.ImportParameters((New-P256Params ([Convert]::FromBase64String($rec.public)) $null))
    if (-not $pub.VerifyData($probe, $sig, [Security.Cryptography.HashAlgorithmName]::SHA256)) {
        throw "stored key $($rec.key_id) does not verify against its own public half"
    }
}

function Save-Keys($keys) {
    Write-JsonVerified $KeyPath $keys
    $back = Read-Json $KeyPath
    foreach ($slot in 'active', 'pending') {
        if ($keys[$slot]) {
            if ($back.$slot.public -ne $keys[$slot].public) { throw "$slot key did not read back" }
            Test-KeyPair $back.$slot
        }
    }
}

function Get-Keys {
    $k = Read-Json $KeyPath
    $h = [ordered]@{}
    if ($k) {
        foreach ($slot in 'active', 'pending') { if ($k.$slot) { $h[$slot] = $k.$slot } }
    }
    return $h
}

# ============================================================================
# IPF1 envelope (must match the control server's src/wire.php)
# ============================================================================

function New-Request($state, [hashtable]$plain, $signerRec) {
    $serverRaw = [Convert]::FromBase64String($state.server_key)
    $eph = [Security.Cryptography.ECDiffieHellman]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $epk = Get-RawPublic ($eph.ExportParameters($false))
    $peer = [Security.Cryptography.ECDiffieHellman]::Create()
    $peer.ImportParameters((New-P256Params $serverRaw $null))
    # K = SHA256("IPF1" || Z || epk)
    $k = $eph.DeriveKeyFromHash($peer.PublicKey, [Security.Cryptography.HashAlgorithmName]::SHA256, (Get-Bytes 'IPF1'), $epk)
    $keys = @{}
    foreach ($l in 'req-enc', 'req-mac', 'resp-enc', 'resp-mac') { $keys[$l] = Get-Hmac $k (Get-Bytes $l) }

    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $keys['req-enc']; $aes.IV = Get-RandomBytes 16
    $pt = Get-Bytes ($plain | ConvertTo-Json -Depth 6 -Compress)
    $ct = $aes.CreateEncryptor().TransformFinalBlock($pt, 0, $pt.Length)
    $kid = [string]$state.server_key_id
    $mac = Get-Hmac $keys['req-mac'] (Join-Bytes 'IPF1|req|' $kid $epk $aes.IV $ct)
    $env = [ordered]@{ v = 1; kid = $kid; epk = [Convert]::ToBase64String($epk); iv = [Convert]::ToBase64String($aes.IV);
                       ct = [Convert]::ToBase64String($ct); mac = [Convert]::ToBase64String($mac) }
    if ($signerRec) {
        $sig = (Get-Signer $signerRec).SignData((Join-Bytes 'IPF1|sig|' $kid $epk $aes.IV $ct $mac), [Security.Cryptography.HashAlgorithmName]::SHA256)
        $env['sig'] = [Convert]::ToBase64String($sig)
    }
    return @{ body = ($env | ConvertTo-Json -Compress); keys = $keys; epk = $epk; nonce = $plain.nonce }
}

function Open-Response($ctx, [string]$body) {
    try { $env = $body | ConvertFrom-Json } catch { $env = $null }
    if ($null -eq $env -or $env.v -ne 1 -or -not $env.ct) {
        $why = if ($env -and $env.error) { "$($env.error): $($env.message)" } else { $body.Substring(0, [Math]::Min(120, $body.Length)) }
        throw "unauthenticated response from server ($why)"
    }
    $iv = [Convert]::FromBase64String($env.iv); $ct = [Convert]::FromBase64String($env.ct); $mac = [Convert]::FromBase64String($env.mac)
    $expect = Get-Hmac $ctx.keys['resp-mac'] (Join-Bytes 'IPF1|resp|' $ctx.epk $iv $ct)
    if (-not (Test-BytesEqual $expect $mac)) { throw 'response failed authentication - ignored (possible tampering in transit)' }
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $ctx.keys['resp-enc']; $aes.IV = $iv
    $resp = $Utf8.GetString($aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)) | ConvertFrom-Json
    if ($resp.req_nonce -ne $ctx.nonce) { throw 'response is not bound to this request - ignored (possible replay)' }
    return $resp
}

function Invoke-Http([string]$method, [string]$url, [string]$body, [int]$timeoutSec) {
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Method = $method; $req.Timeout = $timeoutSec * 1000; $req.ReadWriteTimeout = $timeoutSec * 1000
    $req.AllowAutoRedirect = $false; $req.UserAgent = "ipfailover-agent/$AGENT_VERSION"
    if ($body) {
        $b = Get-Bytes $body
        $req.ContentType = 'application/json'; $req.ContentLength = $b.Length
        $s = $req.GetRequestStream(); $s.Write($b, 0, $b.Length); $s.Close()
    }
    try { $resp = $req.GetResponse() }
    catch [Net.WebException] {
        if ($_.Exception.Response) { $resp = $_.Exception.Response } else { throw "cannot reach $url : $($_.Exception.Message)" }
    }
    try { $sr = New-Object IO.StreamReader($resp.GetResponseStream(), $Utf8); return $sr.ReadToEnd() } finally { $resp.Close() }
}

function Invoke-Agent($state, [hashtable]$plain, $signerRec, [string]$nonce) {
    $plain['ts'] = (Get-UnixTime) + [int]$state.clock_offset
    if ($nonce) { $plain['nonce'] = $nonce } else { $plain['nonce'] = ConvertTo-Hex (Get-RandomBytes 16) }
    $ctx = New-Request $state $plain $signerRec
    $resp = Open-Response $ctx (Invoke-Http 'POST' ($state.control_url.TrimEnd('/') + '/api/v1.php') $ctx.body 30)
    if ($resp.server_ts) { $state.clock_offset = [int]$resp.server_ts - (Get-UnixTime) }  # authenticated, so trusted
    if ($resp.server_key -and $resp.server_key.public_key -and ([Convert]::FromBase64String($resp.server_key.public_key)).Length -eq 65) {
        $state.server_key_id = $resp.server_key.kid; $state.server_key = $resp.server_key.public_key
        Write-Log 'INFO' "server key rotated; now pinned to $($state.server_key_id)"
    }
    return $resp
}

# ============================================================================
# Provisioning, state, status
# ============================================================================

function Get-MachineId {
    try {
        if ($script:OnWindows) {
            $g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
            return 'win:' + (ConvertTo-Hex (Get-Sha256 (Get-Bytes $g)))
        }
        return 'linux:' + (ConvertTo-Hex (Get-Sha256 (Get-Bytes ((Get-Content /etc/machine-id -Raw).Trim()))))
    } catch { return '' }
}

function Use-Profile($state) {
    if (-not (Test-Path -LiteralPath $ProfilePath)) { return $state }
    $p = Read-Json $ProfilePath
    Remove-Securely $ProfilePath   # consumed whether or not it applies: it is a live credential
    if ($null -eq $p -or $p.format -ne 'ipfailover-provisioning' -or -not $p.enroll_token) {
        Write-Log 'ERROR' 'provisioning.json is not a valid IP Failover profile; ignored and deleted'
        return $state
    }
    if ($state -and $state.enrolled) {
        Write-Log 'WARN' "already enrolled as $($state.agent_uid) - new profile discarded. Run uninstall.ps1 first to re-provision."
        return $state
    }
    if ($p.control_url -notmatch '^https?://' -or ([Convert]::FromBase64String($p.server_key)).Length -ne 65) {
        Write-Log 'ERROR' 'profile has an invalid URL or server key; ignored'
        return $state
    }
    Write-Log 'INFO' "provisioning profile for $($p.site_name) ($($p.agent_uid)) applied and destroyed"
    return [pscustomobject][ordered]@{
        control_url = $p.control_url; server_key_id = $p.server_key_id; server_key = $p.server_key
        agent_uid = $p.agent_uid; site_name = $p.site_name; enroll_token = $p.enroll_token
        enrolled = $false; interval = 300; clock_offset = 0; ip_check_urls = @(); rotation_sent = $false
    }
}

function Get-ObservedIp([string[]]$urls, [string]$family) {
    foreach ($u in $urls) {
        try {
            $ip = (Invoke-Http 'GET' $u $null 8).Trim()
            $parsed = $null
            if ([Net.IPAddress]::TryParse($ip, [ref]$parsed) -and $parsed.AddressFamily -eq $family) { return $ip }
        } catch { }
    }
    return $null
}

function Write-Status([hashtable]$s) {
    $s['updated_at'] = Get-UnixTime
    $s['version'] = $AGENT_VERSION
    try { Write-JsonVerified $StatusPath $s } catch { Write-Log 'WARN' "status not written: $($_.Exception.Message)" }
}

# ============================================================================
# One check-in
# ============================================================================

function Invoke-Cycle($state) {
    $keys = Get-Keys
    if (-not $keys['active'] -and -not $keys['pending']) {
        $rec = New-KeyRecord; $rec.protector = $script:DekProtector
        $keys['active'] = $rec
        Save-Keys $keys
        Write-Log 'INFO' "identity key $($rec.key_id) created under the $($rec.protector) protector (written, flushed, read back, pair verified)"
    }
    $null = Get-Dek  # sets $script:DekProtector (and upgrades it if possible)

    $urls = @($state.ip_check_urls)
    if ($urls.Count -eq 0 -or -not $urls[0]) { $urls = @('https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://v4.ident.me') }
    $base = @{
        agent = $state.agent_uid; observed_ipv4 = (Get-ObservedIp $urls 'InterNetwork')
        observed_ipv6 = (Get-ObservedIp @('https://api6.ipify.org') 'InterNetworkV6')
        version = $AGENT_VERSION; platform = 'windows'; os = [Environment]::OSVersion.VersionString
        hostname = [Environment]::MachineName; key_protector = $script:DekProtector; machine_id = (Get-MachineId)
    }

    if (-not $state.enrolled) {
        $req = $base.Clone(); $req['type'] = 'enroll'; $req['enroll_token'] = $state.enroll_token; $req['public_key'] = $keys['active'].public
        $resp = Invoke-Agent $state $req $keys['active'] $null
        if ($resp.ok) {
            $state.enrolled = $true
            $state.PSObject.Properties.Remove('enroll_token')   # single use; gone now
            Write-Log 'INFO' "enrolled as $($state.agent_uid)"
        }
    } else {
        $slot = 'active'
        if ($keys['pending'] -and $state.rotation_sent) { $slot = 'pending' }
        $req = $base.Clone(); $req['type'] = 'checkin'
        $resp = Invoke-Agent $state $req $keys[$slot] $null
        if ($resp.error -eq 'bad_signature' -and $slot -eq 'pending') {
            Write-Log 'WARN' 'server did not accept the rotated key; falling back to the current key'
            $state.rotation_sent = $false; $slot = 'active'
            $resp = Invoke-Agent $state $req $keys['active'] $null
        }
        if ($resp.error -eq 'clock_skew') {
            Write-Log 'WARN' 'clock corrected from authenticated server time; retrying'
            $resp = Invoke-Agent $state $req $keys[$slot] $null
        }
        if ($resp.key_promoted -and $keys['pending']) {
            $keys['active'] = $keys['pending']; $keys.Remove('pending'); Save-Keys $keys
            $state.rotation_sent = $false
            Write-Log 'INFO' "key rotation complete: now $($keys['active'].key_id)"
        }
    }
    if (-not $resp.ok) { return $resp }

    $state.interval = [Math]::Max(60, [Math]::Min(86400, [int]$resp.interval))
    $state.ip_check_urls = @($resp.ip_check_urls | Where-Object { $_ -match '^https?://' })

    if ($resp.rotate_key -and -not $keys['pending']) {
        $rec = New-KeyRecord; $rec.protector = $script:DekProtector
        $keys['pending'] = $rec; Save-Keys $keys
        $nonce = ConvertTo-Hex (Get-RandomBytes 16)
        $proof = (Get-Signer $rec).SignData((Get-Bytes "IPF1|rotate|$($state.agent_uid)|$nonce|$($rec.public)"), [Security.Cryptography.HashAlgorithmName]::SHA256)
        $r = Invoke-Agent $state @{ type = 'rotate'; agent = $state.agent_uid; new_public_key = $rec.public;
                                    new_key_proof = [Convert]::ToBase64String($proof); key_protector = $script:DekProtector } $keys['active'] $nonce
        $state.rotation_sent = [bool]$r.ok
        if ($r.ok) { Write-Log 'INFO' "key rotation requested by server: pending key $($rec.key_id) registered" }
        else { Write-Log 'WARN' "key rotation failed: $($r.message)" }
    }
    if ($resp.update -and $resp.update.files) { Install-Update $resp.update }
    return $resp
}

function Install-Update($u) {
    # Every byte arrived inside the authenticated response; the hash is
    # checked again here and each script must parse before anything is swapped.
    $staged = @()
    foreach ($f in $u.files) {
        if ($f.name -notmatch '^[A-Za-z0-9_.-]+\.ps1$') { Write-Log 'ERROR' "update refused: bad file name $($f.name)"; return }
        $bytes = [Convert]::FromBase64String($f.content)
        if ((ConvertTo-Hex (Get-Sha256 $bytes)) -ne $f.sha256) { Write-Log 'ERROR' "update $($u.version) refused: hash mismatch on $($f.name)"; return }
        $tmp = Join-Path $InstallDir ($f.name + '.next')
        [IO.File]::WriteAllBytes($tmp, $bytes)
        $errs = $null; $tok = $null
        [void][Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tok, [ref]$errs)
        if ($errs.Count -gt 0) { Remove-Item -Force $tmp; Write-Log 'ERROR' "update $($u.version) refused: $($f.name) does not parse"; return }
        $staged += , @($tmp, (Join-Path $InstallDir $f.name))
    }
    foreach ($s in $staged) { Move-Item -Force -LiteralPath $s[0] -Destination $s[1] }
    Write-Log 'INFO' "updated to $($u.version); restarting"
    exit 10   # run-agent.ps1 restarts us on the new code
}

function Invoke-Decommission($state) {
    Write-Log 'WARN' 'DECOMMISSIONED by the control server: removing identity and scheduled tasks'
    foreach ($p in $KeyPath, $MasterPath, $StatePath, $ProfilePath) { Remove-Securely $p }
    if ($script:OnWindows) {
        try { (Open-TpmKey $false).Delete() } catch { }
        foreach ($t in 'IPFailoverAgent', 'IPFailoverTray') { try { Unregister-ScheduledTask -TaskName $t -Confirm:$false } catch { } }
    }
    Write-Status @{ server_ok = $false; decommissioned = $true; server_error = 'Decommissioned by the control server' }
    exit 20
}

# ============================================================================
# Main loop
# ============================================================================

foreach ($d in $DataDir, $PublicDir) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null } }

$state = Use-Profile (Read-Json $StatePath)
if (-not $state) {
    Write-Log 'ERROR' "not provisioned: no provisioning profile at $ProfilePath (run install.ps1 with the profile from the survey)"
    Write-Status @{ server_ok = $false; server_error = 'Not provisioned - run install.ps1 with a provisioning profile' }
    exit 1
}
Write-JsonVerified $StatePath $state
Write-Log 'INFO' "IP Failover agent $AGENT_VERSION for $($state.site_name) -> $($state.control_url)"

# The tray's "Check now" signals this event. Any interactive user may SET it,
# nothing else: it can only make us check in sooner.
$checkNow = $null
if ($script:OnWindows) {
    try {
        $sec = New-Object Security.AccessControl.EventWaitHandleSecurity
        $sec.AddAccessRule((New-Object Security.AccessControl.EventWaitHandleAccessRule(
            (New-Object Security.Principal.SecurityIdentifier 'S-1-5-4'),
            [Security.AccessControl.EventWaitHandleRights]'Modify, Synchronize', 'Allow')))
        $sec.AddAccessRule((New-Object Security.AccessControl.EventWaitHandleAccessRule(
            (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'),
            [Security.AccessControl.EventWaitHandleRights]::FullControl, 'Allow')))
        $created = $false
        $checkNow = New-Object Threading.EventWaitHandle($false, 'AutoReset', $EventName, [ref]$created, $sec)
    } catch { Write-Log 'INFO' "check-now signal unavailable ($($_.Exception.Message)); the tray button will be disabled" }
}

$prevStatus = Read-Json $StatusPath
while ($true) {
    $resp = $null; $err = $null
    try { $resp = Invoke-Cycle $state } catch { $err = $_.Exception.Message }
    try { Write-JsonVerified $StatePath $state } catch { Write-Log 'ERROR' "state not saved: $($_.Exception.Message)" }

    $st = @{ agent_uid = $state.agent_uid; site = $state.site_name; interval = [int]$state.interval
             key_protector = $script:DekProtector; server_ok = ($null -eq $err -and $resp -and $resp.ok) }
    if ($st.server_ok) {
        $st['last_success_at'] = Get-UnixTime
        $st['ip'] = $resp.ip; $st['targets'] = @($resp.targets); $st['enabled'] = $resp.agent.enabled
        $st['decommission'] = [bool]$resp.decommission
        $flag = ''
        if ($resp.ip.mismatch) { $flag = " - HELD: $($resp.ip.detail)" }
        Write-Log 'INFO' "checked in; authoritative IP $($resp.ip.authoritative) ($($resp.ip.source))$flag"
    } else {
        if ($err) { $st['server_error'] = $err } else { $st['server_error'] = "$($resp.error): $($resp.message)" }
        foreach ($k in 'last_success_at', 'ip', 'targets', 'enabled') { if ($prevStatus -and $prevStatus.$k) { $st[$k] = $prevStatus.$k } }
        Write-Log 'ERROR' $st['server_error']
    }
    Write-Status $st
    $prevStatus = [pscustomobject]$st

    if ($st.server_ok -and $resp.decommission) { Invoke-Decommission $state }
    if ($Once) { if ($st.server_ok) { exit 0 } else { exit 1 } }

    $fatal = $resp -and (@('unknown_agent', 'enroll_invalid', 'enroll_expired', 'protector_too_weak') -contains $resp.error)
    if ($st.server_ok) { $wait = [int]$state.interval } elseif ($fatal) { $wait = 900 } else { $wait = [Math]::Min(60, [int]$state.interval) }
    if ($checkNow) {
        if ($checkNow.WaitOne([TimeSpan]::FromSeconds($wait))) {
            Write-Log 'INFO' 'check requested from the tray'
            Start-Sleep -Seconds 2   # coalesce double-clicks
            [void]$checkNow.WaitOne(0)
        }
    } else {
        Start-Sleep -Seconds $wait
    }
}

#Requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$dir = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($dir) | Out-Null
$privatePath = Join-Path $dir 'release-private.encrypted.pem'
$publicPath = Join-Path $dir 'release-public.pem'
if ((Test-Path $privatePath) -or (Test-Path $publicPath)) { throw 'Key files already exist. Refusing to replace an established signing identity.' }
$secret = Read-Host 'Offline signing key passphrase (16+ characters)' -AsSecureString
$confirm = Read-Host 'Repeat passphrase' -AsSecureString
$plain = [Net.NetworkCredential]::new('', $secret).Password
$again = [Net.NetworkCredential]::new('', $confirm).Password
if ($plain.Length -lt 16 -or $plain -cne $again) { throw 'Passphrases must match and contain at least 16 characters.' }
$key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $pbe = [Security.Cryptography.PbeParameters]::new([Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc, [Security.Cryptography.HashAlgorithmName]::SHA256, 600000)
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($privatePath, $key.ExportEncryptedPkcs8PrivateKeyPem($plain, $pbe), $utf8)
    [IO.File]::WriteAllText($publicPath, $key.ExportSubjectPublicKeyInfoPem(), $utf8)
    $fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($key.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
    Write-Host "Created PUBLIC key: $publicPath"
    Write-Host "Public key SHA256 (SPKI DER): $fingerprint"
    Write-Host "Keep $privatePath and its passphrase offline. Give only release-public.pem to the build/server operator."
} finally { $key.Dispose(); $plain = $null; $again = $null; $secret.Dispose(); $confirm.Dispose() }

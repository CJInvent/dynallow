#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('windows-x64','windows-arm64','docker')][string]$Target,
    [Parameter(Mandatory)][ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$Sequence,
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$PrivateKey,
    [Parameter(Mandatory)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'
if (Test-Path $OutputFile) { throw 'Output exists. Refusing to overwrite a signed release.' }
$bytes = [IO.File]::ReadAllBytes((Resolve-Path $InputFile))
if ($bytes.Length -lt 1 -or $bytes.Length -gt 48000000) { throw 'Release payload must be 1..48,000,000 bytes.' }
$name = if ($Target -eq 'docker') { 'agent.php' } else { 'DynAllow.Agent.exe' }
if ($Target -eq 'docker') {
    $code = [Text.Encoding]::UTF8.GetString($bytes)
    if ($code -notmatch "const AGENT_VERSION = '$([regex]::Escape($Version))';" -or $code -notmatch "const RELEASE_SEQUENCE = $Sequence;") {
        throw 'Docker source version/sequence do not match the requested release. Update both constants before signing.'
    }
} else {
    # Build metadata sidecar produced by Build-Windows.ps1. Authenticode-sign the EXE BEFORE running this script.
    $meta = Get-Content -Raw ($InputFile + '.build.json') | ConvertFrom-Json
    if ($meta.version -ne $Version -or $meta.sequence -ne $Sequence -or $meta.target -ne $Target) { throw 'Build metadata does not match release target/version/sequence.' }
}
$manifest = [ordered]@{
    format = 'dynallow-release-v1'; target = $Target; version = $Version; sequence = $Sequence
    files = @([ordered]@{ name = $name; size = $bytes.Length; sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() })
}
$raw = [Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 5 -Compress))
$secret = Read-Host 'Offline signing key passphrase' -AsSecureString
$plain = [Net.NetworkCredential]::new('', $secret).Password
$key = [Security.Cryptography.ECDsa]::Create()
try {
    $key.ImportFromEncryptedPem([IO.File]::ReadAllText((Resolve-Path $PrivateKey)), $plain)
    if ($key.ExportParameters($false).Curve.Oid.Value -ne '1.2.840.10045.3.1.7') { throw 'Expected ECDSA P-256 key.' }
    $signature = $key.SignData($raw, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
    $files = [ordered]@{}; $files[$name] = [Convert]::ToBase64String($bytes)
    $bundle = [ordered]@{ manifest = [Convert]::ToBase64String($raw); signature = [Convert]::ToBase64String($signature); files = $files }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputFile), ($bundle | ConvertTo-Json -Depth 5 -Compress), [Text.UTF8Encoding]::new($false))
    Write-Host "Signed $Target $Version sequence $Sequence. Upload $OutputFile in the server's Releases page."
} finally { $key.Dispose(); $plain = $null; $secret.Dispose() }

#Requires -Version 7.4
[CmdletBinding()]
param(
    [switch]$Development,
    [string]$PublicKey,
    [ValidateSet('win-x64','win-arm64')][string]$Runtime = 'win-x64',
    [ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version = '3.0.0',
    [ValidateRange(1,2147483647)][int]$Sequence = 1,
    [string]$OutputDirectory = 'artifacts/windows'
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Native AOT for Windows requires Windows, .NET 10 SDK and Visual Studio C++ build tools.' }
if ($Development -and $PublicKey) { throw 'Development builds do not use a release signing key.' }
if (-not $Development -and -not $PublicKey) { throw 'Production builds require -PublicKey. Use -Development for key-free SHA-256 updates.' }
$pem = $null
if (-not $Development) {
    $pem = [IO.File]::ReadAllText((Resolve-Path $PublicKey))
    if ($pem.Contains('PRIVATE KEY')) { throw 'Provide PUBLIC key only.' }
    $key = [Security.Cryptography.ECDsa]::Create()
    try { $key.ImportFromPem($pem); if ($key.ExportParameters($false).Curve.Oid.Value -ne '1.2.840.10045.3.1.7') { throw 'Expected P-256 public key.' } }
    finally { $key.Dispose() }
}
$root = Split-Path -Parent $PSScriptRoot
$out = [IO.Path]::GetFullPath($OutputDirectory)
$work = Join-Path ([IO.Path]::GetTempPath()) ('dynallow-build-' + [Guid]::NewGuid().ToString('N'))
$project = Join-Path $work 'ControlServer/agents/windows-native'
$channel = if ($Development) { 'dev-sha256' } else { 'signed' }
try {
    New-Item -ItemType Directory -Path $project -Force | Out-Null
    # Build an isolated source snapshot: concurrent builds never rewrite the working tree or trust file.
    Get-ChildItem (Join-Path $root 'ControlServer/agents/windows-native') -File | Copy-Item -Destination $project
    if ($pem) { [IO.File]::WriteAllText((Join-Path $work 'ControlServer/release-public.pem'), $pem) }
    [IO.File]::WriteAllText((Join-Path $project 'BuildInfo.cs'), "namespace DynAllow; internal static partial class BuildInfo { public const string Version = `"$Version`"; public const int Sequence = $Sequence; }")
    $devValue = $Development.IsPresent.ToString().ToLowerInvariant()
    & dotnet publish $project -c Release -r $Runtime -p:PublishAot=true -p:StripSymbols=true -p:Version=$Version "-p:DevelopmentUpdates=$devValue" -o $out
    if ($LASTEXITCODE -ne 0) { throw 'Native AOT build failed.' }
    $exe = Join-Path $out 'DynAllow.Agent.exe'
    $hostArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    if (($Runtime -eq 'win-x64' -and $hostArch -eq 'x64') -or ($Runtime -eq 'win-arm64' -and $hostArch -eq 'arm64')) {
        & $exe self-test
        if ($LASTEXITCODE -ne 0) { throw 'Native executable self-tests failed.' }
    }
    @{ version = $Version; sequence = $Sequence; target = $Runtime.Replace('win-', 'windows-'); channel = $channel } | ConvertTo-Json | Set-Content ($exe + '.build.json') -Encoding utf8NoBOM
    if ($Development) { Write-Host "DEV SHA-256 build: $exe. Package with tools/New-DevRelease.py; no signing required." }
    else { Write-Host "Production build: $exe. Authenticode-sign, then use Sign-Release.ps1." }
} finally {
    if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}

#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PublicKey,
    [ValidateSet('win-x64','win-arm64')][string]$Runtime = 'win-x64',
    [ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version = '3.0.0',
    [ValidateRange(1,2147483647)][int]$Sequence = 1,
    [string]$OutputDirectory = 'artifacts/windows'
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Native AOT for Windows must be built on Windows with .NET 10 SDK and Visual Studio C++ build tools.' }
$root = Split-Path -Parent $PSScriptRoot
$pem = [IO.File]::ReadAllText((Resolve-Path $PublicKey))
if ($pem.Contains('PRIVATE KEY')) { throw 'Provide PUBLIC key only.' }
$key = [Security.Cryptography.ECDsa]::Create()
try { $key.ImportFromPem($pem); if ($key.ExportParameters($false).Curve.Oid.Value -ne '1.2.840.10045.3.1.7') { throw 'Expected P-256 public key.' } }
finally { $key.Dispose() }
$project = Join-Path $root 'ControlServer/agents/windows-native'
$anchor = Join-Path $root 'ControlServer/release-public.pem'
$info = Join-Path $project 'BuildInfo.cs'
$original = [IO.File]::ReadAllText($info)
$previousAnchor = if (Test-Path $anchor) { [IO.File]::ReadAllText($anchor) } else { $null }
$out = [IO.Path]::GetFullPath($OutputDirectory)
try {
    [IO.File]::WriteAllText($anchor, $pem, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($info, "namespace DynAllow; internal static class BuildInfo { public const string Version = `"$Version`"; public const int Sequence = $Sequence; }", [Text.UTF8Encoding]::new($false))
    & dotnet publish $project -c Release -r $Runtime -p:PublishAot=true -p:StripSymbols=true -p:Version=$Version -o $out
    if ($LASTEXITCODE -ne 0) { throw 'Native AOT build failed.' }
    $exe = Join-Path $out 'DynAllow.Agent.exe'
    $hostArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    if (($Runtime -eq 'win-x64' -and $hostArch -eq 'x64') -or ($Runtime -eq 'win-arm64' -and $hostArch -eq 'arm64')) {
        & $exe self-test
        if ($LASTEXITCODE -ne 0) { throw 'Native executable self-tests failed.' }
    }
    @{ version = $Version; sequence = $Sequence; target = $Runtime.Replace('win-', 'windows-') } | ConvertTo-Json | Set-Content ($exe + '.build.json') -Encoding utf8NoBOM
    Write-Host "Built $exe. Authenticode-sign this executable, then create its offline-signed release bundle with Sign-Release.ps1."
} finally {
    [IO.File]::WriteAllText($info, $original)
    if ($null -eq $previousAnchor) { Remove-Item $anchor -ErrorAction SilentlyContinue } else { [IO.File]::WriteAllText($anchor, $previousAnchor) }
}

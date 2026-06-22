param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$bridgeDir = Join-Path $repoRoot "roslyn_bridge"
$project = Join-Path $bridgeDir "RoslynBridge.csproj"
$outputDir = Join-Path $bridgeDir "bin\Release\net8.0\win-x64"
$binDir = Join-Path $bridgeDir "bin"
$objDir = Join-Path $bridgeDir "obj"
$logsDir = Join-Path $bridgeDir "logs"
$appDataDir = Join-Path $bridgeDir ".appdata"
$dotnetDir = Join-Path $bridgeDir ".dotnet"
$nugetDir = Join-Path $bridgeDir "NuGet"

Write-Host "Building Roslyn Bridge from $bridgeDir" -ForegroundColor Cyan

Get-Process RoslynBridge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($Clean) {
    Remove-Item -Recurse -Force $binDir, $objDir, $logsDir, $appDataDir, $dotnetDir, $nugetDir -ErrorAction SilentlyContinue
}

dotnet publish $project `
    -c $Configuration `
    -r $Runtime `
    --self-contained false `
    -p:PublishReadyToRun=false `
    -o $outputDir

Write-Host "Done. Output: $outputDir" -ForegroundColor Green

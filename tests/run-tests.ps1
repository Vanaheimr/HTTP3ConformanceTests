<#
.SYNOPSIS
    Builds the harnesses, starts the demo host, drives every gated harness against it and prints
    one verdict.

.DESCRIPTION
    The counterpart to HTTP2ConformanceTests/tests/run-tests.ps1. One process per harness, each
    self-reporting its own check count; this script only starts the server, collects the exit
    codes and says pass or fail once.

    What it does NOT run: h3bench (a benchmark has no verdict to give) and h3interop (it talks to
    eight public servers on the open internet, so it belongs in the nightly, not in a gate).

.PARAMETER NoBuild
    Skip the build step. Assumes a current Release build.

.PARAMETER Filter
    Only run harnesses whose name contains this substring.

.PARAMETER Port
    UDP port for the demo host. Default 4433.

.EXAMPLE
    pwsh tests/run-tests.ps1
    pwsh tests/run-tests.ps1 -NoBuild -Filter attack
#>
[CmdletBinding()]
param(
    [switch] $NoBuild,
    [string] $Filter = '',
    [int]    $Port   = 4433
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# Every gated harness: a name, the project that builds it, and the executable to run. Adding one
# means adding a row here and nothing else.
$harnesses = @(
    @{ Name = 'h3semantics'; Project = 'tests/h3semantics/h3semantics.csproj'
       Covers = 'RFC 9114 semantics from a foreign client (.NET HttpClient over msquic)' }
    @{ Name = 'h3attack';    Project = 'tests/h3attack/h3attack.csproj'
       Covers = 'malformed, undersized, spoofed and flooded datagrams over raw UDP' }
) | Where-Object { $Filter -eq '' -or $_.Name -like "*$Filter*" }

if ($harnesses.Count -eq 0) {
    Write-Host "No harness matches -Filter '$Filter'." -ForegroundColor Yellow
    exit 1
}

if (-not $NoBuild) {
    Write-Host '=== Building ===' -ForegroundColor Cyan
    # The demo host first: without it there is nothing to drive.
    foreach ($project in @('samples/H3Server/H3Server.csproj') + ($harnesses | ForEach-Object { $_.Project })) {
        dotnet build (Join-Path $repoRoot $project) --configuration Release --nologo --verbosity quiet
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Build failed: $project" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host ''
}

# The demo host writes its log to a file rather than the console: its per-request lines would
# interleave with the harness output and make both unreadable. On a failure the tail is printed.
$serverLog = Join-Path ([System.IO.Path]::GetTempPath()) "h3server-run-tests-$PID.log"
Write-Host "=== Starting the demo host on UDP/$Port ===" -ForegroundColor Cyan
$server = Start-Process -FilePath 'dotnet' `
                        -ArgumentList "run --project samples/H3Server --configuration Release --no-build -- $Port" `
                        -WorkingDirectory $repoRoot -PassThru -WindowStyle Hidden `
                        -RedirectStandardOutput $serverLog

try {
    # Wait for the line the server prints once its socket is bound, rather than sleeping a guessed
    # number of seconds. A fixed sleep is either too short on a cold machine or wasted on a warm one.
    $ready = $false
    foreach ($attempt in 1..60) {
        Start-Sleep -Milliseconds 500
        if ($server.HasExited) { break }
        if ((Test-Path $serverLog) -and (Select-String -Path $serverLog -Pattern 'Listening on' -Quiet)) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        Write-Host 'The demo host did not come up.' -ForegroundColor Red
        if (Test-Path $serverLog) { Get-Content $serverLog -Tail 20 }
        exit 1
    }
    Write-Host "  up after $($attempt * 0.5)s`n"

    $results = @()
    foreach ($harness in $harnesses) {
        Write-Host "=== $($harness.Name) ===" -ForegroundColor Cyan
        $exe = Join-Path $repoRoot "tests/$($harness.Name)/bin/Release/net10.0/$($harness.Name).exe"
        if (-not (Test-Path $exe)) {
            # Non-Windows drops the .exe suffix.
            $exe = Join-Path $repoRoot "tests/$($harness.Name)/bin/Release/net10.0/$($harness.Name)"
        }

        $env:H3_PORT = $Port
        $output = & $exe 2>&1
        $code   = $LASTEXITCODE
        $output | ForEach-Object { Write-Host $_ }

        $verdict = ($output | Select-String -Pattern '(\d+)/(\d+) checks passed' | Select-Object -Last 1)
        $results += [pscustomobject]@{
            Name    = $harness.Name
            Passed  = if ($verdict) { [int] $verdict.Matches[0].Groups[1].Value } else { 0 }
            Total   = if ($verdict) { [int] $verdict.Matches[0].Groups[2].Value } else { 0 }
            Ok      = $code -eq 0
            Skipped = $code -eq 2
        }
        Write-Host ''
    }

    Write-Host '=== Summary ===' -ForegroundColor Cyan
    foreach ($result in $results) {
        $label  = if ($result.Skipped) { 'SKIP' } elseif ($result.Ok) { 'PASS' } else { 'FAIL' }
        $colour = if ($result.Skipped) { 'Yellow' } elseif ($result.Ok) { 'Green' } else { 'Red' }
        Write-Host ("  {0,-14} {1}  {2}/{3} checks" -f $result.Name, $label, $result.Passed, $result.Total) `
                   -ForegroundColor $colour
    }

    $checksPassed = ($results | Measure-Object -Property Passed -Sum).Sum
    $checksTotal  = ($results | Measure-Object -Property Total  -Sum).Sum
    $failed       = @($results | Where-Object { -not $_.Ok -and -not $_.Skipped })

    Write-Host ''
    if ($failed.Count -eq 0) {
        Write-Host "  $checksPassed/$checksTotal checks passed across $($results.Count) harnesses." -ForegroundColor Green
        exit 0
    }

    Write-Host "  $checksPassed/$checksTotal checks passed — $($failed.Count) harness(es) failed: $($failed.Name -join ', ')" `
               -ForegroundColor Red
    Write-Host "  Demo host log: $serverLog"
    exit 1
}
finally {
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
}

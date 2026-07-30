<#
    Browser interop check for H3Server — the counterpart of `H3Get --interop` for the server side.

    Starts H3Server, launches a headless Chrome or Edge on https://localhost:<port>/browser, waits for
    the page to post its verdict back to /report and prints what the server logged. Exits 0 only if
    every check passed, so this can gate a build.

    Two browser flags are unavoidable and neither is a workaround for a defect on our side:

      --ignore-certificate-errors-spki-list=<pin>   The certificate is self-signed. This pins the exact
                                                    key instead of installing a CA in the machine's
                                                    trust store, which a test script has no business
                                                    doing. The pin comes from the server's own startup
                                                    output, so it is never stale.
      --enable-features=EnableWebTransportDraft07   Chrome's WebTransport client offers draft-02 by
                                                    default and hides draft-07 behind this flag
                                                    (net/quic/dedicated_web_transport_http3_client.cc).
                                                    We implement draft-13, whose handshake matches
                                                    draft-07's, so without the flag the browser refuses
                                                    the session with net::ERR_METHOD_NOT_SUPPORTED.

    The certificate is deliberately short-lived: WebTransport authenticates it by hash
    (serverCertificateHashes), and that only accepts an ECDSA P-256 certificate valid for at most 14
    days. The page gets the hash from the server, so nothing has to be copied by hand.
#>

[CmdletBinding()]
param(
    [ValidateSet('chrome', 'edge')] [string] $Browser = 'chrome',
    [int] $Port = 4433,
    [int] $TimeoutSeconds = 60,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$workDir  = Join-Path ([System.IO.Path]::GetTempPath()) "h3-browser-interop"
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$serverLog     = Join-Path $workDir 'server.log'
$serverErr     = Join-Path $workDir 'server.err'
$browserProfile = Join-Path $workDir "profile-$Browser"

$browserPaths = @{
    chrome = @(
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
    )
    edge = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
    )
}

$browserExe = $browserPaths[$Browser] | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browserExe) {
    Write-Error "$Browser not found. Looked in: $($browserPaths[$Browser] -join ', ')"
}
Write-Host "Browser: $browserExe ($((Get-Item $browserExe).VersionInfo.ProductVersion))"

# ---- build and start the server -------------------------------------------------------------

Write-Host "Building H3Server ($Configuration) …"
dotnet build (Join-Path $repoRoot 'samples\H3Server\H3Server.csproj') --configuration $Configuration --nologo `
             -consoleLoggerParameters:ErrorsOnly
if ($LASTEXITCODE -ne 0) { Write-Error 'Build failed.' }

$serverExe = Join-Path $repoRoot "samples\H3Server\bin\$Configuration\net10.0\H3Server.exe"
$serverArgs = @(
    "$Port",
    "--cert=$(Join-Path $workDir 'browser-interop.pfx')",
    '--cert-days=13'
)

# A stale certificate from an earlier run would still be loaded (it is only replaced once expired),
# so its hash and pin stay correct — but a leftover from a *different* port or host would not, and
# regenerating costs nothing.
Remove-Item -Force (Join-Path $workDir 'browser-interop.pfx') -ErrorAction SilentlyContinue
Remove-Item -Force $serverLog, $serverErr -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $browserProfile -ErrorAction SilentlyContinue

$server = Start-Process -FilePath $serverExe -ArgumentList $serverArgs -PassThru -WindowStyle Hidden `
                        -RedirectStandardOutput $serverLog -RedirectStandardError $serverErr
try {
    # Wait for the startup banner rather than sleeping a fixed amount: the pin has to be there.
    $pin = $null
    $startupDeadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $startupDeadline) {
        $line = Get-Content $serverLog -ErrorAction SilentlyContinue | Where-Object { $_ -like 'SPKI pin:*' }
        if ($line) { $pin = $line.Split(' ')[2]; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $pin) {
        Get-Content $serverErr -ErrorAction SilentlyContinue | Write-Host
        Write-Error 'Server did not report an SPKI pin — see the output above.'
    }
    Write-Host "SPKI pin: $pin"

    # ---- run the browser --------------------------------------------------------------------

    $browserArgs = @(
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        "--user-data-dir=$browserProfile",
        "--origin-to-force-quic-on=localhost:$Port",   # no Alt-Svc source, so point it at HTTP/3 directly
        "--ignore-certificate-errors-spki-list=$pin",
        '--enable-features=EnableWebTransportDraft07',
        "https://localhost:$Port/browser"
    )
    $browserProcess = Start-Process -FilePath $browserExe -ArgumentList $browserArgs -PassThru -WindowStyle Hidden
    try {
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $done = $false
        while ((Get-Date) -lt $deadline) {
            if ((Get-Content $serverLog -Raw -ErrorAction SilentlyContinue) -match 'checks passed') { $done = $true; break }
            Start-Sleep -Milliseconds 300
        }
    }
    finally {
        Stop-Process -Id $browserProcess.Id -Force -ErrorAction SilentlyContinue
    }

    # ---- report -----------------------------------------------------------------------------

    Write-Host ''
    Get-Content $serverLog | Select-Object -Skip 1 | Write-Host

    if (-not $done) {
        Write-Host ''
        Write-Error "No report within $TimeoutSeconds s. The server log above is the whole story: no `"New connection`" line means not a single datagram arrived."
    }

    $summary = (Get-Content $serverLog | Where-Object { $_ -match 'checks passed' } | Select-Object -Last 1)
    if ($summary -match '(\d+)/(\d+) checks passed' -and $matches[1] -eq $matches[2]) {
        Write-Host ''
        Write-Host "${Browser}: all checks passed." -ForegroundColor Green
        exit 0
    }

    Write-Host ''
    Write-Host "${Browser}: $summary" -ForegroundColor Red
    exit 1
}
finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}

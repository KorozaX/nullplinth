# Run the Rust test suite on the GNU toolchain.
#
# Why this script exists: the MinGW build links WebView2Loader.dll dynamically and cargo does
# not place it next to test binaries, so a bare "cargo test" fails with STATUS_ENTRYPOINT_NOT_FOUND
# (0xc0000139). Copying the loader into the target directories fixes the DLL search path.
#
# Usage: pwsh -File scripts/run-backend-tests.ps1 [-TestArgs @('--test','backend_tests')]
param(
    [string[]]$TestArgs = @()
)

$ErrorActionPreference = "Stop"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$root = Split-Path -Parent $PSScriptRoot
$crate = Join-Path $root "src-tauri"
Push-Location $crate
try {
    cargo build --tests 2>&1 | Out-Null
    $loader = Get-ChildItem -Path "target\debug\build" -Recurse -Filter "WebView2Loader.dll" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($loader) {
        foreach ($dir in @("target\debug", "target\debug\deps")) {
            $dest = Join-Path $crate $dir
            if (Test-Path $dest) { Copy-Item $loader.FullName $dest -Force }
        }
    } else {
        Write-Warning "WebView2Loader.dll not found; tests that link tauri may fail to start."
    }
    cargo test @TestArgs -- --test-threads=1
    exit $LASTEXITCODE
} finally {
    Pop-Location
}

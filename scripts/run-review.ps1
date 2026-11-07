$ErrorActionPreference = "Stop"
Get-Process nullplinth -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9223"
$p = Start-Process -FilePath "src-tauri\target\release\nullplinth.exe" -PassThru
Start-Sleep -Seconds 7
node scripts\review-cdp.mjs 9223 review-cdp 2>&1 | Out-String
if (-not $p.HasExited) { $p.Kill() }

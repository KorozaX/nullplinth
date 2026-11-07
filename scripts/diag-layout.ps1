param([int]$Width = 1024, [int]$Height = 768, [int]$Port = 9223)
# Measures the real WebView2 layout through the CDP endpoint and reports overflow offenders.
$ErrorActionPreference = "Stop"
$native = @"
using System;
using System.Runtime.InteropServices;
public class WinMove2 {
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
}
"@
Add-Type -TypeDefinition $native
Get-Process nullplinth -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$Port"
$p = Start-Process -FilePath "src-tauri\target\release\nullplinth.exe" -PassThru
Start-Sleep -Seconds 6
$p.Refresh()
[void][WinMove2]::MoveWindow($p.MainWindowHandle, 10, 10, $Width, $Height, $true)
Start-Sleep -Seconds 3
$targets = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json" -TimeoutSec 10
$page = $targets | Where-Object { $_.type -eq "page" } | Select-Object -First 1
Write-Output ("window=" + $Width + "x" + $Height + " url=" + $page.url)
$ws = New-Object System.Net.WebSockets.ClientWebSocket
$ws.ConnectAsync([Uri]$page.webSocketDebuggerUrl, [Threading.CancellationToken]::None).Wait()
$expr = Get-Content -Raw "scripts\diag-layout.js"
$payload = @{ id = 7; method = "Runtime.evaluate"; params = @{ expression = $expr; returnByValue = $true } } | ConvertTo-Json -Compress -Depth 6
$bytes = [Text.Encoding]::UTF8.GetBytes($payload)
$ws.SendAsync((New-Object ArraySegment[byte] -ArgumentList (, $bytes)), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).Wait()
$buffer = New-Object byte[] 262144
do {
  $res = $ws.ReceiveAsync((New-Object ArraySegment[byte] -ArgumentList (, $buffer)), [Threading.CancellationToken]::None).Result
  $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $res.Count)
} while (-not ($text -match 'id.:7'))
$json = $text | ConvertFrom-Json
$json.result.result.value
$ws.Dispose()
if (-not $p.HasExited) { $p.Kill() }

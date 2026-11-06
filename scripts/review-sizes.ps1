param([string]$ExePath, [string]$OutDir = "shots4")
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$native = @'
using System;
using System.Runtime.InteropServices;
public class WinCap5 {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
}
'@
Add-Type -TypeDefinition $native
$proc = Start-Process -FilePath $ExePath -PassThru
$deadline = (Get-Date).AddSeconds(20)
$handle = [IntPtr]::Zero
while ((Get-Date) -lt $deadline) {
    $p = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne 0) { $handle = $p.MainWindowHandle; break }
    Start-Sleep -Milliseconds 400
}
if ($handle -eq [IntPtr]::Zero) { throw "no window" }
Start-Sleep -Milliseconds 3500
function Capture([string]$name) {
    [void][WinCap5]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 900
    $r = New-Object WinCap5+RECT
    [void][WinCap5]::GetWindowRect($handle, [ref]$r)
    $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $gfx.GetHdc()
    $ok = [WinCap5]::PrintWindow($handle, $hdc, 2)
    $gfx.ReleaseHdc($hdc); $gfx.Dispose()
    $path = Join-Path $OutDir ($name + ".png")
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output ("shot=" + $path + " ok=" + $ok + " " + $w + "x" + $h)
}
function Key([string]$k) { [void][WinCap5]::SetForegroundWindow($handle); Start-Sleep -Milliseconds 300; [System.Windows.Forms.SendKeys]::SendWait($k); Start-Sleep -Milliseconds 1200 }

# 1366x768 physical
[void][WinCap5]::MoveWindow($handle, 20, 20, 1366, 768, $true)
Start-Sleep -Milliseconds 2500
Capture "01-1366-overview"
Key "%2"; Capture "02-1366-events"
Key "%3"; Capture "03-1366-network"
# 1024x768 physical
[void][WinCap5]::MoveWindow($handle, 20, 20, 1024, 768, $true)
Start-Sleep -Milliseconds 2500
Key "%1"; Capture "04-1024-overview"
Key "%2"; Capture "05-1024-events"
if (-not $proc.HasExited) { $proc.Kill() }
Write-Output "done"

param([string]$ExePath, [string]$OutDir = "shots3")
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$native = @'
using System;
using System.Runtime.InteropServices;
public class WinCap4 {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
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
[void][WinCap4]::ShowWindow($handle, 3)
Start-Sleep -Milliseconds 4000
function Capture([string]$name) {
    [void][WinCap4]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 900
    $r = New-Object WinCap4+RECT
    [void][WinCap4]::GetWindowRect($handle, [ref]$r)
    $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $gfx.GetHdc()
    $ok = [WinCap4]::PrintWindow($handle, $hdc, 2)
    $gfx.ReleaseHdc($hdc); $gfx.Dispose()
    $path = Join-Path $OutDir ($name + ".png")
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output ("shot=" + $path + " ok=" + $ok + " " + $w + "x" + $h)
}
function Key([string]$k) {
    [void][WinCap4]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 400
    [System.Windows.Forms.SendKeys]::SendWait($k)
    Start-Sleep -Milliseconds 1500
}
Capture "01-overview"
Key "%2"; Capture "02-events"
Key "%3"; Capture "03-network"
Key "%4"; Capture "04-alerts"
Key "%6"; Capture "05-sources"
Key "%7"; Capture "06-settings"
if (-not $proc.HasExited) { $proc.Kill() }
Write-Output "done"

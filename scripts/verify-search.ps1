param([string]$ExePath, [string]$OutDir = "shots7")
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$native = @'
using System;
using System.Runtime.InteropServices;
public class WinCap7 {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);
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
[void][WinCap7]::ShowWindow($handle, 3)
Start-Sleep -Milliseconds 4000
function Rect { $r = New-Object WinCap7+RECT; [void][WinCap7]::GetWindowRect($handle, [ref]$r); return $r }
function Click([double]$fx, [double]$fy) {
    $r = Rect
    $x = [int]($r.Left + ($r.Right - $r.Left) * $fx)
    $y = [int]($r.Top + ($r.Bottom - $r.Top) * $fy)
    [void][WinCap7]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 300
    [void][WinCap7]::SetCursorPos($x, $y)
    Start-Sleep -Milliseconds 150
    [WinCap7]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
    [WinCap7]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 700
}
function Capture([string]$name) {
    [void][WinCap7]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 800
    $r = Rect; $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $gfx.GetHdc()
    $ok = [WinCap7]::PrintWindow($handle, $hdc, 2)
    $gfx.ReleaseHdc($hdc); $gfx.Dispose()
    $path = Join-Path $OutDir ($name + ".png")
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output ("shot=" + $path + " ok=" + $ok + " " + $w + "x" + $h)
}
function Key([string]$k) { [void][WinCap7]::SetForegroundWindow($handle); Start-Sleep -Milliseconds 300; [System.Windows.Forms.SendKeys]::SendWait($k); Start-Sleep -Milliseconds 1200 }

Key "%2"
Capture "01-events-empty"
# free text box sits right of the dataset and range selects
Click 0.69 0.281
Key "root"
Start-Sleep -Milliseconds 1800
Capture "02-events-root-search"
if (-not $proc.HasExited) { $proc.Kill() }
Write-Output "done"
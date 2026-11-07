param([string]$ExePath, [string]$OutDir = "review")
// Captures the running app at the four required resolutions and every section.
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$native = @'
using System;
using System.Runtime.InteropServices;
public class ReviewCap {
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
$deadline = (Get-Date).AddSeconds(25)
$handle = [IntPtr]::Zero
while ((Get-Date) -lt $deadline) {
    $p = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne 0) { $handle = $p.MainWindowHandle; break }
    Start-Sleep -Milliseconds 400
}
if ($handle -eq [IntPtr]::Zero) { throw "no window" }
Start-Sleep -Milliseconds 3500
function Capture([string]$name) {
    [void][ReviewCap]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 900
    $r = New-Object ReviewCap+RECT
    [void][ReviewCap]::GetWindowRect($handle, [ref]$r)
    $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $gfx.GetHdc()
    $ok = [ReviewCap]::PrintWindow($handle, $hdc, 2)
    $gfx.ReleaseHdc($hdc); $gfx.Dispose()
    $path = Join-Path $OutDir ($name + ".png")
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output ("shot=" + $path + " ok=" + $ok + " " + $w + "x" + $h)
}
function Key([string]$k) { [void][ReviewCap]::SetForegroundWindow($handle); Start-Sleep -Milliseconds 300; [System.Windows.Forms.SendKeys]::SendWait($k); Start-Sleep -Milliseconds 1200 }

$sizes = @(@(1024,768), @(1280,720), @(1366,768), @(1920,1080))
$names = @("overview","events","network","alerts","investigations","sources","settings")
foreach ($size in $sizes) {
    $w = $size[0]; $h = $size[1]
    [void][ReviewCap]::MoveWindow($handle, 10, 10, $w, $h, $true)
    Start-Sleep -Milliseconds 2200
    for ($i = 0; $i -lt $names.Count; $i++) {
        Key ("%" + ($i + 1))
        Capture ("{0}x{1}-{2}" -f $w, $h, $names[$i])
    }
}
if (-not $proc.HasExited) { $proc.Kill() }
Write-Output "done"

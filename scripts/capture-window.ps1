# Capture a screenshot of a running NULLPLINTH window for visual review.
# Usage: pwsh -File scripts/capture-window.ps1 -OutFile shot.png [-ExePath app.exe] [-WaitSeconds 12]
param(
    [string]$OutFile = "shot.png",
    [string]$Title = "NULLPLINTH",
    [int]$WaitSeconds = 12,
    [string]$ExePath = ""
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$native = @'
using System;
using System.Runtime.InteropServices;
public class WinCap {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
'@
Add-Type -TypeDefinition $native

$proc = $null
if ($ExePath) { $proc = Start-Process -FilePath $ExePath -PassThru }
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$handle = [IntPtr]::Zero
while ((Get-Date) -lt $deadline) {
    $target = if ($proc) { Get-Process -Id $proc.Id -ErrorAction SilentlyContinue } else { Get-Process | Where-Object { $_.MainWindowTitle -like "*$Title*" } | Select-Object -First 1 }
    if ($target -and $target.MainWindowHandle -ne 0) { $handle = $target.MainWindowHandle; break }
    Start-Sleep -Milliseconds 400
}
if ($handle -eq [IntPtr]::Zero) { throw "no window handle found for $Title" }

[void][WinCap]::ShowWindow($handle, 3)
[void][WinCap]::SetForegroundWindow($handle)
Start-Sleep -Milliseconds 1500

$rect = New-Object WinCap+RECT
[void][WinCap]::GetWindowRect($handle, [ref]$rect)
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
if ($w -le 0 -or $h -le 0) { throw "invalid window size" }

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $gfx.GetHdc()
# 2 = PW_RENDERFULLCONTENT, required to capture WebView2 content
$ok = [WinCap]::PrintWindow($handle, $hdc, 2)
$gfx.ReleaseHdc($hdc)
$gfx.Dispose()
$bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output ("captured=" + $ok + " path=" + $OutFile + " size=" + $w + "x" + $h)
if ($proc -and -not $proc.HasExited) { $proc.Kill() }

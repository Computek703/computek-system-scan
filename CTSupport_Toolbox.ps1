# ==============================================================
#  Compu-TEK / CT-Support Technician Toolbox
#  Website : https://ctsupport.net
# ==============================================================

# --- Auto-elevate ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# --- Banner ---
$Version = "1.3"
$Build   = (Get-Date).ToString('yyyy-MM-dd')

$ascii = @"
  #####                                    #######               
 #     #  ####  #    # #####  #    #          #    ###### #    # 
 #       #    # ##  ## #    # #    #          #    #      #   #  
 #       #    # # ## # #    # #    # #####    #    #####  ####   
 #       #    # #    # #####  #    #          #    #      #  #   
 #     # #    # #    # #      #    #          #    #      #   #  
  #####   ####  #    # #       ####           #    ###### #    # 
"@

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host $ascii -ForegroundColor red
    Write-Host ("="*60) -ForegroundColor Blue
    Write-Host "             Compu-TEK | CT-Support Technician Toolbox" -ForegroundColor White
    Write-Host "                     https://ctsupport.net" -ForegroundColor White
    Write-Host ("                     Version {0}  |  Build Date: {1}" -f $Version,$Build) -ForegroundColor White
    Write-Host ("="*60) -ForegroundColor Blue
    Write-Host ""
}

# --- Discover scripts dynamically ---
$folder = Join-Path (Split-Path -Parent $PSCommandPath) "scripts"
$scripts = Get-ChildItem $folder -Filter "*.ps1" -File | Sort-Object Name

if (-not $scripts) {
    Show-Banner
    Write-Host "No PowerShell scripts found in this directory." -ForegroundColor Yellow
    Read-Host "Press Enter to close"
    exit
}

# --- Menu loop ---
$exitToolbox = $false
do {
    Show-Banner
    Write-Host "Select a tool to run:`n" -ForegroundColor Cyan

    for ($i=0; $i -lt $scripts.Count; $i++) {
        Write-Host ("  {0,2}. {1}" -f ($i+1), $scripts[$i].BaseName) -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  A. Run ALL scripts" -ForegroundColor Yellow
    Write-Host "  X. Exit" -ForegroundColor Yellow
    Write-Host ("="*60) -ForegroundColor Blue

    $choice = Read-Host "Enter your choice (e.g. 1,3 or A)"
    switch -Regex ($choice) {
        '^[Xx]$' {
            $exitToolbox = $true
        }
        '^[Aa]$' {
            foreach ($s in $scripts) {
                Show-Banner
                Write-Host "Running: $($s.BaseName)" -ForegroundColor Cyan
                Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass","-Command `"& { . '$($s.FullName)'; Write-Host ''; Read-Host 'Press Enter to close this window...'; exit }`""
                Start-Sleep 1
            }
            Read-Host "`nAll tools launched. Press Enter to return to menu"
        }
        default {
            $nums = $choice -split '[,; ]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
            $valid = $nums | Where-Object { $_ -ge 1 -and $_ -le $scripts.Count }
            if ($valid) {
                foreach ($n in $valid) {
                    $s = $scripts[$n-1]
                    Show-Banner
                    Write-Host "`nLaunching: $($s.BaseName)`n" -ForegroundColor Cyan
                    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass","-Command `"& { . '$($s.FullName)'; Write-Host ''; Read-Host 'Press Enter to close this window...'; exit }`""
                    Start-Sleep 1
                }
                Read-Host "`nSelected tools launched. Press Enter to return to menu"
            } else {
                Read-Host "Invalid input. Press Enter to continue"
            }
        }
    }
} until ($exitToolbox)

Write-Host "`nExiting CT-Support Toolbox..." -ForegroundColor Cyan
Start-Sleep 1
exit

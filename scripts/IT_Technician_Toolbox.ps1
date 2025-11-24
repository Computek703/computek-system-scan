# ==============================================================
#  IT Technician Toolbox - PowerShell Edition (v1.3)
# ==============================================================

# --- Ensure script runs as administrator ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
 ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- Console Setup ---
$host.UI.RawUI.WindowTitle = "IT Technician Toolbox"
Clear-Host
Write-Host "`n=== IT TECHNICIAN TOOLBOX ===`n" -ForegroundColor Cyan

# --- Log file path ---
$logFile = "$env:TEMP\toolbox_log.txt"

# --- Logging Function ---
function Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -Append -FilePath $logFile
}

# --- Menu Loop ---
do {
    Write-Host "`n[1] System Information"
    Write-Host "[2] Network Information"
    Write-Host "[3] Flush DNS / Renew IP"
    Write-Host "[4] Test Internet Connection"
    Write-Host "[5] Clear Temp Files"
    Write-Host "[6] Run SFC (System File Checker)"
    Write-Host "[7] Run CHKDSK (Check Disk)"
    Write-Host "[8] Run DISM (Repair Windows Image)"
    Write-Host "[9] Open Task Manager"
    Write-Host "[10] Clear Print Queue"
    Write-Host "[11] Enable BitLocker Encryption"
    Write-Host "[0] Reboot System"
    Write-Host "[X] Exit Toolbox"
    $choice = Read-Host "`nChoose an option"

    switch ($choice.ToUpper()) {
        "1" {
            Write-Host "`n--- SYSTEM INFORMATION ---" -ForegroundColor Yellow
            systeminfo
            Log "Displayed system information"
        }
        "2" {
            Write-Host "`n--- NETWORK INFORMATION ---" -ForegroundColor Yellow
            ipconfig /all
            Log "Displayed network information"
        }
        "3" {
            Write-Host "`nFlushing DNS..." -ForegroundColor Yellow
            ipconfig /flushdns
            Write-Host "Releasing IP..."
            ipconfig /release
            Write-Host "Renewing IP..."
            ipconfig /renew
            Log "Flushed DNS and renewed IP"
        }
        "4" {
            Write-Host "`nTesting internet connection..." -ForegroundColor Yellow
            ping 8.8.8.8
            ping www.google.com
            Log "Tested internet connection"
        }
        "5" {
            $confirm = Read-Host "Are you sure you want to clear temp files? (Y/N)"
            if ($confirm -match "^[Yy]$") {
                Write-Host "`nClearing temporary files..." -ForegroundColor Yellow
                Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Temp files cleared." -ForegroundColor Green
                Log "Cleared temp files"
            } else {
                Write-Host "Canceled clearing temp files." -ForegroundColor DarkGray
            }
        }
        "6" {
            Write-Host "`nRunning System File Checker..." -ForegroundColor Yellow
            sfc /scannow
            Log "Ran SFC scan"
        }
        "7" {
            Write-Host "`n--- AVAILABLE DRIVES ---" -ForegroundColor Yellow
            $drives = Get-PSDrive -PSProvider 'FileSystem' | Where-Object { $_.Free -gt 0 }
            $i = 1
            foreach ($d in $drives) {
                Write-Host "[$i] $($d.Name):\" -ForegroundColor Cyan
                $i++
            }
            Write-Host "[0] Cancel" -ForegroundColor DarkGray
            $selection = Read-Host "Select a drive number"
            if ($selection -ne "0" -and $selection -match "^\d+$" -and $selection -le $drives.Count) {
                $target = $drives[$selection - 1].Name + ":"
                Write-Host "`nRunning CHKDSK on $target..." -ForegroundColor Yellow
                chkdsk $target /f /r
                Log "Ran CHKDSK on $target"
            } else {
                Write-Host "Canceled CHKDSK." -ForegroundColor DarkGray
            }
        }
        "8" {
            Write-Host "`nRunning DISM Health Restore..." -ForegroundColor Yellow
            DISM /Online /Cleanup-Image /RestoreHealth
            Log "Ran DISM RestoreHealth"
        }
        "9" {
            Start-Process taskmgr
            Log "Opened Task Manager"
        }
        "10" {
            Write-Host "`nClearing print queue..." -ForegroundColor Yellow
            try {
                Stop-Service -Name Spooler -Force
                $printDir = "$env:SystemRoot\System32\spool\PRINTERS"
                if (Test-Path $printDir) {
                    Remove-Item "$printDir\*" -Force -Recurse -ErrorAction SilentlyContinue
                }
                Start-Service -Name Spooler
                Write-Host "Print queue cleared successfully." -ForegroundColor Green
                Log "Cleared print queue successfully"
            } catch {
                Write-Host "Failed to clear print queue: $_" -ForegroundColor Red
                Log "Error clearing print queue: $_"
            }
        }
        "11" {
    Write-Host "`n=== ENABLE BITLOCKER ENCRYPTION (USED SPACE ONLY) ===" -ForegroundColor Cyan

    # --- STEP 1: Ensure BitLocker service is enabled ---
    Write-Host "Checking BitLocker service (BDESVC)..." -ForegroundColor Yellow
    try {
        $svc = Get-Service -Name "BDESVC" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Write-Host "Starting BitLocker service..." -ForegroundColor DarkYellow
            Set-Service -Name "BDESVC" -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name "BDESVC" -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "Could not verify or start BDESVC service: $_" -ForegroundColor Red
    }

    # --- STEP 2: Check and remove policy blocks ---
    Write-Host "Checking for BitLocker policy restrictions..." -ForegroundColor Yellow
    $regPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker",
        "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            foreach ($name in @("PreventDeviceEncryption", "PreventAutoEncryption", "DisableAutoEncryption")) {
                $val = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).$name
                if ($val -eq 1) {
                    Write-Host "Detected $name=1 → removing restriction..." -ForegroundColor Yellow
                    Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
                }
            }
        }
    }
    Write-Host "BitLocker restrictions cleared (if any)." -ForegroundColor Green

    # --- STEP 3: Detect encryptable drives (skip flash drive) ---
    $scriptDrive = (Get-Item $PSScriptRoot).PSDrive.Name
    $allDrives = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.DriveLetter -ne $scriptDrive }
    $eligibleDrives = @()

    foreach ($d in $allDrives) {
        $letter = "$($d.DriveLetter):"
        try {
            $status = (& manage-bde -status $letter 2>$null) -join "`n"
            if ($status -match "Conversion Status:\s+(Used Space Only Encrypted|Fully Encrypted|Encryption in Progress)") {
                Write-Host "$letter is already encrypted or encrypting - skipping." -ForegroundColor DarkGray
            } else {
                $eligibleDrives += $d
            }
        } catch {
            Write-Host "Could not read BitLocker status for $letter" -ForegroundColor Red
        }
    }

    if (-not $eligibleDrives) {
        Write-Host "`nNo drives available for encryption. All fixed drives already encrypted." -ForegroundColor Green
        break
    }

    Write-Host "`nAvailable drives for BitLocker:" -ForegroundColor Yellow
    $i = 1
    foreach ($d in $eligibleDrives) {
        Write-Host "[$i] $($d.DriveLetter):  $($d.FileSystemLabel)" -ForegroundColor Cyan
        $i++
    }
    Write-Host "[A] Encrypt All Listed Drives" -ForegroundColor Yellow
    Write-Host "[0] Cancel" -ForegroundColor DarkGray

    $choiceBL = Read-Host "Select a drive number (or A for all)"
    $targets = @()
    if ($choiceBL.ToUpper() -eq "A") {
        $targets = $eligibleDrives
    } elseif ($choiceBL -match "^\d+$" -and [int]$choiceBL -le $eligibleDrives.Count -and $choiceBL -ne "0") {
        $targets += $eligibleDrives[[int]$choiceBL - 1]
    } else {
        Write-Host "Canceled BitLocker encryption." -ForegroundColor DarkGray
        break
    }

    # --- STEP 4: Prepare key storage folder on flash drive ---
    $FlashDir = $PSScriptRoot
    $KeyDir = Join-Path $FlashDir ("BitLockerKeys\" + $env:COMPUTERNAME)
    if (-not (Test-Path $KeyDir)) { New-Item -Path $KeyDir -ItemType Directory | Out-Null }

    # --- STEP 5: Encrypt selected drives (used space only) ---
    foreach ($drive in $targets) {
        $letter = "$($drive.DriveLetter):"
        Write-Host "`nEnabling BitLocker (used space only) on $letter..." -ForegroundColor Yellow
        $keyFile = Join-Path $KeyDir ("BitLockerKey_${letter.TrimEnd(':')}.txt")

        try {
            manage-bde -protectors -add $letter -RecoveryPassword > $keyFile
            manage-bde -on $letter -UsedSpaceOnly -RecoveryPassword > $null
            Write-Host "BitLocker enabled on $letter (Used Space Only). Key saved to: $keyFile" -ForegroundColor Green

            Write-Host "`nBitLocker initialization complete on $letter (Used Space Only)." -ForegroundColor Green
Write-Host "Encryption will begin automatically after the next reboot." -ForegroundColor Yellow

$pending = ($status -match "Encryption Pending")
if ($pending) {
    Write-Host "`nSystem reboot required to start encryption on $letter." -ForegroundColor Cyan
    $confirm = Read-Host "Reboot now? (Y/N)"
    if ($confirm -match "^[Yy]$") {
        Write-Host "Restarting system to begin encryption..." -ForegroundColor Yellow
        Restart-Computer -Force
    } else {
        Write-Host "Reboot postponed. Encryption will start next time the computer restarts." -ForegroundColor DarkGray
    }
}
            Write-Progress -Activity "Encrypting $letter" -Completed
            Write-Host "Drive $letter encryption complete." -ForegroundColor Green
        } catch {
            Write-Host "Failed to enable BitLocker on $letter : $_" -ForegroundColor Red
        }
    }

    Write-Host "`nBitLocker encryption complete. Verify with 'manage-bde -status'." -ForegroundColor Cyan
}
        "0" {
            $confirmReboot = Read-Host "Are you sure you want to reboot now? (Y/N)"
            if ($confirmReboot -match "^[Yy]$") {
                Write-Host "`nRebooting system..." -ForegroundColor Yellow
                Log "System reboot initiated"
                Restart-Computer -Force
            } else {
                Write-Host "Reboot canceled." -ForegroundColor DarkGray
            }
        }
        "X" {
            Write-Host "`nExiting IT Technician Toolbox..." -ForegroundColor Cyan
            Log "Exited Toolbox"
            break
        }
        default {
            Write-Host "Invalid selection. Try again." -ForegroundColor Red
        }
    }

    if ($choice.ToUpper() -ne "X") {
        Write-Host "`nPress Enter to continue..." -ForegroundColor DarkGray
        [void][System.Console]::ReadLine()
        Clear-Host
        Write-Host "=== IT TECHNICIAN TOOLBOX ===`n" -ForegroundColor Cyan
    }

} while ($choice.ToUpper() -ne "X")

Write-Host "`nGoodbye!" -ForegroundColor Cyan
Start-Sleep 1
exit

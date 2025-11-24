# ==============================================================
#  PRE-CLONE SYSTEM PREPARATION TOOL - v4.5 (Compu-Tek Edition)
# ==============================================================

# --- Elevate to Admin ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
 ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Requesting admin rights..." -ForegroundColor Yellow
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- Setup ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $ScriptDir) { $ScriptDir = Get-Location }
$Computer = $env:COMPUTERNAME
$Time = Get-Date -Format "yyyyMMdd_HHmmss"

Clear-Host
Write-Host "==== PRE-CLONE SYSTEM PREPARATION TOOL ====" -ForegroundColor Cyan
Write-Host "Running as Administrator.`n" -ForegroundColor Green

# ==============================================================
#   BITLOCKER SECTION (prompt + progress monitor, detects Used Space Only)
# ==============================================================

Write-Host "Checking BitLocker status..." -ForegroundColor Cyan
$decryptedAny = $false
$encrypted = @()

# Detect encrypted volumes
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object {
    $_.Name -match "^[A-Z]$" -and
    (Get-Volume -DriveLetter $_.Name -ErrorAction SilentlyContinue).DriveType -ne 'Removable'
}

foreach ($d in $drives) {
    $mp = $d.Name + ":"
    $statusOutput = & manage-bde -status $mp 2>$null
    if (-not $statusOutput) { continue }

    # Detect any encryption state that means the drive is not fully decrypted
    if ($statusOutput -match "Conversion Status:\s+(Used Space Only Encrypted|Fully Encrypted|Encryption in Progress|Decryption in Progress)") {
        $encrypted += $mp
    }
}

if ($encrypted.Count -gt 0) {
    Write-Host "`nEncrypted volumes detected:" -ForegroundColor Yellow
    $encrypted | ForEach-Object { Write-Host " - $_" -ForegroundColor Cyan }

    $confirm = Read-Host "`nDo you want to decrypt these drives now? (Y/N)"
    if ($confirm -match "^[Yy]$") {
        $decryptedAny = $true
        $KeyDir = Join-Path $ScriptDir ("BitLockerKeys\" + $Computer)
        if (-not (Test-Path $KeyDir)) { New-Item -Path $KeyDir -ItemType Directory | Out-Null }

        foreach ($mp in $encrypted) {
            Write-Host "`nStarting BitLocker decryption for $mp..." -ForegroundColor Yellow

            # Export protector info
            $outFile = Join-Path $KeyDir ("BitLockerKey_{0}_{1}.txt" -f ($mp.TrimEnd(":")), $Time)
            $protectorInfo = & manage-bde -protectors -get $mp 2>$null
            if ($protectorInfo) {
                $keyLines = $protectorInfo | Select-String -Pattern "Password|ID:|Numerical Password" -Context 0,2
                if ($keyLines) {
                    $keyLines | ForEach-Object { $_.Line } | Out-File $outFile
                } else {
                    $protectorInfo | Out-File $outFile
                }
                Write-Host "Saved BitLocker key for $mp → $outFile" -ForegroundColor Green
            }

            # Begin decryption
            & manage-bde -protectors -disable $mp | Out-Null
            & manage-bde -off $mp | Out-Null

            Write-Host "Monitoring decryption progress on $mp (updates every 60s) ..." -ForegroundColor Cyan

            do {
                $out = (& manage-bde -status $mp 2>$null) -join "`n"
                $percent = 0
                $conv = "Unknown"

                if ($out -match "Percentage Encrypted:\s+([\d\.]+)%") {
                    try { $percent = [math]::Round([double]$matches[1]) } catch { $percent = 0 }
                }
                if ($out -match "Conversion Status:\s+([A-Za-z\s]+)") {
                    try { $conv = $matches[1].Trim() } catch { $conv = "Unknown" }
                }

                Write-Progress -Activity "Decrypting $mp" `
                    -Status ("{0}% encrypted ({1})" -f $percent, $conv) `
                    -PercentComplete $percent

                Write-Host ("{0} - {1}% encrypted ({2})" -f $mp, $percent, $conv) -ForegroundColor Yellow
                Start-Sleep -Seconds 60
            } while ($conv -notmatch "Fully Decrypted")

            Write-Progress -Activity "Decrypting $mp" -Completed
            Write-Host "Drive $mp fully decrypted." -ForegroundColor Green
        }
    } else {
        Write-Host "Skipping BitLocker decryption. No keys or folders created." -ForegroundColor Yellow
    }
} else {
    Write-Host "No encrypted volumes detected." -ForegroundColor Green
}

Write-Host ""
Write-Host "BitLocker section complete." -ForegroundColor Green

# ==============================================================
#   PREVENT AUTO-REENCRYPTION (only if decryption occurred)
# ==============================================================

if ($decryptedAny) {
    Write-Host "Applying BitLocker re-encryption prevention..." -ForegroundColor Cyan
    try {
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v PreventDeviceEncryption /t REG_DWORD /d 1 /f | Out-Null
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v PreventAutoEncryption /t REG_DWORD /d 1 /f | Out-Null
        reg add "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE" /v DisableAutoEncryption /t REG_DWORD /d 1 /f | Out-Null
        Set-Service -Name "BDESVC" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name "BDESVC" -Force -ErrorAction SilentlyContinue
        Write-Host "BitLocker auto-encryption prevention applied successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to apply BitLocker prevention: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Skipped re-encryption prevention (no drives were decrypted)." -ForegroundColor DarkGray
}

# ==============================================================
#   SECURE BOOT STATUS
# ==============================================================

Write-Host "Checking Secure Boot..." -ForegroundColor Cyan
try {
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        $sb = Confirm-SecureBootUEFI
        if ($sb) {
            Write-Host "Secure Boot is ENABLED - cannot be disabled from Windows." -ForegroundColor Yellow
        } else {
            Write-Host "Secure Boot is DISABLED." -ForegroundColor Green
        }
    } else {
        Write-Host "Secure Boot check not supported on this system." -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "Secure Boot query failed." -ForegroundColor Red
}

# ==============================================================
#   CHKDSK SMART MODE
# ==============================================================

Write-Host "Running CHKDSK smart check..." -ForegroundColor Cyan
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:' }

foreach ($d in $drives) {
    $drive = "$($d.Name):"
    if ((Get-Volume -DriveLetter $d.Name -ErrorAction SilentlyContinue).DriveType -eq 'Removable') {
        Write-Host "Skipped CHKDSK on removable drive $drive"
        continue
    }

    Write-Host "Running quick CHKDSK on $drive..." -ForegroundColor Yellow
    $output = cmd /c "chkdsk $drive" 2>&1

    if ($output -match 'errors found' -or $output -match 'corrupt') {
        Write-Host "Errors detected on $drive - rerunning with /R..." -ForegroundColor Yellow
        Start-Process cmd "/c chkdsk $drive /r" -Wait -NoNewWindow
        Write-Host "CHKDSK /R completed on $drive" -ForegroundColor Green
    } else {
        Write-Host "$drive is clean." -ForegroundColor Green
    }
}

# ==============================================================
#   SUMMARY
# ==============================================================

Write-Host "`n==== SUMMARY ====" -ForegroundColor Cyan
if ($decryptedAny) {
    Write-Host "BitLocker keys saved in: $ScriptDir\BitLockerKeys\$Computer" -ForegroundColor Yellow
    Write-Host "BitLocker auto-encryption prevention applied." -ForegroundColor Cyan
} else {
    Write-Host "No BitLocker actions performed." -ForegroundColor DarkGray
}
Write-Host "Secure Boot status checked." -ForegroundColor Cyan

$reboot = Read-Host "Reboot now? (Y/N)"
if ($reboot -match '^[Yy]') { Restart-Computer -Force }

Write-Host ""
Write-Host "Press any key to close..." -ForegroundColor Cyan
[void][System.Console]::ReadKey($true)

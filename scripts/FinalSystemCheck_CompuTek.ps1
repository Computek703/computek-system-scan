# =====================================================
#  FINAL SYSTEM READINESS CHECK - COMPU-TEK
# =====================================================
$Host.UI.RawUI.WindowTitle = "Final System Readiness Check - Compu-TEK"
Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "      FINAL SYSTEM READINESS CHECK - COMPU-TEK" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

$BitLockerSkipped = $false
$SpeakerTestFailed = $false

# --- 1. Windows Edition & Activation ---
$edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
Write-Host "[INFO] Windows Edition: $edition" -ForegroundColor Cyan

try {
    $l = Get-CimInstance SoftwareLicensingProduct |
         Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 }
    if ($l) {
        Write-Host "[OK] Windows is activated." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Windows not activated!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to determine activation status." -ForegroundColor Yellow
}

# --- 1b. Disable and verify Hibernation ---
try {
    Write-Host "`n[INFO] Checking hibernation status..." -ForegroundColor Cyan
    $hiberStatus = (powercfg /a) | Select-String "Hibernate"

    if ($hiberStatus -match "not available") {
        Write-Host "[OK] Hibernation already disabled." -ForegroundColor Green
    } else {
        Write-Host "[INFO] Disabling hibernation..." -ForegroundColor Cyan
        powercfg -h off | Out-Null
        Start-Sleep -Seconds 1
        $check = (powercfg /a) | Select-String "not available"
        if ($check) {
            Write-Host "[OK] Hibernation successfully disabled." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Could not confirm hibernation is off." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "[WARN] Unable to modify hibernation settings." -ForegroundColor Yellow
}

# --- 2. BitLocker (skip for Home/Core editions) ---
if ($edition -match 'Home' -or $edition -match 'Core' -or $edition -match 'SingleLanguage') {
    Write-Host "[INFO] BitLocker check skipped: Windows Home/Core edition detected." -ForegroundColor Cyan
    $BitLockerSkipped = $true
}
else {
    try {
        Write-Host "`n[INFO] Checking and repairing BitLocker configuration..." -ForegroundColor Cyan

        # --- Step 1: Remove prevention flags that could block encryption ---
        $regPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker",
            "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
        )

        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                foreach ($name in @("PreventDeviceEncryption", "PreventAutoEncryption", "DisableAutoEncryption")) {
                    $val = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).$name
                    if ($val -eq 1) {
                        Write-Host "[FIX] Removing BitLocker restriction flag: $name" -ForegroundColor Yellow
                        Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        Write-Host "[OK] BitLocker policy flags verified." -ForegroundColor Green

        # --- Step 2: Check BitLocker status per drive ---
        $oldPref = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Import-Module BitLocker -ErrorAction SilentlyContinue | Out-Null
        $WarningPreference = $oldPref

        $vols = Get-BitLockerVolume -ErrorAction Stop
        if ($vols) {
            foreach ($v in $vols) {
                $label = (Get-Volume -DriveLetter $v.MountPoint.TrimEnd(':') -ErrorAction SilentlyContinue).FileSystemLabel
                if ($label -match 'Ventoy' -or $label -match 'VTOYEFI' -or
                    $v.MountPoint -match 'Ventoy' -or $v.MountPoint -match 'VTOYEFI') { continue }

                $status = $v.EncryptionPercentage
                $state  = $v.VolumeStatus
                $prot   = $v.ProtectionStatus

                if ($state -match "FullyEncrypted" -or $state -match "UsedSpaceOnlyEncrypted" -or $status -eq 100) {
                    Write-Host "[OK] BitLocker active on drive $($v.MountPoint) ($state, $status%)" -ForegroundColor Green
                }
                elseif ($prot -eq 'Off' -or $state -match "FullyDecrypted") {
                    Write-Host "[WARN] BitLocker off on drive $($v.MountPoint)" -ForegroundColor Yellow
                }
                else {
                    Write-Host "[INFO] BitLocker unknown state on $($v.MountPoint) ($state)" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "[INFO] No BitLocker volumes found." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "[WARN] Unable to query BitLocker status or clear flags." -ForegroundColor Yellow
    }
}

# --- 3. Active Virus Protection ---
try {
    $defender = $null
    $otherAV  = $null

    try { $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue } catch {}

    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue

    if ($defender -and $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
        Write-Host "[OK] Microsoft Defender active and protecting." -ForegroundColor Green
    }
    elseif ($avProducts -and ($avProducts.productState -ne $null)) {
        $names = ($avProducts.displayName | Sort-Object -Unique) -join ", "
        Write-Host "[INFO] Third-party AV detected: $names (Defender off)" -ForegroundColor Cyan
    }
    else {
        Write-Host "[WARN] No active antivirus protection detected!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to verify antivirus protection." -ForegroundColor Yellow
}

# --- 4. Splashtop Streamer ---
try {
    $svc = Get-Service -Name "SplashtopRemoteService" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Host "[OK] Splashtop Streamer running." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Splashtop Streamer not detected or not running!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to check Splashtop service." -ForegroundColor Yellow
}

# --- 5. Windows Updates ---
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and Type='Software'")
    $count    = $result.Updates.Count
    if ($count -gt 0) {
        Write-Host "[WARN] Pending Windows Updates: $count" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] Windows is up to date." -ForegroundColor Green
    }
} catch {
    if ($_.Exception.HResult -eq -2145124318) {
        Write-Host "[INFO] Updates managed by WSUS or policy." -ForegroundColor Cyan
    } else {
        Write-Host "[INFO] Windows Update check skipped due to restriction." -ForegroundColor Cyan
    }
}

# --- 6. Device Manager ---
try {
    $e = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Error' }
    if ($null -ne $e -and $e.Count -gt 0) {
        foreach ($i in $e) {
            Write-Host "[WARN] Device Issue: $($i.FriendlyName) ($($i.InstanceId))" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] No device issues found." -ForegroundColor Green
    }
} catch {
    Write-Host "[WARN] Unable to query Device Manager." -ForegroundColor Yellow
}

# --- 7. System Restore Point (Hardened for field use) ---
try {
    Write-Host "`n[INFO] Checking System Restore configuration..." -ForegroundColor Cyan

    # Detect system drive
    $sysDrive = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).SystemDrive
    if (-not $sysDrive) { 
        Write-Host "[WARN] Unable to detect system drive for restore point." -ForegroundColor Yellow
        throw "No system drive" 
    }

    # Check if System Protection is enabled
    $shadowInfo = vssadmin list shadowstorage 2>$null
    $enabled = $shadowInfo -match [regex]::Escape($sysDrive)

    if (-not $enabled) {
        Write-Host "[INFO] System Protection appears OFF for $sysDrive. Attempting to enable..." -ForegroundColor Cyan
        try {
            Enable-ComputerRestore -Drive $sysDrive -ErrorAction Stop
            Write-Host "[OK] System Protection enabled." -ForegroundColor Green
        } catch {
            Write-Host "[WARN] Could not enable System Protection. It may be disabled by policy on this machine." -ForegroundColor Yellow
            Write-Host "[INFO] Skipping restore point creation." -ForegroundColor DarkGray
            throw "ProtectionOff"
        }
    } else {
        Write-Host "[OK] System Protection already active on $sysDrive." -ForegroundColor Green
    }

    # Attempt to create restore point
    try {
        $dateLabel = (Get-Date).ToString("yyyy-MM-dd_HHmm")
        Write-Host "[INFO] Creating System Restore Point..." -ForegroundColor Cyan

        Checkpoint-Computer `
            -Description "Compu-TEK Readiness Check - $dateLabel" `
            -RestorePointType MODIFY_SETTINGS `
            -ErrorAction Stop

        Write-Host "[OK] Restore Point created successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Restore point could NOT be created. (Likely VSS or policy issue)" -ForegroundColor Yellow
    }

} catch {
    # This catches all failures, but *never* ends the script
    Write-Host "[INFO] System Restore section skipped due to environment restrictions." -ForegroundColor DarkGray
}

# --- 8. Audio Device / Speaker Check ---
try {
    Write-Host ""
    Write-Host "---------------------------------------------------"
    Write-Host "[8/8] Checking audio output devices..." -ForegroundColor Cyan

    $audioDevices = Get-CimInstance Win32_SoundDevice -ErrorAction SilentlyContinue
    $activeAudio  = $audioDevices | Where-Object { $_.Status -eq "OK" }

    if (-not $activeAudio) {
        Write-Host "[WARN] No active audio output device detected!" -ForegroundColor Yellow
        $SpeakerTestFailed = $true
    }
    else {
        $device = $activeAudio | Select-Object -First 1
        $driver = $device.DriverProviderName
        $name   = $device.Name

        Write-Host ("[OK] Active audio device detected: " + $name) -ForegroundColor Green

        if ($driver -match "Microsoft") {
            Write-Host "[WARN] Generic Microsoft audio driver in use -- verify correct sound driver installed." -ForegroundColor Yellow
        } else {
            Write-Host ("[INFO] Audio driver provider: " + $driver) -ForegroundColor Cyan
        }

        try {
            $code = @"
using System;
using System.Runtime.InteropServices;

[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
    void RegisterControlChangeNotify(IntPtr pNotify);
    void UnregisterControlChangeNotify(IntPtr pNotify);
    void GetChannelCount(out uint pnChannelCount);
    void SetMasterVolumeLevel(float fLevelDB, Guid pguidEventContext);
    void SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext);
    void GetMasterVolumeLevel(out float pfLevelDB);
    void GetMasterVolumeLevelScalar(out float pfLevel);
    void SetChannelVolumeLevel(uint nChannel, float fLevelDB, Guid pguidEventContext);
    void SetChannelVolumeLevelScalar(uint nChannel, float fLevel, Guid pguidEventContext);
    void GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
    void GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
    void SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext);
    void GetMute(out bool pbMute);
    void GetVolumeStepInfo(out uint pnStep, out uint pnStepCount);
    void VolumeStepUp(Guid pguidEventContext);
    void VolumeStepDown(Guid pguidEventContext);
    void QueryHardwareSupport(out uint pdwHardwareSupportMask);
    void GetVolumeRange(out float pflVolumeMindB, out float pflVolumeMaxdB, out float pflVolumeIncrementdB);
}

[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
    void NotImpl1();
    void GetDefaultAudioEndpoint(uint dataFlow, uint role, out IMMDevice ppDevice);
}

[Guid("D666063F-1587-4E43-81F1-B948E807363F"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
    void Activate(ref Guid id, uint clsCtx, IntPtr pActivationParams, out IAudioEndpointVolume aev);
}

[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
class MMDeviceEnumeratorComObject {}

public class VolumeControl {
    public static void SetVolumeToHalf() {
        var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
        IMMDevice device;
        enumerator.GetDefaultAudioEndpoint(0, 1, out device);
        Guid IID_IAudioEndpointVolume = typeof(IAudioEndpointVolume).GUID;
        IAudioEndpointVolume volume;
        device.Activate(ref IID_IAudioEndpointVolume, 23, IntPtr.Zero, out volume);
        volume.SetMute(false, Guid.Empty);
        volume.SetMasterVolumeLevelScalar(0.5f, Guid.Empty);
    }
}
"@
            Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
            [VolumeControl]::SetVolumeToHalf()
            Write-Host "[INFO] Speaker volume set to 50% and unmuted." -ForegroundColor Cyan
        } catch {
            Write-Host "[INFO] Unable to modify speaker volume (non-fatal)." -ForegroundColor DarkGray
        }

        try {
            Write-Host "[INFO] Playing Compu-Tek test melody..." -ForegroundColor Cyan

            function Play-Note {
                param ([int]$freq, [int]$dur)
                if ($dur -lt 150) { $dur = 150 }
                Start-Sleep -Milliseconds 30
                [console]::Beep($freq, $dur)
                Start-Sleep -Milliseconds ($dur + 150)
            }

            $notes = @{
                "G" = 392; "A" = 440; "B" = 494;
                "C" = 522; "D" = 588; "E" = 658
            }

            $melody = @(
                @("G",200),@("G",200),@("G",200),
                @("C",600),@("E",200),
                @("G",200),@("G",200),@("G",200),
                @("C",600),@("E",200),
                @("C",200),@("C",200),
                @("B",200),@("B",200),
                @("A",200),@("A",200),
                @("G",600)
            )

            foreach ($note in $melody) {
                try {
                    $freq = $notes[$note[0]]
                    $dur  = $note[1]
                    Play-Note -freq $freq -dur $dur
                } catch {
                    Start-Sleep -Milliseconds 300
                }
            }

            Write-Host "[OK] Speaker test melody completed successfully." -ForegroundColor Green
        } catch {
            Write-Host "[WARN] Speaker test failed during melody playback." -ForegroundColor Yellow
            $SpeakerTestFailed = $true
        }
    }

    $disabled = $audioDevices | Where-Object { $_.Status -ne "OK" }
    if ($disabled) {
        foreach ($d in $disabled) {
            Write-Host ("[WARN] Disabled or problem audio device: " + $d.Name) -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "[WARN] Unable to query audio devices." -ForegroundColor Yellow
    $SpeakerTestFailed = $true
}

# --- Summary ---
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "All checks complete. Review results above." -ForegroundColor Cyan
if ($BitLockerSkipped) {
    Write-Host "[INFO] BitLocker test skipped automatically due to Home/Core edition." -ForegroundColor DarkGray
}
if ($SpeakerTestFailed) {
    Write-Host "[WARN] Speaker test failed -- no audible output detected." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Press Enter to close this window..." -ForegroundColor Cyan
[void][System.Console]::ReadLine()
exit




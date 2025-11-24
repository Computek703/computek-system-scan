# Compu-TEK Technician Toolbox

A portable PowerShell-based launcher that discovers every `.ps1` script in the `scripts/` directory, presents them in a menu, and starts them in elevated PowerShell windows. Use it from a USB stick or shared folder to run common post-scam and readiness checks on Windows systems.

## Launching the toolbox

1. Copy the repository contents to a Windows workstation (USB, network share, or local folder).
2. Double-click `Launch_CTSupport_Toolbox.bat`. The batch file opens an elevated PowerShell window and runs `CTSupport_Toolbox.ps1`.
3. Pick an individual tool by number, or choose **A** to launch all scripts. New `.ps1` files dropped into the `scripts/` directory are automatically listed the next time the menu appears.

> All tools request administrative rights up front so they can read system state, create logs, and make changes when needed.

## Included tools

### FinalSystemCheck_CompuTek.ps1
End-of-job readiness checklist:
- Reports Windows edition and activation status, disables hibernation, and confirms BitLocker policy flags are not blocking encryption.
- Checks antivirus posture (Defender or third-party), Splashtop service health, pending Windows Updates, and Device Manager errors.
- Attempts to enable System Protection and create a restore point when allowed by policy.
- Verifies audio devices, un-mutes/sets volume to 50%, and plays a short melody to confirm speaker output.

### IT_Technician_Toolbox.ps1
Quick access maintenance menu with logging to `%TEMP%\toolbox_log.txt`:
- System and network information, DNS flush + IP renew, internet connectivity tests.
- Temp file cleanup, SFC, CHKDSK (drive picker), DISM restore health, Task Manager launch, and print queue reset.
- BitLocker “used space only” enablement workflow that stores recovery keys under `BitLockerKeys/<COMPUTERNAME>` next to the script.

### PreClone.ps1
Pre-imaging helper focused on BitLocker and disk health:
- Detects encrypted volumes, exports recovery info, decrypts if approved, and monitors progress.
- Optionally blocks automatic re-encryption and disables the BitLocker service when decryption occurred.
- Checks Secure Boot state, runs CHKDSK (smart mode), and summarizes actions, including key save location.

### PostScam_SystemIntegrityScanner.ps1
Two-week lookback audit for scam cleanup:
- Scans user profiles for startup items, Run keys, and downloaded installers tied to common remote-access tools.
- Flags suspicious services, scheduled tasks, hosts file entries, firewall rules, new admins, recent users, unsigned drivers, recent installs, and PowerShell abuse events.
- Logs results to `PostScam_Audit_<COMPUTER>_<timestamp>.txt` in the script directory.

### RemoteAccessScanAndRemove.ps1
Finds and removes remote access clients:
- Detects ScreenConnect/ConnectWise, TeamViewer, AnyDesk, VNC variants, Splashtop, Zoho Assist, and Chrome Remote Desktop via services, processes, and uninstall entries.
- Searches common download/startup folders for leftover installers, then provides a numbered removal menu.
- Creates separate scan, removal, and error logs in the `%TEMP%` directory.

## Notes
- The launcher sorts scripts alphabetically; rename files to control menu order.
- All scripts run with `-ExecutionPolicy Bypass` to simplify use on locked-down machines.
- Keep the `scripts/` folder alongside the launcher so discovery and key-storage paths remain valid.

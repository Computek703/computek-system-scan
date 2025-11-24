<#
 RemoteAccessScanAndRemove.ps1
 - Detects and uninstalls remote access apps
 - Stops services & processes (including disabled)
 - Scans for leftover installers and startup entries
 - Logs actions and summarizes results
#>

$ErrorActionPreference = 'Continue'
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$ScanLog   = Join-Path $env:TEMP "RemoteAccess_Scan_$timestamp.txt"
$RemoveLog = Join-Path $env:TEMP "RemoteAccess_Remove_$timestamp.txt"
$ErrorLog  = Join-Path $env:TEMP "RemoteAccess_Error_$timestamp.txt"

function Log-Scan   { param($m) $m | Out-File -FilePath $ScanLog   -Append -Encoding utf8 }
function Log-Remove { param($m) $m | Out-File -FilePath $RemoveLog -Append -Encoding utf8 }
function Log-Error  { param($m) $m | Out-File -FilePath $ErrorLog  -Append -Encoding utf8 }

function Split-UninstallString {
    param($u)
    if (-not $u) { return @{Exe=''; Args=$null} }
    $u = $u.Trim()
    if ($u -match '^\s*"([^"]+)"\s*(.*)$') {
        return @{Exe = $Matches[1]; Args = if ($Matches[2]) { $Matches[2].Trim() } else { $null } }
    }
    $parts = $u -split '\s+',2
    return @{Exe = $parts[0]; Args = if ($parts.Count -gt 1) { $parts[1] } else { $null } }
}

function Find-InstalledStrict {
    param($patterns)
    $results = @()
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($rp in $regPaths) {
        Get-ChildItem $rp -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and ($p.DisplayName -or $p.Publisher -or $p.InstallLocation)) {
                foreach ($pat in $patterns) {
                    if ($p.DisplayName -like $pat -or $p.Publisher -like $pat -or $p.InstallLocation -like $pat) {
                        $results += [pscustomobject]@{
                            DisplayName     = $p.DisplayName
                            Publisher       = $p.Publisher
                            UninstallString = $p.UninstallString
                            RegistryKey     = $_.PSPath
                        }
                        break
                    }
                }
            }
        }
    }
    return $results | Select-Object -Unique
}

function Stop-Kill-ServiceProcess {
    param($ServiceNames,$ProcessNames)

    foreach ($s in $ServiceNames) {
        $svc = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $s }
        if ($svc) {
            Write-Host "Stopping service $s (State: $($svc.State))..." -ForegroundColor DarkYellow
            try {
                sc.exe stop $s | Out-Null
                Start-Sleep -Seconds 2
                sc.exe delete $s | Out-Null
                Write-Host "Service $s stopped and removed." -ForegroundColor Green
            } catch {
                Write-Host "Could not stop/remove service $s" -ForegroundColor Yellow
                Log-Remove "Service $s could not be stopped/removed."
            }
        }
    }

    foreach ($p in $ProcessNames) {
        $procs = Get-Process -Name $p -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            Write-Host "Killing process $($proc.ProcessName)..." -ForegroundColor DarkYellow
            try {
                Stop-Process -Id $proc.Id -Force
                Write-Host "Process $($proc.ProcessName) killed." -ForegroundColor Green
            } catch {
                Write-Host "Could not kill process $($proc.ProcessName)" -ForegroundColor Yellow
                Log-Remove "Process $($proc.ProcessName) could not be killed."
            }
        }
    }
}

function Invoke-SmartUninstall {
    param($Product)

    $display = if ($Product.Installed -and $Product.Installed[0].DisplayName) {
        $Product.Installed[0].DisplayName
    } else {
        $Product.Key
    }

    $uninst  = if ($Product.Installed) { $Product.Installed[0].UninstallString } else { $null }

    Stop-Kill-ServiceProcess -ServiceNames $Product.Services -ProcessNames $Product.Processes

    Write-Host ""
    Write-Host "=== Uninstall: ${display} ===" -ForegroundColor Magenta
    Log-Remove "Attempting uninstall for ${display} at $(Get-Date)"

    if ($uninst) {
        $split = Split-UninstallString -u $uninst
        $exe = $split.Exe
        $args = $split.Args

        if ($exe -and (Test-Path $exe)) {
            if ($exe -imatch 'msiexec' -and $uninst -match '{[0-9A-Fa-f-]+}') {
                $guid = $Matches[0]
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x",$guid,"/qn","/norestart" -Wait
            } else {
                if ($args) {
                    Start-Process -FilePath $exe -ArgumentList $args -Wait
                } else {
                    Start-Process -FilePath $exe -Wait
                }
            }
        } else {
            Write-Host "Uninstaller not found for $display" -ForegroundColor Yellow
            Log-Error "Uninstaller not found for $display"
        }
    } else {
        Write-Host "No uninstaller string for $display - manual removal required." -ForegroundColor Yellow
        Log-Error "$display detected but no uninstall entry found"
    }
}

# --- Known products ---
$KnownProducts = @(
    @{Key='ScreenConnect'; DisplayNames=@('*ScreenConnect*','*ConnectWise Control*'); Procs=@('ScreenConnect.ClientService'); Svcs=@('ScreenConnect Client')},
    @{Key='TeamViewer'; DisplayNames=@('*TeamViewer*'); Procs=@('TeamViewer','TeamViewer_Service'); Svcs=@('TeamViewer')},
    @{Key='AnyDesk'; DisplayNames=@('*AnyDesk*'); Procs=@('AnyDesk'); Svcs=@('AnyDesk Service')},
    @{Key='UltraViewer'; DisplayNames=@('*UltraViewer*'); Procs=@('UltraViewer'); Svcs=@()},
    @{Key='LogMeIn'; DisplayNames=@('*LogMeIn*'); Procs=@('LogMeIn','LogMeInSystray','LogMeInMaintenanceService'); Svcs=@('LogMeIn','LMIGuardianSvc')},
    @{Key='RescueCallingCard'; DisplayNames=@('*Rescue Calling Card*','*LogMeIn Rescue*','*LogMeIn Rescue Calling Card*'); Procs=@('RescueCallingCard','CallingCard'); Svcs=@('RescueCallingCard','LMIRfsClientNP')},
    @{Key='VNC'; DisplayNames=@('*RealVNC*','*TightVNC*','*UltraVNC*','*VNC Server*','*VNC Viewer*'); Procs=@('vncserver','winvnc','tvnserver','vncviewer'); Svcs=@('VNC Server','WinVNC','uvnc_service','tvnserver')},
    @{Key='Splashtop'; DisplayNames=@('*Splashtop*'); Procs=@('SRService','Splashtop'); Svcs=@('SplashtopRemoteService')},
    @{Key='ZohoAssist'; DisplayNames=@('*Zoho*','*Zoho Corporation*','*Zoho Assist*'); Procs=@('Zoho','ZohoMeeting'); Svcs=@()},
    @{Key='ChromeRemoteDesktop'; DisplayNames=@('*Chrome Remote Desktop*'); Procs=@('remoting_host'); Svcs=@('chromoting')}
)

Write-Host "Scanning for remote access tools..." -ForegroundColor Cyan
$scanResults = @()

foreach ($prod in $KnownProducts) {
    $installed = Find-InstalledStrict -patterns $prod.DisplayNames
    $svc  = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $prod.Svcs }
    $proc = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in $prod.Procs }

    if ($installed -or $proc -or $svc) {
        $scanResults += [pscustomobject]@{
            Key=$prod.Key; Installed=$installed; Processes=$prod.Procs; Services=$prod.Svcs
        }
        Write-Host "Detected: $($prod.Key)" -ForegroundColor Green
    }
}

# --- check for leftover installers ---
Write-Host "`nChecking for leftover installers..." -ForegroundColor Cyan
$searchPaths = @(
    "$env:USERPROFILE\Downloads",
    "$env:PUBLIC\Downloads",
    "$env:TEMP",
    "$env:USERPROFILE\Desktop"
) | Where-Object { Test-Path $_ }

$installerHits = @()
foreach ($path in $searchPaths) {
    foreach ($prod in $KnownProducts) {
        foreach ($name in $prod.DisplayNames) {
            $found = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -like $name -and $_.Extension -match '\.(exe|msi|zip|rar)$'
            }
            if ($found) {
                foreach ($f in $found) {
                    $installerHits += $f.FullName
                    Write-Host "[Installer] $($f.Name) — $path" -ForegroundColor Yellow
                    Log-Scan "Installer found: $($f.FullName)"
                }
            }
        }
    }
}

# --- check startup folders ---
Write-Host "`nChecking Windows Startup folders..." -ForegroundColor Cyan
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
) | Where-Object { Test-Path $_ }

$startupHits = @()
foreach ($folder in $startupPaths) {
    $items = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue
    foreach ($prod in $KnownProducts) {
        foreach ($name in $prod.DisplayNames) {
            $match = $items | Where-Object { $_.Name -like $name }
            if ($match) {
                foreach ($m in $match) {
                    $startupHits += $m.FullName
                    Write-Host "[Startup] $($m.Name) — $folder" -ForegroundColor Yellow
                    Log-Scan "Startup entry found: $($m.FullName)"
                }
            }
        }
    }
}

# --- Display summary ---
Write-Host "`n===== SCAN SUMMARY =====" -ForegroundColor Cyan
if ($scanResults) { Write-Host ("Detected remote access apps: {0}" -f $scanResults.Count) -ForegroundColor Green }
if ($installerHits) { Write-Host ("Installer files found: {0}" -f $installerHits.Count) -ForegroundColor Yellow }
if ($startupHits) { Write-Host ("Startup entries found: {0}" -f $startupHits.Count) -ForegroundColor Yellow }
if (-not $scanResults -and -not $installerHits -and -not $startupHits) { Write-Host "No threats or installers found." -ForegroundColor Green }

# open folders if needed
if ($installerHits) {
    Write-Host "`nOpening folder of first installer for review..." -ForegroundColor Cyan
    Start-Process explorer.exe "/select,$($installerHits[0])"
}
elseif ($startupHits) {
    Write-Host "`nOpening startup folder for review..." -ForegroundColor Cyan
    Start-Process explorer.exe (Split-Path $startupHits[0])
}

# --- Removal Menu ---
if (-not $scanResults) {
    Write-Host "`nNo supported remote access software found." -ForegroundColor Green
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "`nDetected remote access clients:" -ForegroundColor Cyan
$menu = @()
[int]$i=0
foreach ($r in $scanResults) {
    $i++
    $summary = "$($r.Key)"
    if ($r.Installed) { $summary += " (Installed:$($r.Installed[0].DisplayName))" }
    $menu += [pscustomobject]@{Index=$i; Key=$r.Key; Ref=$r}
    Write-Host ("{0,2}. {1}" -f $i,$summary) -ForegroundColor Yellow
}

$sel = Read-Host "Enter number(s) to remove (e.g. 1,3) or 'a' for all, 'q' to quit"
if ($sel -eq 'q') { exit }
if ($sel -eq 'a') { $indices=$menu.Index } else {
    $indices = ($sel -split '[,; ]+' | Where-Object {$_ -match '^\d+$'}) -as [int[]]
}
$indices = $indices | Where-Object {$_ -ge 1 -and $_ -le $menu.Count}
if (-not $indices) { Write-Host "No valid selection. Exiting."; Read-Host "Press Enter to exit"; exit }

$confirm = Read-Host "Type YES to confirm removal of: $($indices -join ',')"
if ($confirm -ne 'YES') { Write-Host "Cancelled."; Read-Host "Press Enter to exit"; exit }

foreach ($idx in $indices) {
    $entry = ($menu | Where-Object {$_.Index -eq $idx}).Ref
    Write-Host ""
    Write-Host "Removing $($entry.Key)..." -ForegroundColor Red
    Invoke-SmartUninstall -Product $entry
    Write-Host "Completed removal for $($entry.Key)." -ForegroundColor Green
}

Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Cyan
Write-Host " Scan Log: $ScanLog"
Write-Host " Removal Log: $RemoveLog"
Write-Host " Error Log: $ErrorLog"
Write-Host ""
Read-Host "Press Enter to close this window..."
exit


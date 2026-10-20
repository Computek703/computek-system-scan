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

function Test-MatchesAnyPattern {
    param($Text,$Patterns)
    if (-not $Text) { return $false }
    foreach ($pattern in @($Patterns)) {
        if ($Text -like $pattern) { return $true }
    }
    return $false
}

function Get-AdditionalDriveRoots {
    $roots = @()
    try {
        $logicalDisks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 2 OR DriveType = 3" -ErrorAction Stop
        $roots = @($logicalDisks | Where-Object {
            $_.DeviceID -and $_.DeviceID -ne $env:SystemDrive
        } | ForEach-Object {
            "{0}\" -f $_.DeviceID
        })
    } catch {
        $roots = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object {
            $_.Root -match '^[A-Za-z]:\\$' -and $_.Root.TrimEnd('\') -ne $env:SystemDrive
        } | ForEach-Object { $_.Root })
    }
    return @($roots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)
}

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
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
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

    $allServices = @(Get-WmiObject Win32_Service -ErrorAction SilentlyContinue)
    foreach ($servicePattern in @($ServiceNames)) {
        $services = @($allServices | Where-Object {
            (Test-MatchesAnyPattern -Text $_.Name -Patterns $servicePattern) -or
            (Test-MatchesAnyPattern -Text $_.DisplayName -Patterns $servicePattern)
        })
        foreach ($svc in $services) {
            $serviceName = $svc.Name
            Write-Host "Stopping service $serviceName (State: $($svc.State))..." -ForegroundColor DarkYellow
            try {
                sc.exe stop $serviceName | Out-Null
                Start-Sleep -Seconds 2
                sc.exe delete $serviceName | Out-Null
                Write-Host "Service $serviceName stopped and removed." -ForegroundColor Green
            } catch {
                Write-Host "Could not stop/remove service $serviceName" -ForegroundColor Yellow
                Log-Remove "Service $serviceName could not be stopped/removed."
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
    @{Key='ScreenConnect'; DisplayNames=@('*ScreenConnect*','*ConnectWise Control*'); Procs=@('ScreenConnect.ClientService','ScreenConnect.WindowsClient'); Svcs=@('ScreenConnect Client*'); FilePatterns=@('*screenconnect*','*connectwise*control*')},
    @{Key='TeamViewer'; DisplayNames=@('*TeamViewer*'); Procs=@('TeamViewer','TeamViewer_Service','TeamViewer_Desktop','TeamViewer_Note'); Svcs=@('TeamViewer*'); FilePatterns=@('*teamviewer*')},
    @{Key='TeamRemoteDesktop'; DisplayNames=@('*Team Remote Desktop*'); Procs=@('TeamRemoteDesktop'); Svcs=@(); FilePatterns=@('*team*remote*desktop*')},
    @{Key='AnyDesk'; DisplayNames=@('*AnyDesk*'); Procs=@('AnyDesk'); Svcs=@('AnyDesk*'); FilePatterns=@('*anydesk*')},
    @{Key='RustDesk'; DisplayNames=@('*RustDesk*'); Procs=@('rustdesk','rustdesk_service'); Svcs=@('RustDesk*'); FilePatterns=@('*rustdesk*')},
    @{Key='UltraViewer'; DisplayNames=@('*UltraViewer*'); Procs=@('UltraViewer','UltraViewer_Service'); Svcs=@('*UltraViewer*'); FilePatterns=@('*ultraviewer*')},
    @{Key='LogMeIn'; DisplayNames=@('*LogMeIn*'); Procs=@('LogMeIn','LogMeInSystray','LogMeInMaintenanceService'); Svcs=@('LogMeIn*','LMIGuardianSvc*'); FilePatterns=@('*logmein*')},
    @{Key='RescueCallingCard'; DisplayNames=@('*Rescue Calling Card*','*LogMeIn Rescue*','*GoTo Rescue Calling Card*'); Procs=@('RescueCallingCard','CallingCard'); Svcs=@('RescueCallingCard*','LMIRfsClientNP*'); FilePatterns=@('*rescue*calling*card*','*rescuecallingcard*')},
    @{Key='GoToAssist'; DisplayNames=@('*GoToAssist*'); Procs=@('g2ax_comm_customer','g2ax_service','g2a_customer'); Svcs=@('GoToAssist*'); FilePatterns=@('*gotoassist*','*g2a_customer*')},
    @{Key='GoToOpener'; DisplayNames=@('*GoTo Opener*'); Procs=@('GoTo Opener','g2mcomm'); Svcs=@('GoTo Opener*'); FilePatterns=@('*goto*opener*')},
    @{Key='GoToResolve'; DisplayNames=@('*GoTo Resolve*'); Procs=@('GoToResolve','GoToResolveUnattended','GoToResolveAgent'); Svcs=@('GoTo Resolve*'); FilePatterns=@('*goto*resolve*')},
    @{Key='RealVNC'; DisplayNames=@('*RealVNC*','*VNC Server*','*VNC Viewer*'); Procs=@('vncserver','vncviewer','vncserverui','vncagent'); Svcs=@('VNC Server*','vncserver*'); FilePatterns=@('*realvnc*','*vnc*server*','*vnc*viewer*')},
    @{Key='TightVNC'; DisplayNames=@('*TightVNC*'); Procs=@('tvnserver','tvnviewer'); Svcs=@('tvnserver*','TightVNC*'); FilePatterns=@('*tightvnc*')},
    @{Key='UltraVNC'; DisplayNames=@('*UltraVNC*'); Procs=@('winvnc','vncviewer'); Svcs=@('uvnc_service*','WinVNC*'); FilePatterns=@('*ultravnc*','*uvnc*')},
    @{Key='TigerVNC'; DisplayNames=@('*TigerVNC*'); Procs=@('winvnc4','vncviewer64'); Svcs=@('TigerVNC*'); FilePatterns=@('*tigervnc*')},
    @{Key='Splashtop'; DisplayNames=@('*Splashtop*'); Procs=@('SRService','Splashtop','SplashtopRemoteService','SRManager'); Svcs=@('SplashtopRemoteService*','Splashtop*'); FilePatterns=@('*splashtop*')},
    @{Key='ZohoAssist'; DisplayNames=@('*Zoho Assist*'); Procs=@('ZohoAssist','ZohoURS','ZohoAssistAgent'); Svcs=@('Zoho Assist*','ZohoAssist*'); FilePatterns=@('*zoho*assist*','*zohoassist*')},
    @{Key='ChromeRemoteDesktop'; DisplayNames=@('*Chrome Remote Desktop*'); Procs=@('remoting_host','remote_assistance_host'); Svcs=@('chromoting*'); FilePatterns=@('*chrome*remote*desktop*','*chromeremotedesktop*')},
    @{Key='NetSupportManager'; DisplayNames=@('*NetSupport Manager*','*NetSupport Client*'); Procs=@('client32','pcicfgui','pcideply'); Svcs=@('NetSupport*','NSClient*'); FilePatterns=@('*netsupport*')},
    @{Key='TacticalRMM'; DisplayNames=@('*Tactical RMM*','*Tactical Agent*'); Procs=@('tacticalrmm','tacticalagent','tacticalagent-v2'); Svcs=@('tacticalrmm*','tacticalagent*'); FilePatterns=@('*tactical*rmm*','*tacticalagent*')},
    @{Key='MeshCentral'; DisplayNames=@('*Mesh Agent*','*MeshCentral Agent*'); Procs=@('MeshAgent','meshagent64','meshagent'); Svcs=@('Mesh Agent*','MeshAgent*'); FilePatterns=@('*meshagent*','*meshcentral*')},
    @{Key='RemoteUtilities'; DisplayNames=@('*Remote Utilities*','*Remote Utilities - Host*'); Procs=@('rutserv','rutview','rfusclient','rutserver'); Svcs=@('Remote Utilities*','rutserv*'); FilePatterns=@('*remote*utilities*','*rutserv*')},
    @{Key='DWService'; DisplayNames=@('*DWService*','*DWAgent*'); Procs=@('dwagent','dwagsvc','dwagentui'); Svcs=@('DWAgent*','DWService*'); FilePatterns=@('*dwagent*','*dwservice*')},
    @{Key='Supremo'; DisplayNames=@('*Supremo*'); Procs=@('Supremo','SupremoService'); Svcs=@('Supremo*'); FilePatterns=@('*supremo*')},
    @{Key='AeroAdmin'; DisplayNames=@('*AeroAdmin*'); Procs=@('AeroAdmin'); Svcs=@('AeroAdmin*'); FilePatterns=@('*aeroadmin*')},
    @{Key='AmmyyAdmin'; DisplayNames=@('*Ammyy Admin*','*Ammyy*'); Procs=@('AA_v3','Ammyy_Admin'); Svcs=@('Ammyy*'); FilePatterns=@('*ammyy*','*aa_v3*')},
    @{Key='Atera'; DisplayNames=@('*Atera Agent*','*AteraAgent*'); Procs=@('AteraAgent','AteraAgentService','AgentPackageMonitoring'); Svcs=@('AteraAgent*'); FilePatterns=@('*atera*agent*','*ateraagent*')},
    @{Key='NableTakeControl'; DisplayNames=@('*N-able Take Control*','*Take Control Agent*','*SolarWinds Take Control*'); Procs=@('BASupSrvc','BASupApp','BASupSrvcUpdater','BASupSrvcCnfg','TakeControl'); Svcs=@('BASupportExpressStandaloneService*','Take Control Agent*'); FilePatterns=@('*take*control*agent*','*basupsrvc*')},
    @{Key='NableRMM'; DisplayNames=@('*N-able N-central*','*N-able N-sight*','*Advanced Monitoring Agent*'); Procs=@('winagent','msp-agent-core','msp-agent'); Svcs=@('Windows Agent Service*','Advanced Monitoring Agent*','N-able*Agent*'); FilePatterns=@('*n-able*n-central*','*n-able*n-sight*','*msp-agent*')},
    @{Key='SimpleHelp'; DisplayNames=@('*SimpleHelp*'); Procs=@('SimpleService','SimpleHelp'); Svcs=@('SimpleHelp*'); FilePatterns=@('*simplehelp*')},
    @{Key='BeyondTrustBomgar'; DisplayNames=@('*BeyondTrust Remote Support*','*Bomgar*'); Procs=@('bomgar-scc','bomgar-rep','bomgar-pac'); Svcs=@('Bomgar*','BeyondTrust*Remote*Support*'); FilePatterns=@('*bomgar*','*beyondtrust*remote*support*')},
    @{Key='Dameware'; DisplayNames=@('*Dameware*','*DameWare*'); Procs=@('DWRCS','DameWare.MiniRemoteControl'); Svcs=@('DameWare Mini Remote Control*','DWRCS*'); FilePatterns=@('*dameware*','*dwrcs*')},
    @{Key='ISLOnline'; DisplayNames=@('*ISL Online*','*ISL AlwaysOn*','*ISL Light*'); Procs=@('ISLAlwaysOn','ISLLight','ISLClient'); Svcs=@('ISL AlwaysOn*','ISL Online*'); FilePatterns=@('*isl*alwayson*','*isl*light*','*islonline*')},
    @{Key='RemotePC'; DisplayNames=@('*RemotePC*'); Procs=@('RemotePCService','RemotePCViewer','RemotePCDesktop'); Svcs=@('RemotePC*'); FilePatterns=@('*remotepc*')},
    @{Key='IperiusRemote'; DisplayNames=@('*Iperius Remote*'); Procs=@('IperiusRemote','IperiusRemoteService'); Svcs=@('Iperius Remote*','IperiusRemote*'); FilePatterns=@('*iperius*remote*')},
    @{Key='GetScreen'; DisplayNames=@('*Getscreen.me*','*GetScreen*'); Procs=@('getscreen','getscreen-agent'); Svcs=@('Getscreen*','GetScreen*'); FilePatterns=@('*getscreen*')},
    @{Key='AnyViewer'; DisplayNames=@('*AnyViewer*'); Procs=@('AnyViewer'); Svcs=@('AnyViewer*'); FilePatterns=@('*anyviewer*')},
    @{Key='Radmin'; DisplayNames=@('*Radmin Server*','*Radmin Viewer*'); Procs=@('r_server','Radmin'); Svcs=@('Radmin Server*'); FilePatterns=@('*radmin*')},
    @{Key='LiteManager'; DisplayNames=@('*LiteManager*'); Procs=@('ROMServer','ROMViewer'); Svcs=@('ROMService*','LiteManager*'); FilePatterns=@('*litemanager*','*romserver*')},
    @{Key='NoMachine'; DisplayNames=@('*NoMachine*'); Procs=@('nxserver','nxnode','nxplayer'); Svcs=@('NoMachine*','nxserver*'); FilePatterns=@('*nomachine*')},
    @{Key='Parsec'; DisplayNames=@('*Parsec*'); Procs=@('parsecd','parsec'); Svcs=@('Parsec*'); FilePatterns=@('*parsec*')},
    @{Key='Remotely'; DisplayNames=@('*Remotely*'); Procs=@('Remotely_Agent','Remotely_Desktop'); Svcs=@('Remotely*'); FilePatterns=@('*remotely*agent*','*remotely*desktop*')},
    @{Key='JumpDesktop'; DisplayNames=@('*Jump Desktop Connect*','*Jump Desktop*'); Procs=@('JumpConnect','JumpDesktop'); Svcs=@('Jump Desktop Connect*'); FilePatterns=@('*jump*desktop*')},
    @{Key='FixMeIT'; DisplayNames=@('*FixMe.IT*','*FixMeIT*'); Procs=@('FixMeIT','Techinline'); Svcs=@('FixMe.IT*','Techinline*'); FilePatterns=@('*fixmeit*','*fixme.it*','*techinline*')},
    @{Key='KaseyaVSA'; DisplayNames=@('*Kaseya Agent*','*Kaseya VSA*'); Procs=@('AgentMon','KaseyaRemoteControlHost','KaUsrTsk'); Svcs=@('Kaseya Agent*','KaseyaAgent*'); FilePatterns=@('*kaseya*agent*','*agentmon*','*kaseyaremotecontrolhost*')},
    @{Key='DattoRMM'; DisplayNames=@('*Datto RMM*','*CentraStage*'); Procs=@('CagService','AEMAgent'); Svcs=@('CagService*','Datto RMM*','CentraStage*'); FilePatterns=@('*datto*rmm*','*centrastage*','*cagservice*')},
    @{Key='NinjaOne'; DisplayNames=@('*NinjaOne*','*NinjaRMM*','*Ninja Remote*'); Procs=@('NinjaRMMAgent','NinjaOneAgent','ncstreamer','ncplayer','QClauncher','QCncstreamer'); Svcs=@('NinjaRMMAgent*','NinjaOne*','NinjaRemote*'); FilePatterns=@('*ninjaone*','*ninjarmm*','*ninja*remote*','*ncstreamer*','*qclauncher*','*qcncstreamer*')},
    @{Key='Pulseway'; DisplayNames=@('*Pulseway*','*PC Monitor*'); Procs=@('PCMonitorManager','PCMonitorService','Pulseway'); Svcs=@('PC Monitor*','Pulseway*'); FilePatterns=@('*pulseway*','*pcmonitor*')},
    @{Key='LevelRMM'; DisplayNames=@('*Level RMM*','*Level Agent*'); Procs=@('level-agent','levelagent'); Svcs=@('Level*Agent*'); FilePatterns=@('*level*rmm*','*level*agent*')},
    @{Key='FleetDeck'; DisplayNames=@('*FleetDeck*'); Procs=@('fleetdeck-agent','FleetDeck'); Svcs=@('FleetDeck*'); FilePatterns=@('*fleetdeck*')},
    @{Key='Action1'; DisplayNames=@('*Action1 Agent*','*Action1 Connector*'); Procs=@('action1_agent','action1_connector'); Svcs=@('Action1*'); FilePatterns=@('*action1*')},
    @{Key='ManageEngine'; DisplayNames=@('*ManageEngine Endpoint Central*','*ManageEngine Remote Access Plus*','*Desktop Central Agent*'); Procs=@('dcagentservice','dcagenttrayicon','UEMSAgent'); Svcs=@('ManageEngine*','DesktopCentral*','UEMS*'); FilePatterns=@('*manageengine*','*desktopcentral*','*remote*access*plus*')},
    @{Key='ConnectWiseAutomate'; DisplayNames=@('*ConnectWise Automate*','*LabTech*'); Procs=@('LTService','LTSvcMon'); Svcs=@('LTService*','LTSvcMon*'); FilePatterns=@('*connectwise*automate*','*labtech*','*ltservice*')},
    @{Key='ScreenMeet'; DisplayNames=@('*ScreenMeet*'); Procs=@('ScreenMeetSupport','ScreenMeetLive'); Svcs=@('ScreenMeet*'); FilePatterns=@('*screenmeet*')},
    @{Key='Alpemix'; DisplayNames=@('*Alpemix*'); Procs=@('Alpemix'); Svcs=@('Alpemix*'); FilePatterns=@('*alpemix*')},
    @{Key='Sunlogin'; DisplayNames=@('*Sunlogin*','*Sunflower Remote Control*'); Procs=@('SunloginClient','SunloginRemote'); Svcs=@('Sunlogin*'); FilePatterns=@('*sunlogin*','*sunflower*remote*control*')},
    @{Key='ToDesk'; DisplayNames=@('*ToDesk*'); Procs=@('ToDesk','ToDesk_Service'); Svcs=@('ToDesk*'); FilePatterns=@('*todesk*')},
    @{Key='HopToDesk'; DisplayNames=@('*HopToDesk*'); Procs=@('HopToDesk'); Svcs=@('HopToDesk*'); FilePatterns=@('*hoptodesk*')},
    @{Key='HelpWire'; DisplayNames=@('*HelpWire*'); Procs=@('HelpWire','HelpWireAgent'); Svcs=@('HelpWire*'); FilePatterns=@('*helpwire*')},
    @{Key='eHorus'; DisplayNames=@('*eHorus*','*Pandora RC Agent*'); Procs=@('ehorus_agent','PandoraRC'); Svcs=@('eHorus*','Pandora RC*'); FilePatterns=@('*ehorus*','*pandora*rc*')},
    @{Key='DeskIn'; DisplayNames=@('*DeskIn*'); Procs=@('DeskIn'); Svcs=@('DeskIn*'); FilePatterns=@('*deskin*')},
    @{Key='TSplusRemoteSupport'; DisplayNames=@('*TSplus Remote Support*'); Procs=@('TSplus-RemoteSupport'); Svcs=@('TSplus Remote Support*'); FilePatterns=@('*tsplus*remote*support*')}
)

Write-Host "Scanning for remote access tools..." -ForegroundColor Cyan
$scanResults = @()
$allServices = @(Get-WmiObject Win32_Service -ErrorAction SilentlyContinue)
$allProcesses = @(Get-Process -ErrorAction SilentlyContinue)

foreach ($prod in $KnownProducts) {
    $installed = Find-InstalledStrict -patterns $prod.DisplayNames
    $svc = @($allServices | Where-Object {
        (Test-MatchesAnyPattern -Text $_.Name -Patterns $prod.Svcs) -or
        (Test-MatchesAnyPattern -Text $_.DisplayName -Patterns $prod.Svcs)
    })
    $proc = @($allProcesses | Where-Object { $_.ProcessName -in $prod.Procs })

    if ($installed -or $proc -or $svc) {
        $scanResults += [pscustomobject]@{
            Key=$prod.Key; Installed=$installed; Processes=$prod.Procs; Services=$prod.Svcs
        }
        Write-Host "Detected: $($prod.Key)" -ForegroundColor Green
    }
}

# --- check for leftover installers ---
Write-Host "`nChecking for leftover installers..." -ForegroundColor Cyan
$additionalDriveRoots = @(Get-AdditionalDriveRoots)
$searchPaths = @(
    "$env:USERPROFILE\Downloads",
    "$env:PUBLIC\Downloads",
    "$env:TEMP",
    "$env:USERPROFILE\Desktop"
)
$searchPaths += $additionalDriveRoots
$searchPaths = @($searchPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)

if ($additionalDriveRoots.Count -gt 0) {
    Write-Host ("Additional drives: {0}" -f ($additionalDriveRoots -join ', ')) -ForegroundColor DarkCyan
}

$installerHits = @()
$allFilePatterns = @($KnownProducts | ForEach-Object { $_.FilePatterns } | Select-Object -Unique)
foreach ($path in $searchPaths) {
    Write-Host "Scanning: $path" -ForegroundColor DarkGray
    $candidateFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -match '\.(exe|msi|msix|msixbundle|appx|appxbundle|zip|rar|7z)$'
    }
    foreach ($f in $candidateFiles) {
        if (Test-MatchesAnyPattern -Text $f.Name -Patterns $allFilePatterns) {
            $installerHits += $f.FullName
            Write-Host "[Installer] $($f.Name) - $path" -ForegroundColor Yellow
            Log-Scan "Installer found: $($f.FullName)"
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
        foreach ($name in $prod.FilePatterns) {
            $match = $items | Where-Object { $_.Name -like $name }
            if ($match) {
                foreach ($m in $match) {
                    $startupHits += $m.FullName
                    Write-Host "[Startup] $($m.Name) - $folder" -ForegroundColor Yellow
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


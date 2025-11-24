<# 
 PostScam_SystemIntegrityScanner.ps1  — Technician Edition
 Fully integrated multi-user and system scan
#>

# --- Elevation ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
 ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Requesting administrative privileges..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"" -Verb RunAs
    exit
}

$Host.UI.RawUI.WindowTitle = "Post-Scam System Integrity Scanner"
$ErrorActionPreference = "SilentlyContinue"
$now = Get-Date
$lookback = (Get-Date).AddDays(-14)
$computer = $env:COMPUTERNAME
$ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not (Test-Path $ScriptFolder)) { $ScriptFolder = $PWD }
$log = Join-Path $ScriptFolder ("PostScam_Audit_{0}_{1}.txt" -f $computer,$now.ToString('yyyyMMdd_HHmmss'))

function Log { param($m,[string]$c="Gray")
    Write-Host $m -ForegroundColor $c
    "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),$m | Out-File -FilePath $log -Append -Encoding UTF8
}
function Open-Select { param($p) if(Test-Path $p){Start-Process explorer.exe "/select,`"$p`""}}
function Is-SuspiciousPath($p){if(!$p){return $false};$p=$p.ToLower();return($p -match "\\users\\.*\\appdata" -or $p -match "\\downloads" -or $p -match "\\programdata\\" -or $p -match "\\temp\\" -or $p -match "\\roaming")}

$RAKeys=@('screenconnect','connectwise','anydesk','teamviewer','ultraviewer','realvnc','tightvnc','ultravnc',
'splashtop','zoho assist','ammyy','aero admin','supremo','dwservice','rustdesk','chrome remote desktop','crd')
$installerExt='exe','msi','zip','rar'
$summary=[ordered]@{StartupItems=0;RunKeyHits=0;ServicesSuspicious=0;ServicesDisabledHits=0;SchedTasksSuspicious=0;
InstallersFound=0;HostsAnomalies=0;FirewallFindings=0;NewAdmins=0;RecentUsers=0;PSAbuseEvents=0;UnsignedDrivers=0;RecentInstalls=0}

Clear-Host
Write-Host "=== Post-Scam System Integrity Scanner (Technician Edition) ===`n" -ForegroundColor Cyan
Log "Log: $log" "DarkGray"

# ------------------ USER PROFILES ------------------
$UserProfiles=Get-ChildItem "C:\Users" -Directory|Where-Object{$_.Name -notmatch "^(Default|Public|All Users|Default User)$"}
Log ("Scanning {0} profiles" -f $UserProfiles.Count) "DarkGray"

foreach($profile in $UserProfiles){
 $UserName=$profile.Name
 Log "`n--- USER PROFILE: $UserName ---" "Cyan"

 # Startup folders
 $startup=@("$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")|Where-Object{Test-Path $_}
 foreach($f in $startup){
   foreach($it in (Get-ChildItem $f -Force -ErrorAction SilentlyContinue|Where-Object{!$_.PSIsContainer})){
     if($RAKeys|Where-Object{$it.Name.ToLower()-like"*$_*"}){Log "Startup item: $($it.FullName)" "Yellow";$summary.StartupItems++;Open-Select $it.FullName}
   }
 }

 # Run keys
 $ntuser="$($profile.FullName)\NTUSER.DAT"
 if(Test-Path $ntuser){
  try{
   reg load HKU\TempHive "$ntuser" >$null 2>&1
   foreach($rk in "HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\Run","HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\RunOnce"){
     if(Test-Path $rk){
      (Get-ItemProperty $rk).PSObject.Properties|Where-Object{Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider'}|ForEach-Object{
        $v=[string]$_.Value
        if($RAKeys|Where-Object{$v.ToLower()-like"*$_*"}){Log "RunKey ($UserName): $rk -> $($_.Name) = $v" "Yellow";$summary.RunKeyHits++}
      }
     }
   }
  }finally{reg unload HKU\TempHive >$null 2>&1}
 }

 # Installer search
 foreach($r in "$($profile.FullName)\Downloads","$($profile.FullName)\Desktop"){
  if(Test-Path $r){
   foreach($f in (Get-ChildItem $r -Recurse -Force -ErrorAction SilentlyContinue|Where-Object{!$_.PSIsContainer -and $_.Extension.TrimStart('.').ToLower() -in $installerExt})){
    if($RAKeys|Where-Object{$f.Name.ToLower()-like"*$_*"}){Log "Installer ($UserName): $($f.FullName)" "Yellow";Open-Select $f.FullName;$summary.InstallersFound++}
   }
  }
 }
}

# ------------------ SERVICES ------------------
Log "`n[Services]" "Cyan"
Get-WmiObject Win32_Service|ForEach-Object{
 $img=$_.PathName
 $isRA=$false
 foreach($k in $RAKeys){if($_.Name -match [regex]::Escape($k) -or ($img -and $img.ToLower()-like"*${k}*")){$isRA=$true;break}}
 $sus=Is-SuspiciousPath $img
 if($isRA -or $sus){
  $c=if($_.State -eq'Stopped'-and $_.StartMode -eq'Disabled'){$summary.ServicesDisabledHits++;'DarkYellow'}else{'Yellow'}
  Log ("Service: {0} [{1}/{2}] -> {3}" -f $_.Name,$_.State,$_.StartMode,$img) $c
  $summary.ServicesSuspicious++
 }
}

# ------------------ TASKS ------------------
Log "`n[Scheduled Tasks]" "Cyan"
$susp='powershell','wscript','cscript','mshta','bitsadmin','curl','wget','invoke-webrequest','downloadstring','regsvr32'
try{
 Get-ScheduledTask|ForEach-Object{
  $a=($_.Actions|ForEach-Object{$_.Execute+" "+$_.Arguments})-join' '
  if(($RAKeys|Where-Object{$a -like"*$_*"}) -or ($susp|Where-Object{$a -like"*$_*"}) -or (Is-SuspiciousPath $a)){
   Log ("Task: {0} -> {1}" -f $_.TaskName,$a) "Yellow";$summary.SchedTasksSuspicious++
  }
 }
}catch{Log "Unable to enumerate tasks" "DarkGray"}

# ------------------ HOSTS ------------------
Log "`n[Hosts File]" "Cyan"
$hosts="$env:SystemRoot\System32\drivers\etc\hosts"
if(Test-Path $hosts){
 $lines=Get-Content $hosts|Where-Object{$_ -and $_ -notmatch '^#'}
 if($lines){
    Log "Hosts file contains custom entries - review." "Yellow"
    Open-Select $hosts
    $summary.HostsAnomalies=$lines.Count
 } else {
    Log "No custom hosts entries." "Green"
 }
}else{
 Log "Hosts not found" "DarkYellow"
}

# ------------------ FIREWALL ------------------
Log "`n[Firewall]" "Cyan"
$fw=Get-NetFirewallRule -ErrorAction SilentlyContinue
if($fw){
 $cand=$fw|Where-Object{$_.Enabled -eq'True' -and ($_.DisplayName -match 'remote|rdp|vnc|anydesk|teamviewer|screenconnect|connectwise|ultraviewer|chrome remote')}
 if($cand){$cand|ForEach-Object{Log ("Firewall: {0} [{1}/{2}]" -f $_.DisplayName,$_.Direction,$_.Action) "Yellow"};$summary.FirewallFindings=$cand.Count}
 else{Log "No obvious remote rules." "Green"}
}else{Log "Firewall API unavailable." "DarkGray"}

# ------------------ ADMINS & USERS ------------------
Log "`n[Local Admins / Recent Users]" "Cyan"
try{
 $admins=(net localgroup administrators)2>$null|Where-Object{$_ -and $_ -notmatch 'Alias name|Comment|Members|completed'}
 foreach($a in $admins){Log "Local Admin: $a" "Yellow";$summary.NewAdmins++}
}catch{}
try{
 $u=Get-LocalUser|Where-Object{$_.Enabled -and $_.LastLogon -ge $lookback}
 foreach($x in $u){Log ("Recent user: {0} ({1})" -f $x.Name,$x.LastLogon) "Yellow"}
 $summary.RecentUsers=$u.Count
}catch{}

# ------------------ POWERSHELL LOGS ------------------
Log "`n[PowerShell Abuse]" "Cyan"
try{
 $ps=Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 200
 $bad=$ps|Where-Object{$_.TimeCreated -ge $lookback -and $_.Message -match 'DownloadString|Invoke-Expression|IEX|FromBase64String|Invoke-WebRequest|curl|wget'}
 foreach($b in $bad){Log ("PS Event: {0}" -f $b.TimeCreated) "Yellow"}
 $summary.PSAbuseEvents=$bad.Count
}catch{Log "PowerShell log unavailable" "DarkGray"}

# ------------------ UNSIGNED DRIVERS ------------------
Log "`n[Unsigned Drivers]" "Cyan"
try{
 $drv=(driverquery /v /fo csv|ConvertFrom-Csv)
 $u=$drv|Where-Object{$_.'Signed' -and $_.'Signed'.ToLower() -notmatch 'yes|true'}
 foreach($d in $u){Log ("Unsigned: {0}" -f $d.ModuleName) "Yellow"}
 $summary.UnsignedDrivers=$u.Count
}catch{Log "driverquery unavailable" "DarkGray"}

# ------------------ RECENT INSTALLS ------------------
Log "`n[Recent Installs]" "Cyan"
$roots = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
          'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'

foreach ($r in $roots) {
    if (Test-Path $r) {
        Get-ChildItem $r | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            $d = $null
            if ($p.InstallDate -and $p.InstallDate.ToString() -match '^\d{8}$') {
                $d = [datetime]::ParseExact($p.InstallDate, 'yyyyMMdd', $null)
            } elseif ($p.InstallDate -is [datetime]) {
                $d = $p.InstallDate
            }

            if ($d -and $d -ge $lookback) {
                $name = if ($p.DisplayName) { $p.DisplayName } else { "(no name)" }
                Log ("Recent install: {0} ({1})" -f $name, $d) "Yellow"
                $summary.RecentInstalls++
            }
        }
    }
}

# ------------------ RDP POSTURE ------------------
Log "`n[RDP Posture]" "Cyan"
try{
 $rdp=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
 if($rdp -eq 0){Log "RDP Enabled (verify NLA)" "Yellow"}else{Log "RDP Disabled" "Green"}
}catch{Log "RDP key unreadable" "DarkGray"}

# ------------------ SUMMARY ------------------
Write-Host "`n==================== SUMMARY ====================" -ForegroundColor Cyan
$summary.GetEnumerator()|Sort-Object Name|ForEach-Object{
 $l="{0,-22}: {1}" -f $_.Key,$_.Value
 Write-Host $l -ForegroundColor ($(if($_.Value -gt 0){"Yellow"}else{"DarkGray"}))
}
Write-Host "`nLog saved to: $log" -ForegroundColor DarkGray
Write-Host "`nPress Enter to close..." -ForegroundColor Cyan
[void][System.Console]::ReadLine();exit
